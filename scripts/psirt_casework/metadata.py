"""One verified metadata entry for repeated loopback status requests.

Stat identities invalidate this cache; they do not replace the loader's hash
verification. This is a single-user local optimization, not protection against
an adversary able to rewrite the report root and preserve filesystem metadata.
"""
import copy
import os
import re
import stat
import threading
from pathlib import Path

from psirt_daily.pipeline import no_symlinks, read_json
from .store import Invalid

ARTIFACTS = ('manifest.json', 'capture.json', 'index.html', 'report_presentation_used.json')
SOURCES = ('kev', 'dt', 'salesforce', 'jira')
STATE_LIMIT = 262144


def _identity(path):
    no_symlinks(path)
    value = path.stat()
    if not stat.S_ISREG(value.st_mode):
        raise Invalid('MetadataFileRejected')
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _small(value, run_id):
    """Keep only the existing public metadata contract, never source payloads."""
    if not isinstance(value, dict) or value.get('run_id') != run_id:
        raise Invalid('MetadataResultRejected')
    sources = value.get('sources')
    if (not isinstance(sources, dict) or set(sources) != set(SOURCES) or
            type(value.get('synthetic')) is not bool or type(value.get('offline')) is not bool):
        raise Invalid('MetadataResultRejected')
    result = {key: value.get(key) for key in ('run_id', 'captured_at', 'mode', 'synthetic', 'offline')}
    if any(item is not None and (not isinstance(item, str) or len(item) > 256)
           for key, item in result.items() if key not in ('synthetic', 'offline')):
        raise Invalid('MetadataResultRejected')
    result['sources'] = {}
    for name in SOURCES:
        source = sources[name]
        if not isinstance(source, dict):
            raise Invalid('MetadataResultRejected')
        status, complete, observed = (source.get(key) for key in ('status', 'complete', 'observed_at'))
        if (status not in ('SUCCESS', 'PARTIAL', 'FAILED') or type(complete) is not bool or
                (observed is not None and (not isinstance(observed, str) or len(observed) > 256))):
            raise Invalid('MetadataResultRejected')
        result['sources'][name] = {'status': status, 'complete': complete, 'observed_at': observed}
    return result


class MetadataCache:
    """Call ``loader(state)`` only when the pinned report's identity changes.

    The loader must validate the supplied state's manifest/artifact hashes and
    return the same small dictionary as ``service.view_metadata``. No timers or
    source collectors are invoked here; the cache retains at most one entry.
    """
    def __init__(self, root, loader):
        self.root = Path(os.path.abspath(root))
        no_symlinks(self.root)
        self.loader = loader
        self.lock = threading.Lock()
        self.entry = None

    def _snapshot(self):
        path = self.root / 'state.json'
        _identity(path)
        with path.open('rb') as stream:
            raw = stream.read(STATE_LIMIT + 1)
        if len(raw) > STATE_LIMIT:
            raise Invalid('MetadataStateTooLarge')
        state = read_json(raw)
        if not isinstance(state, dict) or not isinstance(state.get('latest_run'), str):
            raise Invalid('MetadataStateRejected')
        run = Path(state['latest_run'])
        digest = state.get('manifest_sha256')
        if (not run.is_absolute() or run.parent != self.root / 'runs' or
                not re.fullmatch(r'[A-Za-z0-9_+.-]+', run.name) or run.name in ('.', '..') or
                not isinstance(digest, str) or not re.fullmatch(r'[a-f0-9]{64}', digest)):
            raise Invalid('MetadataRunRejected')
        files = (self.root / '.psirt-ops', *(run / name for name in ARTIFACTS))
        key = (str(run), digest, tuple(_identity(file) for file in files))
        return state, key

    def get(self):
        with self.lock:
            for _ in range(2):
                state, before = self._snapshot()
                if self.entry is not None and self.entry[0] == before:
                    return copy.deepcopy(self.entry[1])
                # A failed validation must never fall back to an older entry.
                self.entry = None
                value = _small(self.loader(copy.deepcopy(state)), Path(state['latest_run']).name)
                _, after = self._snapshot()
                if before == after:
                    self.entry = (before, copy.deepcopy(value))
                    return copy.deepcopy(value)
            raise Invalid('MetadataChangedDuringValidation')
