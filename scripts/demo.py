#!/usr/bin/env python3
"""Run the isolated synthetic demonstration; never selects live collection."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'runtime/demo'


def child(*args):
    result = subprocess.run([sys.executable, '-B', *map(str, args)], cwd=ROOT,
                            capture_output=True, text=True)
    if result.stderr:
        print(result.stderr, file=sys.stderr, end='')
    try:
        receipt = json.loads(result.stdout)
    except ValueError:
        raise RuntimeError('InvalidChildReceipt') from None
    if result.returncode != receipt.get('exit_code', result.returncode):
        raise RuntimeError('ChildReceiptMismatch')
    return receipt


def build():
    receipt = child(ROOT / 'scripts/run_psirt_ops.py', '--mode', 'snapshot-replay',
                    '--snapshot', ROOT / 'examples/snapshot.json', '--presentation',
                    ROOT / 'examples/presentation.json', '--output-dir', OUTPUT,
                    '--report-date', '2026-10-26')
    if receipt.get('exit_code') == 0:
        # A share demo is opt-in: viewing it must not start timed collection.
        settings = OUTPUT / 'refresh-settings.json'
        try:
            with settings.open('x', encoding='utf-8') as target:
                json.dump({'schema': 'psirt-refresh-settings/1', 'auto_enabled': False}, target)
            os.chmod(settings, 0o600)
        except FileExistsError:
            pass
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['build', 'start', 'stop', 'status'])
    args = parser.parse_args()
    try:
        if args.action == 'build':
            result = build()
        else:
            if args.action == 'start' and not (OUTPUT / 'state.json').exists():
                result = build()
                if result.get('exit_code'):
                    print(json.dumps(result, ensure_ascii=False))
                    return result['exit_code']
            result = child(ROOT / 'scripts/run_psirt_casework.py', args.action,
                           '--output-dir', OUTPUT)
        print(json.dumps(result, ensure_ascii=False))
        return result.get('exit_code', 0)
    except Exception as exc:
        print(json.dumps({'exit_code': 2, 'error_type': type(exc).__name__}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
