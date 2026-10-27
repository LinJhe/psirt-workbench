"""Local SF authentication circuit; called only by the live, root-locked collector.

Contains safe error codes and dates, never authentication values or response text.
Read/replay rendering must not mutate this file or attempt authentication.
"""
import json
import os
import urllib.error
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from psirt_daily.pipeline import encoded, no_symlinks, read_json, sync_directory, write_new

EXPIRED = 'INVALID_OPERATION_WITH_EXPIRED_PASSWORD'
ERROR_CODES = frozenset({EXPIRED, 'INVALID_SESSION_ID', 'INVALID_AUTH_HEADER',
    'INVALID_LOGIN', 'API_DISABLED_FOR_ORG', 'REQUEST_LIMIT_EXCEEDED',
    'INVALID_FIELD', 'MALFORMED_QUERY', 'INSUFFICIENT_ACCESS',
    'INSUFFICIENT_ACCESS_OR_READONLY', 'QUERY_TIMEOUT'})
SCHEMA = 'psirt-sf-auth-block/1'
BODY_LIMIT = 8192


def error_code(exc):
    """Consume at most 8193 error bytes once; expose only an allowlisted code."""
    if not isinstance(exc, urllib.error.HTTPError):
        return None
    if hasattr(exc, '_psirt_error_code'):
        return exc._psirt_error_code
    code = None
    try:
        raw = exc.read(BODY_LIMIT + 1)
        if isinstance(raw, bytes) and len(raw) <= BODY_LIMIT:
            data = json.loads(raw)
            entries = data if isinstance(data, list) else [data]
            codes = {row.get('errorCode') for row in entries
                     if isinstance(row, dict) and isinstance(row.get('errorCode'), str)}
            # Conflicting codes must not claim one unambiguous expiry diagnosis.
            if len(entries) <= 8 and len(codes) == 1 and next(iter(codes)) in ERROR_CODES:
                code = next(iter(codes))
    except Exception:
        pass  # Unknown/malformed/oversized responses stay unknown, not expired.
    exc._psirt_error_code = code
    return code


def _date(value):
    if not isinstance(value, str) or len(value) > 80:
        raise ValueError('SFAuthStateRejected')
    try:
        stamp = datetime.fromisoformat(value)
        if stamp.tzinfo is None:
            raise ValueError()
    except ValueError:
        raise ValueError('SFAuthStateRejected') from None
    return value


def load(root):
    if root is None:
        return None
    path = Path(root) / 'sf-auth-state.json'
    no_symlinks(path)
    if not path.exists():
        return None
    if path.stat().st_size > 4096:
        raise ValueError('SFAuthStateRejected')
    state = read_json(path.read_bytes())
    allowed = {'schema', 'blocked', 'error_code', 'first_failed_at', 'last_failed_at',
               'last_attempt_at', 'cleared_at'}
    if (not isinstance(state, dict) or set(state) != allowed or state['schema'] != SCHEMA
            or type(state['blocked']) is not bool or state['error_code'] != EXPIRED):
        raise ValueError('SFAuthStateRejected')
    for key in ('first_failed_at', 'last_failed_at', 'last_attempt_at'):
        _date(state[key])
    if state['cleared_at'] is not None:
        _date(state['cleared_at'])
    return state


def _save(root, state):
    path = Path(root) / 'sf-auth-state.json'
    no_symlinks(path)
    temporary = path.with_name('sf-auth-state-' + uuid4().hex + '.tmp')
    write_new(temporary, encoded(state))
    temporary.chmod(0o600)
    os.replace(temporary, path)
    sync_directory(path.parent)


def update(root, source, previous=None):
    """Persist an observed expiry; only a complete REST observation clears it."""
    if root is None or source.get('attempted') is not True:
        return previous
    at = _date(source['attempted_at'])
    expired = any(error.get('error_code') == EXPIRED and error.get('http_status') == 401
                  for error in source.get('errors', []))
    if expired:
        state = {'schema': SCHEMA, 'blocked': True, 'error_code': EXPIRED,
                 'first_failed_at': previous['first_failed_at'] if previous and previous['blocked'] else at,
                 'last_failed_at': at, 'last_attempt_at': at, 'cleared_at': None}
        _save(root, state)
        return state
    if previous and previous['blocked']:
        state = {**previous, 'last_attempt_at': at}
        if source.get('status') == 'SUCCESS' and source.get('complete') is True:
            state.update(blocked=False, cleared_at=source.get('observed_at') or at)
        _save(root, state)
        return state
    return previous


def decorate(source, state, *, attempted, at):
    """Public source metadata; skipped runs retain the original failure date."""
    blocked = bool(state and state['blocked'])
    source.update(attempted=attempted, attempted_at=at if attempted else None,
                  auth_blocked=blocked, auth_error_code=state['error_code'] if blocked else None,
                  auth_blocked_at=state['first_failed_at'] if blocked else None)
    if not attempted and blocked:
        source.update(status='FAILED', complete=False, observed_at=state['last_failed_at'],
                      skipped_reason='AUTHENTICATION_REQUIRES_MANUAL_RECOVERY',
                      errors=[{'type': 'AuthenticationBlocked', 'http_status': 401,
                               'error_code': EXPIRED}])
    return source
