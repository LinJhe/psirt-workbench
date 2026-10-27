"""Shared, time-bounded effort totals over local records; no I/O or mutation."""
from datetime import date, datetime

from .store import TZ, timestamp

RULE_VERSION = 'case-effort/2'


def _time(value):
    if isinstance(value, datetime):
        return value.astimezone(TZ) if value.tzinfo is not None else None
    try:
        return timestamp(value)
    except (TypeError, ValueError):
        return None


def unique_work(records):
    """Use one latest revision per work ID, including shared and unbound work."""
    latest = {}
    for record in records or []:
        if not isinstance(record, dict) or not record.get('id') or not isinstance(record.get('payload'), dict):
            continue
        key = str(record['id'])
        previous = latest.get(key)
        if previous is None or record.get('version', 0) > previous.get('version', 0):
            latest[key] = record
    return list(latest.values())


def _excluded_reason(payload, moment):
    if moment is None:
        return 'AS_OF_UNKNOWN'
    try:
        work_date = date.fromisoformat(payload.get('work_date', ''))
    except (TypeError, ValueError):
        return 'WORK_DATE_INVALID'
    if work_date > moment.date():
        return 'WORK_DATE_FUTURE'
    start, end = _time(payload.get('start')), _time(payload.get('end'))
    has_start, has_end = bool(payload.get('start')), bool(payload.get('end'))
    if has_start != has_end:
        return 'WORK_PERIOD_INCOMPLETE'
    if has_start:
        if not start or not end or end <= start or start.date() != work_date or end.date() != work_date:
            return 'WORK_PERIOD_INVALID'
        if end > moment:
            return 'WORK_PERIOD_NOT_FINISHED'
    # Both endpoints may legitimately be omitted for recorded net minutes.
    # They cannot prove interval overlap, but that does not invalidate the record.
    if type(payload.get('minutes')) is not int or payload['minutes'] < 0:
        return 'MINUTES_INVALID'
    if payload.get('measurement') not in ('measured', 'estimated'):
        return 'MEASUREMENT_UNKNOWN'
    return None


def summarize_work(records, as_of):
    """Use the same eligibility and unknown semantics in every casework view.

    Records outside the calculation time remain in the caller's original list.
    An empty measured set is unknown, even if estimated work exists.
    """
    moment = _time(as_of)
    unique = unique_work(records)
    eligible, excluded = [], []
    for record in unique:
        reason = _excluded_reason(record['payload'], moment)
        if reason:
            excluded.append({'id': str(record['id']), 'reason': reason})
        else:
            eligible.append(record)
    measured = [r for r in eligible if r['payload']['measurement'] == 'measured']
    estimated = [r for r in eligible if r['payload']['measurement'] == 'estimated']

    def ids(items):
        return sorted(str(record['id']) for record in items)

    shared = [r for r in eligible if len(set(r['payload'].get('case_ids', []) +
              ([r['payload']['case_id']] if r['payload'].get('case_id') else []))) > 1]
    return {'rule_version': RULE_VERSION, 'as_of': moment.isoformat() if moment else None,
            'actual_minutes': sum(r['payload']['minutes'] for r in measured) if measured else None,
            'estimated_minutes': sum(r['payload']['minutes'] for r in estimated) if estimated else None,
            'record_count': len(eligible), 'stored_record_count': len(unique),
            'measured_record_count': len(measured), 'measured_record_ids': ids(measured),
            'estimated_record_ids': ids(estimated), 'shared_record_ids': ids(shared),
            'untimed_record_ids': ids([r for r in eligible if not r['payload'].get('start')]),
            'excluded_records': sorted(excluded, key=lambda item: item['id']),
            'label': '本機唯一工作紀錄；依計算時間納入已登錄實測分鐘，估計另列'}
