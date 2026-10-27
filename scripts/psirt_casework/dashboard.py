"""Evidence-bound dashboard over the existing projection; no reads or writes."""
from .store import STAGES, timestamp
from .effort import summarize_work

VERSION = 'case-dashboard/1'
EMPTY_BLOCKERS = {'', '-', '--', '—', '無', '沒有', '暫無', '尚無', '無卡點', '無阻塞',
                  'none', 'n/a', 'na', 'nil', 'null', 'not applicable'}
METRICS = {
    'total': ('範圍內案件', 'neutral'),
    'active': ('已確認階段進行中', 'info'),
    'waiting': ('已登錄等待／卡點', 'warning'),
    'overdue': ('已確認承諾／修補期限逾期', 'danger'),
    'jira_done': ('已追蹤 Jira 完成', 'success'),
    'stage_unknown': ('目前階段待確認', 'neutral'),
}


def _time(value):
    try:
        return timestamp(value)
    except (ValueError, TypeError):
        return None


def _text(value):
    return isinstance(value, str) and bool(value.strip())


def _unique(records):
    """Projection records use stable Store IDs; shared associations are not copies."""
    result = {}
    for record in records or []:
        if not isinstance(record, dict) or not record.get('id') or not isinstance(record.get('payload'), dict):
            continue
        key = str(record['id'])
        prior = result.get(key)
        if prior is None or record.get('version', 0) > prior.get('version', 0):
            result[key] = record
    return list(result.values())


def _records(data, rows, key):
    records = data.get(key)
    return _unique(records if isinstance(records, list) else [r for row in rows for r in row.get(key, [])])


def _related(records, row, key):
    linked = {str(record.get('id')) for record in row.get(key, [])}
    return [record for record in records if str(record['id']) in linked or
            row['id'] in record['payload'].get('case_ids', []) or record['payload'].get('case_id') == row['id']]


def _current(row, moment):
    stage = row.get('stage')
    if stage not in STAGES or stage == 'unknown' or not moment:
        return 'unknown'
    entered = row.get('entered_at')
    if entered and (not _time(entered) or _time(entered) > moment):
        return 'unknown'
    return stage


def _completed(visit, moment):
    entered, exited = _time(visit.get('entered_at')), _time(visit.get('exited_at'))
    return bool(moment and visit.get('confirmation') == 'confirmed' and
                all(_text(visit.get(key)) for key in ('entry_evidence', 'exit_evidence', 'reviewer')) and
                entered and exited and entered <= exited <= moment)


def _timeline(row, current, moment):
    result = []
    for key, (label, _, _) in STAGES.items():
        if key == 'unknown':
            continue
        visits = [visit for visit in row.get('stage_visits', []) if visit.get('stage') == key]
        completed = [visit for visit in visits if _completed(visit, moment)]
        state = 'current' if key == current else 'completed' if completed else 'unknown'
        note = None
        if state == 'current':
            latest = visits[-1] if visits else {}
            reentry = latest.get('event') == 'reentry' or any(v.get('id') != latest.get('id') for v in completed)
            note = '重新進入此階段；既往離開紀錄保留' if reentry else '目前已確認階段；不代表前面各階段已完成'
        elif state == 'completed':
            note = '已有確認進出證據；不等於整案完成'
        result.append({'key': key, 'stage': key, 'label': label, 'state': state, 'note': note,
                       'visits': list(dict.fromkeys(v['id'] for v in visits if v.get('id')))})
    return result


def _due(row, kind, moment):
    item = row.get('dates', {}).get(kind, {})
    expected = {'commitment': 'COMMITMENT_OVERDUE', 'remediation': 'REMEDIATION_DUE_EXCEEDED',
                'followup': 'FOLLOWUP_DUE'}[kind]
    # Preserve UNKNOWN from the projection, including unresolved legacy conflicts.
    if item.get('state') != expected or not moment:
        return False
    basis = item.get('basis') or {}
    at = _time(item.get('at'))
    required = ('evidence', 'confirmed_by') + (('basis_version', 'trigger_event', 'scope') if kind == 'remediation' else ())
    if basis.get('confirmation') != 'confirmed' or not all(_text(basis.get(key)) for key in required) or not at or at > moment:
        return False
    ended = _time(basis.get('completed_at'))
    return not (ended and ended <= moment and _text(basis.get('completion_evidence')))


def _waiting(row, waits, moment):
    # row.blocker has already passed the projection's shared confirmation resolver.
    blocker = str(row.get('blocker') or '').strip().casefold().rstrip(' .。')
    if blocker not in EMPTY_BLOCKERS:
        return True
    for record in waits:
        payload = record['payload']
        start, end = _time(payload.get('start')), _time(payload.get('end'))
        if not moment or not start or start > moment or not _text(payload.get('evidence')):
            continue
        # A future end has not happened yet. Missing, malformed, or backwards
        # end times cannot establish that this evidenced wait has ended.
        if end is None or end < start or end > moment:
            return True
    return False


def _deliveries(records, moment):
    received, accepted = [], []
    for record in _unique(records):
        payload = record['payload']
        at = _time(payload.get('received_at'))
        if not moment or not at or at > moment or not all(_text(payload.get(key)) for key in ('title', 'outcome', 'evidence', 'reviewer')):
            continue
        received.append(str(record['id']))
        accepted_at = _time(payload.get('accepted_at'))
        if (payload.get('acceptance') == 'accepted' and accepted_at and at <= accepted_at <= moment and
                _text(payload.get('acceptance_evidence'))):
            accepted.append(str(record['id']))
    return {'received': len(received), 'accepted': len(accepted), 'pending': len(received) - len(accepted),
            'percent': round(100 * len(accepted) / len(received), 1) if received else None,
            'received_ids': sorted(received), 'accepted_ids': sorted(accepted),
            'label': '本機已登錄交付的接受比例（非整案完成率）'}


def _work(records, moment):
    return summarize_work(records, moment)


def build(projection):
    """Build clickable scope counts and evidence-backed stage/delivery views."""
    data = projection or {}
    moment = _time(data.get('as_of'))
    source = data.get('source') or {}
    rows = list({row['id']: row for row in data.get('cases', []) or [] if isinstance(row, dict) and row.get('id')}.values())
    complete = bool(moment and source.get('status') == 'SUCCESS' and source.get('complete') is True and
                    (data.get('counts') or {}).get('total') is not None)
    worklogs, waits, deliveries = (_records(data, rows, key) for key in ('worklogs', 'waits', 'deliveries'))
    cases = {}
    for row in rows:
        key = row['id']
        stage = _current(row, moment)
        flags = {'jira_done': row.get('jira_status_category') == 'done', 'stage_unknown': stage == 'unknown',
                 'waiting': bool(_waiting(row, _related(waits, row, 'waits'), moment)),
                 'overdue': _due(row, 'commitment', moment) or _due(row, 'remediation', moment),
                 'followup_due': _due(row, 'followup', moment)}
        flags['active'] = stage != 'unknown' and not flags['jira_done']
        state = next((name for name in ('overdue', 'waiting', 'jira_done', 'active') if flags[name]), 'stage_unknown')
        own_work = _work(_related(worklogs, row, 'worklogs'), moment)
        cases[key] = {'id': key, 'stage': stage, 'state': state, 'label': METRICS[state][0], 'tone': METRICS[state][1],
                      'flags': flags, 'timeline': _timeline(row, stage, moment),
                      'deliveries': _deliveries(_related(deliveries, row, 'deliveries'), moment),
                      'actual_minutes': own_work['actual_minutes'], 'worklog_count': own_work['record_count']}

    def metric(key, label, tone):
        ids = sorted(key_ for key_, row in cases.items() if key == 'total' or row['flags'][key])
        return {'key': key, 'label': label, 'value': len(ids) if complete else None,
                'observed_count': len(ids), 'case_ids': ids, 'tone': tone}

    delivery = _deliveries(deliveries, moment)
    work = _work(worklogs, moment)
    work.update(received_count=delivery['received'], accepted_count=delivery['accepted'])
    return {'schema': VERSION, 'as_of': data.get('as_of'),
            'scope': {'label': '本輪未結案＋本機已追蹤案件（非完整歷史）', 'complete': complete,
                      'status': source.get('status'), 'historical': bool(source.get('historical'))},
            'metrics': {key: metric(key, label, tone) for key, (label, tone) in METRICS.items()},
            'followup_due': metric('followup_due', '本人追蹤日已到（非期限逾期）', 'warning'),
            'stages': [{'key': key, 'label': values[0], 'count': sum(row['stage'] == key for row in cases.values()) if complete else None,
                        'observed_count': sum(row['stage'] == key for row in cases.values()),
                        'case_ids': sorted(id_ for id_, row in cases.items() if row['stage'] == key)} for key, values in STAGES.items()],
            'cases': cases, 'work': work, 'deliveries': delivery,
            'limits': ['範圍為本輪未結案與本機已追蹤案件；不是全公司清單或完整歷史結案率',
                       '來源不完整時總數為 Unknown，已觀測案件仍可篩選',
                       '進行中、等待及逾期可重疊，各卡片不能相加當總案件數',
                       '節點完成僅表示已有確認進出證據；不依階段位置推算整案完成百分比',
                       'Jira 完成、本機結案節點及交付已接受均不等於修補完成、確認受影響或正式風險接受',
                       '交付比例僅為本機已接受／已收到；無收到紀錄時為 Unknown',
                       '工時僅為本機登錄紀錄，不由 Jira assignee 推算個人工時；未登錄不是零',
                       '跨案共用工時與交付按唯一紀錄 ID 計算；各案件列不可直接相加',
                       '本人追蹤日不當作修補逾期；未確認期限不當作準時']}
