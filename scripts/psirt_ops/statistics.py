"""Pure, compact Jira/KEV statistics anchored to the captured cutoff.

Exact counts require complete sources and sufficient field evidence. Observed
counts and source references remain available when that requirement is unmet.
No clock, source collection, filesystem or database access is used here.
"""
import json
import re
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

SCHEMA = 'psirt-statistics/1'
TAIPEI = ZoneInfo('Asia/Taipei')
CVE = re.compile(r'CVE-\d{4}-\d{4,}\Z')


def _dict(value):
    return value if isinstance(value, dict) else {}


def _text(value):
    return value.strip() if isinstance(value, str) and value.strip() else None


def _cve(value):
    value = (_text(value) or '').upper()
    return value if CVE.fullmatch(value) else None


def _instant(value):
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed.astimezone(TAIPEI) if parsed.utcoffset() is not None else None
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None


def _day(value):
    try:
        if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', value):
            return None
        return date.fromisoformat(value)
    except ValueError:
        return None


def _source_complete(source):
    return source.get('status') == 'SUCCESS' and source.get('complete') is True


def _source_fields(source):
    return {key: source.get(key) for key in ('status', 'observed_at')}


def _periods(config):
    start, end = _instant(config.get('window_start')), _instant(config.get('cutoff'))
    errors = []
    if start is None:
        errors.append('QUERY_START_UNKNOWN')
    if end is None:
        errors.append('CUTOFF_UNKNOWN')
    if start is not None and end is not None and start > end:
        errors.append('QUERY_START_AFTER_CUTOFF')
    week = (end - timedelta(days=end.weekday())).replace(hour=0, minute=0, second=0, microsecond=0) if end else None
    return {'query': {'start': start.isoformat() if start else None,
                      'end': end.isoformat() if end else None},
            'calendar_week': {'start': week.isoformat() if week else None,
                              'end': end.isoformat() if end else None,
                              'timezone': 'Asia/Taipei', 'basis': 'capture.config.cutoff'},
            'errors': errors}, (start, end, week)


def _groups(rows, identify):
    groups, warnings = {}, []
    if not isinstance(rows, list):
        return groups, ['ROWS_NOT_AVAILABLE'], False
    valid = True
    for position, row in enumerate(rows):
        key = identify(row) if isinstance(row, dict) else None
        if key is None:
            valid = False
            warnings.append('ROW_ID_UNKNOWN')
            continue
        groups.setdefault(key, []).append((position, row))
    if any(len(group) > 1 for group in groups.values()):
        warnings.append('DUPLICATE_IDS_DEDUPLICATED')
    return groups, warnings, valid


def _added(comparison, source_complete, identify):
    changes = _dict(comparison.get('changes'))
    groups, warnings, valid = _groups(changes.get('added'), identify)
    comparable = source_complete and comparison.get('comparison') == 'COMPARABLE' and valid
    return sorted(groups) if comparable else None


def _kev(source, comparison, bounds):
    catalog = _dict(source.get('raw'))
    rows = catalog.get('vulnerabilities')
    groups, warnings, valid = _groups(rows, lambda row: _cve(row.get('cveID')))
    # CISA count declares source rows; user statistics count distinct CVE IDs.
    # Preserve de-duplicated observations while rejecting a truncated catalog.
    if 'count' in catalog:
        declared = catalog['count']
        if type(declared) is not int or declared < 0:
            valid = False
            warnings.append('CATALOG_DECLARED_COUNT_INVALID')
        elif not isinstance(rows, list) or declared != len(rows):
            valid = False
            warnings.append('CATALOG_DECLARED_COUNT_MISMATCH')
    complete = _source_complete(source) and valid
    start, end, week = bounds
    ids = {'catalog': sorted(groups), 'window': [], 'week': []}
    dates_complete = True
    for key, group in groups.items():
        days = {_day(row.get('dateAdded')) for _, row in group}
        if None in days or len(days) != 1:
            dates_complete = False
            warnings.append('DATE_ADDED_UNKNOWN_OR_CONFLICTING')
        # Keep all observed memberships, but never claim an exact date total
        # when a missing/conflicting date prevents a unique classification.
        known = days - {None}
        if start and end and start <= end and any(start.date() <= value <= end.date() for value in known):
            ids['window'].append(key)
        if week and end and any(week.date() <= value <= end.date() for value in known):
            ids['week'].append(key)
    for key in ('window', 'week'):
        ids[key].sort()
    observed = {key: len(value) for key, value in ids.items()}
    counts = {'catalog': observed['catalog'] if complete else None,
              'window': observed['window'] if complete and dates_complete and start and end and start <= end else None,
              'week': observed['week'] if complete and dates_complete and week and end else None}
    ids['added'] = _added(comparison, complete, lambda row: _cve(row.get('cveID')))
    counts['added'] = len(ids['added']) if ids['added'] is not None else None
    return {**_source_fields(source), 'complete': complete, 'counts': counts,
            'observed_counts': observed, 'ids': ids,
            'comparison': comparison.get('comparison', 'UNKNOWN'),
            'catalog_version': catalog.get('catalogVersion'),
            'declared_rows': catalog.get('count') if type(catalog.get('count')) is int else None,
            'observed_rows': len(rows) if isinstance(rows, list) else 0,
            'date_precision': 'day', 'warnings': sorted(set(warnings))}


def _jira(source, comparison, bounds):
    groups, warnings, valid = _groups(source.get('raw'), lambda row: _text(row.get('key')))
    complete = _source_complete(source) and valid
    start, end, week = bounds
    keys = {name: [] for name in ('total', 'open', 'done', 'unknown', 'window_created', 'window_updated', 'week_created', 'week_updated')}
    keys['total'] = sorted(groups)
    dates_complete = {'created': True, 'updated': True}
    for key, rows in groups.items():
        categories = set()
        for _, row in rows:
            status = _dict(_dict(row.get('fields')).get('status'))
            categories.add(_text(_dict(status.get('statusCategory')).get('key')))
        if categories <= {'new', 'indeterminate'}:
            keys['open'].append(key)
        elif categories == {'done'}:
            keys['done'].append(key)
        else:
            keys['unknown'].append(key)
        for field in dates_complete:
            timestamps = {_instant(_dict(row.get('fields')).get(field)) for _, row in rows}
            if None in timestamps or len(timestamps) != 1:
                dates_complete[field] = False
                warnings.append(field.upper() + '_UNKNOWN_OR_CONFLICTING')
            known = timestamps - {None}
            if start and end and start <= end and any(start <= value <= end for value in known):
                keys['window_' + field].append(key)
            if week and end and any(week <= value <= end for value in known):
                keys['week_' + field].append(key)
    for value in keys.values():
        value.sort()
    observed = {key: len(value) for key, value in keys.items()}
    counts = {key: value if complete else None for key, value in observed.items()}
    if keys['unknown']:
        warnings.append('STATUS_CATEGORY_UNKNOWN_OR_CONFLICTING')
        counts['open'] = counts['done'] = None
    for field, known in dates_complete.items():
        if not known or not (start and end and start <= end):
            counts['window_' + field] = None
        if not known or not (week and end):
            counts['week_' + field] = None
    keys['added'] = _added(comparison, complete, lambda row: _text(row.get('key')))
    counts['added'] = len(keys['added']) if keys['added'] is not None else None
    return {**_source_fields(source), 'complete': complete, 'counts': counts,
            'observed_counts': observed, 'keys': keys,
            'comparison': comparison.get('comparison', 'UNKNOWN'), 'warnings': sorted(set(warnings))}


def _identity(*parts):
    # Same composite identity as dt_statistics: instance/project/component/native
    # vulnerability. A project is never promoted into a product/SKU mapping.
    return json.dumps(parts, ensure_ascii=False, separators=(',', ':'))


def _finding_index(source):
    rows = source.get('raw')
    if not isinstance(rows, list):
        return {}, False, ['DT_FINDINGS_NOT_AVAILABLE']
    instance = _text(_dict(source.get('scope')).get('instance'))
    complete = _source_complete(source)
    warnings, findings = [], {}
    if not instance:
        complete = False
        warnings.append('DT_INSTANCE_UNKNOWN')
    for position, row in enumerate(rows):
        if not isinstance(row, dict):
            complete = False
            warnings.append('DT_FINDING_INVALID')
            continue
        project = _text(_dict(row.get('project')).get('uuid'))
        component = _text(_dict(row.get('component')).get('uuid'))
        vulnerability = _dict(row.get('vulnerability'))
        native = _text(vulnerability.get('uuid'))
        if not native and _text(vulnerability.get('source')) and _text(vulnerability.get('vulnId')):
            native = _identity(vulnerability['source'], vulnerability['vulnId'])
        verified = bool(instance and project and component and native)
        key = (_identity(instance, project, component, native) if verified else
               _identity('unverified-finding', instance, project, _text(row.get('id')) or position))
        if not verified:
            complete = False
            warnings.append('DT_FINDING_IDENTITY_INCOMPLETE')
        cves = {_cve(vulnerability.get('vulnId'))}
        aliases = vulnerability.get('aliases') or []
        if not isinstance(aliases, list):
            complete = False
            warnings.append('DT_ALIASES_INVALID')
            aliases = []
        cves.update(_cve(alias.get('cveId')) for alias in aliases if isinstance(alias, dict))
        cves.discard(None)
        if not cves:
            complete = False
            warnings.append('DT_CVE_MAPPING_UNKNOWN')
        evidence = 'capture.json#/sources/dt/raw/' + str(position)
        if key in findings:
            warnings.append('DT_DUPLICATE_FINDING_DEDUPLICATED')
            old = findings[key]
            if set(old['cve_ids']) != cves:
                complete = False
                warnings.append('DT_FINDING_CVE_MAPPING_CONFLICT')
            old['cve_ids'] = sorted(set(old['cve_ids']) | cves)
            old['evidence_refs'].append(evidence)
        else:
            findings[key] = {'key': key, 'project_id': project, 'cve_ids': sorted(cves),
                             'identity_verified': verified, 'evidence_refs': [evidence]}
    if any(isinstance(page, dict) and page.get('complete') is False for page in source.get('pages', []) or []):
        complete = False
        warnings.append('DT_PAGINATION_INCOMPLETE')
    return findings, complete, sorted(set(warnings))


def _matches(index, candidate_ids, complete):
    candidates = set(candidate_ids or [])
    findings = []
    for key in sorted(index):
        row = index[key]
        hits = sorted(candidates.intersection(row['cve_ids']))
        if hits:
            findings.append({**row, 'cve_ids': hits})
    cves = sorted({cve for row in findings for cve in row['cve_ids']})
    projects = sorted({row['project_id'] for row in findings if row['project_id']})
    observed = {'cves': len(cves), 'findings': len(findings), 'projects': len(projects)}
    return {'complete': complete,
            'counts': {key: value if complete else None for key, value in observed.items()},
            'observed_counts': observed, 'cve_ids': cves, 'project_ids': projects,
            'findings': findings}


def build(capture, comparisons):
    """Return deterministic shared statistics without mutating either input."""
    config, sources = _dict(capture.get('config')), _dict(capture.get('sources'))
    comparisons = _dict(comparisons)
    periods, bounds = _periods(config)
    kev = _kev(_dict(sources.get('kev')), _dict(comparisons.get('kev')), bounds)
    jira = _jira(_dict(sources.get('jira')), _dict(comparisons.get('jira')), bounds)
    index, dt_complete, warnings = _finding_index(_dict(sources.get('dt')))
    matches = _matches(index, kev['ids']['catalog'], kev['complete'] and dt_complete)
    matches['added'] = _matches(index, kev['ids']['added'], matches['complete'] and kev['ids']['added'] is not None)
    matches.update(scope_note=config.get('dt_scope_note'), warnings=warnings,
                   basis='ALL_OBSERVED_KEV_CATALOG', product_count=None)
    matches['added']['basis'] = 'COMPATIBLE_BASELINE_ADDED_ONLY'
    return {'schema': SCHEMA, 'synthetic': capture.get('synthetic'),
            'captured_at': capture.get('captured_at'), 'periods': periods,
            'kev': kev, 'jira': jira, 'kev_dt': matches}
