"""Bounded read-only collectors using explicit environment credentials.

GET only; Salesforce uses an externally provisioned access token.
No shared cache is touched. TLS uses system trust; redirects are refused.
"""
from __future__ import annotations
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from confluence_weekly.adapters import (
    CISA_KEV_URL, ConfluenceRestClient, KevLiveSource, resolve_token,
)
from fetch_kev import index_catalog

ROOT = Path(__file__).resolve().parents[2]



class ConfigurationUnavailable(ValueError):
    """A required environment variable is absent; never carries its value."""
    def __init__(self, key):
        self.configuration_key = key
        super().__init__('Required configuration is unavailable')


def required_env(key):
    value = os.environ.get(key, '').strip()
    if not value:
        raise ConfigurationUnavailable(key)
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('InvalidConfigurationValue')
    return value


def instance_url(value, *, allow_path=False):
    """Reject credentials, query strings, and unsafe endpoint configuration."""
    parsed = urllib.parse.urlsplit(value)
    try:
        parsed.port
        valid = (parsed.scheme == 'https' and bool(parsed.hostname)
                 and parsed.username is None and parsed.password is None
                 and not parsed.query and not parsed.fragment
                 and (allow_path or parsed.path in ('', '/'))
                 and not any(ord(c) <= 32 or ord(c) == 127 for c in value)
                 and '\\' not in value)
    except ValueError:
        valid = False
    if not valid:
        raise ValueError('InvalidInstanceURL')
    return value.rstrip('/')

def now():
    return datetime.now(ZoneInfo('Asia/Taipei')).isoformat()


def safe_error(exc):
    from .sf_auth import error_code
    status = getattr(exc, 'code', getattr(exc, 'status', None))
    result = {'type': type(exc).__name__, 'http_status': status if type(status) is int else None,
              'cause': type(getattr(exc, 'reason', exc)).__name__}
    if isinstance(exc, ConfigurationUnavailable):
        result['configuration_key'] = exc.configuration_key
    code = error_code(exc)
    if code:
        result['error_code'] = code
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('RedirectRefused')


class Reader:
    def __init__(self):
        self.audit = []
        self.opener = urllib.request.build_opener(NoRedirect())

    def get(self, url, headers=None):
        if urllib.parse.urlsplit(url).scheme != 'https':
            raise ValueError('HTTPSRequired')
        row = {'method': 'GET', 'url': url, 'started_at': now()}
        try:
            req = urllib.request.Request(url, headers=headers or {}, method='GET')
            with self.opener.open(req, timeout=30) as response:
                body = response.read()
                row['http_status'] = response.status
                return json.loads(body), dict(response.headers)
        except Exception as exc:
            row['error'] = safe_error(exc)
            raise
        finally:
            row['completed_at'] = now()
            self.audit.append(row)

    def transport(self, method, url, headers, body):
        if method != 'GET' or body is not None:
            raise PermissionError('ReadOnlyGuard')
        data, _ = self.get(url, headers)
        return 200, json.dumps(data).encode()


def envelope(scope, version):
    return {'status': 'FAILED', 'scope': scope, 'source_version': version,
            'schema_version': 'psirt-live-records/1', 'rule_version': 'read-only/1',
            'synthetic': False, 'observed_at': now(), 'source_updated_at': None,
            'complete': False, 'raw': None, 'pages': [], 'errors': []}


def paginate_jira(get, path, params, field):
    rows, pages, start = [], [], 0
    for _ in range(100):
        page = get(path, {**params, 'startAt': start, 'maxResults': 100})
        batch = page[field]
        pages.append({'startAt': page['startAt'], 'returned': len(batch), 'total': page['total']})
        if page['startAt'] != start:
            return rows, pages, False
        rows.extend(batch)
        start += len(batch)
        if start >= page['total']:
            ids = [r.get('key', r.get('id')) for r in rows]
            return rows, pages, (len(set(ids)) == len(rows) == page['total']
                                 and len({p['total'] for p in pages}) == 1)
        if not batch:
            break
    return rows, pages, False


def collect_kev(reader, cfg):
    result = envelope({'url': CISA_KEV_URL}, 'CISA-KEV-JSON')
    raw = KevLiveSource(transport=reader.transport).load_raw()
    index_catalog(raw)
    result.update(status='SUCCESS', complete=True, raw=raw,
                  source_updated_at=raw.get('dateReleased'), observed_at=now(),
                  pages=[{'returned': len(raw['vulnerabilities']), 'total': raw['count']}])
    return result


def collect_jira(reader, cfg):
    base = instance_url(required_env('JIRA_URL'), allow_path=True)
    headers = {'Authorization': 'Bearer '+required_env('JIRA_TOKEN')}
    def get(path, params):
        url = base+'/rest/api/2/'+path+'?'+urllib.parse.urlencode(params)
        return reader.get(url, headers)[0]
    project = cfg['jira_project']
    if not re.fullmatch(r'[A-Z][A-Z0-9_]*', project):
        raise ValueError('InvalidProject')
    result = envelope({'instance': base, 'project': project, 'selection': 'all statuses including Done'},
                      'Jira-REST-v2; backend-version-unverified')
    query = f'project = {project} ORDER BY key ASC'
    fields = 'summary,status,priority,resolution,assignee,created,updated,duedate,fixVersions,customfield_11504'
    issues, pages, complete = paginate_jira(get, 'search', {'jql': query, 'fields': fields}, 'issues')
    result.update(raw=[{'id': i['key'], **i} for i in issues], pages=pages,
                  query=query, complete=complete, status='SUCCESS' if complete else 'PARTIAL', details={})
    start = datetime.fromisoformat(cfg['window_start'])
    cutoff = datetime.fromisoformat(cfg['cutoff'])
    selected = set(cfg['sample_issues'])
    for i in issues:
        if (i['fields'].get('status',{}).get('statusCategory',{}).get('key') != 'done'
                or start <= datetime.fromisoformat(i['fields']['updated']) <= cutoff):
            selected.add(i['key'])
    result['detail_scope'] = sorted(selected)
    for key in sorted(selected):
        if not re.fullmatch(re.escape(project) + r'-\d+', key):
            raise ValueError('DetailScopeRejected')
        try:
            issue = get('issue/'+key, {'fields': '*all', 'expand': 'names,changelog'})
            comments, cp, cc = paginate_jira(get, 'issue/'+key+'/comment', {}, 'comments')
            issue['fields']['comment'] = {'comments': comments, 'pages': cp, 'complete': cc}
            history = issue.get('changelog', {})
            issue['_history_complete'] = len(history.get('histories', [])) == history.get('total')
            issue['_observed_at'] = now()
            result['details'][key] = issue
            if not cc or not issue['_history_complete']:
                result['status'] = 'PARTIAL'
                result['complete'] = False
        except Exception as exc:
            result['errors'].append({'issue': key, **safe_error(exc)})
            result.update(status='PARTIAL', complete=False)
    result['observed_at'] = now()
    return result


def dt_key():
    return required_env('DT_API_KEY')


def dt_pages(reader, url, headers):
    """Retain observed rows on incomplete pages; header totals are declarations.

    A partial response never supplies a verified total. Keep the established
    (rows, pages, complete) interface so callers can report known evidence
    without promoting it to a complete inventory.
    """
    rows, pages, expected = [], [], None
    for number in range(1, 101):
        page = {'page': number, 'returned': 0, 'total': None}
        try:
            data, response_headers = reader.get(url+'?'+urllib.parse.urlencode(
                {'pageNumber': number, 'pageSize': 100}), headers)
        except Exception as exc:
            page.update(query_failed=True, incomplete_reason='request_failed', error=safe_error(exc))
            pages.append(page)
            return rows, pages, False
        if not isinstance(data, list):
            page.update(incomplete_reason='response_not_list')
            pages.append(page)
            return rows, pages, False
        page['returned'] = len(data)
        retained = [row for row in data if isinstance(row, dict)]
        rows.extend(retained)
        pages.append(page)
        if len(retained) != len(data):
            page.update(retained=len(retained), incomplete_reason='invalid_record_shape')
            return rows, pages, False
        if not isinstance(response_headers, dict):
            page['incomplete_reason'] = 'invalid_response_headers'
            return rows, pages, False
        total = next((v for k,v in response_headers.items()
                      if isinstance(k, str) and k.lower() == 'x-total-count'), None)
        if total is None:
            page['incomplete_reason'] = 'missing_total_header'
            return rows, pages, False
        if (isinstance(total, str) and len(total.strip()) <= 20
                and total.strip().isascii() and total.strip().isdigit()):
            total = int(total.strip())
        if type(total) is not int or total < 0:
            page['incomplete_reason'] = 'invalid_total_header'
            return rows, pages, False
        page['total'] = total
        if expected is None:
            expected = total
        if total != expected:
            page['incomplete_reason'] = 'total_changed'
            return rows, pages, False
        if len(rows) >= total:
            if len(rows) != total:
                page['incomplete_reason'] = 'count_exceeds_declared_total'
            return rows, pages, len(rows) == total
        if not data:
            page['incomplete_reason'] = 'empty_page_before_total'
            return rows, pages, False
    pages[-1]['incomplete_reason'] = 'page_limit_reached'
    return rows, pages, False


def collect_dt(reader, cfg):
    base = instance_url(cfg['dt_base'], allow_path=True)
    headers = {'X-Api-Key': dt_key(), 'Accept': 'application/json'}
    result = envelope({'instance': base, 'project_uuids': sorted(cfg['dt_projects']),
                       'filters': 'all findings including suppressed; explicit UUID only'}, 'UNKNOWN')
    result.update(raw=[], projects=[], components=[], finding_responses=[])
    version, _ = reader.get(base+'/api/version', headers)
    result['source_version'] = str(version.get('version', version))
    result['version_response'] = version
    complete = True
    for pid in cfg['dt_projects']:
        if not re.fullmatch(r'[0-9a-f-]{36}', pid):
            raise ValueError('InvalidProjectUUID')
        try:
            project, _ = reader.get(base+'/api/v1/project/'+pid, headers)
            result['projects'].append(project)
            # Bounded pagination must verify the declared total before success.
            observed = {}
            for endpoint, collection, api in (('components', 'components', 'component'),
                                              ('findings', 'finding_responses', 'finding')):
                records, pages, endpoint_complete = dt_pages(reader, base+'/api/v1/'+api+'/project/'+pid, headers)
                observed[endpoint] = records
                # Save each endpoint immediately: a later failed request must
                # not discard an earlier successful component inventory.
                result[collection].append({'project_uuid': pid, 'records': records})
                result['pages'].append({'project': pid, 'endpoint': endpoint, 'returned': len(records),
                                        'pages': pages, 'complete': endpoint_complete,
                                        'declared_total': next((p['total'] for p in pages if p['total'] is not None), None),
                                        'verified_total': len(records) if endpoint_complete else None})
                result['errors'].extend({'project': pid, 'endpoint': endpoint, 'page': p['page'],
                                         'reason': p['incomplete_reason'], **p.get('error', {})}
                                        for p in pages if p.get('incomplete_reason'))
                complete = complete and endpoint_complete
            components, findings = observed['components'], observed['findings']
            for f in findings:
                c, v = f.get('component', {}), f.get('vulnerability', {})
                cid = c.get('uuid') if isinstance(c, dict) else None
                vid = (v.get('uuid') or v.get('vulnId')) if isinstance(v, dict) else None
                if not cid or not vid:
                    result['errors'].append({'project': pid, 'endpoint': 'findings',
                                              'reason': 'finding_identity_missing'})
                    complete = False
                    continue
                result['raw'].append({'id': pid+'/'+cid+'/'+vid, 'project': project,
                                       'component': c, 'vulnerability': v,
                                       'analysis': f.get('analysis'), 'attribution': f.get('attribution')})
            component_ids = [c.get('uuid') for c in components]
            complete = complete and all(component_ids) and len(set(component_ids)) == len(components)
        except Exception as exc:
            result['errors'].append({'project': pid, **safe_error(exc)})
            complete = False
    ids = [r['id'] for r in result['raw']]
    complete = complete and len(ids) == len(set(ids))
    result.update(status='SUCCESS' if complete else 'PARTIAL' if result['projects'] else 'FAILED',
                  complete=complete, observed_at=now())
    if result['status'] == 'FAILED':
        result['raw'] = None
    return result


def sf_query(reader, host, session, query):
    path = '/services/data/v58.0/query?'+urllib.parse.urlencode({'q': query})
    rows, pages, seen = [], [], set()
    while path:
        if (path in seen or len(seen) >= 100 or not path.startswith('/services/data/v58.0/query')
                or path.startswith('//')):
            return rows, pages, False
        seen.add(path)
        try:
            data, _ = reader.get(host+path, {'Authorization': 'Bearer '+session})
            if (not isinstance(data, dict) or not isinstance(data.get('records'), list)
                    or type(data.get('done')) is not bool or type(data.get('totalSize')) is not int
                    or data['totalSize'] < 0 or any(not isinstance(r, dict) or not isinstance(r.get('Id'), str)
                    or not r['Id'] for r in data['records'])):
                raise ValueError('SalesforceQueryPageInvalid')
            next_path = None if data['done'] else data.get('nextRecordsUrl')
            rows.extend(data['records'])
            pages.append({'returned': len(data['records']), 'total': data['totalSize'], 'done': data['done']})
            if not data['done'] and (not isinstance(next_path, str) or not next_path):
                raise ValueError('SalesforceContinuationMissing')
            path = next_path
        except Exception as exc:
            # Keep all verified earlier pages and expose only safe error facts.
            pages.append({'query_failed': True, 'returned': 0, 'error': safe_error(exc)})
            return rows, pages, False
    return rows, pages, (len({r['Id'] for r in rows}) == len(rows) == pages[-1]['total']
                         and len({p['total'] for p in pages}) == 1)


def collect_sf(reader, cfg):
    host = instance_url(required_env('SF_INSTANCE_URL'))
    session = required_env('SF_ACCESS_TOKEN')
    owner = cfg['sf_owner']
    if not re.fullmatch(r'[A-Za-z0-9() _-]+', owner):
        raise ValueError('InvalidOwner')
    numbers = cfg['sf_explicit_cases']
    if not all(re.fullmatch(r'Q-\d{6}-\d+', n) for n in numbers):
        raise ValueError('InvalidCaseNumber')
    where = "Owner.Name = '"+owner+"'"
    if numbers:
        where += ' OR CaseNumber IN ('+','.join("'"+n+"'" for n in numbers)+')'
    result = envelope({'instance': host, 'case_filter': where, 'all_statuses': True,
                       'email_window_start': cfg['window_start']}, 'Salesforce REST v58.0')
    query = ('SELECT Id,CaseNumber,Subject,Status,IsClosed,Owner.Name,CreatedDate,LastModifiedDate '
             'FROM Case WHERE ('+where+') ORDER BY Id')
    cases, pages, complete = sf_query(reader, host, session, query)
    result.update(raw=[{'id': c['Id'], **c} for c in cases], pages=[{'endpoint': 'Case', 'query': query, 'pages': pages}], emails=[],
                  case_index_complete=complete)
    result['errors'].extend(p['error'] for p in pages if p.get('query_failed'))
    utc_start = datetime.fromisoformat(cfg['window_start']).astimezone(ZoneInfo('UTC')).strftime('%Y-%m-%dT%H:%M:%SZ')
    utc_end = datetime.fromisoformat(cfg['cutoff']).astimezone(ZoneInfo('UTC')).strftime('%Y-%m-%dT%H:%M:%SZ')
    for offset in range(0, len(cases), 75):
        # An authentication failure cannot be cured by trying every Case batch.
        if any(e.get('http_status') == 401 for e in result['errors']):
            complete = False
            break
        ids = [c['Id'] for c in cases[offset:offset+75]]
        if not all(re.fullmatch(r'[A-Za-z0-9]{15,18}', i) for i in ids):
            raise ValueError('InvalidCaseID')
        query = ('SELECT Id,ParentId,Subject,Incoming,MessageDate,LastModifiedDate,Status,TextBody,HtmlBody FROM EmailMessage '
                 'WHERE ParentId IN ('+','.join("'"+i+"'" for i in ids)+') '
                 f'AND MessageDate >= {utc_start} AND MessageDate <= {utc_end} ORDER BY Id')
        try:
            emails, ep, ec = sf_query(reader, host, session, query)
            result['emails'].extend(emails)
            result['pages'].append({'endpoint': 'EmailMessage', 'case_ids': ids, 'query': query, 'pages': ep})
            result['errors'].extend(p['error'] for p in ep if p.get('query_failed'))
            complete = complete and ec
        except Exception as exc:
            result['errors'].append(safe_error(exc)); complete = False
    observed = any(not p.get('query_failed') for group in result['pages'] for p in group['pages'])
    result.update(complete=complete, status='SUCCESS' if complete else 'PARTIAL' if observed else 'FAILED', observed_at=now(),
                  auth_note='externally provisioned access token; all business requests GET')
    if result['status'] == 'FAILED':
        result['raw'] = None
    return result


def collect_weekly(reader, cfg):
    if not cfg.get('weekly_page'):
        return {'status': 'NOT_CONFIGURED', 'observed_at': now(),
                'fallback': 'local generic weekly template'}
    page_id = str(cfg['weekly_page'])
    if not re.fullmatch(r'\d+', page_id):
        raise ValueError('InvalidPageID')
    base = instance_url(required_env('CONFLUENCE_URL'), allow_path=True)
    client = ConfluenceRestClient(base, required_env('CONFLUENCE_TOKEN'),
                                  transport=reader.transport,
                                  writes_enabled=False, max_attempts=1)
    page = client.get_page(page_id)
    if not page:
        raise ValueError('WeeklyPageUnavailable')
    return {'status': 'SUCCESS', 'observed_at': now(), 'page': page,
            'source': base+'/pages/viewpage.action?pageId='+page_id}


def collect(cfg, *, output_root=None, retry_sf=False):
    from . import sf_auth
    reader = Reader()
    sources = {}
    for name, action in [('kev', collect_kev), ('dt', collect_dt), ('salesforce', collect_sf), ('jira', collect_jira)]:
        print('Collecting '+name+' (read-only)...', file=sys.stderr, flush=True)
        auth_state = sf_auth.load(output_root) if name == 'salesforce' else None
        attempted_at = now()
        if name == 'salesforce' and auth_state and auth_state['blocked'] and not retry_sf:
            source = envelope({'requested_config': cfg['scope_version']}, 'UNKNOWN')
            sources[name] = sf_auth.decorate(source, auth_state, attempted=False, at=None)
            print(name+': FAILED', file=sys.stderr, flush=True)
            continue
        try:
            sources[name] = action(reader, cfg)
        except Exception as exc:
            sources[name] = {**envelope({'requested_config': cfg['scope_version']}, 'UNKNOWN'),
                             'errors': [safe_error(exc)]}
        if name == 'salesforce':
            sources[name].update(attempted=True, attempted_at=attempted_at)
            auth_state = sf_auth.update(output_root, sources[name], auth_state)
            sf_auth.decorate(sources[name], auth_state, attempted=True, at=attempted_at)
        print(name+': '+sources[name]['status'], file=sys.stderr, flush=True)
    try:
        weekly = collect_weekly(reader, cfg)
    except Exception as exc:
        weekly = {'status': 'FAILED', 'observed_at': now(), 'errors': [safe_error(exc)],
                  'fallback': 'local generic weekly template'}
    return {'capture_schema': 'psirt-ops/1', 'synthetic': False, 'origin_mode': 'live',
            'config': cfg, 'captured_at': now(), 'sources': sources, 'weekly_template': weekly,
            'http_audit': reader.audit}
