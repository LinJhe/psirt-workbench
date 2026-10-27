"""Standalone synthetic captures; no company settings, cases or credentials."""
import copy


def capture():
    at = '2026-10-18T12:00:00+08:00'
    cfg = {'cutoff': at, 'window_start': '2026-10-12T00:00:00+08:00',
           'dt_scope_note': 'Synthetic fixture only; not company data',
           'sample_issues': [], 'jira_project': 'FIXTURE', 'dt_projects': [],
           'dt_base': 'https://fixture.invalid', 'sf_owner': 'FIXTURE',
           'sf_explicit_cases': [], 'weekly_page': 'FIXTURE'}
    sources = {n: {'status': 'SUCCESS', 'complete': True, 'synthetic': True,
                   'scope': {'test': 'only'}, 'source_version': 'test/1',
                   'schema_version': '1', 'rule_version': '1', 'observed_at': at,
                   'pages': [], 'raw': []} for n in ('kev','dt','jira','salesforce')}
    sources['kev']['raw'] = {'catalogVersion': 'synthetic/1', 'dateReleased': at,
                             'count': 1, 'vulnerabilities': [{'cveID': 'CVE-2026-99999', 'dateAdded': '2026-01-01'}]}
    return {'capture_schema': 'psirt-ops/1', 'synthetic': True, 'config': cfg,
            'captured_at': at, 'sources': sources, 'weekly_template': {'status': 'FAILED'},
            'background': {'rows': []}}


def sample():
    c = capture(); dt = c['sources']['dt']
    dt.update(scope={'instance':'https://fixture.invalid','project_uuids':['p1','p2']},
              projects=[], components=[], raw=[])
    for pid in ('p1','p2'):
        p={'uuid':pid,'name':'Synthetic board '+pid,'version':'1'}
        comp={'uuid':'shared-local-id','name':'kernel','version':'6.1','purl':'pkg:generic/kernel@6.1'}
        dt['projects'].append(p); dt['components'].append({'project_uuid':pid,'records':[comp]})
        dt['raw'].append({'id':pid+'/finding','project':p,'component':comp,
                         'vulnerability':{'uuid':'v1','vulnId':'CVE-2026-99999','source':'NVD',
                                          'severity':'CRITICAL','description':'Synthetic example'},
                         'analysis':{'state':'NOT_AFFECTED','isSuppressed':False}})
    return c


def unrated_sample():
    c = sample(); rows = c['sources']['dt']['raw']
    rows[1]['vulnerability'].update(uuid='v2',vulnId='CVE-2026-90002',severity='HIGH')
    for number, severity in enumerate(('UNASSIGNED',None,'UNRECOGNIZED'),3):
        row=copy.deepcopy(rows[0]); row['id']='fixture/'+str(number)
        row['vulnerability'].update(uuid='v'+str(number),vulnId='CVE-2026-9000'+str(number),severity=severity)
        rows.append(row)
    return c
