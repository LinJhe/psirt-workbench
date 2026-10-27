"""Immutable runs, per-source complete baselines, independent human review."""
import copy
import fcntl
import os
from datetime import datetime
from pathlib import Path
from uuid import uuid4
from zoneinfo import ZoneInfo

from psirt_daily.pipeline import encoded, sha, read_json, write_new, no_symlinks, sync_directory, diff, raw_index
from .reports import analyze, daily_markdown, action_markdown, weekly_markdown
from .html_report import render as render_html

ROOT = Path(__file__).resolve().parents[2]
NAMES = ('kev', 'dt', 'salesforce', 'jira')


def now():
    return datetime.now(ZoneInfo('Asia/Taipei')).isoformat()


def compatibility(src):
    return {k: src[k] for k in ('scope', 'source_version', 'schema_version', 'rule_version', 'synthetic')}


def compare(name, src, previous=None, ref=None):
    from psirt_ops.sf_messages import email_coverage, email_items
    result = {'comparison': 'SOURCE_INCOMPLETE', 'counts': None, 'changes': None,
              'email_counts': None, 'email_changes': None, 'baseline_ref': ref,
              'last_successful_at': previous.get('observed_at') if previous else None}
    if name == 'salesforce':
        result['email_coverage'] = email_coverage(src)
    if src['status'] != 'SUCCESS' or src['complete'] is not True:
        return result
    raw_index(name, src['raw'])
    if not previous:
        result['comparison'] = 'FIRST_BASELINE'
    elif compatibility(src) != compatibility(previous):
        result['comparison'] = 'INCOMPATIBLE_BASELINE'
    elif datetime.fromisoformat(src['observed_at']) < datetime.fromisoformat(previous['observed_at']):
        result['comparison'] = 'OLDER_OBSERVATION'
    else:
        result['comparison'] = 'COMPARABLE'
        result['changes'] = diff(name, previous['raw'], src['raw'])
        result['counts'] = {k: len(v) for k, v in result['changes'].items()}
        if name == 'salesforce' and email_coverage(src)['complete'] and email_coverage(previous)['complete']:
            before = [{'id': r['Id'], **r} for _, r in email_items(previous)]
            after = [{'id': r['Id'], **r} for _, r in email_items(src)]
            result['email_changes'] = diff('salesforce', before, after)
            result['email_counts'] = {k: len(v) for k,v in result['email_changes'].items()}
    return result


def prepare(path, mode):
    root = Path(os.path.abspath(path))
    no_symlinks(root)
    root.mkdir(parents=True, exist_ok=True)
    marker = root/'.psirt-ops'
    if not marker.exists():
        if any(root.iterdir()):
            raise ValueError('OutputMustBeEmptyOrOpsManaged')
        write_new(marker, encoded({'schema': 'psirt-ops/1', 'mode': mode}))
    for child in root.iterdir():
        no_symlinks(child)
    if read_json(marker.read_bytes()) != {'schema': 'psirt-ops/1', 'mode': mode}:
        raise ValueError('OutputModeMismatch')
    return root


def load_baseline(root, ref):
    path = root/ref['path']
    if Path(ref['path']).is_absolute() or '..' in Path(ref['path']).parts:
        raise ValueError('UnsafeBaselinePath')
    no_symlinks(path)
    content = path.read_bytes()
    if sha(content) != ref['sha256']:
        raise ValueError('BaselineHashMismatch')
    src = read_json(content)['sources'][ref['source']]
    if src['status'] != 'SUCCESS' or not src['complete']:
        raise ValueError('IncompleteBaselineRejected')
    return src


def execution_metadata(mode, trigger):
    """Describe the requested operation; never treat report time as a fetch."""
    if mode not in {'live', 'snapshot-replay', 'report-rebuild'}:
        raise ValueError('InvalidRunMode')
    if trigger not in {'cli', 'direct', 'page-manual', 'page-auto', 'salesforce-retry', 'page-rebuild'}:
        raise ValueError('InvalidRunTrigger')
    if ((trigger == 'salesforce-retry' and mode != 'live')
            or (trigger == 'page-rebuild' and mode != 'report-rebuild')):
        raise ValueError('RunTriggerModeMismatch')
    return {'trigger': trigger, 'operation': 'source-refresh' if mode == 'live' else mode,
            'source_collection_requested': mode == 'live', 'built_in_scheduler': False}


def run(output_dir, mode, cfg=None, snapshot=None, presentation_path=None, report_date=None, *, retry_sf=False, trigger='direct'):
    if retry_sf and mode != 'live':
        raise ValueError('SalesforceRetryRequiresLiveMode')
    execution = execution_metadata(mode, 'salesforce-retry' if retry_sf else trigger)
    if mode in ('snapshot-replay','report-rebuild'):
        from psirt_daily.offline import install_offline_guard
        install_offline_guard()
    storage_mode = read_json((Path(output_dir)/'.psirt-ops').read_bytes())['mode'] if mode=='report-rebuild' else mode
    root = prepare(output_dir, storage_mode)
    with (root/'.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        started = now()
        from .weekly_presentation import load_presentation
        presentation = load_presentation(presentation_path)
        selected_report_date = report_date or started[:10]
        from datetime import date
        date.fromisoformat(selected_report_date)
        state_path = root/'state.json'
        if not state_path.exists() and (root/'runs').exists() and any((root/'runs').iterdir()):
            raise ValueError('MissingStateWithExistingRuns')
        state = read_json(state_path.read_bytes()) if state_path.exists() else {'baselines': {}}
        previous = {n: load_baseline(root, ref) for n,ref in state['baselines'].items()}
        review_path = root/'human_review.json'
        if not review_path.exists():
            write_new(review_path, encoded({'schema': 'psirt-human-review/1', 'reviews': {}}))
        review_bytes = review_path.read_bytes()
        review = read_json(review_bytes)
        if not isinstance(review.get('reviews'), dict):
            raise ValueError('InvalidHumanReview')
        input_hash = None
        if mode == 'live':
            from .adapters import collect
            cfg = copy.deepcopy(cfg)
            cfg['cutoff'] = started
            capture = collect(cfg, output_root=root, retry_sf=retry_sf)
            capture['background'] = {'rows': []}
        else:
            if mode=='report-rebuild':
                from psirt_casework.service import latest_run
                latest, _manifest = latest_run(root)
                snapshot=latest/'capture.json'
                if presentation_path is None: presentation=read_json((latest/'report_presentation_used.json').read_bytes())
            original = Path(snapshot).read_bytes()
            input_hash = sha(original)
            capture = read_json(original)
        if capture.get('capture_schema') != 'psirt-ops/1' or set(capture['sources']) != set(NAMES):
            raise ValueError('InvalidCapture')
        if mode == 'live' and capture['synthetic']:
            raise ValueError('SyntheticLiveRejected')
        # Synthetic replay and real replay must also have distinct roots.
        if 'synthetic' in state and state['synthetic'] != capture['synthetic']:
            raise ValueError('SyntheticRealMixRejected')
        comparisons = {n: compare(n, capture['sources'][n], previous.get(n), state['baselines'].get(n)) for n in NAMES}
        from psirt_casework.store import read_snapshot
        from psirt_casework.effective import resolve
        manual = read_snapshot(root/'casework', capture['synthetic'])
        effective = resolve(manual,review)
        data = analyze(capture, comparisons, effective['review'])
        data['effective_manual'] = effective
        run_id = datetime.now(ZoneInfo('Asia/Taipei')).strftime('%Y%m%dT%H%M%S%z')+'-'+uuid4().hex[:8]
        dest = root/'runs'/run_id
        no_symlinks(dest)
        dest.mkdir(parents=True)
        artifacts = {}
        def save(name, content):
            content = content.encode() if isinstance(content,str) else encoded(content)
            write_new(dest/name, content)
            artifacts[name] = sha(content)
        save('capture.json', capture)
        save('human_review_used.json', review)
        save('effective_manual_used.json',effective)
        save('report.json', {'comparisons': comparisons, 'analysis': data})
        banner = '**合成資料測試，不是真實案件**\n\n' if capture['synthetic'] else ''
        save('Daily_PSIRT.md', banner+daily_markdown(capture,data,comparisons,mode,run_id))
        save('Vance_Action_List.md', banner+action_markdown(capture,data))
        from .sf_triage import build as build_sf_triage
        triage = build_sf_triage(capture, comparisons, effective['sf_review'], run_id, mode, started)
        from psirt_casework.inbox import build as build_inbox
        inbox = build_inbox(root, capture, manual, comparisons['salesforce'], run_id, started)
        save('sf-inbox.json', inbox)
        triage['inbox'] = inbox
        from .weekly_presentation import build as build_weekly, markdown as weekly_md, html as weekly_html
        weekly = build_weekly(capture, data, triage, presentation, selected_report_date)
        save('report_presentation_used.json', presentation)
        save('weekly_presentation_audit.json', weekly['audit'])
        save('Weekly_PSIRT_Company_Format.md', weekly_md(weekly))
        save('Weekly_PSIRT_Company_Format.html', weekly_html(weekly))
        from psirt_casework.resources import navigation, build as build_resources
        from psirt_casework.resources_web import render as render_resources
        from psirt_casework.companion import enhance
        page = navigation(render_html(capture,data,comparisons,mode,run_id))
        save('index.html', enhance(page))
        resources = build_resources(capture,manual,started,run_id)
        save('resources.json', resources)
        save('resources.html', enhance(render_resources(page,resources)))
        from .dt_statistics import build as build_dt_statistics, render as render_dt_statistics
        statistics = build_dt_statistics(capture, run_id, mode)
        save('dt-statistics.json', statistics)
        save('dt-statistics.html', enhance(render_dt_statistics(page, statistics)))
        from .sf_triage import build as build_sf_triage, render as render_sf_triage
        save('sf-triage.json', triage)
        save('sf-triage.html', enhance(render_sf_triage(page, triage)))
        # Personal records have one writer outside collection. Reporting only reads
        # a coherent SQLite snapshot; no API refresh may overwrite manual records.
        from psirt_casework.store import read_snapshot
        from psirt_casework.projection import build as build_casework
        from psirt_casework.web import render as render_casework
        prior_casework = None
        prior_run = Path(state['latest_run']) if state.get('latest_run') else None
        if prior_run is not None:
            if prior_run.parent != root/'runs':
                raise ValueError('InvalidCaseworkBaselinePath')
            no_symlinks(prior_run/'manifest.json')
            prior_manifest_bytes = (prior_run/'manifest.json').read_bytes()
            if sha(prior_manifest_bytes) != state.get('manifest_sha256'):
                raise ValueError('CaseworkBaselineManifestMismatch')
            prior_manifest = read_json(prior_manifest_bytes)
            if 'casework.json' in prior_manifest['artifacts_sha256']:
                no_symlinks(prior_run/'casework.json')
                previous_bytes = (prior_run/'casework.json').read_bytes()
                if sha(previous_bytes) != prior_manifest['artifacts_sha256']['casework.json']:
                    raise ValueError('CaseworkBaselineHashMismatch')
                prior_casework = read_json(previous_bytes)
        fallback_ref = '../../'+state['baselines']['jira']['path'] if 'jira' in state['baselines'] else 'unavailable'
        casework = build_casework(capture,manual,review,started,prior_casework,previous.get('jira'),run_id,fallback_ref,effective)
        save('casework_manual_used.json',manual)
        save('casework.json',casework)
        save('casework.html',enhance(render_casework(page,casework)))
        manifest = {'schema': 'psirt-ops-manifest/1', 'run_id': run_id, 'mode': mode,
                    'execution': execution,
                    'synthetic': capture['synthetic'], 'started_at': started, 'completed_at': now(),
                    'original_capture_at': capture['captured_at'], 'replay_input_sha256': input_hash,
                    'artifacts_sha256': artifacts.copy(), 'human_review_sha256': sha(review_bytes),
                    'scope_config': capture['config'], 'comparisons': comparisons,
                    'sources': {n: {k:v for k,v in s.items() if k in ('scope','status','complete','pages','errors','observed_at','source_version','source_updated_at','detail_scope','attempted','attempted_at','auth_blocked','auth_error_code','auth_blocked_at','skipped_reason','case_index_complete')}
                                for n,s in capture['sources'].items()},
                    'code_sha256': {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in sorted(list((ROOT/'scripts/psirt_ops').glob('*.py'))+list((ROOT/'scripts/psirt_casework').glob('*.py'))+list((ROOT/'scripts/psirt_casework/assets').glob('*')))},
                    'herdr': {'status': 'NOT_LOCATED_IN_CHECKED_PATHS', 'version': None,
                              'integrated': False, 'installed_by_this_task': False},
                    'limits': ['Source refresh may be requested manually or by an open work page when enabled and due; no system scheduler',
                               'Snapshot replay and report rebuild reuse saved sources without collecting company APIs',
                               'Exact CVE match is a candidate, not Affected',
                               'DT explicit UUID scope only', 'Human-reviewed fields require evidence; unmapped is Unknown']}
        save('manifest.json', manifest)
        baselines = copy.deepcopy(state['baselines'])
        for name, source in capture['sources'].items():
            if source['status'] == 'SUCCESS' and source['complete'] and comparisons[name]['comparison'] != 'OLDER_OBSERVATION':
                baselines[name] = {'path': str((dest/'capture.json').relative_to(root)),
                                   'sha256': artifacts['capture.json'], 'source': name}
        sync_directory(dest)
        new_state = {'baselines': baselines, 'synthetic': capture['synthetic'], 'latest_run': str(dest),
                     'manifest_sha256': artifacts['manifest.json']}
        temp = root/('state-'+uuid4().hex+'.tmp')
        write_new(temp, encoded(new_state))
        os.replace(temp, state_path)
        sync_directory(root)
        return {'run_dir': str(dest), 'html_path': str(dest/'index.html'), 'mode': mode, 'synthetic': capture['synthetic'],
                'sources': {n:s['status'] for n,s in capture['sources'].items()},
                'comparisons': {n:{k:v for k,v in c.items() if k in ('comparison','counts','email_counts')} for n,c in comparisons.items()},
                'exit_code': 0 if all(s['status']=='SUCCESS' and s['complete'] for s in capture['sources'].values()) else 1}
