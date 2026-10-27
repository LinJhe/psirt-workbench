"""Explicit binding between current local records and an immutable report."""
import hashlib
import json
import re
from html import escape
from pathlib import Path
from .store import encoded, Invalid
from psirt_daily.pipeline import no_symlinks

ASSET = Path(__file__).with_name('assets') / 'report-version.js'
DOWNLOADS = ('casework.json', 'casework_manual_used.json', 'effective_manual_used.json',
             'sf-triage.json', 'sf-inbox.json', 'manifest.json', 'capture.json', 'report.json',
             'human_review_used.json', 'weekly_presentation_audit.json', 'report_presentation_used.json',
             'dt-statistics.json', 'resources.json', 'Daily_PSIRT.md', 'Vance_Action_List.md',
             'Weekly_PSIRT_Company_Format.md', 'Weekly_PSIRT_Company_Format.html')


def digest(value):
    return hashlib.sha256(encoded(value).encode()).hexdigest()


def describe(run, manifest, manual, legacy):
    """Use the caller's already pinned run and coherent manual snapshot."""
    def saved(name):
        expected = manifest.get('artifacts_sha256', {}).get(name)
        if expected is None:
            return None
        path = run / name; no_symlinks(path)
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise Invalid('報告人工版本雜湊不一致')
        return digest(json.loads(raw))
    current, old = digest(manual), saved('casework_manual_used.json')
    legacy_current, legacy_old = digest(legacy), saved('human_review_used.json')
    match = ('UNKNOWN' if old is None or legacy_old is None else
             'MATCH' if current == old and legacy_current == legacy_old else 'CHANGED')
    return {'schema': 'psirt-report-version/1', 'report_run_id': run.name,
            'report_generated_at': manifest.get('started_at'),
            'source_captured_at': manifest.get('original_capture_at'),
            'capture_sha256': manifest.get('artifacts_sha256', {}).get('capture.json'),
            'current_manual_sha256': current, 'report_manual_sha256': old,
            'current_legacy_sha256': legacy_current, 'report_legacy_sha256': legacy_old,
            'matches_report': match}


def pin_downloads(html, run_id):
    if not re.fullmatch(r'[A-Za-z0-9_+.-]+', run_id) or run_id in ('.', '..'):
        raise Invalid('報告批次識別不合法')
    pattern = r'href=([\"\'])(' + '|'.join(re.escape(name) for name in DOWNLOADS) + r')\1'
    return re.sub(pattern, lambda m: 'href=' + m[1] + '/runs/' + run_id + '/' + m[2] + m[1]
                  + ' data-report-artifact="' + m[2] + '"', html)


def section(data, editable, kind):
    meta = data.get('report_version') or {
        'report_run_id': data.get('run_id'), 'report_generated_at': data.get('generated_at', data.get('as_of')),
        'report_manual_sha256': data.get('manual_sha256', (data.get('inbox') or {}).get('manual_sha256')),
        'current_manual_sha256': data.get('manual_sha256', (data.get('inbox') or {}).get('manual_sha256')),
        'matches_report': 'UNKNOWN' if editable else 'HISTORICAL'}
    artifacts = [('casework.json', '案件 JSON'), ('casework_manual_used.json', '人工紀錄')] if kind == 'casework' else [('sf-triage.json', '判讀 JSON'), ('sf-inbox.json', '來信待辦 JSON')]
    artifacts += [('manifest.json', '驗證 manifest')]
    run_id = str(meta.get('report_run_id') or '')
    prefix = '/runs/' + run_id + '/' if editable and re.fullmatch(r'[A-Za-z0-9_+.-]+', run_id) and run_id not in ('.', '..') else ''
    status = {'CHANGED': '有較新的本機紀錄；下載仍是最近已產生的固定報告。請使用既有快照產生新報告。',
              'MATCH': '目前人工紀錄與這份報告一致；停留時間仍依各自計算時間顯示。',
              'HISTORICAL': '固定歷史報告；後續人工修改不會改寫這份檔案。',
              'UNKNOWN': '此報告未提供足夠人工版本資訊，是否一致待確認。'}
    e = lambda value: escape(str(value) if value is not None else '待確認', quote=True)
    return ('<aside id="report-version" data-editable="' + str(editable).lower() + '" aria-label="下載報告版本">'
            '<h3>最近已產生報告（固定版本）</h3><p id="report-version-state" role="status">' + status[meta.get('matches_report', 'UNKNOWN')] + '</p>'
            '<p>批次：<span id="report-version-run">' + e(run_id) + '</span>｜產生：<span id="report-version-time">' + e(meta.get('report_generated_at')) + '</span></p>'
            '<p>' + ' · '.join('<a data-report-artifact="' + name + '" href="' + e(prefix + name) + '">' + label + '</a>' for name, label in artifacts) + '</p>'
            '<details><summary>核對來源與人工資料摘要</summary><pre id="report-version-evidence">' + e(json.dumps(meta, ensure_ascii=False, indent=2)) + '</pre></details></aside>')
