"""Single-user loopback workbench; page-driven refresh, no system scheduler."""
import fcntl
import hashlib
import hmac
import json
import mimetypes
import os
import secrets
import subprocess
import sys
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen, ProxyHandler, build_opener
from uuid import uuid4

from psirt_daily.pipeline import no_symlinks, sha, read_json
from .store import Store, Invalid, Conflict, encoded, now, read_snapshot
from .effective import resolve
from .projection import build
from .web import render

ROOT=Path(__file__).resolve().parents[2]
DEFAULT=ROOT/'runtime/demo'
RECEIPT='.casework-service.json'
VERSION='casework-loopback/1'
CHILDREN=[]
ARTIFACTS={'index.html','casework.html','casework.json','casework_manual_used.json','effective_manual_used.json',
           'Daily_PSIRT.md','Vance_Action_List.md','Weekly_PSIRT_Company_Format.html','Weekly_PSIRT_Company_Format.md',
           'dt-statistics.html','dt-statistics.json','sf-triage.html','sf-triage.json','report.json','human_review_used.json',
           'capture.json','manifest.json','weekly_presentation_audit.json','report_presentation_used.json','sf-inbox.json',
           'resources.html','resources.json'}


class ServiceVersionMismatch(Invalid):
    """Safe, actionable error without exposing receipt/control information."""
    code = 'ServiceVersionMismatch'

    def __init__(self):
        super().__init__('程式版本已更新，請先停止本服務再開啟')


def version():
    paths=sorted(list((ROOT/'scripts/psirt_casework').glob('*.py'))+list((ROOT/'scripts/psirt_casework/assets').glob('*'))+list((ROOT/'scripts/psirt_ops').glob('*.py'))+list((ROOT/'scripts/psirt_ops/assets').glob('*.js')))
    return VERSION+':'+sha(b''.join(p.read_bytes() for p in paths))


def checked_root(path):
    root=Path(os.path.abspath(path));no_symlinks(root)
    marker=read_json((root/'.psirt-ops').read_bytes())
    if marker.get('schema')!='psirt-ops/1' or marker.get('mode') not in ('live','snapshot-replay'):raise Invalid('非既有 PSIRT 資料根目錄')
    for name in ('state.json','human_review.json',RECEIPT,'casework','.casework-service.lock'):no_symlinks(root/name)
    return root


def latest_run(root,state=None):
    if state is None:state=read_json((root/'state.json').read_bytes())
    run=Path(state['latest_run'])
    if run.parent != root/'runs':raise Invalid('報告路徑不合法')
    no_symlinks(run/'manifest.json');raw=(run/'manifest.json').read_bytes()
    if sha(raw)!=state['manifest_sha256']:raise Invalid('報告清單雜湊不一致')
    manifest=read_json(raw)
    for name in ('capture.json','index.html','report_presentation_used.json'):
        no_symlinks(run/name)
        if sha((run/name).read_bytes())!=manifest['artifacts_sha256'][name]:raise Invalid('來源／報告雜湊不一致')
    return run,manifest


def context(root):
    state=read_json((root/'state.json').read_bytes())
    run,manifest=latest_run(root,state);capture=read_json((run/'capture.json').read_bytes())
    legacy=read_json((root/'human_review.json').read_bytes())
    manual=read_snapshot(root/'casework',capture['synthetic']);effective=resolve(manual,legacy)
    fallback=None;ref='unavailable'
    if 'jira' in state['baselines']:
        from psirt_ops.pipeline import load_baseline
        fallback=load_baseline(root,state['baselines']['jira']);ref='../../'+state['baselines']['jira']['path']
    prior=None
    if 'casework.json' in manifest['artifacts_sha256']:
        raw=(run/'casework.json').read_bytes()
        if sha(raw)!=manifest['artifacts_sha256']['casework.json']:raise Invalid('案件報告雜湊不一致')
        prior=read_json(raw)
    projection=build(capture,manual,legacy,now(),prior,fallback,run.name,ref,effective)
    from .report_version import describe
    projection['report_version']=describe(run,manifest,manual,legacy)
    projection['workspace']=True
    return run,capture,projection


def local_request(receipt,path='/health',method='GET'):
    req=Request(receipt['origin']+path,method=method,headers={'X-PSIRT-Control':receipt['control']})
    with build_opener(ProxyHandler({})).open(req,timeout=4) as response:return json.load(response)


def sf_context(root):
    from .inbox import build as build_inbox, checked_artifact
    from psirt_ops.sf_triage import build as build_triage
    state=read_json((root/'state.json').read_bytes())
    run,manifest=latest_run(root,state)
    capture=checked_artifact(run,manifest,'capture.json')
    manual=read_snapshot(root/'casework',capture['synthetic'])
    legacy=read_json((root/'human_review.json').read_bytes())
    triage=build_triage(capture,manifest['comparisons'],resolve(manual,legacy)['sf_review'],run.name,manifest['mode'],now())
    triage['inbox']=build_inbox(root,capture,manual,manifest['comparisons']['salesforce'],run.name,now(),history_state=state)
    # A replay can retain origin_mode=live; only the actual root enables collection.
    triage['inbox']['can_retry_source']=read_json((root/'.psirt-ops').read_bytes())['mode']=='live'
    from .report_version import describe
    triage['report_version']=describe(run,manifest,manual,legacy)
    triage['inbox']['report_version']=triage['report_version']
    return run,capture,triage


def resources_context(root):
    from .resources import build as build_resources
    run,_=latest_run(root)
    capture=read_json((run/'capture.json').read_bytes())
    manual=read_snapshot(root/'casework',capture['synthetic'])
    return run,capture,build_resources(capture,manual,now(),run.name)


def workspace_shell(run):
    from .resources import navigation
    from .companion import strip
    return navigation(strip((run/'index.html').read_text()))


def view_metadata(root,run=None):
    if run is None:run,_=latest_run(root)
    capture=read_json((run/'capture.json').read_bytes())
    return {'run_id':run.name,'captured_at':capture['captured_at'],'mode':capture.get('origin_mode'),
            'synthetic':capture['synthetic'],'sources':{k:{f:s.get(f) for f in ('status','complete','observed_at')} for k,s in capture['sources'].items()},
            'offline':read_json((root/'.psirt-ops').read_bytes())['mode']!='live'}


def active_page(root,run,html):
    from .refresh_web import enhance
    from .report_version import pin_downloads
    return enhance(pin_downloads(html,run.name),view_metadata(root,run))


def inspect(root,allow_old=False):
    root=checked_root(root);path=root/RECEIPT
    if not path.exists():return None
    receipt=read_json(path.read_bytes())
    if receipt.get('root')!=str(root) or receipt.get('uid')!=os.getuid():raise Invalid('服務使用者／根目錄不一致')
    parsed=urlsplit(receipt['origin'])
    if parsed.scheme!='http' or parsed.hostname!='127.0.0.1' or not parsed.port or parsed.path or parsed.query or parsed.username:raise Invalid('非本機服務位址')
    try:health=local_request(receipt)
    except (OSError,ValueError):return None
    for key in ('instance','uid','root','version'):
        if health.get(key)!=receipt.get(key):raise Invalid('服務身分不一致')
    if not allow_old and receipt['version']!=version():raise ServiceVersionMismatch()
    return receipt


def start(root):
    root=checked_root(root);existing=inspect(root)
    if existing:return public(existing,True)
    latest_run(root)
    log=root/'casework-service.log';no_symlinks(log)
    fd=os.open(log,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
    with os.fdopen(fd,'ab') as stream:
        child=subprocess.Popen([sys.executable,'-B',str(ROOT/'scripts/run_psirt_casework.py'),'serve','--output-dir',str(root)],
                         stdin=subprocess.DEVNULL,stdout=stream,stderr=stream,start_new_session=True,close_fds=True,cwd=ROOT)
    CHILDREN.append(child)
    for _ in range(80):
        if child.poll() not in (None,0):raise Invalid('服務啟動失敗；請查看本機服務紀錄')
        receipt=inspect(root)
        if receipt:return public(receipt,False)
        time.sleep(.1)
    raise Invalid('本機服務未就緒；未刷新來源')


def public(receipt,reused=False):
    return {k:receipt[k] for k in ('instance','root','uid','version','origin','started_at')}|{'url':receipt['origin']+'/casework.html','reused':reused,'exit_code':0}


def stop(root):
    receipt=inspect(root,allow_old=True)
    if not receipt:return {'stopped':False,'reason':'服務未執行','exit_code':0}
    local_request(receipt,'/control/stop','POST')
    for _ in range(50):
        try:local_request(receipt)
        except OSError:return {'stopped':True,'instance':receipt['instance'],'exit_code':0}
        time.sleep(.1)
    raise Invalid('停止尚未確認')


class Server(ThreadingHTTPServer):
    daemon_threads=True;request_queue_size=8
    def __init__(self,root):
        from .refresh import Manager
        from .metadata import MetadataCache
        self.root=root;self.tokens={};self.mutation=threading.Lock();self.slots=threading.BoundedSemaphore(8)
        self.refresh=Manager(root)
        self.metadata=MetadataCache(root,lambda state:view_metadata(root,latest_run(root,state)[0]))
        self.token_lock=threading.Lock();self.closing=False
        super().__init__(('127.0.0.1',0),Handler)
        self.origin='http://127.0.0.1:'+str(self.server_port)
        self.receipt={'origin':self.origin,'root':str(root),'uid':os.getuid(),'instance':uuid4().hex,
                      'version':version(),'started_at':now(),'control':secrets.token_urlsafe(32)}
    def get_request(self):
        conn,addr=super().get_request();conn.settimeout(5);return conn,addr
    def process_request(self,request,address):
        if not self.slots.acquire(blocking=False):self.shutdown_request(request);return
        try:super().process_request(request,address)
        except BaseException:self.slots.release();raise
    def process_request_thread(self,request,address):
        try:super().process_request_thread(request,address)
        finally:self.slots.release()
    def token(self):
        with self.token_lock:
            now_=time.monotonic();self.tokens={k:v for k,v in self.tokens.items() if v>now_}
            if len(self.tokens)>128:self.tokens.pop(next(iter(self.tokens)))
            token=secrets.token_urlsafe(32);self.tokens[token]=now_+900;return token
    def token_valid(self,token):
        with self.token_lock:return self.tokens.get(token,0)>time.monotonic()


class Handler(BaseHTTPRequestHandler):
    server_version='PSIRTLocal';sys_version='';protocol_version='HTTP/1.0'
    def log_message(self,*args):pass  # No payloads, request tokens or company data in logs.
    def send(self,status,body,ctype='application/json; charset=utf-8'):
        raw=body if isinstance(body,bytes) else encoded(body).encode()
        self.send_response(status);self.send_header('Content-Type',ctype);self.send_header('Content-Length',str(len(raw)))
        for k,v in {'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY'}.items():self.send_header(k,v)
        self.end_headers()
        if self.command!='HEAD':self.wfile.write(raw)
    def guard(self,write=False,control=False):
        if self.headers.get_all('Host')!=[self.server.origin[7:]]:raise PermissionError('HostRejected')
        origins=self.headers.get_all('Origin') or []
        if len(origins)>1 or (origins and origins!=[self.server.origin]):raise PermissionError('OriginRejected')
        if self.headers.get('Sec-Fetch-Site')=='cross-site':raise PermissionError('CrossSiteRejected')
        if control:
            if not hmac.compare_digest(self.headers.get('X-PSIRT-Control',''),self.server.receipt['control']):raise PermissionError('ControlRejected')
        elif write:
            if origins!=[self.server.origin]:raise PermissionError('OriginRequired')
            if not self.server.token_valid(self.headers.get('X-PSIRT-Token','')):raise PermissionError('TokenExpiredOrMissing')
    def body(self):
        if self.headers.get('Content-Type')!='application/json' or self.headers.get('Transfer-Encoding'):raise Invalid('JSONRequired')
        values=self.headers.get_all('Content-Length') or []
        if len(values)!=1 or not values[0].isdigit() or not 0<int(values[0])<=131072:raise Invalid('RequestSizeRejected')
        raw=self.rfile.read(int(values[0]));body=json.loads(raw)
        if not isinstance(body,dict):raise Invalid('ObjectRequired')
        return body
    def do_HEAD(self):self.do_GET()
    def do_GET(self):self.handle_safe(False)
    def do_POST(self):self.handle_safe(True)
    def do_OPTIONS(self):self.send(405,{'error':'CrossOriginNotSupported'})
    def handle_safe(self,write):
        self.committed=False
        try:self.dispatch(write)
        except PermissionError as exc:self.send(403,{'error':str(exc)})
        except Conflict as exc:self.send(409,{'error':str(exc),'committed':self.committed})
        except (Invalid,ValueError,KeyError,TypeError) as exc:self.send(400,{'error':str(exc) if isinstance(exc,Invalid) else type(exc).__name__,'committed':self.committed})
        except (BrokenPipeError,ConnectionResetError):pass
        except Exception as exc:self.send(500,{'error':type(exc).__name__,'committed':self.committed})
    def dispatch(self,write):
        path=self.path;control=path in ('/health','/control/stop')
        self.guard(write,control)
        if control:
            if path=='/health' and not write:self.send(200,{k:v for k,v in self.server.receipt.items() if k!='control'});return
            if path=='/control/stop' and write:
                if not self.server.mutation.acquire(blocking=False):raise Conflict('正在保存／產報，請完成後停止')
                try:
                    self.server.refresh.close()
                    self.server.closing=True
                finally:self.server.mutation.release()
                self.send(200,{'stopping':True});threading.Thread(target=self.server.shutdown,daemon=True).start();return
            self.send(405,{'error':'MethodRejected'});return
        root=self.server.root
        if write:
            data=self.body()
            if path not in ('/api/records','/api/rebuild','/api/backup','/api/refresh'):self.send(404,{'error':'PathRejected'});return
            if not self.server.mutation.acquire(blocking=False):raise Conflict('另一項保存／產報操作執行中，請稍後重送')
            try:
                if self.server.closing:raise Conflict('服務停止中')
                if path=='/api/refresh':
                    action=data.get('action')
                    if action=='auto' and set(data)=={'action','enabled'} and isinstance(data['enabled'],bool):
                        state=self.server.refresh.set_auto(data['enabled'])
                    elif action in ('manual','tick') and set(data)=={'action'}:
                        state=getattr(self.server.refresh,action)()
                    elif action=='retry_salesforce' and set(data)=={'action'}:
                        state=self.server.refresh.retry_salesforce()
                    else:raise Invalid('RefreshFieldsRejected')
                    self.send(200,{'refresh':state,'latest':self.server.metadata.get()})
                elif path=='/api/records':
                    if set(data)!={'kind','id','payload','expected_version','operation_id'}:raise Invalid('RequestFieldsRejected')
                    if data['kind']=='sf_email':
                        from .inbox import validate_record
                        _,capture,triage=sf_context(root)
                    elif data['kind']=='bookmark': _,capture,_=resources_context(root)
                    else: _,capture,_=context(root)
                    store=Store(root/'casework',capture['synthetic'])
                    record=store.replay_operation(**data) if data['kind']=='sf_email' else None
                    if record is None:
                        if data['kind']=='sf_email':
                            validate_record(data,triage['inbox'])
                            from .mail_triage import validate_review
                            row=next(row for row in triage['inbox']['rows'] if row['id']==data['id'])
                            validate_review(data['payload'],row,triage['inbox'])
                        record=store.save(**data)
                    self.committed=True
                    # Save returned only after commit. Independently read the current version.
                    current=store.get(data['kind'],data['id'])
                    revision=next((r for r in store.history(data['kind'],data['id']) if r['version']==record['version']),None)
                    if not revision or revision['payload']!=record['payload'] or current['version']<record['version']:raise Invalid('ReadbackNotConfirmed')
                    self.send(200,{'record':record,'current':current,'committed_and_read_back':True,'operation_id':data['operation_id']})
                elif path=='/api/backup':
                    if data:raise Invalid('RequestFieldsRejected')
                    _,capture,_=context(root)
                    if not (root/'casework/worklog.sqlite3').exists():raise Invalid('尚無人工資料可備份')
                    backup=Store(root/'casework',capture['synthetic']).backup()
                    self.send(200,{'path':str(backup),'sha256':sha(backup.read_bytes())})
                else:
                    if data:raise Invalid('RequestFieldsRejected')
                    result=rebuild(root)
                    self.send(200,result)
            finally:self.server.mutation.release()
            return
        if path=='/api/session':
            self.send(200,{'session':self.server.token()});return
        if path=='/api/refresh':
            self.send(200,{'session':self.server.token(),'refresh':self.server.refresh.status(),'latest':self.server.metadata.get()});return
        if path=='/api/state':
            run,_,projection=context(root);self.send(200,{'session':self.server.token(),'projection':projection,'latest':view_metadata(root,run)});return
        if path=='/api/sf-inbox':
            run,_,triage=sf_context(root);self.send(200,{'session':self.server.token(),'inbox':triage['inbox'],'latest':view_metadata(root,run)});return
        if path=='/api/resources':
            run,_,resources=resources_context(root);self.send(200,{'session':self.server.token(),'resources':resources,'latest':view_metadata(root,run)});return
        from .companion import enhance
        if path=='/resources.html':
            from .resources_web import render as render_resources
            run,_,resources=resources_context(root)
            self.send(200,active_page(root,run,enhance(render_resources(workspace_shell(run),resources,editable=True))).encode(),'text/html; charset=utf-8');return
        if path=='/sf-triage.html':
            from psirt_ops.sf_triage import render as render_triage
            run,_,triage=sf_context(root)
            self.send(200,active_page(root,run,enhance(render_triage(workspace_shell(run),triage,editable=True))).encode(),'text/html; charset=utf-8');return
        if path in ('/','/casework.html'):
            run,_,projection=context(root)
            self.send(200,active_page(root,run,enhance(render(workspace_shell(run),projection,editable=True))).encode(),'text/html; charset=utf-8');return
        parts=path.lstrip('/').split('/')
        if len(parts)==1 and parts[0] in ARTIFACTS:
            run,manifest=latest_run(root);name=parts[0]
        elif len(parts)==3 and parts[0]=='runs' and parts[1] not in ('.','..') and parts[2] in ARTIFACTS:
            run=root/'runs'/parts[1];no_symlinks(run);name=parts[2];manifest=read_json((run/'manifest.json').read_bytes())
        else:self.send(404,{'error':'PathRejected'});return
        target=run/name;no_symlinks(target)
        if not target.is_file():self.send(404,{'error':'ArtifactUnavailable'});return
        raw=target.read_bytes()
        if name!='manifest.json' and sha(raw)!=manifest['artifacts_sha256'].get(name):raise Invalid('ArtifactHashMismatch')
        if len(parts)==1 and name in ('index.html','dt-statistics.html'):
            from .resources import navigation
            raw=active_page(root,run,enhance(navigation(raw.decode()))).encode()
        self.send(200,raw,(mimetypes.guess_type(name)[0] or 'application/octet-stream')+'; charset=utf-8')


def rebuild(root):
    from .refresh import _latest, SOURCES
    root=checked_root(root)
    _,prior,_,prior_capture,prior_artifacts=_latest(root)
    receipt=root/('casework-rebuild-'+uuid4().hex+'.json')
    began=datetime.fromisoformat(now())
    proc=subprocess.run([sys.executable,'-B',str(ROOT/'scripts/run_psirt_ops.py'),'--mode','report-rebuild','--trigger','page-rebuild','--output-dir',str(root),'--result-file',str(receipt)],
                        cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=120)
    no_symlinks(receipt)
    if not receipt.is_file() or receipt.stat().st_size>2_000_000:
        raise Invalid('RebuildReceiptMissing')
    result=read_json(receipt.read_bytes())
    if (not isinstance(result,dict) or type(result.get('exit_code')) is not int or
            result['exit_code']!=proc.returncode):
        raise Invalid('RebuildExitMismatch')
    if proc.returncode not in (0,1):raise Invalid('RebuildNotCompleted')
    _,run,manifest,capture,artifacts=_latest(root)
    if (run==prior or result.get('run_dir')!=str(run) or
            result.get('html_path')!=str(run/'index.html') or
            result.get('mode')!='report-rebuild' or manifest.get('mode')!='report-rebuild' or
            result.get('synthetic') is not prior_capture['synthetic'] or
            capture['synthetic'] is not prior_capture['synthetic']):
        raise Invalid('RebuildCurrentReportMismatch')
    try:
        started=datetime.fromisoformat(manifest['started_at'])
        ended=datetime.fromisoformat(manifest['completed_at'])
        fresh=started.utcoffset() is not None and ended.utcoffset() is not None and began<=started<=ended
    except (KeyError,TypeError,ValueError):
        fresh=False
    if not fresh:raise Invalid('RebuildStaleReportRejected')
    if (artifacts['capture.json']!=prior_artifacts['capture.json'] or
            manifest.get('replay_input_sha256')!=sha(prior_artifacts['capture.json']) or
            manifest.get('original_capture_at')!=prior_capture.get('captured_at')):
        raise Invalid('RebuildSourceChanged')
    report=run/'casework.html';no_symlinks(report)
    if not report.is_file() or sha(report.read_bytes())!=manifest.get('artifacts_sha256',{}).get('casework.html'):
        raise Invalid('RebuildReportHashMismatch')
    statuses=result.get('sources')
    if (not isinstance(statuses,dict) or set(statuses)!=set(SOURCES) or
            any(statuses[name] not in {'SUCCESS','PARTIAL','FAILED'} or
                statuses[name]!=capture.get('sources',{}).get(name,{}).get('status') or
                statuses[name]!=manifest.get('sources',{}).get(name,{}).get('status') for name in SOURCES)):
        raise Invalid('RebuildSourceStatusMismatch')
    complete=all(statuses[name]=='SUCCESS' and capture['sources'][name].get('complete') is True for name in SOURCES)
    if proc.returncode!=(0 if complete else 1):raise Invalid('RebuildCompletenessMismatch')
    result['url']='/runs/'+run.name+'/casework.html'
    return result


def serve(root):
    root=checked_root(root);latest_run(root)
    lock=root/'.casework-service.lock'
    with lock.open('a') as handle:
        fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
        server=Server(root)
        temp=root/('.casework-service-'+uuid4().hex+'.tmp')
        fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as f:f.write(encoded(server.receipt));f.flush();os.fsync(f.fileno())
        os.replace(temp,root/RECEIPT)
        try:server.serve_forever(poll_interval=.1)
        finally:server.server_close()
