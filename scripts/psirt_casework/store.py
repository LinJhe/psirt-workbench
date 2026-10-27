"""Transactional, revisioned personal records; no dependency on API snapshots."""
import hashlib
import json
import re
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

TZ = ZoneInfo('Asia/Taipei')
CATEGORIES = {'triage':'情報與初判', 'technical_analysis':'技術分析', 'coordination':'修補協調',
              'verification':'驗證覆核', 'communication':'揭露與溝通', 'reporting':'會議與報告',
              'improvement':'流程改善與開發', 'learning':'學習'}
STAGES = {
 'unknown':('待確認','PSIRT','先核對來源與目前進度'),
 'intake':('登錄與分流','PSIRT','來源、產品／版本、問題證據與關聯案'),
 'handoff':('確認承接','PSIRT／PM／具名技術窗口','具名承接人、交付物、接受證據與追蹤日'),
 'analysis':('分析與影響判定','RD／DQV、PM、PSIRT','技術證據、產品與客戶範圍、未知與處置方向'),
 'planning':('修補規劃','RD／PM／PSIRT','對策、目標版本、交付承諾、驗證與發布安排'),
 'development':('開發與自測','RD／供應商','可識別版本、變更說明、自測證據與限制'),
 'verification':('正式驗證','DQV／QA／QT 或指定單位','有效性、回歸、相容性；失敗須修正重測'),
 'release':('發布交付與溝通','PM／PSIRT／權責者','實際交付版本、必要通知／公告及核准證據'),
 'closure':('結案覆核','PSIRT／PM／治理單位','技術處置或風險接受、必要溝通、完整證據、後續承接'),
 'monitoring':('後續監控','PSIRT／PM','發布後問題與再發評估；不因本機標記而正式結案')}
DATE_KINDS = {'followup':'本人追蹤日', 'remediation':'正式修補期限', 'commitment':'對方承諾',
              'estimate':'預估日期', 'ai_suggestion':'AI 建議日期'}

MAIL_REVIEW_FIELDS = {'review_version','analysis_digest','reviewed_category','reviewed_summary',
                     'reviewed_attention','answer_assessment','reply_ids','answer_note',
                     'reviewed_reply_fact','reply_note'}


class Invalid(ValueError): pass
class Conflict(ValueError): pass


def now(): return datetime.now(TZ).isoformat(timespec='seconds')
def encoded(obj): return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def timestamp(value):
    if not value: return None
    try:
        t = datetime.fromisoformat(value)
        if t.tzinfo is None: raise ValueError()
        return t.astimezone(TZ)
    except (ValueError, TypeError): raise Invalid('日期時間不合法，須包含時區')


def integer(v, name, minimum=0, maximum=1440):
    if isinstance(v, bool) or not re.fullmatch(r'\d+', str(v)): raise Invalid(name+'須為非負整數')
    n = int(v)
    if not minimum <= n <= maximum: raise Invalid(name+'超出範圍')
    return n


def validate(kind, original):
    if not isinstance(original, dict): raise Invalid('資料格式不合法')
    d = json.loads(encoded(original))
    for k,v in d.items():
        if not isinstance(v, (str, int, dict, list, type(None))) or isinstance(v, bool): raise Invalid('欄位型別不合法')
        if isinstance(v, str) and (len(v)>6000 or '\x00' in v): raise Invalid('欄位過長或含不合法字元')
    common = {'case_id','evidence','correction_reason','reviewer','reviewed_at'}
    fields = {
        'case': {'stage','stage_event','stage_visit_id','stage_confirmation','entered_at','exited_at','entry_evidence','exit_evidence',
                 'accepted_by','owner_kind','acceptance','accepted_at','assigned_at','acceptance_evidence',
                 'deliverable','next_action','blocker','dates','product','product_version','product_evidence',
                 'record_confirmation','exit_conditions','completed_work','completed_evidence','legacy_resolution','legacy_digest'},
        'worklog': {'task','work_date','minutes','start','end','excluded_minutes','category','measurement','outcome','case_ids','recording_mode'},
        'wait': {'stage','start','end','waiting_for','deliverable','reason','followup_at','resolution_evidence'},
        'delivery': {'case_ids','title','received_at','acceptance','accepted_at','acceptance_evidence','outcome'}}
    fields['sf_email']={'instance','email_id','source_digest','state','next_action','outcome','followup_at'}|MAIL_REVIEW_FIELDS
    fields['bookmark']={'title','url','category','note','status'}
    if kind not in fields or set(d)-common-fields[kind]: raise Invalid('不支援的紀錄或欄位')
    for name in list(d):
        if d[name] is None and name not in ('dates','case_ids','minutes','excluded_minutes'): d[name]=''
    key = d.get('case_id','')
    if key and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}',key): raise Invalid('案件識別碼不合法')
    if kind in ('case','wait') and not key: raise Invalid('請選案件')
    if 'case_ids' in d:
        ids=d['case_ids']
        if not isinstance(ids,list) or len(ids)>100 or any(not isinstance(k,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}',k) for k in ids):
            raise Invalid('關聯案件清單不合法')
        d['case_ids']=sorted(set(ids+([key] if key else [])))
    for name,value in d.items():
        if name!='case_ids' and isinstance(value,list): raise Invalid('此欄位不接受清單')
        if name!='dates' and isinstance(value,dict): raise Invalid('此欄位不接受物件')
        if isinstance(value,int) and name not in ('minutes','excluded_minutes'): raise Invalid('文字欄位不接受數字')
    timestamp(d.get('reviewed_at'))
    if d.get('reviewed_at') and not d.get('reviewer','').strip(): raise Invalid('覆核時間須有覆核者')
    if kind=='worklog':
        if not key and not d.get('case_ids') and not d.get('task','').strip(): raise Invalid('請選案件或填一般任務')
        try:
            if date.fromisoformat(d['work_date']).isoformat()!=d['work_date']: raise ValueError()
        except (KeyError,ValueError,TypeError): raise Invalid('工作日期不合法')
        if d.get('category') not in CATEGORIES: raise Invalid('請選主要工作類型')
        if d.get('measurement') not in ('measured','estimated'): raise Invalid('請區分實測或估計')
        if not d.get('outcome','').strip(): raise Invalid('請記錄本次成果或尚未取得成果的原因')
        if not d.get('evidence','').strip(): raise Invalid('工時須記錄產出或工作證據')
        if d.get('recording_mode','backfill') not in ('backfill','manual','timer'): raise Invalid('登錄方式不合法')
        start,end = timestamp(d.get('start')),timestamp(d.get('end'))
        excluded = integer(d.get('excluded_minutes',0),'扣除分鐘')
        minutes = integer(d.get('minutes',0),'實際分鐘',1)
        if bool(start)!=bool(end): raise Invalid('開始與結束須成對提供')
        if start:
            span = (end-start).total_seconds()/60
            if start.date()!=end.date() or start.date().isoformat()!=d['work_date']:
                raise Invalid('時段須在登錄日期內；跨日工作請分兩筆')
            if span<=0 or not span.is_integer() or span-excluded!=minutes: raise Invalid('時段扣除後須等於實際分鐘')
            d['start'],d['end'] = start.isoformat(),end.isoformat()
        elif excluded: raise Invalid('只有分鐘的補登請直接填淨分鐘，扣除填 0')
        d.update(minutes=minutes,excluded_minutes=excluded)
    elif kind=='case':
        if d.get('stage_event','update') not in ('update','reenter'): raise Invalid('階段操作意圖不合法')
        if d.get('stage_visit_id') and not re.fullmatch(r'[A-Za-z0-9_-]+:[0-9]+',d['stage_visit_id']): raise Invalid('階段歷程識別碼不合法')
        if d.get('record_confirmation','pending') not in ('pending','confirmed'): raise Invalid('人工內容確認狀態不合法')
        if d.get('record_confirmation')=='confirmed' and not (d.get('reviewer') and d.get('evidence')): raise Invalid('確認交付／下一步須有覆核者與證據')
        if d.get('stage') not in STAGES: raise Invalid('未知工作節點')
        if d.get('stage_confirmation') not in ('pending','suggested','confirmed'): raise Invalid('節點確認狀態不合法')
        if d.get('stage_confirmation')=='confirmed' and not d.get('evidence','').strip(): raise Invalid('確認節點須有證據')
        if d.get('stage_confirmation')=='confirmed' and not d.get('reviewer','').strip(): raise Invalid('確認節點須記錄覆核者')
        entered,exited = timestamp(d.get('entered_at')),timestamp(d.get('exited_at'))
        if entered and not d.get('entry_evidence','').strip(): raise Invalid('進入時間需要事件證據，不能拿觀測時間代替')
        if exited and (not entered or exited<entered or not d.get('exit_evidence','').strip()): raise Invalid('離開時間需要有效進入時間與離開證據')
        if d.get('owner_kind') not in ('person','team','queue','unknown'): raise Invalid('承接者類型不合法')
        if d.get('acceptance') not in ('pending','confirmed'): raise Invalid('承接狀態不合法')
        timestamp(d.get('assigned_at')); timestamp(d.get('accepted_at'))
        if d.get('acceptance')=='confirmed':
            if d.get('owner_kind')!='person' or not all(d.get(k,'').strip() for k in ('accepted_by','acceptance_evidence','accepted_at')):
                raise Invalid('確認承接須為具名個人，並有接受時間與證據；Team／Queue 不算個人承接')
        if d.get('product') or d.get('product_version'):
            if not d.get('product_evidence','').strip(): raise Invalid('產品／版本須有來源')
        if d.get('completed_work') and not d.get('completed_evidence','').strip(): raise Invalid('已完成事項須有證據')
        if d.get('legacy_resolution') and not all(d.get(k,'').strip() for k in ('legacy_digest','reviewer','correction_reason')):
            raise Invalid('處理歷史覆核衝突須有來源雜湊、覆核者與理由')
        dates = d.get('dates',{})
        if not isinstance(dates,dict) or set(dates)-set(DATE_KINDS): raise Invalid('日期種類不合法')
        for name,item in dates.items():
            if not isinstance(item,dict) or set(item)-{'at','confirmation','evidence','basis_version','trigger_event','scope','confirmed_by','completed_at','completion_evidence'}:
                raise Invalid('日期依據格式不合法')
            if any(not isinstance(v,str) or len(v)>2000 for v in item.values()): raise Invalid('日期依據不合法')
            if item.get('confirmation') not in ('pending','confirmed'): raise Invalid('日期確認狀態不合法')
            if item.get('at'): timestamp(item['at'])
            if item.get('completed_at'):
                timestamp(item['completed_at'])
                if not item.get('completion_evidence','').strip(): raise Invalid('完成承諾須有交付證據')
            if item.get('confirmation')=='confirmed':
                required = ['at','evidence','confirmed_by']
                if name=='remediation': required += ['basis_version','trigger_event','scope']
                if not all(item.get(k,'').strip() for k in required): raise Invalid(DATE_KINDS[name]+'缺少確認依據')
                if name=='ai_suggestion': raise Invalid('AI 建議不能標成已確認的正式安排')
    elif kind=='wait':
        if d.get('stage','unknown') not in STAGES: raise Invalid('等待節點不合法')
        start,end = timestamp(d.get('start')),timestamp(d.get('end'))
        if not start: raise Invalid('等待需有開始時間')
        if end and (end<start or not d.get('resolution_evidence','').strip()): raise Invalid('解除等待需要有效時間與證據')
        if not all(d.get(k,'').strip() for k in ('waiting_for','deliverable','reason','evidence')): raise Invalid('請填等待對象、交付物、原因與來源證據')
        timestamp(d.get('followup_at'))
    elif kind=='bookmark':
        from .resources import safe_url, CATEGORIES as LINK_CATEGORIES
        if not d.get('title','').strip() or len(d['title'])>120: raise Invalid('網址名稱必填，最多 120 字')
        d['url']=safe_url(d.get('url'))
        if d.get('category') not in LINK_CATEGORIES: raise Invalid('網址分類不合法')
        if d.get('status') not in ('active','archived'): raise Invalid('網址狀態不合法')
        if len(d.get('note',''))>1000: raise Invalid('網址備註最多 1000 字')
        if not d.get('reviewer','').strip(): raise Invalid('請記錄登錄者')
    elif kind=='sf_email':
        from .inbox import STATES
        if d.get('state') not in STATES: raise Invalid('郵件處理狀態不合法')
        if not all(d.get(k,'').strip() for k in ('instance','email_id','reviewer')): raise Invalid('郵件來源與登錄者必填')
        if not re.fullmatch(r'[a-f0-9]{64}',d.get('source_digest','')): raise Invalid('郵件來源證據摘要不合法')
        if d['state'] in ('pending','following') and not d.get('next_action','').strip(): raise Invalid('待處理／待追蹤須填下一步')
        if d['state']=='done' and not d.get('outcome','').strip(): raise Invalid('完成須填處理結果；不等於正式案件結案')
        timestamp(d.get('followup_at'))
        if set(d)&MAIL_REVIEW_FIELDS:
            if d.get('review_version')!='1' or not MAIL_REVIEW_FIELDS<=set(d):
                raise Invalid('來信覆核格式已更新，請重新開啟工作頁；未保存')
            if not re.fullmatch(r'[a-f0-9]{64}',d.get('analysis_digest','')):
                raise Invalid('來信判讀輸入版本不合法')
            enums={'reviewed_category':{'unknown','vulnerability','inquiry','notification','other'},
                   'reviewed_attention':{'priority','normal','reference'},
                   'answer_assessment':{'unchecked','unanswered','partial','answered','not_required'},
                   'reviewed_reply_fact':{'unknown','sent_human','automated','draft_or_failed','internal','not_found'}}
            if any(d.get(name) not in options for name,options in enums.items()):
                raise Invalid('來信覆核選項不合法')
            ids=[part.strip() for part in d.get('reply_ids','').split(',') if part.strip()]
            if len(ids)>100 or len(ids)!=len(set(ids)) or any(not re.fullmatch(r'[A-Za-z0-9_-]{1,100}',v) for v in ids):
                raise Invalid('回覆郵件識別碼不合法或重複')
            d['reply_ids']=','.join(sorted(ids))
            if d['reviewed_reply_fact'] in {'sent_human','automated','draft_or_failed','internal'} and (not ids or not d.get('reply_note','').strip()):
                raise Invalid('確認寄送性質須選回信並填覆核依據')
            if d['reviewed_reply_fact']=='not_found' and not d.get('reply_note','').strip():
                raise Invalid('未見回信須說明已核對範圍')
            if d['answer_assessment'] in {'answered','partial'} and (d['reviewed_reply_fact']!='sent_human' or not ids or not d.get('answer_note','').strip()):
                raise Invalid('確認完整／部分回答須有已寄出人工回信及問題對照依據')
            if d['answer_assessment'] in {'unanswered','not_required'} and not d.get('answer_note','').strip():
                raise Invalid('未回答／不需回覆須說明覆核理由與範圍')
    else:
        if not d.get('case_ids') and not key: raise Invalid('交付須關聯案件')
        if not all(d.get(k,'').strip() for k in ('title','evidence','outcome','reviewer')): raise Invalid('交付須有名稱、成果、來源及登錄者')
        if not timestamp(d.get('received_at')): raise Invalid('交付須有實際取得時間')
        if d.get('acceptance') not in ('pending','accepted'): raise Invalid('交付接受狀態不合法')
        if d.get('acceptance')=='accepted':
            accepted=timestamp(d.get('accepted_at'))
            if not accepted or accepted<timestamp(d['received_at']) or not d.get('acceptance_evidence','').strip(): raise Invalid('接受交付須有有效時間與證據')
    return d


class Store:
    def __init__(self, directory, synthetic=False):
        self.directory=Path(directory).absolute();self.path=self.directory/'worklog.sqlite3'
        from psirt_daily.pipeline import no_symlinks
        no_symlinks(self.path)
        self.directory.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.synthetic=synthetic
        self.actor='DEMO Vance' if synthetic else 'Vance'
        with self.connect() as db:
            db.executescript('''
              CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS records(kind TEXT,id TEXT,version INTEGER,payload TEXT,
                created_at TEXT,updated_at TEXT,observed_at TEXT,actor TEXT,PRIMARY KEY(kind,id));
              CREATE TABLE IF NOT EXISTS revisions(kind TEXT,id TEXT,version INTEGER,payload TEXT,
                at TEXT,observed_at TEXT,actor TEXT,PRIMARY KEY(kind,id,version));
              CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY,digest TEXT,result TEXT);
            ''')
            expected=encoded({'schema':1,'synthetic':synthetic,'purpose':'psirt-personal-casework'})
            row=db.execute("SELECT value FROM meta WHERE key='identity'").fetchone()
            if row and row[0]!=expected: raise Invalid('資料庫模式或版本不符；禁止合成／真實混用')
            db.execute("INSERT OR IGNORE INTO meta VALUES('identity',?)",(expected,))
        self.path.chmod(0o600)

    @contextmanager
    def connect(self):
        db=sqlite3.connect(self.path,timeout=10);db.row_factory=sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON');db.execute('PRAGMA synchronous=FULL')
        try:
            with db: yield db
        finally: db.close()

    @staticmethod
    def row(row):
        if not row:return None
        d=dict(row);d['payload']=json.loads(d['payload']);return d

    def records(self,kind=None):
        with self.connect() as db:
            rows=db.execute('SELECT * FROM records'+(' WHERE kind=?' if kind else '')+' ORDER BY created_at,id', (kind,) if kind else ()).fetchall()
        return [self.row(r) for r in rows]

    def get(self,kind,id):
        with self.connect() as db:return self.row(db.execute('SELECT * FROM records WHERE kind=? AND id=?',(kind,id)).fetchone())

    def history(self,kind,id):
        with self.connect() as db:rows=db.execute('SELECT * FROM revisions WHERE kind=? AND id=? ORDER BY version',(kind,id)).fetchall()
        return [self.row(r) for r in rows]

    def replay_operation(self,kind,id,payload,expected_version,operation_id):
        """Acknowledge an already committed request before current-source checks.

        New operations still pass source validation and save's transactional guard.
        This read never updates a record or bypasses payload equality.
        """
        d=validate(kind,payload);version=integer(expected_version,'版本',0,1000000)
        digest=hashlib.sha256(encoded([kind,id,d,version]).encode()).hexdigest()
        with self.connect() as db:
            prior=db.execute('SELECT * FROM operations WHERE id=?',(operation_id,)).fetchone()
        if not prior:return None
        if prior['digest']!=digest:raise Conflict('同一操作已送出不同內容；請回讀最新版本')
        return json.loads(prior['result'])

    def save(self,kind,id,payload,expected_version,operation_id):
        if not isinstance(id,str) or not isinstance(operation_id,str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,100}',id) or not re.fullmatch(r'[a-zA-Z0-9_-]{8,100}',operation_id): raise Invalid('紀錄或操作識別碼不合法')
        version=integer(expected_version,'版本',0,1000000)
        d=validate(kind,payload)
        if kind=='case' and id!=d['case_id']: raise Invalid('案件 ID 不一致')
        if kind=='sf_email':
            from .inbox import identity
            if id!=identity(d['instance'],d['email_id']): raise Invalid('郵件 ID 不一致')
        if not self.synthetic and any(k.startswith('DEMO-') for k in [d.get('case_id','')]+d.get('case_ids',[])): raise Invalid('合成案例不可存入真實紀錄')
        digest=hashlib.sha256(encoded([kind,id,d,version]).encode()).hexdigest()
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            prior=db.execute('SELECT * FROM operations WHERE id=?',(operation_id,)).fetchone()
            if prior:
                if prior['digest']!=digest:raise Conflict('同一操作已送出不同內容；請回讀最新版本')
                return json.loads(prior['result'])
            old=db.execute('SELECT * FROM records WHERE kind=? AND id=?',(kind,id)).fetchone()
            if (old['version'] if old else 0)!=version: raise Conflict('版本衝突，未覆蓋；請回讀並核對其他修改')
            if kind=='sf_email' and old and json.loads(old['payload']).get('review_version') and not d.get('review_version'):
                raise Conflict('這封信已有新版覆核紀錄；請重新開啟工作頁，舊表單未覆蓋任何內容')
            if old and not d.get('correction_reason','').strip(): raise Invalid('更新須填更正／推進原因，保留原版本')
            if kind=='case':
                # Resolve a stable visit only after deduplication and optimistic lock.
                # Client-supplied IDs can identify the edited visit, never invent one.
                previous=json.loads(old['payload']) if old else {}
                from .projection import stage_visits
                history=[self.row(row) for row in db.execute('SELECT * FROM revisions WHERE kind=? AND id=? ORDER BY version',(kind,id))]
                current_visit=stage_visits(history)[-1]['id'] if history else None
                if d.get('stage_visit_id') and d['stage_visit_id']!=current_visit: raise Conflict('階段歷程版本不符，請重新選取編輯')
                event=d.get('stage_event','update')
                if event=='reenter':
                    if not old or previous.get('stage')!=d.get('stage'): raise Invalid('重新進入須是已保存的同一階段；換階段請用更新')
                    if not all(previous.get(k) for k in ('entered_at','entry_evidence','exited_at','exit_evidence','reviewer','evidence')) or previous.get('stage_confirmation')!='confirmed':
                        raise Invalid('重新進入前須先保存有證據的離開紀錄')
                    if not d.get('entered_at') or not d.get('entry_evidence') or timestamp(d['entered_at'])<timestamp(previous['exited_at']):
                        raise Invalid('重新進入須有新的進入時間及證據，時間不得早於前次離開')
                    visit_id=id+':'+str(version+1)
                else:
                    if old and previous.get('stage')==d.get('stage') and previous.get('exited_at') and not d.get('exited_at') and d.get('entered_at') and timestamp(d['entered_at'])>=timestamp(previous['exited_at']):
                        raise Invalid('已離開後再次進入，請明確選擇「重新進入同階段」')
                    visit_id=current_visit if old and previous.get('stage')==d.get('stage') else id+':'+str(version+1)
                d['stage_visit_id']=visit_id
                d['stage_event']=event
            if kind=='worklog' and d.get('start'):
                for r in db.execute("SELECT id,payload FROM records WHERE kind='worklog' AND id<>?",(id,)):
                    other=json.loads(r['payload'])
                    if other.get('start') and timestamp(d['start'])<timestamp(other['end']) and timestamp(other['start'])<timestamp(d['end']):
                        raise Conflict('與既有工時時段重疊；請拆分時段，不重複計時')
            at=now();observed=old['observed_at'] if old else at
            if old and kind=='case' and json.loads(old['payload']).get('stage')!=d.get('stage'):observed=at
            result={'kind':kind,'id':id,'version':version+1,'payload':d,'created_at':old['created_at'] if old else at,
                    'updated_at':at,'observed_at':observed,'actor':self.actor}
            db.execute('INSERT OR REPLACE INTO records VALUES(?,?,?,?,?,?,?,?)',
                       (kind,id,version+1,encoded(d),result['created_at'],at,observed,self.actor))
            db.execute('INSERT INTO revisions VALUES(?,?,?,?,?,?,?)',(kind,id,version+1,encoded(d),at,observed,self.actor))
            db.execute('INSERT INTO operations VALUES(?,?,?)',(operation_id,digest,encoded(result)))
        return result

    def snapshot(self):
        return read_snapshot(self.directory,self.synthetic)

    def backup(self):
        folder=self.directory/'backups';folder.mkdir(exist_ok=True,mode=0o700)
        from uuid import uuid4
        target=folder/('worklog-'+datetime.now(TZ).strftime('%Y%m%dT%H%M%S')+'-'+uuid4().hex[:8]+'.sqlite3')
        from contextlib import closing
        with self.connect() as source, closing(sqlite3.connect(target)) as dest:source.backup(dest)
        target.chmod(0o600);return target


def read_snapshot(directory, synthetic=False):
    """Read-only coherent export. Reporting must not create/migrate the personal DB."""
    from psirt_daily.pipeline import no_symlinks
    path=Path(directory).absolute()/'worklog.sqlite3'
    no_symlinks(path)
    result={'schema':'psirt-casework/1','synthetic':synthetic,'records':[],'revisions':[], 'available':path.exists()}
    if not path.exists(): return result
    from urllib.parse import quote
    db=sqlite3.connect('file:'+quote(str(path))+'?mode=ro',uri=True)
    db.row_factory=sqlite3.Row
    try:
        db.execute('BEGIN')
        identity=db.execute("SELECT value FROM meta WHERE key='identity'").fetchone()
        if not identity or json.loads(identity[0])!={'schema':1,'synthetic':synthetic,'purpose':'psirt-personal-casework'}:
            raise Invalid('資料庫模式不符')
        result['records']=[Store.row(r) for r in db.execute('SELECT * FROM records ORDER BY kind,id')]
        result['revisions']=[Store.row(r) for r in db.execute('SELECT * FROM revisions ORDER BY kind,id,version')]
    finally: db.close()
    return result
