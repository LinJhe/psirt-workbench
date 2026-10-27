"""Local bookmarks: navigation only; never fetch a URL or request account access."""
import copy
from urllib.parse import urlsplit, parse_qsl, unquote
from .store import Invalid, encoded
from psirt_daily.pipeline import sha

CATEGORIES={'systems':'公司系統','documents':'文件與會議','collaboration':'Outlook／Teams 協作','reference':'學習與參考'}


def safe_url(value):
    if not isinstance(value,str) or not value or len(value)>4096:raise Invalid('請填完整 HTTP／HTTPS 網址')
    decoded=unquote(value)
    if any(ord(c)<33 or ord(c)==127 for c in value) or any(ord(c)<32 or ord(c)==127 for c in decoded) or '\\' in value:
        raise Invalid('網址不可含空白、控制字元或反斜線')
    try:
        p=urlsplit(value);_ = p.port  # Reject an invalid port before storing.
        if p.scheme not in ('https','http') or not p.hostname or p.username is not None or p.password is not None:raise ValueError()
    except ValueError:raise Invalid('只接受完整 HTTP／HTTPS 網址；不可內嵌帳密')
    forbidden={'access_token','refresh_token','id_token','client_secret','password','passwd','authorization','code'}
    if any(k.lower() in forbidden for part in (p.query,p.fragment) for k,_ in parse_qsl(part)):
        raise Invalid('請保存一般頁面網址，不要保存登入憑證或授權回呼網址')
    return value


def defaults(capture):
    rows=[]
    def add(id,title,url,category,note):
        if not url:return
        try:safe_url(url)
        except Invalid:return
        rows.append({'id':id,'title':title,'url':url,'category':category,'note':note,'status':'active'})
    sources=capture['sources']
    add('resource-jira','Jira',sources.get('jira',{}).get('scope',{}).get('instance'),'systems','沿用既有快照的來源實例；開啟仍使用公司登入。')
    add('resource-salesforce','Salesforce',sources.get('salesforce',{}).get('scope',{}).get('instance'),'systems','沿用既有快照的來源實例；不是從這裡刷新資料。')
    add('resource-weekly','Confluence／PSIRT Weekly',capture.get('weekly_template',{}).get('source'),'documents','既有報告記錄的頁面；未確認是當週最新週報。')
    add('resource-outlook','Outlook 網頁入口','https://outlook.office.com/mail/','collaboration','Microsoft 通用入口；公司帳號可用性尚未驗證。未讀取郵件。')
    add('resource-teams','Teams 網頁入口','https://teams.microsoft.com/','collaboration','Microsoft 通用入口；未讀取或傳送聊天訊息。也可新增指定聊天／頻道連結。')
    add('resource-first','FIRST PSIRT Services Framework','https://www.first.org/standards/frameworks/psirts/psirt_services_framework_v1-1','reference','四大核心學習手冊的參考來源；不是公司 SOP。')
    add('resource-dt-guide','Dependency-Track 使用與影響分析','https://docs.dependencytrack.org/usage/impact-analysis/','reference','官方工具文件；不是公司的 DT 網頁入口。公司 DT 入口請新增實際常用網址。')
    return rows


def build(capture,manual,generated_at,run_id):
    rows={r['id']:{'id':r['id'],'payload':r,'version':0,'origin':'既有來源／通用入口','record':None,'revisions':[]} for r in defaults(capture)}
    for record in manual.get('records',[]):
        if record['kind']!='bookmark':continue
        p=record['payload'];safe_url(p['url'])
        rows[record['id']]={'id':record['id'],'payload':copy.deepcopy(p),'version':record['version'],'origin':'本機保存','record':record,
                            'revisions':[r for r in manual.get('revisions',[]) if r['kind']=='bookmark' and r['id']==record['id']]}
    return {'schema':'psirt-resources/1','synthetic':capture['synthetic'],'generated_at':generated_at,'run_id':run_id,
            'manual_sha256':sha(encoded(manual).encode()),'categories':CATEGORIES,'rows':list(rows.values()),
            'source_at':capture.get('captured_at'),
            'note':'只保存與開啟連結，不代表帳號已串接；網站登入與權限仍由各公司系統管理。'}


def navigation(shell):
    # Older immutable index snapshots predate the editable casework page. The
    # loopback route already exists; repair its navigation only in the view.
    if 'href="casework.html"' not in shell:
        shell=shell.replace('</nav>','<a href="casework.html">案件流程與時程<span class="nav-index">07</span></a></nav>',1)
    if 'href="resources.html"' not in shell:
        return shell.replace('</nav>','<a href="resources.html">重要網址<span class="nav-index">08</span></a></nav>',1)
    return shell
