"""Casework view uses the existing report shell; historical reports remain immutable."""
import base64
import hashlib
import json
import re
from html import escape
from pathlib import Path
from .store import STAGES, CATEGORIES, DATE_KINDS
from .report_version import section as report_section, ASSET as REPORT_SCRIPT
from .work_page import compact_shell

ASSETS=Path(__file__).with_name('assets')


def render(shell,data,editable=False):
    prefix=shell.split('<main>',1)[0]
    prefix=re.sub(r'href="#([^\"]+)"',r'href="index.html#\1"',prefix)
    prefix=prefix.replace('<title>PSIRT 工作台','<title>案件流程與時程')
    prefix=prefix.replace('href="casework.html"','href="casework.html" aria-current="page"')
    script=REPORT_SCRIPT.read_text()+'\n'+(ASSETS/'dashboard.js').read_text()+'\n'+(ASSETS/'casework.js').read_text()
    h=base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
    prefix=prefix.replace("default-src 'none';","default-src 'none'; script-src 'sha256-"+h+"';"+(" connect-src 'self';" if editable else ''))
    prefix=prefix.replace('</head>','<style>'+(ASSETS/'casework.css').read_text()+'\n'+(ASSETS/'dashboard.css').read_text()+'</style></head>')
    prefix=compact_shell(prefix)
    def field(label,name,type='text',required=False):
        tag='<textarea name="'+name+'"'+(' required' if required else '')+'></textarea>' if type=='textarea' else '<input name="'+name+'" type="'+type+'"'+(' required' if required else '')+'>'
        return '<label>'+escape(label)+tag+'</label>'
    def select(label,name,options):
        return '<label>'+escape(label)+'<select name="'+name+'">'+''.join('<option value="'+escape(k)+'">'+escape(v)+'</option>' for k,v in options.items())+'</select></label>'
    def common(kind):
        return field('來源／證據（待確認案件可留空）','evidence','textarea',kind!='case')+field('登錄／覆核者','reviewer')+field('覆核時間（台灣時間）','reviewed_at','datetime-local')+field('更新／更正原因（修改既有紀錄必填）','correction_reason','textarea')
    def form(kind,title,content):
        return '<details class="cw-editor"><summary>'+title+'</summary><form data-kind="'+kind+'"><fieldset'+('' if editable else ' disabled')+'><legend>'+title+'</legend><input type="hidden" name="record_id"><input type="hidden" name="expected_version" value="0"><div class="cw-fields">'+content+common(kind)+'</div><button type="submit">保存紀錄</button> <button type="button" data-reset>清空表單／新增</button><p class="cw-form-status" role="status"></p></fieldset></form></details>'
    date_fields=[]
    for kind,label in DATE_KINDS.items():
        block=field('日期時間（台灣時間）','date_'+kind+'_at','datetime-local')+select('確認狀態','date_'+kind+'_confirmation',{'pending':'待確認','confirmed':'已確認（需依據）'})
        for k,t in [('evidence','依據／來源'),('confirmed_by','確認者'),('basis_version','制度／依據版本'),('trigger_event','起算事件'),('scope','適用範圍'),('completion_evidence','完成交付證據')]:
            block+=field(t,'date_'+kind+'_'+k)
        block+=field('實際完成時間（有證據才填）','date_'+kind+'_completed_at','datetime-local')
        date_fields.append('<details class="cw-date"><summary>'+label+'</summary><div class="cw-fields">'+block+'</div></details>')
    case_form=field('案件編號','case_id',required=True)+field('產品','product')+field('產品版本','product_version')+field('產品／版本來源','product_evidence')
    case_form+=select('主要階段（候選分類，非公司 SOP）','stage',{k:v[0] for k,v in STAGES.items()})+select('階段確認','stage_confirmation',{'pending':'待確認','suggested':'建議待覆核','confirmed':'有證據確認'})
    case_form+=select('本次階段操作','stage_event',{'update':'更新／更正本次紀錄（不新增同階段歷程）','reenter':'已離開後重新進入同階段（新增歷程）'})
    case_form+='<p>重新進入前，先保存前次離開時間與證據。選擇重新進入會清空表單的進出時間與事件證據，請填本次進入資料；前段紀錄仍保留。單純時間更正使用更新。</p><input type="hidden" name="stage_visit_id">'
    for name,label,type in [('entered_at','進入階段時間（台灣時間）','datetime-local'),('entry_evidence','進入事件證據','text'),('exited_at','離開階段時間（轉換前可先保存）','datetime-local'),('exit_evidence','離開事件證據','text'),('accepted_by','實際承接者','text'),('accepted_at','接受時間（台灣時間）','datetime-local'),('acceptance_evidence','接受證據','text'),('deliverable','下一份交付','text'),('exit_conditions','完成／退出條件','textarea'),('next_action','下一步','textarea'),('blocker','卡點','textarea'),('completed_work','已完成事項','textarea'),('completed_evidence','完成事項來源','textarea')]:case_form+=field(label,name,type)
    case_form+=select('承接者類型','owner_kind',{'unknown':'待確認','person':'具名個人','team':'團隊','queue':'佇列'})+select('承接確認','acceptance',{'pending':'尚未確認承接','confirmed':'已有接受證據'})
    case_form+=select('交付／下一步／卡點確認','record_confirmation',{'pending':'待確認（可先暫存）','confirmed':'已覆核，有來源證據'})
    case_form+=''.join(date_fields)+field('明確採用本次 Store 內容的理由（不改舊檔）','legacy_resolution','textarea')+'<input type="hidden" name="legacy_digest">'
    work_form=field('關聯案件（逗號分隔，可留空）','case_ids')+field('工作內容／一般任務','task')+field('工作日期','work_date','date',True)+field('淨工作分鐘','minutes','number',True)
    work_form+=select('工作類型','category',CATEGORIES)+select('分鐘性質','measurement',{'measured':'實際投入（人工登錄）','estimated':'估計，另列不計入實際'})+select('登錄方式','recording_mode',{'backfill':'事後補登','manual':'當次人工登錄'})
    work_form+=field('開始（選填，台灣時間）','start','datetime-local')+field('結束（選填，台灣時間）','end','datetime-local')+field('時段排除分鐘（有起迄才填）','excluded_minutes','number')+field('產出／尚未取得成果的原因','outcome','textarea',True)
    wait_form=field('案件編號','case_id',required=True)+select('等待所在階段','stage',{k:v[0] for k,v in STAGES.items()})+field('等待對象','waiting_for',required=True)+field('等待交付物','deliverable',required=True)+field('原因','reason','textarea',True)+field('開始（台灣時間）','start','datetime-local',True)+field('結束（台灣時間）','end','datetime-local')+field('解除等待證據','resolution_evidence','textarea')+field('本人追蹤時間（台灣時間）','followup_at','datetime-local')
    delivery_form=field('關聯案件（逗號分隔）','case_ids',required=True)+field('實際取得的交付物','title',required=True)+field('取得時間（台灣時間）','received_at','datetime-local',True)+field('交付成果與限制','outcome','textarea',True)+select('交付接受狀態','acceptance',{'pending':'已取得，待接受／覆核','accepted':'已有接受證據'})+field('接受時間（台灣時間）','accepted_at','datetime-local')+field('接受證據','acceptance_evidence','textarea')
    notice='本機工作頁：讀取與保存本機紀錄本身不取數；自動更新開啟時，頁面依到期狀態觸發既有範圍更新。' if editable else '歷史報告：本頁唯讀。人工保存須由本機工作頁操作；此檔不會因後續修改而改變。'
    body=['<main><section class="cw" id="casework" data-editable="'+str(editable).lower()+'"><div class="cw-title"><div><h2>案件流程與時程'+('' if editable else ' <span class="work-mode">固定報告 · 唯讀</span>')+'</h2></div><button id="cw-refresh" type="button"'+('' if editable else ' disabled')+'>讀取最新本機紀錄</button></div>',
      '<p id="cw-status" role="status"></p><p id="cw-source-summary"></p><details class="cw-source-evidence"><summary>查看來源時間、更新說明與本機操作</summary><p class="cw-banner">'+notice+'</p><p id="cw-times"></p>'+('<button id="cw-rebuild" type="button">使用既有快照產生新報告</button> <button id="cw-backup" type="button">備份人工紀錄</button>' if editable else '')+'</details>',
      '<details class="cw-dashboard-fold"><summary>案件統計與進度圖 · 全部已觀測案件，不隨下方篩選改變</summary><div id="cw-dashboard"></div><div class="cw-cards" id="cw-counts"></div><div class="cw-stages" id="cw-stages"></div></details>',
      '<p id="cw-dashboard-filter" role="status" hidden></p>',
      '<div class="cw-controls"><label>搜尋案件／產品／交付／承接人<input id="cw-search" type="search"></label><label>顯示範圍<select id="cw-filter"><option value="all">全部已觀測案件</option><option value="commitment_overdue">承諾逾期</option><option value="followup_due">待追蹤</option><option value="deadline_unknown">正式期限未知</option><option value="acceptance_unknown">承接未知</option><option value="conflicts">人工紀錄衝突</option></select></label><button id="cw-clear" type="button">清除篩選</button></div><p id="cw-count"></p>',
      '<div class="cw-scroll" tabindex="0" aria-label="案件清單，可左右捲動"><table><thead><tr><th>案件／來源狀態</th><th>實際階段／停留</th><th>承接／指派</th><th>下一步／交付／卡點</th><th>追蹤日／日期判讀</th><th>操作</th></tr></thead><tbody id="cw-rows"></tbody></table></div>',
      '<div id="cw-detail" tabindex="-1" hidden></div><details open><summary>本週交付與階段變化</summary><div id="cw-weekly"></div></details>',
      '<details open><summary>實際工時與等待（獨立計算）</summary><div id="cw-effort"></div><div id="cw-records"></div></details>',
      '<details><summary>新增／修改案件與時間紀錄</summary><p>來源 Jira 狀態與 Assignee 保留原文。以下為本機人工紀錄；確認階段與承接需要證據，沒有公司期限就保留待確認。</p>',
      form('case','案件節點、承接與日期',case_form),form('worklog','實際工時／一般工作',work_form),form('wait','等待紀錄',wait_form),form('delivery','實際取得交付',delivery_form),'</details>',
      '<details><summary>計算口徑與資料來源</summary><ul>'+''.join('<li>'+escape(t)+'</li>' for t in data['limits'])+'</ul><p>案件分母：本輪未結案索引及本機已追蹤案件（含有紀錄的已關閉案件）。紀錄不足與未登錄均標待確認。等待採區間聯集，實際工時採唯一工作紀錄；同一份交付以唯一交付 ID 計數。</p><pre id="cw-provenance"></pre></details>',
      report_section(data,editable,'casework')+'<p><a href="index.html">返回總覽</a></p>',
      '<pre id="cw-data" hidden>'+escape(json.dumps(data,ensure_ascii=False,separators=(',',':')))+'</pre></section></main><script>'+script+'</script></body></html>']
    return prefix+''.join(body)
