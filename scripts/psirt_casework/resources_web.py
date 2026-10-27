"""Resource links use the current visual shell and existing local persistence."""
import base64
import hashlib
import json
import re
from html import escape
from pathlib import Path
from .resources import navigation
ASSETS=Path(__file__).with_name('assets')


def render(shell,data,editable=False):
    prefix=navigation(shell).split('<main>',1)[0]
    prefix=re.sub(r'href="#([^\"]+)"',r'href="index.html#\1"',prefix)
    prefix=prefix.replace('<title>PSIRT 工作台','<title>重要網址')
    prefix=prefix.replace('href="resources.html"','href="resources.html" aria-current="page"')
    script=(ASSETS/'resources.js').read_text();digest=base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
    prefix=prefix.replace("default-src 'none';","default-src 'none'; script-src 'sha256-"+digest+"';"+(" connect-src 'self';" if editable else ''))
    prefix=prefix.replace('</head>','<style>'+(ASSETS/'sf-inbox.css').read_text()+'.res-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px}.res-card{min-width:0;overflow-wrap:anywhere}.res-card a{color:#dec7ff;font-size:1.15rem}.res-card p{font-size:14px}.res-card button{margin-right:8px}.res-card details{margin-top:10px}#res-edit{scroll-margin-top:20px}</style></head>')
    label='可新增、編輯與封存本機書籤；封存可恢復，不會刪除歷程。' if editable else '本輪歷史報告唯讀；要保存請使用 Launcher 開啟本機工作頁。'
    form='''<details id="res-edit" open><summary>新增／編輯網址</summary><form id="res-form"><fieldset'''+('' if editable else ' disabled')+'''><div class="sfi-form">
      <label>名稱<input name="title" required maxlength="120"></label><label>完整網址<input name="url" type="url" required maxlength="4096" placeholder="https://..."></label>
      <label>分類<select name="category"></select></label><label>顯示狀態<select name="status"><option value="active">使用中</option><option value="archived">已封存（可恢復）</option></select></label>
      <label>用途／備註<textarea name="note" maxlength="1000"></textarea></label><label>更新原因（修改既有紀錄必填）<input name="correction_reason"></label>
      </div><button type="submit">保存網址</button> <button id="res-clear" type="button">清空表單／新增</button><p id="res-form-status" role="status"></p></fieldset></form></details>'''
    body='''<main><section class="sfi" id="resources" data-editable="'''+str(editable).lower()+'''">
      <p class="sfi-eyebrow">WORKSPACE / USEFUL LINKS</p><h2>重要網址</h2><p>公司系統、文件、Outlook 與 Teams，集中在同一個工作入口。</p>
      <p>'''+label+'''</p><p>'''+escape(data['note'])+'''</p>
      <div class="sfi-controls"><label>搜尋名稱／網址／用途<input id="res-search" type="search"></label><label>分類<select id="res-category"><option value="all">全部分類</option></select></label>
      <label>顯示<select id="res-filter"><option value="active">使用中</option><option value="archived">已封存</option><option value="all">全部</option></select></label>
      <button id="res-read" type="button"'''+('' if editable else ' disabled')+'''>讀回本機網址</button></div><p id="res-count"></p><p id="res-status" role="status"></p><div id="res-list" class="res-grid"></div>
      '''+form+'''<details><summary>資料時間與本機版本</summary><pre id="res-meta"></pre></details>
      <pre id="res-data" hidden>'''+escape(json.dumps(data,ensure_ascii=False,separators=(',',':')))+'''</pre></section></main><script>'''+script+'''</script></body></html>'''
    return prefix+body
