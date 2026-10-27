"""Embed the mail work queue in the existing Salesforce page, no second platform."""
from html import escape
from pathlib import Path
from .inbox import STATES
ASSETS=Path(__file__).with_name('assets')


def assets():
    return (ASSETS/'sf-inbox.js').read_text(),(ASSETS/'sf-inbox.css').read_text()


def section(editable):
    options={'attention':'未完成＋來源更新待覆核',**STATES,'all':'全部已觀測來信'}
    return '''<section id="sfi" data-editable="'''+str(editable).lower()+'''" class="sfi" aria-label="來信待辦，跨日保留">
      <div id="sfi-health" class="sfi-health"><p id="sfi-coverage"></p><p id="sfi-currentness"></p><p id="sfi-source-warning" class="sfi-warning"></p>
      <div class="sfi-health-actions"><button id="sfi-retry" type="button" disabled>重試 Salesforce 連線</button><p id="sfi-retry-note">只在目前本機工作頁、既有 live 授權範圍可重試；歷史報告不會取數。</p></div>
      <details id="sfi-source-evidence"><summary>查看來源證據、時間與範圍</summary><p id="sfi-times"></p><p id="sfi-source-error"></p></details></div>
      <div class="sfi-controls" role="search" aria-label="來信待辦篩選"><label>搜尋案件／信件／下一步<input id="sfi-search" type="search"></label>
      <label>處理狀態<select id="sfi-filter">'''+''.join('<option value="'+k+'">'+escape(v)+'</option>' for k,v in options.items())+'''</select></label>
      <label>通報分類<select id="sfi-category"><option value="all">全部分類</option><option value="vulnerability">漏洞通報</option><option value="inquiry">詢問／追蹤</option><option value="notification">通知</option><option value="other">其他</option><option value="unknown">待確認</option></select></label>
      <label>回答狀態<select id="sfi-answer"><option value="all">全部回答狀態</option><option value="unchecked">尚未核對</option><option value="unanswered">尚未回答</option><option value="partial">部分回答</option><option value="answered">已回答（人工覆核）</option><option value="not_required">不需回答（人工覆核）</option></select></label>
      <button id="sfi-clear" type="button">清除篩選</button></div>
      <p id="sfi-status" role="status"></p><p id="sfi-results" role="status" aria-live="polite"></p>
      <div class="sfi-list-head" aria-hidden="true"><span>案件／主旨</span><span>回答／待辦狀態</span><span>下一步／追蹤日</span></div>
      <div id="sfi-rows"></div><div class="sfi-controls"><button id="sfi-prev" type="button">上一頁</button><span id="sfi-page"></span><button id="sfi-next" type="button">下一頁</button></div>
      <details class="sfi-statistics"><summary>全部已觀測統計 · 不隨篩選改變</summary>      <p class="sfi-count-scope">以下統計為全部已觀測來信，與下方篩選筆數分開。</p>
      <div id="sfi-counts" class="sfi-cards"></div>
</details>
      <details class="sfi-method"><summary>本機覆核、讀回與產生報告</summary><p>分類與一句重點為規則初判，待你覆核；不是 AI 已判定或正式產品影響結論。展開信件不會自動改變處理狀態。</p><p>'''+('可保存到本機；不回寫 Salesforce。' if editable else '歷史報告唯讀；保存請使用 Launch-PSIRT.cmd 開啟本機工作頁，再選 Salesforce。')+'''</p>
      <div class="sfi-local-actions"><button id="sfi-refresh" type="button"'''+('' if editable else ' disabled')+'''>讀回本機狀態（不取信）</button>
      <button id="sfi-rebuild" type="button"'''+('' if editable else ' disabled')+'''>將目前狀態存成新報告（不取信）</button></div></details>
      <details><summary>來源範圍與計算限制</summary><pre id="sfi-provenance"></pre></details>
      </section>'''
