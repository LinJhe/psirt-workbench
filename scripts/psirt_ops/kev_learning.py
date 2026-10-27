"""Offline KEV learning aid, separate from source observations and formal decisions."""
from html import escape

VERSION = 'share-edition/1'

QUESTIONS = (
    ('01', '什麼東西出問題？', '廠商、產品用途、弱點元件、受影響版本。', '說得出這個元件在系統中負責什麼，不只念 CVE 編號。'),
    ('02', '漏洞怎麼成立？', '缺陷與被突破的限制，例如目錄限制或訊息來源驗證。', '用白話解釋原因；原廠未公開的細節標未知，不補猜測。'),
    ('03', '攻擊者需要什麼？', '遠端／本機、登入與權限、使用者操作、功能和設定。', '分清無須登入與需管理權限，列出可到達的入口。'),
    ('04', '成功後能做什麼？', '讀取、修改、執行程式、提權、服務中斷及影響邊界。', '不把檔案操作直接擴大成完整接管；指出影響停在哪一層。'),
    ('05', '為什麼現在要關注？', '實際利用、公開 PoC、情報時間及可信來源。', '加入 KEV ≠ 剛發現漏洞；已遭利用 ≠ 組織 已遭入侵。'),
    ('06', '跟我們有什麼關係？', '產品／版本／build／設定、部署資產及盤點涵蓋範圍。', '對外產品與內部系統分開找窗口；零命中不能超出查詢範圍。'),
    ('07', '現在怎麼處置？', '修補版本、暫時緩解、暴露限制、必要的入侵調查。', '解釋方案為何有效、限制及副作用；修補不代表排除既有入侵。'),
    ('08', '誰承接、如何驗收？', '承接人、下一步、缺口、期限依據與驗證證據。', '回應期限與修補期限分開；未確認的人員與日期保留待確認。'),
)

SOURCES = (
    ('CISA KEV 官方目錄', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', '確認收錄與 dateAdded；不能直接推導公司產品受影響。'),
    ('FIRST PSIRT Services Framework 1.1', 'https://www.first.org/standards/frameworks/psirts/psirt_services_framework_v1.1', '產品範圍、漏洞驗證、處置、交付，以及 PSIRT 與企業 CSIRT 的合作。'),
    ('CMU SEI · SSVC 2.0（2021）', 'https://www.sei.cmu.edu/library/prioritizing-vulnerability-response-a-stakeholder-specific-vulnerability-categorization-version-20/', '依利害關係人與實際情境決定處置；本頁不是完整 SSVC 評分器。'),
    ('FIRST · CVSS v4.0 User Guide', 'https://www.first.org/cvss/v4.0/user-guide', 'CVSS 基礎分數描述嚴重程度，不能單獨代表公司風險。'),
    ('FIRST · Using EPSS', 'https://www.first.org/epss/using-epss', 'EPSS 是機率訊號；已有實際利用證據時，不能因低分忽略。'),
    ('NIST SP 800-40 Rev.4（2022）', 'https://csrc.nist.gov/pubs/sp/800/40/r4/final', '修補管理包含識別、排序、取得、安裝與驗證。'),
)


STYLE = '''
html{scroll-behavior:auto!important}
.kev-learning{--kl-line:#3b3554;--kl-purple:#cfb4f7;--kl-muted:#abb6ce}
.kev-learning p{line-height:1.9}.kl-eyebrow{font:10px/1.6 Consolas,monospace;letter-spacing:2px;color:#b79adf;margin-bottom:8px}
.kl-meta{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}.kl-meta span{border:1px solid #403750;border-radius:4px;padding:5px 10px;font-size:11px;color:#c4b6d8;background:#1b192b}
.kl-intro{max-width:900px;color:#c2c9dc;font-size:13px}.kl-current{border-left:3px solid #ac85d9;background:#1d1a2c;padding:13px 16px;margin:18px 0;color:#c9c7e2;font-size:12px}.kl-current.kl-incomplete{background:#2c201d;border-color:#caa169;color:#e9c89e}
.kl-jumps{display:flex;flex-wrap:wrap;gap:9px;margin:20px 0}.kl-jumps a,.kl-entry a{padding:8px 12px;border:1px solid #53406e;border-radius:5px;background:#241c33;color:#d2b7f5;text-decoration:none;font-size:12px}.kl-entry{margin:18px 0}.kl-jumps a:hover,.kl-entry a:hover{background:#37264a;border-color:#ad89d9}
.kl-panel{border:1px solid var(--kl-line);background:#131727;border-radius:8px;padding:22px;margin:24px 0}.kl-panel h3,.kl-case h3{color:#d6c0f5;font-size:18px;line-height:1.7;margin:0 0 9px}.kl-panel>p{font-size:12px;color:var(--kl-muted)}
.kl-scroll{max-width:100%;overflow-x:auto;min-width:0}.kl-diagram{display:block;width:100%;min-width:780px;height:auto}.kl-diagram text{font-family:'Microsoft JhengHei','Segoe UI',sans-serif;fill:#e3d9f2;font-size:17px}.kl-diagram .kl-small{fill:#b7bdd3;font-size:13px}.kl-diagram rect,.kl-diagram polygon{fill:#221e34;stroke:#8e6eb4;stroke-width:1.5}.kl-diagram .kl-unknown{fill:#30251e;stroke:#c6a472}.kl-diagram .kl-action{fill:#172d33;stroke:#78b7c2}.kl-diagram .kl-edge{fill:none;stroke:#ab8bca;stroke-width:1.5;marker-end:url(#kl-arrow)}.kl-diagram .kl-return{stroke-dasharray:6 5}.kl-diagram a:hover rect,.kl-diagram a:focus rect{stroke:#e1c5ff;fill:#352644}.kl-diagram .kl-label{paint-order:stroke;stroke:#131727;stroke-width:5px;stroke-linejoin:round}
.kl-table{width:100%;border-collapse:collapse;font-size:13px;margin-top:16px}.kl-table caption{text-align:left;color:#c7c0da;font-size:12px;padding-bottom:10px}.kl-table th,.kl-table td{border:1px solid #3c3551;padding:13px 15px;vertical-align:top;text-align:left;line-height:1.9}.kl-table th{background:#272036;color:#dac5f4;font-weight:600}.kl-table td{color:#bdc7dc;background:#171b29}.kl-table th:first-child{min-width:190px}.kl-table td{min-width:220px}.kl-table .kl-number{color:#a98acb;font:11px Consolas,monospace;margin-right:9px}
.kl-levels{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:13px;margin:20px 0}.kl-level{padding:20px;border:1px solid #41364f;border-top:2px solid #a780cd;border-radius:6px;background:#1a1b2c}.kl-level b{color:#dec5fa;font-size:14px}.kl-level p{color:#b8c0d6;font-size:12px;margin:9px 0}.kl-case{border:1px solid #3c3450;border-left:3px solid #ac87cf;background:#181b2a;border-radius:7px;padding:21px;margin:16px 0}.kl-case>p{color:#c0c9dd;font-size:13px}.kl-case small{color:#aeb3cc;font-size:11px}.kl-case b{color:#e0d6ef}.kl-case details{background:#111626}.kl-note{border:1px dashed #76568f;background:#221c30;padding:15px 18px;border-radius:5px;color:#d5c5e9;font-size:13px}.kl-source-list{list-style:disc;padding-left:20px}.kl-source-list li{margin:14px 0;color:#b7c0d6;font-size:12px}.kl-source-list p{margin:4px 0}.kev-learning [id]{scroll-margin-top:24px}.kev-learning [id]:target{outline:1px solid #b193d2;outline-offset:5px}
.sidebar nav a[href="#kev-learning"]{margin-top:0;border:1px solid #413653;background:#1b1728;color:#d2bce9}
@media(max-width:850px){.kl-panel{padding:16px}.kl-levels{grid-template-columns:minmax(0,1fr)}.kl-case{padding:17px}.kl-jumps{gap:8px}.kl-jumps a{padding:7px 10px}.kl-table th,.kl-table td{padding:11px 12px}.kl-panel h3,.kl-case h3{font-size:16px}.kl-meta{gap:7px}}
@media print{.kev-learning,.kl-panel,.kl-level,.kl-case,.kl-note,.kl-current,.kl-table td{background:white;color:#222}.kl-table th{background:#eee;color:#222}.kl-panel h3,.kl-case h3,.kl-case>p,.kl-level b,.kl-level p,.kl-table td,.kl-intro{color:#222}.kl-diagram rect,.kl-diagram polygon{fill:#fff;stroke:#555}.kl-diagram text{fill:#222}.kl-diagram .kl-label{stroke:#fff}}
'''


def flow_diagram():
    out = ['<div class="kl-panel" id="kl-flow"><h3>從新 KEV 到可覆核的處置</h3>',
           '<p>點選方框可跳到判讀表或既有案件指南。窄螢幕可左右滑動；下方另有文字版。</p>',
           '<div class="kl-scroll" tabindex="0" aria-label="KEV 判讀流程圖，可左右捲動">',
           '<svg class="kl-diagram" viewBox="0 0 1000 850" role="img" aria-labelledby="kl-flow-title kl-flow-desc" xmlns="http://www.w3.org/2000/svg">',
           '<title id="kl-flow-title">KEV 取數、理解、關聯判讀與處置流程</title>',
           '<desc id="kl-flow-desc">取數失敗保留未知並查來源；取數成功先理解漏洞，再查產品與內部系統關聯。未知補證據，可能受影響則安排初評與必要緩解。有證據排除須限定範圍。處置由確認承接人交付，驗證後覆核；新情報或設定改變重新評估。緊急風險不必等待完整分析才升級。</desc>',
           '<defs><marker id="kl-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 10 5 0 10Z" fill="#ab8bca"/></marker></defs>']
    def edge(path):out.append('<path class="kl-edge" d="'+path+'"/>')
    def box(x,y,w,title,sub,anchor,kind=''):
        out.append(f'<a href="#{anchor}"><rect class="{kind}" x="{x}" y="{y}" width="{w}" height="68" rx="7"/><text x="{x+w/2}" y="{y+27}" text-anchor="middle">{escape(title)}</text><text class="kl-small" x="{x+w/2}" y="{y+49}" text-anchor="middle">{escape(sub)}</text></a>')
    box(325,20,350,'01　確認取數與比較基準','成功時間、範圍、日期與異動分開看','kl-boundaries')
    box(720,20,260,'取數失敗／不完整','Unknown；查來源，不報零','kl-boundaries','kl-unknown')
    edge('M675 54H720');edge('M500 88V125')
    box(325,125,350,'02　讀懂漏洞與利用條件','產品用途 → 攻擊條件 → 技術影響','kl-eight')
    edge('M500 193V230')
    out.append('<polygon points="500,230 645,300 500,370 355,300"/><text x="500" y="294" text-anchor="middle">03　跟我們有關嗎？</text><text class="kl-small" x="500" y="318" text-anchor="middle">產品／版本／設定／部署證據</text>')
    edge('M355 300H160V425');edge('M500 370V425');edge('M645 300H840V425')
    for x,label in ((160,'有證據排除'),(500,'有／可能相關'),(840,'未知／缺資料')):
        out.append(f'<text class="kl-small kl-label" x="{x}" y="405" text-anchor="middle">{label}</text>')
    box(20,425,280,'限定範圍記錄理由','留存證據、覆核與重評觸發','guide-judgment')
    box(360,425,280,'04　排序與選擇處置','實際利用、暴露、影響與控制','kl-response','kl-action')
    box(700,425,280,'補齊最能改變判斷的證據','缺版本、盤點或設定 → 找窗口','kl-eight','kl-unknown')
    edge('M500 493V535')
    box(360,535,280,'05　確認承接與交付','Owner、下一步、時限依據','guide-response','kl-action')
    edge('M500 603V645')
    box(360,645,280,'06　驗證、溝通與覆核','有效處置證據；剩餘事項有去處','guide-validation','kl-action')
    out.append('<path class="kl-edge kl-return" d="M980 459H990V300H645"/><path class="kl-edge kl-return" d="M360 679H320V459H360"/><text class="kl-small kl-label" x="305" y="580" text-anchor="end">驗證未通過</text>')
    edge('M160 493V770H360');edge('M500 713V738')
    box(360,738,280,'重新檢視','新情報／新版本／設定改變','guide-closure')
    out.append('</svg></div><details><summary>流程文字版與緊急處理原則</summary><p>取數完整後，先讀原廠公告並查產品／內部系統關聯。資料不足列待確認，指定補證據動作；可能受影響則依風險安排處置與實際承接；有證據排除時記錄適用版本、設定與理由。驗證、交付和覆核完成後仍保留重評觸發。</p><p>取數失敗不代表零。緊急風險可在補證據的同時協調暫時緩解與升級；疑似入侵交事件應變窗口，不等分析全部完成。</p></details></div>')
    return ''.join(out)


def render(capture, comparisons):
    kev = capture['sources']['kev']
    complete = kev['status'] == 'SUCCESS' and kev['complete']
    counts = comparisons.get('kev', {}).get('counts')
    added = str(counts['added']) if complete and counts is not None else 'Unknown（來源或比較基準不足）'
    scope = escape(str(capture['sources']['dt'].get('scope', 'Unknown')), quote=True)
    out = ['<section id="kev-learning" class="kev-learning" data-learning-version="'+VERSION+'">',
           '<div class="kl-eyebrow">KEV / UNDERSTAND → ASSESS → ACT</div><h2>05　KEV 判讀工作法</h2>',
           '<p class="kl-intro">把「有沒有命中」往前接上漏洞理解，往後接上有證據的處置。每筆新增能說明事件；可能相關的漏洞能交出一張處置卡。</p>',
           '<div class="kl-meta"><span>通用判讀方法 · 分享版</span><span>學習與工作建議 · 非 組織 核准 SOP</span><span>靜態案例 ≠ 本輪新增</span></div>',
           '<div class="kl-current'+('' if complete else ' kl-incomplete')+'">本頁 KEV 來源狀態：<b>'+escape(str(kev['status']))+'</b>；來源觀測時間：'+escape(str(kev.get('observed_at','Unknown')))+'<br>相較可用基準新增：'+escape(added)+'。本輪數字與取數範圍請回到 <a href="#kev-dt">KEV / DT</a> 核對；教材日期不代表重新取數。</div>',
           '<nav class="kl-jumps" aria-label="KEV 學習章節"><a href="#kl-flow">判讀流程</a><a href="#kl-eight">八項判讀表</a><a href="#kl-levels">掌握深度</a><a href="#kl-examples">合成情境</a><a href="#kl-boundaries">判斷界線</a></nav>',
           flow_diagram(),
           '<div class="kl-panel" id="kl-eight"><h3>八項判讀表：一張可覆核的處置卡</h3><div class="kl-scroll" tabindex="0" aria-label="八項 KEV 判讀表，可左右捲動"><table class="kl-table"><caption>沒有證據的欄位寫待確認，並列出取得證據的下一步。</caption><thead><tr><th scope="col">要回答的問題</th><th scope="col">需要的資料</th><th scope="col">能做到什麼才算掌握</th></tr></thead><tbody>']
    for num, question, evidence, standard in QUESTIONS:
        out.append('<tr><th scope="row"><span class="kl-number">'+num+'</span>'+escape(question)+'</th><td>'+escape(evidence)+'</td><td>'+escape(standard)+'</td></tr>')
    out += ['</tbody></table></div></div>',
            '<div id="kl-levels"><h3>掌握深度：依事件相關性深入</h3><div class="kl-levels">',
            '<div class="kl-level"><b>01 / 每筆新增</b><p>能用約一分鐘說清產品、攻擊條件、影響、處置方向，以及還不知道什麼。</p><p>這是練習目標，不是公司 SLA；不要求背完所有 CVE。</p></div>',
            '<div class="kl-level"><b>02 / 可能相關</b><p>完成八項判讀卡，對齊產品版本、實際部署、缺口、證據來源與承接。</p><p>掃描結果是線索；不受影響必須有適用範圍與理由。</p></div>',
            '<div class="kl-level"><b>03 / 高風險或確認相關</b><p>能追出入口 → 弱點元件 → 權限／信任邊界 → 實際影響 → 修補為何有效。</p><p>需要時與 RD／原廠合作驗證，不必獨自重現每筆漏洞。</p></div></div></div>',
            '<div id="kl-examples" class="kl-panel"><h3>合成情境：先查範圍，再下結論</h3><p>合成產品 A 有一個本機觸發條件；合成產品 B 只有元件名稱相似。前者需確認出貨版本與權限配置，後者需先查版本對應。這裡沒有真實漏洞公告、利用紀錄或公司受影響判定。</p></div>',
            '<div class="kl-panel" id="kl-boundaries"><h3>分清訊號、判定與完成證據</h3><div class="kl-scroll" tabindex="0" aria-label="KEV、CVSS、EPSS 判讀差異"><table class="kl-table"><thead><tr><th scope="col">訊號</th><th scope="col">可以支持什麼</th><th scope="col">不能直接推論什麼</th></tr></thead><tbody>',
            '<tr><th scope="row">KEV</th><td>已知存在實際利用；需要納入優先判讀。</td><td>組織 已受影響、已遭入侵，或漏洞剛被發現。</td></tr>',
            '<tr><th scope="row">CVSS 基礎分數</th><td>漏洞本身的技術嚴重程度。</td><td>公司風險排名；分數低就不需處理。</td></tr>',
            '<tr><th scope="row">EPSS</th><td>未來 30 天遭利用的機率估計訊號。</td><td>低機率可推翻已知利用證據。</td></tr>',
            '<tr><th scope="row">DT 沒有命中</th><td>在成功取得且已涵蓋的資料中未找到匹配。</td><td>所有公司產品都不受影響；失敗可當作零。</td></tr>',
            '<tr><th scope="row">已修補／已關單</th><td>需要再核對 build、部署、驗證與處置理由。</td><td>所有客戶已安裝、已排除入侵或風險完全消失。</td></tr></tbody></table></div>',
            '<details><summary>本輪 DT 範圍，為什麼不能代表全公司？</summary><p>來源狀態：'+escape(str(capture['sources']['dt']['status']))+'</p><pre>'+scope+'</pre><p>只有範圍完整、產品版本對齊且有判定依據時，才能提出限定範圍的結論。盤點缺漏與來源失敗均須保留未知。</p></details></div>',
            '<div class="kl-panel" id="kl-response"><h3>從分析走到承接與驗收</h3><p>先提出風險理由與處置選項，再找實際可交付的人。對外產品、內部系統與疑似入侵應由對應窗口承接；不自動寄信、開單或發布判定。</p><div class="kl-note">處置卡：產品／版本／設定 → 結論與證據 → 未知與下一步 → 已確認承接人 → 期限及其依據 → 驗收結果與剩餘風險。</div><p>回應期限不等於修補期限；CISA 日期不自動成為 組織 承諾。未取得核定依據的期限標待確認。</p><p><a href="#guide-response">查看案件承接做法 →</a> · <a href="#guide-validation">查看處置驗證做法 →</a></p></div>',
            '<details><summary>官方參考入口與適用限制</summary><p>八項判讀表、分層練習與流程圖是依公開方法整理的工作建議，不是業界統一考試標準，也不是 組織 正式 SOP。參考資料可能更新；本頁沒有本輪重新連線查核。</p><ul class="kl-source-list">']
    for title,url,note in SOURCES:
        out.append('<li><a href="'+escape(url,quote=True)+'">'+escape(title)+'</a><p>'+escape(note)+'</p></li>')
    out += ['</ul><p>外部規範的義務須由權責者確認適用性；此處不替公司設定回應或修補期限。</p></details>',
            '<p><a href="#kev-dt">← 回到本輪 KEV / DT 資料</a></p></section>']
    return ''.join(out)


def attach(page, capture, comparisons):
    if 'id="kev-learning"' in page:
        return page
    page = page.replace('</head>', '<style data-kev-learning="'+VERSION+'">'+STYLE+'</style></head>', 1)
    # Match the main sidebar only; retain the other CLI's case guide and its links.
    page = page.replace('</nav>', '<a href="#kev-learning">KEV 判讀工作法<span class="nav-index">05</span></a></nav>', 1)
    page = page.replace('<section id="kev-dt">', '<p class="kl-entry"><a href="#kev-learning">讀懂 KEV，再判斷怎麼處理 · 流程圖與判讀表 →</a></p><section id="kev-dt">', 1)
    return page.replace('<footer>', render(capture, comparisons)+'<footer>', 1)
