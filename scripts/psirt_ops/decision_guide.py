"""Offline decision aid. Guidance is separate from observations and human signoff."""
from html import escape

VERSION = 'share-edition/1'

STEPS = (
    ('scope', '界定範圍', '這張單要完成什麼？證據適用到哪裡？',
     '先讀原始要求、產品型號、出貨版本／build、主子單與既有處置。把客戶問答、影響判定、修補及驗證任務分清楚。',
     '列出「產品 × 版本 × CVE／問題」對照；找到既有涵蓋工單。相同 CVE 不代表不同產品可共用結論。',
     '範圍、原始需求、來源時間、尚未涵蓋的版本。',
     '問答子任務完成，不等於證明交付版本已含修補。'),
    ('urgency', '判斷急迫性', '如果等到下次回覆，可能付出什麼代價？',
     '核對 KEV／利用情報、攻擊入口與權限、實際部署、業務影響及適用期限。未知不能自動算低風險；案齡也不能單獨決定順序。',
     '提出工作排序與理由。若有緊急風險，分析與暫時緩解／升級並行；有疑似入侵時協調事件應變窗口。',
     '原 Priority、建議順序、風險依據、正式期限來源與下一次檢視時間。',
     'DT 標記 KEV 支持優先查影響，不能證明 組織 已遭利用；CISA 日期也不是自動適用的 組織 交期。'),
    ('hypotheses', '建立假設與取證', '同一個結果，還有哪些合理解釋？什麼證據能區分它們？',
     '測試沒重現，可能是沒有相關程式、已修補、設定阻擋，或測試未達觸發條件。這是待驗證假設，不是可直接選填的結論。',
     '先找最能改變判斷的證據：SBOM 與 build 對應、原始碼／patch、建置設定、攻擊路徑或有辨識力的測試。資料不足時明確向原廠或 RD 提出所需項目與用途。',
     '假設、支持／反駁證據、下一個最小查證動作、提供者與檢視點。',
     '先確認程式與漏洞的關聯，再選能區分假設的測試；不要只重跑相同的一般功能測試。'),
    ('judgment', '形成有限定的判定', '證據支持什麼？又不能支持什麼？',
     '逐一分開：受影響、不受影響、誤報、已修補或仍未知。理由必須對應特定產品版本與設定；補丁存在於原始碼，不代表已進入交付 build。',
     '記錄結論、依據、適用範圍與限制。若仍未知，回到第 3 步補證據；同時維持風險排序與追蹤，不能以時間經過代替答案。',
     '可覆核的技術判定；由公司指定權責者確認。DT 標記及 Jira 狀態只作線索。',
     '「未啟用功能」要分清是測試機設定，還是所有涵蓋的出貨設定；客戶能啟用時，結論必須保留條件。'),
    ('response', '選擇處置並承接', '哪個方案能有效降低風險？誰能實際交付？',
     '比較修補、升級、停用功能或其他緩解的效果、可部署性與副作用。無法修補、停止支援及風險接受是不同路徑，不能標成已修復。',
     '提出建議方案與取捨；取得 RD／PM／驗證窗口的實際承接。需要風險接受或跨部門資源時，帶剩餘風險與建議交有權責者決定。',
     'Owner、具體交付物、建議／預估／已承諾日期的區分、驗收條件與阻塞事項。',
     '沒有 Owner、重要期限受威脅或暫時控制無效時，帶證據升級；不要只再寄同一封進度詢問。'),
    ('validation', '驗證處置有效', '修正的是根因，還是只讓這次測試不出錯？',
     '核對測試產品、版本、build、攻擊條件與結果。區分 RD 自測、指定驗證及發布；確認正常功能與相關變體也被考慮。',
     '若可重現，以原受影響版本作對照、修補版作複測。原版也未觸發時，改用程式碼／patch 與其他適當證據補強，不能把 PoC 失敗直接當修好。',
     '對應 build 的修補與測試證據、剩餘限制、指定驗證者的確認；必要時回到第 5 步。',
     '同一份程式用在兩個產品，仍要確認設定差異、涵蓋範圍與測試代表性。'),
    ('delivery', '交付與必要溝通', '需要保護的人，拿得到也用得到處置嗎？',
     '確認更新或緩解的交付位置、適用版本、安裝方式與必要通知。修補程式完成和客戶可以採取行動，是不同證據。',
     '與 PM／發布及溝通權責者確認交付。依公司政策判斷是否需 advisory、release note、客戶或研究員回覆；不能每案自動套用同一形式。',
     '發布／部署紀錄、必要溝通證據及未完成承諾。產品可下載不等於所有客戶已安裝。',
     '網站已部署修正與韌體待客戶更新的交付方式不同，完成條件要跟產品一致。'),
    ('closure', '覆核收束與回看', '關的是這張任務，還是整個風險？剩餘事項有沒有去處？',
     '依任務範圍與處置理由核對完成條件。誤報／不受影響、風險接受、重複、停止支援及已修復，分開記錄。',
     '整理證據送覆核；剩餘事項要有追蹤位置與實際承接。為條件式判定、緩解或例外設定重新檢查的日期／事件，並回饋共用元件與測試缺口。',
     '處置理由、證據、覆核者、剩餘承接、重查觸發；有新版本／情報／部署變更時重評。',
     '若只是客戶說明任務，仍須核對剩餘安全事項是否已有承接；不可由本指南自動決定收束。'),
)

SOURCES = (
    ('FIRST PSIRT Services Framework 1.1',
     'https://www.first.org/standards/frameworks/psirts/psirt_services_framework_v1-1',
     '參考 §3.3、§4.2 與 §5.3：產品範圍、驗證、處置與溝通。它是可依組織調整的框架，並非 組織 的操作授權。'),
    ('NIST SSDF 1.1 · 2022/02',
     'https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf',
     'RV.2：依風險分析與處置；RV.3：找根因、檢查相似問題並改善開發流程。'),
    ('CISA VEX 最低要求 · 2023/04',
     'https://www.cisa.gov/sites/default/files/2023-04/minimum-requirements-for-vex-508c.pdf',
     '參考 affected、not_affected、fixed、under_investigation 的區分；不受影響需有理由／影響說明。不是 Jira 狀態映射表。'),
    ('CISA VEX 判定理由 · 2022/06',
     'https://www.cisa.gov/sites/default/files/publications/VEX_Status_Justification_Jun22.pdf',
     '區分元件不存在、弱點程式不存在、不可到達等理由。不能只以掃描或測試沒有命中推導不受影響。'),
    ('CMU SEI · SSVC 決策方法',
     'https://sei.cmu.edu/blog/whats-new-in-ssvc-build-explore-and-evolve-your-decision-models/',
     '供應商與部署者的決策需求不同；用明確決策點形成可解釋的工作順序。此處不冒稱已執行完整 SSVC 評分。'),
)

STYLE = '''
.decision-guide{--dg-line:#b8a4ca;--dg-ink:#40304e;--dg-fill:#e8ddef}
.decision-guide p{margin:10px 0;line-height:1.85}.decision-guide a{text-decoration:underline;text-underline-offset:3px}
.dg-intro{max-width:900px}.dg-label{font-size:12px;letter-spacing:1px;color:#68467f;font-weight:600}
.dg-flow{margin:25px 0;padding:20px;border:1px solid var(--dg-line);background:#efe7f5}
.dg-diagram-scroll{overflow-x:auto}.dg-diagram{display:block;width:100%;min-width:720px;height:auto}.dg-diagram text{font-family:'Microsoft JhengHei','Segoe UI',sans-serif;fill:#40304e;font-size:17px}.dg-diagram .dg-small{font-size:14px}.dg-diagram .dg-node{fill:#faf7fc;stroke:#806294;stroke-width:2}.dg-diagram a:hover .dg-node,.dg-diagram a:focus .dg-node{fill:#e0d0ec;stroke:#4c2c65;stroke-width:3}.dg-diagram .dg-edge{fill:none;stroke:#725584;stroke-width:2;marker-end:url(#dg-arrow)}.dg-diagram .dg-return{stroke-dasharray:6 4}.dg-diagram .dg-label-bg{paint-order:stroke;stroke:#efe7f5;stroke-width:6;stroke-linejoin:round}
.dg-flow ol{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:22px;padding:0;list-style:none}
.dg-flow li{position:relative;min-width:0}.dg-flow li:not(:last-child):after{content:'→';position:absolute;right:-19px;top:17px;color:#68467f}
.dg-flow a{display:block;background:#faf7fc;border:1px solid var(--dg-line);padding:12px;color:var(--dg-ink);text-decoration:none;min-height:85px}
.dg-flow a:hover,.dg-flow a:focus-visible{background:#ded0e9}.dg-flow b,.dg-flow small{display:block}.dg-flow small{font-size:12px;margin-top:6px;color:#584466}
.dg-branches{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:16px 0}.dg-branches a{font-size:12px;min-height:100px;border-top:3px solid #8b709f}.dg-branches .dg-unknown{border-top-color:#a16b32;background:#f4eadb}
.dg-flow-note{font-size:12px;color:#584466}.dg-steps{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:15px}.dg-step{min-width:0;background:#eee5f4;border:1px solid var(--dg-line);padding:18px}.dg-step:target{outline:3px solid #8c6ba6;outline-offset:3px}.dg-step h3{font-size:18px}.dg-step .dg-question{font-weight:600;color:var(--dg-ink)}
.decision-guide summary{font-size:14px}.decision-guide dl{margin:12px 0}.decision-guide dt{font-weight:600;margin-top:12px}.decision-guide dd{margin:4px 0 12px;line-height:1.85}.decision-guide ul{list-style:disc;padding-left:22px}.decision-guide li{margin:7px 0}
.dg-table-wrap{overflow:auto;margin:16px 0}.dg-table{width:100%;font-size:13px}.dg-table th,.dg-table td{border:1px solid #c5b5d1;padding:12px;text-align:left;vertical-align:top;min-width:130px}.dg-table th{background:#e5d9ee;font-weight:600}.dg-case{border-left:3px solid #8b709f;padding:16px 20px;background:#ede4f3;margin:18px 0;scroll-margin-top:20px}.dg-case:target{outline:2px solid #8c6ba6}.dg-case h3{font-size:18px}
.dg-case small{color:#665473}.dg-case details{background:#f7f2fa}.dg-source-list{font-size:13px}.dg-source-list li{margin:12px 0}.dg-brief{padding:16px;border:1px dashed #9d82b3;background:#faf7fc}.dg-entry{font-size:13px;padding:12px 0}.dg-entry a{text-decoration:underline}.dg-case-link{font-size:12px}
@media(max-width:1000px){.dg-steps{grid-template-columns:1fr}.dg-branches{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:600px){.dg-flow{padding:14px}.dg-flow ol{grid-template-columns:1fr;gap:22px}.dg-flow li:not(:last-child):after{content:'↓';right:50%;top:auto;bottom:-24px}.dg-flow a{min-height:0}.dg-branches{grid-template-columns:1fr}.dg-branches a{min-height:0}.dg-step,.dg-case{padding:15px}.dg-table th,.dg-table td{min-width:140px}}
@media print{.decision-guide details>*{display:block}.decision-guide details{break-inside:avoid}.dg-step{break-inside:avoid}.dg-steps{display:block}}
'''


def case_link(key):
    anchor = 'guide-scope'
    return '<p class="dg-case-link"><a href="#'+anchor+'">用判斷指南檢查下一步 →</a></p>'


def _flow_row(steps):
    return '<ol>'+''.join('<li><a href="#guide-'+s[0]+'"><b>'+str(STEPS.index(s)+1)+'　'+escape(s[1])+'</b><small>'+escape(s[2])+'</small></a></li>' for s in steps)+'</ol>'


def flow_diagram():
    """Offline SVG with explicit decision branches, return paths and linked steps."""
    out = ['<div class="dg-flow"><h3>案件判斷流程圖</h3>',
           '<p class="dg-flow-note">實線是推進路徑；虛線是回頭查證或重評。點選方框可跳到下方做法。窄螢幕可左右滑動。</p>',
           '<div class="dg-diagram-scroll" tabindex="0" aria-label="可左右捲動的案件流程圖">',
           '<svg class="dg-diagram" viewBox="0 0 1000 1030" role="img" aria-labelledby="dg-chart-title dg-chart-desc" xmlns="http://www.w3.org/2000/svg">',
           '<title id="dg-chart-title">案件判斷、處置與覆核流程</title>',
           '<desc id="dg-chart-desc">界定範圍，判斷急迫性，建立假設與取證，再依證據分流。未知回到取證；受影響安排處置；宣稱修補則驗證；不受影響或誤報需附依據與必要溝通後覆核。驗證失敗退回處置；通過後確認交付並覆核。新情報觸發重新評估。</desc>',
           '<defs><marker id="dg-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#725584"/></marker></defs>']
    for path, back in [('M500 90V110',False),('M500 180V200',False),
                       ('M500 270V310',False),('M350 365H265',False),
                       ('M145 330V235H350',True),('M650 365H735',False),
                       ('M500 420V470',False),('M500 550V600',False),
                       ('M650 365H690V640H650',False),
                       ('M855 400V900H650',False),('M500 680V730',False),
                       ('M350 640H305V510H350',True),('M500 810V860',False),
                       ('M500 940V995H10V55H350',True)]:
        out.append('<path class="dg-edge'+(' dg-return' if back else '')+'" d="'+path+'"/>')

    def node(key, x, y, width, height, title, subtitle):
        out.append('<a href="#guide-'+key+'" aria-label="'+escape(title)+'：查看做法"><rect class="dg-node" x="'+str(x)+'" y="'+str(y)+'" width="'+str(width)+'" height="'+str(height)+'" rx="9"/><text text-anchor="middle" x="'+str(x+width/2)+'" y="'+str(y+29)+'">'+escape(title)+'</text><text class="dg-small" text-anchor="middle" x="'+str(x+width/2)+'" y="'+str(y+54)+'">'+escape(subtitle)+'</text></a>')
    node('scope',350,20,300,70,'① 界定範圍','產品、版本、build、這張單的任務')
    node('urgency',350,110,300,70,'② 判斷急迫性','利用情報、暴露、影響與適用期限')
    node('hypotheses',350,200,300,70,'③ 建立假設與取證','找能支持或排除假設的證據')
    out.append('<a href="#guide-judgment" aria-label="第四步：依證據判定"><path class="dg-node" d="M500 310L650 365L500 420L350 365Z"/><text text-anchor="middle" x="500" y="360">④ 證據支持什麼？</text><text class="dg-small" text-anchor="middle" x="500" y="385">限定產品、版本與設定</text></a>')
    node('hypotheses',25,330,240,70,'仍未知／資料不足','列缺口、提供者與檢視點')
    node('closure',735,330,240,70,'不受影響／誤報','附判定依據與適用範圍')
    node('response',350,470,300,80,'⑤ 選擇處置並承接','修補／緩解；Owner、交付物、時程')
    node('validation',350,600,300,80,'⑥ 驗證處置有效','核對 build、條件、結果與限制')
    node('delivery',350,730,300,80,'⑦ 交付與必要溝通','發布／部署、適用對象與通知')
    node('closure',350,860,300,80,'⑧ 覆核收束與回看','處置理由、剩餘事項、重查條件')
    for x,y,label in [(545,450,'受影響'),(719,530,'宣稱已修補'),
                      (905,675,'必要溝通後覆核'),(240,573,'驗證不通過'),
                      (556,711,'證據通過'),(210,982,'新情報／版本／部署改變 → 重新評估')]:
        out.append('<text class="dg-small dg-label-bg" text-anchor="middle" x="'+str(x)+'" y="'+str(y)+'">'+escape(label)+'</text>')
    out += ['</svg></div><p class="dg-flow-note">急迫風險：第 ② 步即可並行升級、暫時緩解或事件應變。風險接受／停止支援等例外須由權責者核准，再於第 ⑧ 步核對剩餘風險、必要溝通及重查安排；不標成已修復。</p></div>']
    return ''.join(out)


def render():
    out = ['<section id="decision-guide" class="decision-guide" aria-labelledby="decision-guide-title" data-guide-version="'+VERSION+'">',
           '<p class="dg-label">判斷 → 取證 → 處置 → 驗收</p><h2 id="decision-guide-title">04　案件判斷指南</h2>',
           '<div class="dg-intro"><p><b>每次處理工單，先決定需要證明什麼，再決定找誰、問什麼。</b></p>',
           '<p>這是依業界文件整理的工作輔助流程，不是 組織 已核准 SOP，也不會替你判定、改狀態或填入承諾。正式完成條件、權責與期限沿用公司規定；未確認處保留未知。</p>',
           '<p class="muted">指南版本 '+VERSION+' · 通用工作方法與合成案例，與報表來源擷取時間、資料範圍分開。</p></div>',
           '<details><summary>先理解 SBOM、DT、Jira 的關係</summary><dl><dt>SBOM：產品某個版本的軟體材料清單</dt><dd>回答用了什麼元件與版本。清單必須能對回實際 build。</dd><dt>DT：比對漏洞並保存判定</dt><dd>命中是候選；逐項判定要有產品範圍與理由。EXPLOITABLE 不等於有人正在修，RESOLVED 不等於已發布。</dd><dt>Jira：追蹤工作與交付</dt><dd>記錄誰承接、缺什麼、下一個交付物及完成證據。DT 與 Jira 有工作關聯，但不能假設已自動同步，也不必每筆 finding 各開一單。</dd></dl></details>',
           flow_diagram(),
           '<div class="dg-steps">']
    for i, (key, title, question, thinking, action, evidence, trap) in enumerate(STEPS, 1):
        out += ['<div class="dg-step" id="guide-'+key+'"><h3>'+str(i)+'　'+escape(title)+'</h3><p class="dg-question">'+escape(question)+'</p>',
                '<details><summary>展開：思維、做法與過關證據</summary><dl>',
                '<dt>你的思維</dt><dd>'+escape(thinking)+'</dd><dt>怎麼做</dt><dd>'+escape(action)+'</dd>',
                '<dt>本步交付物</dt><dd>'+escape(evidence)+'</dd><dt>判讀提醒</dt><dd>'+escape(trap)+'</dd></dl></details></div>']
    out += ['</div><details><summary>「三種可能」是不是 SOP？如何用證據排除假設？</summary>',
            '<p>它是分析方法，不是固定只能列三種的規定。下面以「測試沒有重現」為例；各假設都尚待查證，可能因產品版本不同而同時成立。</p>',
            '<div class="dg-table-wrap"><table class="dg-table"><thead><tr><th>假設</th><th>能區分它的證據</th><th>結論邊界</th></tr></thead><tbody>',
            '<tr><td>沒有使用受影響程式</td><td>實際 build 的元件／原始碼／建置設定，與原廠受影響範圍對照</td><td>SBOM 沒列出不一定代表不存在；先確認清單完整性。</td></tr>',
            '<tr><td>已有修補</td><td>修補內容、納入紀錄、對應 build 與驗證結果</td><td>版本號沒變也可能 backport；有 commit 不代表交付版本含修補。</td></tr>',
            '<tr><td>仍有漏洞，但測試沒觸發</td><td>確認入口、權限、配置及輸入是否到達問題程式；適當時使用原受影響版對照</td><td>一般功能正常不能排除安全問題。</td></tr>',
            '<tr><td>設定或控制阻止利用</td><td>控制是否生效、能否繞過、是否涵蓋出貨與客戶可調整的設定</td><td>暫時緩解不等於根因修復；條件改變要重查。</td></tr></tbody></table></div>',
            '<p>選下一步時問：「拿到這份資料，會讓哪個假設成立或被排除？」不能改變判斷的重複測試或追問，通常不是優先動作。</p></details>',
            '<div class="dg-case"><h3>合成案例：同一漏洞，兩個版本</h3><p>產品 A 的 v1 與 v2 均有同一漏洞識別碼。只有 v2 提供了對應 build 的排除證據，因此 v1 仍需補查；不得共用結論。這是虛構教學情境，不是真實案件。</p></div>',
            '<details><summary>你、RD、PM、驗證與主管如何分工？</summary><ul><li><b>使用者／PSIRT：</b>整理範圍、分析證據、提出風險與處置建議、審查回覆是否足夠，協調阻塞與追蹤結果。</li><li><b>RD／技術權責者：</b>確認實作、影響與根因，提供修補、build 及自測證據。</li><li><b>指定驗證者：</b>確認測試計畫、範圍與結果。是否由 DQV／QA 承接，依產品流程確認，不假定 使用者 要獨自測試。</li><li><b>PM／發布窗口：</b>安排交付與產品承接；主管或指定權責者核准例外、風險接受與正式結案。</li></ul><p>以上是建議分工；具體 組織 權責以已確認流程為準。缺窗口、缺資料、缺決策要分開處理，不能一律叫 RD 再測。</p></details>',
            '<details><summary>形成判斷與向主管報告：可複用的底稿</summary><div class="dg-brief"><p><b>判斷：</b>針對［產品／版本／設定］，目前支持［結論或仍未知］。</p><p><b>依據與限制：</b>［證據、日期］支持［範圍］；尚未排除［可能性］。</p><p><b>建議：</b>先取得／執行［最能改變判斷的動作］，因為［風險或阻塞理由］。</p><p><b>承接與驗收：</b>［已確認人員或待找窗口］交付［具體證據］，［日期性質］，於［檢視點］重新判斷。</p><p><b>本輪成果：</b>新增哪項有依據的判定、解除哪個阻塞、或完成哪項可驗收的處置？寄信與收到回覆本身不算修復。</p></div></details>',
            '<details><summary>來源、適用限制與 SOP 邊界</summary><p>下列為本指南參考的公開資料；八步流程、假設表與案件套用是針對 使用者 工作情境的整理，不是逐字照搬或正式安全判定。CISA PDF 的可讀摘錄用於判定術語，未聲稱完成全文合規核對。</p><ul class="dg-source-list">']
    for title, url, note in SOURCES:
        out.append('<li><a href="'+escape(url, quote=True)+'">'+escape(title)+'</a><p>'+escape(note)+'</p></li>')
    out += ['</ul><p>要成為正式 SOP，仍需補齊 組織 適用範圍、RACI／核准權責、各階段進出條件、正式時限、例外與升級路徑、表單及版本核准。這裡不自行訂 24／72 小時承諾。</p></details>',
            '<p><a href="#jira">← 回到 Jira 案件</a></p></section>']
    return ''.join(out)


def attach(page):
    """Add static navigation and guidance without touching report data or its CSP."""
    if 'id="decision-guide"' in page:
        return page
    page = page.replace('</head>', '<style data-guide="'+VERSION+'">'+STYLE+'</style></head>', 1)
    nav = '<a href="#decision-guide">案件判斷指南<span class="nav-index">04</span></a>'
    page = page.replace('</nav>', nav+'</nav>', 1)
    entry = '<p class="dg-entry"><a href="#decision-guide">不確定下一步？開啟案件判斷流程與實例 →</a></p>'
    page = page.replace('<section id="jira">', entry+'<section id="jira">', 1)
    return page.replace('<footer>', render()+'<footer>', 1)
