"""Offline Japanese garden presentation; reuse the verified report/card data."""
from .nordic_layout import finish as base_layout


def garden_art():
    import base64
    from pathlib import Path
    data = base64.b64encode((Path(__file__).with_name('assets') / 'kyoto-purple-anime-v1.png').read_bytes()).decode('ascii')
    return ('<div class="garden-art"><img class="garden-illustration" src="data:image/png;base64,'+data+'" '
            'alt="京都庭院實景改繪的紫色動畫風插畫：松樹、石島與池塘倒影" width="1674" height="940">'
            '<span class="garden-caption">京都庭院 · 實景改繪</span></div>')


STYLE = '''
.garden-illustration{display:block;width:100%;height:auto;aspect-ratio:16/9;object-fit:cover;border:1px solid #bba6cf;border-radius:3px;box-shadow:0 8px 24px #3927471a}

.sidebar{background-color:#392747;color:#f1eaf7}.sidebar .text-gray-500,.sidebar nav>div,.sidebar-bottom{color:#c6b4d8}.sidebar nav a{color:#f1eaf7}.sidebar nav svg,.sidebar nav .nav-index{color:#cbb4df}
.workspace-link .kpi-dot{background:#8862a8}.workspace-link:nth-child(2) .kpi-dot{background:#a289be}.workspace-link:nth-child(3) .kpi-dot{background:#a47b9e}
.banner:before{background:#806099}

body{background-color:#ede7f3;background-image:radial-gradient(#89739d1a .6px,transparent .6px);background-size:5px 5px;color:#342d3b}
.sidebar{width:238px;background-color:#392747;background-image:repeating-linear-gradient(90deg,transparent 0,transparent 38px,#a493b30a 38px,#a493b30a 39px);padding:36px 24px;border-right:7px solid #60516d;box-shadow:none}
.sidebar .brand-mark{background:transparent;border:1px solid #cbb5de;border-radius:2px;color:#d5c1e6;font-family:Georgia,serif}
.sidebar nav a{border-radius:0;border-bottom:1px solid #c0b3cb1a;padding:16px 8px}.sidebar nav a:hover,.sidebar nav a:focus-visible{background:#554860;border-color:#8f7ba1}.sidebar nav{margin-top:55px}.sidebar-bottom{color:#bcaec8}
.page-head{position:relative;margin-left:238px;min-height:400px;padding:42px 44px 30px;overflow:hidden;max-width:none;border-bottom:1px solid #bbacc8}
.page-head:before{content:'';position:absolute;left:44px;top:106px;bottom:35px;width:2px;background:#9784a7}
.page-head .head-top{position:relative;z-index:1}.page-head .eyebrow{color:#62546e;letter-spacing:3px;font-size:10px}
.page-head h1{font-family:Yu Mincho,MS Mincho,PMingLiU,serif;font-size:44px;font-weight:400;letter-spacing:5px;color:#352e3c;margin:46px 0 18px;padding-left:22px;position:relative;z-index:1;width:58%}
.page-head p{position:relative;z-index:1;color:#594d63;font-size:12px;padding-left:24px;width:58%;line-height:1.9}
.edition{border:1px solid #7746a2;background:transparent;color:#66388f;border-radius:0;padding:8px 12px;letter-spacing:1.5px;font-size:10px}
.garden-art{position:absolute;right:32px;top:89px;width:43%;max-width:510px;pointer-events:none}.garden-art svg{width:100%;height:auto;display:block}.garden-caption{display:block;text-align:right;margin:9px 22px 0 0;font-family:Yu Mincho,PMingLiU,serif;font-size:11px;letter-spacing:4px;color:#695b76}
main{margin-left:238px;max-width:none;padding:32px 44px 48px}.workspace-links{gap:0;border:1px solid #bbacc8;background:#f5f0fa;margin:0 0 25px}
.workspace-link,.workspace-link:nth-child(2),.workspace-link:nth-child(3){border:0;border-right:1px solid #c8bad4;border-top:3px solid #776389;border-radius:0;box-shadow:none;background:transparent;padding:24px 28px;min-height:200px}
.workspace-link:nth-child(2){border-top-color:#8d7d9b}.workspace-link:nth-child(3){border-right:0;border-top-color:#7c53a1}.workspace-link:hover{background:#e6deee;transform:none;border-color:#b1a1bf}
.workspace-link .overline{color:#52455e;letter-spacing:2px;font-size:11px}.workspace-link .kpi-number{font-family:Georgia,serif;font-size:55px;font-weight:400;color:#514060;margin:16px 0 4px}.workspace-link:nth-child(2) .kpi-number{color:#645770}.workspace-link:nth-child(3) .kpi-number{color:#734d95}.workspace-link h3{color:#4e4358}.workspace-link .kpi-bottom{color:#665872;border-color:#d4c9de}.workspace-link .kpi-dot{border-radius:0;transform:rotate(45deg);width:6px;height:6px}
.banner{border-radius:0;color:#524062;background:#e2d9ea;border-left:3px solid #725c86}.banner.warn{color:#745d35;background:#eee6cf;border-color:#a28b56}.banner.bad{color:#884c36;background:#efdfd5;border-color:#a46447}
section{border-radius:0;border:1px solid #c4b8cf;background:#f5f0fa;box-shadow:none;padding:28px 30px;margin:28px 0}h2{font-family:Yu Mincho,MS Mincho,PMingLiU,serif;font-size:26px;letter-spacing:2px;font-weight:400;border-left:3px solid #857395;padding-left:15px;color:#3e3249}.section-intro{color:#5f526b;font-size:13px}
.metrics .metric{border-radius:0;background:#eae3f0;border-top:1px solid #bfb1cb}.metric span{color:#5c4e68}.metric strong{font-family:Georgia,serif;font-size:34px;color:#554464}.metric:nth-child(2){background:#eae5ef}.metric:nth-child(3){background:#e8ddf1}
.health small,.muted,article .muted{color:#655772}.health{border-color:#d4cadc}.SUCCESS{background:#e1e8d4;color:#4c633b}.FAILED,.PARTIAL{background:#ecddd1;color:#874c34}.method-note summary{color:#5b4c68}
article p{color:#4a3d56}article h3{color:#40324d}details{border-radius:0;background:#ede8f2;border-color:#d3c9dc}summary{color:#564366;font-size:12px}pre{color:#4a3e55}footer,footer a{color:#604f70}
a:focus-visible,summary:focus-visible{outline:2px solid #6c458e;outline-offset:4px}
@media(min-width:1650px){main,.page-head{padding-left:64px;padding-right:64px}.page-head:before{left:64px}}
@media(max-width:1100px) and (min-width:851px){.sidebar{width:210px}.page-head,main{margin-left:210px;padding-left:28px;padding-right:28px}.page-head:before{left:28px}.page-head h1{font-size:34px;letter-spacing:2px}.garden-art{right:18px;top:115px}.workspace-link{padding:22px 18px}}
@media(max-width:850px){.sidebar{position:relative;width:100%;padding:20px 22px;border-right:0;border-bottom:5px solid #60516d}.sidebar nav{margin-top:20px}.sidebar nav a{padding:10px 8px}.page-head{margin:0;padding:26px 22px;min-height:0}.page-head:before{display:none}.page-head h1{width:100%;font-size:30px;letter-spacing:3px;margin:28px 0 15px;padding:0}.page-head p{width:100%;padding:0}.garden-art{position:relative;top:auto;right:auto;width:100%;max-width:400px;margin:24px auto 0}.garden-caption{font-size:10px}.page-head .eyebrow{font-size:9px;letter-spacing:1px}.edition{font-size:9px;padding:6px}main{margin:0;padding:24px 22px}.workspace-links{gap:0}.workspace-link,.workspace-link:nth-child(2),.workspace-link:nth-child(3){border-right:0;border-bottom:1px solid #c8bad4;min-height:0;padding:20px}.workspace-link .kpi-number{font-size:40px}.workspace-link:last-child{border-bottom:0}section{padding:24px 20px}}
'''


def finish(page, vm, data, capture):
    page = base_layout(page, vm, data, capture)
    page = page.replace('</head>', '<style data-theme="japanese-garden">'+STYLE+'</style></head>', 1)
    page = page.replace('FOREST / 03 · 本機草稿', 'GARDEN NEXUS / 10 · 本機草稿', 1)
    page = page.replace('PRODUCT SECURITY', 'PSIRT / SECURITY OPERATIONS', 1)
    page = page.replace('<h1>每日安全工作台</h1>', '<div class="ops-kicker">MONITOR / TRIAGE / FOLLOW THROUGH</div><h1>資安作業<span>控制台</span></h1>', 1)
    # Decorative circuitry, not a chart or a live status indicator.
    circuit = ('<div class="ops-circuit" aria-hidden="true"><svg viewBox="0 0 400 280" fill="none">'
               '<g stroke="currentColor" stroke-width="1"><path d="M200 14 310 78v124l-110 64L90 202V78Z"/>'
               '<path d="M200 36 290 89v102l-90 53-90-53V89Z" stroke-dasharray="3 7"/>'
               '<path d="M0 64h64l48 48h40M0 214h64l48-48h40M400 64h-64l-48 48h-40M400 214h-64l-48-48h-40"/>'
               '<circle cx="64" cy="64" r="4"/><circle cx="64" cy="214" r="4"/>'
               '<circle cx="336" cy="64" r="4"/><circle cx="336" cy="214" r="4"/></g>'
               '<path d="m200 83 43 17v36c0 31-22 51-43 61-21-10-43-30-43-61v-36z" stroke="currentColor" stroke-width="2"/>'
               '<path d="m200 119 15 9v18l-15 9-15-9v-18Z" stroke="#8ff2e0" stroke-width="2"/>'
               '</svg></div>')
    page = page.replace('</header><main>', garden_art()+circuit+'</header><main>', 1)
    page = page.replace("default-src 'none';", "default-src 'none'; img-src data:;", 1)
    # CC0 reference and illustration provenance remain in assets; keep the UI focused on operations.
    from pathlib import Path
    studio = (Path(__file__).with_name('assets') / 'purple-garden-nexus-v10.css').read_text()
    page = page.replace('</head>', '<style data-design="purple-garden-nexus-10">'+studio+'</style></head>', 1)
    return page
