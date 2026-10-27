/* Offline view over a compact, normalized snapshot. No network or persistence. */
(() => {
  'use strict';
  const data = JSON.parse(document.getElementById('dt-data').textContent);
  const $ = id => document.getElementById('dt-' + id);
  const projects = new Map(data.projects.map(x => [x.id, x]));
  const components = new Map(data.components.map(x => [x.key, x]));
  const vulns = new Map(data.vulnerabilities.map(x => [x.key, x]));
  const rank = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3};
  const titles = {components:'元件與版本',cves:'不同 CVE',findings:'Finding 明細',kev:'KEV finding 明細',critical:'Critical finding 明細',projects:'DT 專案（非產品）'};
  let view = 'components', page = 0, exactCve = '';
  const size = 30;
  const text = v => v === null || v === undefined || v === '' ? '待確認' : String(v);
  const severityText = v => v.severity_rated ? v.severity : '未評級／未知（來源：'+text(v.source_severity)+'）';
  function el(tag, value) { const n = document.createElement(tag); if (value !== undefined) n.textContent = text(value); return n; }
  function button(label, action) { const b = el('button', label); b.type='button'; b.addEventListener('click', action); return b; }
  function option(select, value, label) { const o = el('option',label); o.value=value; select.append(o); }
  for (const p of data.projects) option($('project'),p.id,text(p.name)+' / '+text(p.version));
  for (const c of data.components) option($('component'),c.key,text(c.name)+' / '+text(c.version)+' · '+text(projects.get(c.project)?.name));
  function clear() { for (const n of ['search','project','component','severity','kev']) $(n).value=''; exactCve=''; $('detail').hidden=true; page=0; }
  function pick(name) { clear(); view=name; render(); }
  function drill(c) { clear(); $('component').value=c.key; view='findings'; render(); }
  function detail(f) {
    const c=components.get(f.component), v=vulns.get(f.vulnerability), p=projects.get(f.project);
    const box=$('detail'); box.replaceChildren(el('h3',text(v.id)+' · '+text(c.name)+' / '+text(c.version)));
    box.append(el('p','專案：'+text(p?.name)+' / '+text(p?.version)+'；Vendor：待確認'));
    box.append(el('p','來源：'+text(v.source)+'；嚴重度：'+severityText(v)+'；原始 source_severity：'+JSON.stringify(v.source_severity)+'；CVSS v3：'+text(v.cvss)));
    box.append(el('p','CISA KEV：'+text(v.kev)+'；DT isKev：'+text(v.dt_kev)+'；判讀狀態：'+text(f.state)+'；Suppressed：'+text(f.suppressed)));
    box.append(el('pre',v.description || '來源沒有提供描述'));
    box.append(el('pre',JSON.stringify({project_uuid:f.project,component_uuid:c.id,component_version:c.version,cpe:c.cpe,purl:c.purl,cves:v.cves,finding_key:f.key},null,2)));
    box.append(button('關閉明細',()=>{box.hidden=true;})); box.hidden=false;
    box.scrollIntoView({block:'nearest'});
  }
  function render() {
    const q=$('search').value.trim().toLocaleLowerCase(), pid=$('project').value, ck=$('component').value;
    const sev=$('severity').value, kev=$('kev').value;
    const matchKev = v => !kev || (kev==='unknown' ? v.kev===null : String(v.kev)===kev);
    const matchText = values => !q || values.join(' ').toLocaleLowerCase().includes(q);
    const filtered=data.findings.filter(f=>{
      const c=components.get(f.component),v=vulns.get(f.vulnerability),p=projects.get(f.project);
      return (!pid||f.project===pid)&&(!ck||f.component===ck)&&(!sev||v.severity===sev)&&matchKev(v)
        &&(!exactCve||v.cves.includes(exactCve))&&(view!=='kev'||v.kev===true)&&(view!=='critical'||v.severity==='CRITICAL')
        &&matchText([p?.name,p?.version,f.project,c.name,c.version,c.id,c.purl,c.cpe,v.id,v.source,...v.cves]);
    });
    let rows, headers;
    if(view==='components') {
      const related=new Set(filtered.map(f=>f.component));
      rows=data.components.filter(c=>(!pid||c.project===pid)&&(!ck||c.key===ck)&&
        ((sev||kev||exactCve)?related.has(c.key):related.has(c.key)||matchText([c.name,c.version,c.id,c.purl,c.cpe,projects.get(c.project)?.name])));
      headers=['元件','版本','DT 專案','Vendor','已觀測 findings','操作'];
    } else if(view==='projects') {
      rows=data.projects.filter(p=>(!pid||pid===p.id)&&((sev||kev||ck||exactCve)?filtered.some(f=>f.project===p.id):matchText([p.id,p.name,p.version])||filtered.some(f=>f.project===p.id)));
      headers=['DT 專案','版本','UUID','Vendor','操作'];
    } else if(view==='cves') {
      rows=[...new Set(filtered.flatMap(f=>vulns.get(f.vulnerability).cves))].map(id=>({id,links:filtered.filter(f=>vulns.get(f.vulnerability).cves.includes(id))}));
      // The finding filter is the single search contract. Preserve every matched
      // relation when projecting to CVEs, including UUID and identifier matches.
      headers=['CVE','已觀測 findings','DT 專案數（非產品）','操作'];
    } else {rows=filtered;headers=['漏洞／CVE','元件版本','DT 專案','嚴重度','KEV','狀態／Suppressed','操作'];}
    rows.sort((a,b)=>{
      if($('sort').value==='severity'&&a.vulnerability&&b.vulnerability){const d=(rank[vulns.get(a.vulnerability).severity]??9)-(rank[vulns.get(b.vulnerability).severity]??9);if(d)return d;}
      const name=x=>x.vulnerability?vulns.get(x.vulnerability).id:(x.name||x.id);
      return text(name(a)).localeCompare(text(name(b)));
    });
    page=Math.min(page,Math.max(0,Math.ceil(rows.length/size)-1));
    $('head').replaceChildren(); const hr=el('tr'); headers.forEach(h=>{const th=el('th',h);th.scope='col';hr.append(th);}); $('head').append(hr);
    $('rows').replaceChildren();
    for(const r of rows.slice(page*size,(page+1)*size)) {
      let cells;
      if(view==='components') cells=[r.name,r.version,projects.get(r.project)?.name,'待確認',data.findings.filter(f=>f.component===r.key).length,button('查看漏洞',()=>drill(r))];
      else if(view==='projects') cells=[r.name,r.version,r.id,'待確認',button('查看元件',()=>{clear();$('project').value=r.id;view='components';render();})];
      else if(view==='cves') cells=[r.id,r.links.length,new Set(r.links.map(f=>f.project)).size,button('查看關聯',()=>{exactCve=r.id;view='findings';page=0;render();})];
      else {const c=components.get(r.component),v=vulns.get(r.vulnerability);cells=[v.id,text(c.name)+' / '+text(c.version),projects.get(r.project)?.name,severityText(v),v.kev===null?'待確認':v.kev?'是':'否',text(r.state)+' / '+text(r.suppressed),button('漏洞明細',()=>detail(r))];}
      const tr=el('tr'); for(const cell of cells){const td=el('td');td.append(cell instanceof Node?cell:document.createTextNode(text(cell)));tr.append(td);} $('rows').append(tr);
    }
    $('view-title').textContent=titles[view]+(exactCve?' · '+exactCve:'');
    $('results').textContent='符合篩選：'+rows.length+' 列'+(!data.complete?'（僅已觀測；完整總數 Unknown）':'')+(rows.length?'':'；目前篩選沒有符合資料');
    $('page').textContent=(page+1)+' / '+Math.max(1,Math.ceil(rows.length/size));
    $('prev').disabled=page===0; $('next').disabled=(page+1)*size>=rows.length;
    document.querySelectorAll('[data-dt-view]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.dtView===view)));
  }
  document.querySelectorAll('[data-dt-view]').forEach(b=>b.addEventListener('click',()=>pick(b.dataset.dtView)));
  for(const n of ['search','project','component','severity','kev','sort']) $(n).addEventListener(n==='search'?'input':'change',()=>{page=0;exactCve='';$('detail').hidden=true;render();});
  $('clear').addEventListener('click',()=>{clear();render();});
  $('prev').addEventListener('click',()=>{page--;render();}); $('next').addEventListener('click',()=>{page++;render();});
  render();
})();
