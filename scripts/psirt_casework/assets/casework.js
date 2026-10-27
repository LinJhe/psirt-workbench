'use strict';
(() => {
  let data = JSON.parse(document.getElementById('cw-data').textContent);
  const editable = document.getElementById('casework').dataset.editable === 'true';
  let session = null, selectedStage = null, selectedCase = null, saving = false, dashboardFilter = null;
  const forms = Array.from(document.querySelectorAll('form[data-kind]'));
  const unknown = v => v === null || v === undefined || v === '' ? '待確認／Unknown' : String(v);
  const labels = {UNKNOWN:'待確認',FOLLOWUP_DUE:'待追蹤',COMMITMENT_OVERDUE:'承諾逾期',REMEDIATION_DUE_EXCEEDED:'已確認修補期限已過',CONFIRMED_FUTURE:'已確認，尚未到期',COMPLETED:'有證據完成',COMPLETED_LATE:'有證據完成（晚於日期）',REFERENCE_ONLY:'參考日期'};
  function el(tag,text,cls) { const n=document.createElement(tag); if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n; }
  function button(text,action) { const b=el('button',text);b.type='button';b.addEventListener('click',action);return b; }
  function clear(id) { const n=document.getElementById(id);n.replaceChildren();return n; }
  function minutes(v) {return v === null || v === undefined ? '待確認' : Number(v).toLocaleString()+' 分鐘';}
  function evidence(parent,label,value) { const d=el('details');d.append(el('summary',label),el('pre',JSON.stringify(value,null,2)));parent.append(d); }
  function setFilter(key) {selectedStage=null;dashboardFilter=null;document.getElementById('cw-filter').value=key;renderRows();}
  function dashboardSelection() {
    if(!dashboardFilter||!data.dashboard)return null;
    if(dashboardFilter==='followup_due')return data.dashboard.followup_due;
    const [type,key]=dashboardFilter.split(':');
    return type==='metric'?data.dashboard.metrics[key]:data.dashboard.stages.find(s=>s.key===key);
  }
  function selectDashboard(key) {
    dashboardFilter=key;selectedStage=null;document.getElementById('cw-filter').value='all';renderRows();
    document.getElementById('cw-dashboard-filter').scrollIntoView({block:'nearest'});
  }
  function render() {
    window.PSIRT_REPORT_VERSION?.render(data.report_version);
    const s=data.source;
    const sourceSummary=document.getElementById('cw-source-summary');
    sourceSummary.textContent='Jira '+unknown(s.status)+' · '+(s.complete?'已設定範圍完整':'來源不完整 / Unknown，已觀測案件保留')+'；顯示資料 '+unknown(s.displayed_at)+(s.historical?'（歷史成功資料，非本輪成功）':'')+'；待追蹤 '+unknown(data.counts.followup_due)+' 案；承諾逾期 '+unknown(data.counts.commitment_overdue)+' 案。'+(data.synthetic?' 合成驗收資料。':'');
    sourceSummary.className=s.complete?'cw-source-summary':'cw-source-summary cw-alert';
    document.getElementById('cw-times').textContent='Jira：'+s.status+' / '+(s.complete?'完整':'不完整')+'；本輪擷取 '+unknown(s.observed_at)+'；顯示資料 '+unknown(s.displayed_at)+(s.historical?'（歷史成功資料，非本輪成功）':'')+'；計算時間 '+data.as_of+'；人工版本合計 '+data.manual_version+(data.synthetic?' · 合成驗收資料':'');
    window.PSIRT_DASHBOARD.render(document.getElementById('cw-dashboard'),data.dashboard,selectDashboard);
    const cards=clear('cw-counts');
    [['total','案件（同範圍）','all'],['commitment_overdue','已確認承諾逾期','commitment_overdue'],['followup_due','本人待追蹤','followup_due'],['deadline_unknown','正式期限未知','deadline_unknown'],['conflicts','人工紀錄衝突','conflicts']].forEach(([key,label,filter])=>{ const b=button(label,()=>setFilter(filter));b.prepend(el('strong',unknown(data.counts[key])));b.dataset.metric=key;cards.append(b); });
    const stages=clear('cw-stages');Object.entries(data.stages).forEach(([key,v])=>{const b=button(v.label+' · '+unknown(v.count),()=>{dashboardFilter=null;selectedStage=key;renderRows();});b.dataset.stage=key;stages.append(b);});
    renderRows();renderWeekly();renderRecords();if(selectedCase)detail(selectedCase);
    document.getElementById('cw-provenance').textContent=JSON.stringify({source:data.source,manual_sha256:data.manual_sha256,legacy_sha256:data.legacy_sha256,write_authority:data.write_authority,compatibility:data.compatibility,weekly:data.weekly.comparison},null,2);
  }
  function renderRows() {
    const query=document.getElementById('cw-search').value.trim().toLowerCase(), filter=document.getElementById('cw-filter').value;
    const selection=dashboardSelection();
    const rows=data.cases.filter(r=>(!selection||selection.case_ids.includes(r.id))&&(!selectedStage||r.stage===selectedStage)&&(filter==='all'||(data.category_case_ids[filter]||[]).includes(r.id))&&[r.id,r.summary,r.product,r.product_version,r.accepted_by,r.assignee,r.deliverable,r.next_action,r.blocker].some(v=>String(v||'').toLowerCase().includes(query)));
    const banner=clear('cw-dashboard-filter');banner.hidden=!selection;
    if(selection)banner.append(el('span','儀表板篩選：'+selection.label+' · 與搜尋條件交集。 '),button('清除儀表板篩選',()=>{dashboardFilter=null;renderRows();}));
    document.querySelectorAll('[data-dashboard-filter]').forEach(n=>n.setAttribute('aria-pressed',String(n.dataset.dashboardFilter===dashboardFilter)));
    document.getElementById('cw-count').textContent='顯示 '+rows.length+'／已觀測 '+data.observed_count+' 案 · 搜尋與篩選取交集'+(!data.source.complete?'；來源不完整，並非完整案件總數':'');
    const tbody=clear('cw-rows');
    rows.forEach(r=>{const tr=el('tr');tr.dataset.caseId=r.id;
      const first=el('td');let target=null;
      try { const raw=data.source?.scope?.instance;if(typeof raw!=='string'||/[\\\s\u0000-\u001f\u007f]/.test(raw))throw Error('Invalid source origin');const base=new URL(raw); if(base.protocol==='https:'&&!base.username&&!base.password&&!base.search&&!base.hash&&base.pathname==='/')target=base.origin+'/browse/'+encodeURIComponent(r.id); } catch (_) {}
      const title=el(target?'a':'strong',r.id);if(target){title.href=target;title.target='_blank';title.rel='noopener noreferrer';}first.append(title,el('small',r.summary),el('small',unknown(r.jira_status)));
      if(r.legacy_review.state==='CONFLICT')first.append(el('small','人工紀錄衝突，請覆核','cw-alert'));
      const stage=el('td',r.stage_label);stage.append(el('small','停留 '+minutes(r.elapsed_minutes)));
      if(data.dashboard?.cases[r.id]){const progress=el('details',undefined,'cw-row-evidence');progress.append(el('summary','階段進度圖'),window.PSIRT_DASHBOARD.timeline(data.dashboard.cases[r.id]));stage.append(progress);}
      const owner=el('td','已承接：'+unknown(r.accepted_by));owner.append(el('small','指派：'+unknown(r.assignee)));
      const next=el('td');next.append(el('strong','下一步：'+unknown(r.next_action)),el('small','交付：'+unknown(r.deliverable)),el('small','卡點：'+unknown(r.blocker)));
      if(r.manual_summary){const notes=el('details',undefined,'cw-row-evidence');notes.append(el('summary','人工摘要與來源提示'),el('p',r.manual_summary));next.append(notes);}
      const dates=el('td');dates.append(el('strong','追蹤日：'+unknown(r.dates.followup.state==='UNKNOWN'?null:r.dates.followup.at)));['followup','commitment','remediation'].forEach(k=>dates.append(el('small',r.dates[k].label+'：'+labels[r.dates[k].state])));
      const ops=el('td');ops.append(button('查看案件',()=>detail(r.id)));if(editable)ops.append(button('編輯',()=>edit('case',r.record,r.id)));
      tr.append(first,stage,owner,next,dates,ops);tbody.append(tr);
    });
    document.querySelectorAll('[data-stage]').forEach(n=>n.setAttribute('aria-pressed',String(n.dataset.stage===selectedStage)));
  }
  function detail(key) {
    const r=data.cases.find(x=>x.id===key);if(!r){clear('cw-detail').hidden=true;selectedCase=null;return;}selectedCase=key;
    const box=clear('cw-detail');box.hidden=false;box.append(el('h3',r.id+' · '+r.summary));
    if(data.dashboard?.cases[r.id])box.append(window.PSIRT_DASHBOARD.timeline(data.dashboard.cases[r.id]));
    box.append(el('p','產品／版本：'+unknown(r.product)+'／'+unknown(r.product_version)),el('p','主要階段：'+r.stage_label+'；停留 '+minutes(r.elapsed_minutes)+'；等待 '+minutes(r.waiting_minutes)+'；關聯實際工時 '+minutes(r.actual_minutes)),el('p','下一交付：'+unknown(r.deliverable)+'；完成條件：'+unknown(r.exit_conditions)));
    box.append(el('p','來源 '+r.source_status+'；擷取 '+unknown(r.source_observed_at)+(r.source_historical?'（歷史資料）':'')+'；'+r.source_ref));
    if(r.legacy_review.state==='CONFLICT')box.append(el('p','歷史覆核與 Store 內容衝突；需明確覆核，不會覆蓋舊檔。','cw-alert'));
    evidence(box,'日期種類、依據與確認者',r.dates);evidence(box,'每次階段進出與時間',r.stage_visits);evidence(box,'原始人工紀錄、完成事項與覆核',r.record);evidence(box,'歷史 human_review 與衝突',r.legacy_review);evidence(box,'案件修訂紀錄',r.revisions);evidence(box,'關聯工時（共用工作不可逐案累加）',r.worklogs);evidence(box,'等待紀錄',r.waits);evidence(box,'取得交付',r.deliveries);
    box.append(button('關閉明細',()=>{box.hidden=true;selectedCase=null;}));
  }
  function renderWeekly(){const box=clear('cw-weekly'),w=data.weekly;box.append(el('p',w.start+' 至 '+w.end+'；比較：'+w.comparison));box.append(el('p','本週取得交付 '+unknown(w.received_count)+' 份；已接受 '+unknown(w.accepted_count)+' 份；有證據階段變化 '+unknown(w.stage_change_count)+' 次；同階段重新進入 '+unknown(w.reentry_count)+' 次（另列，不當作推進）。'));
    if(w.reason)box.append(el('p',w.reason+'；以下為本機已登錄紀錄，未據此宣稱完整週成果。','cw-alert'));
    const list=el('ul');w.received.forEach(r=>{const li=el('li',r.payload.title+' · '+r.payload.received_at+' · '+r.payload.acceptance+' · '+(r.payload.case_ids||[]).join('／'));li.append(el('small','證據：'+r.payload.evidence));list.append(li);});box.append(list);evidence(box,'本週階段進入／變化證據',{entries:w.stage_entries,changes:w.stage_changes,new_since_previous:w.new_stage_changes,reentries:w.reentries});}
  function renderRecords(){const e=clear('cw-effort'),v=data.effort;e.append(el('p','實際投入：'+minutes(v.actual_minutes)+'；估計另列：'+minutes(v.estimated_minutes)+'；等待區間聯集：'+minutes(v.waiting_union_minutes)));e.append(el('p','以唯一工作 ID 加總，共用工作 '+v.shared_record_ids.length+' 筆；'+v.untimed_record_ids.length+' 筆未登錄起迄，無法驗證時段重疊。'));
    const list=clear('cw-records');[['worklog',data.worklogs],['wait',data.waits],['delivery',data.deliveries]].forEach(([kind,rs])=>rs.forEach(r=>{const n=el('div',kind+' · '+r.id+' · v'+r.version+' · '+(r.payload.task||r.payload.title||r.payload.deliverable),'cw-record');n.dataset.recordId=r.id;evidence(n,'紀錄與證據',r);if(editable)n.append(button('編輯這筆紀錄',()=>edit(kind,r)));list.append(n);}));}
  function edit(kind,record,key){const form=forms.find(f=>f.dataset.kind===kind);if(saving||form.dataset.dirty||form.dataset.request){document.getElementById('cw-status').textContent='請先保存或清空目前表單；保存中或結果未確認時不能切換編輯。';return;}form.reset();form.dataset.dirty='1';delete form.dataset.operation;delete form.dataset.request;const p=record?record.payload:{};
    for(const [name,value] of Object.entries(p)){if(name==='dates'){Object.entries(value).forEach(([k,item])=>Object.entries(item).forEach(([field,v])=>fill(form,'date_'+k+'_'+field,v)));}else fill(form,name,value);}
    fill(form,'correction_reason','');fill(form,'record_id',record?record.id:key||'');fill(form,'expected_version',record?record.version:0);if(key)fill(form,'case_id',key);
    if(kind==='case'){fill(form,'stage_event','update');const r=data.cases.find(c=>c.id===(key||p.case_id));if(r)fill(form,'legacy_digest',r.legacy_review.legacy_digest);}
    if(!record)fill(form,'reviewer','');
    form.closest('details').open=true;form.closest('details').parentElement.closest('details').open=true;form.scrollIntoView({behavior:'smooth',block:'start'});
  }
  function fill(form,name,value){const input=form.elements.namedItem(name);if(!input)return;if(input.type==='datetime-local')input.value=value?new Date(new Date(value).getTime()+8*3600000).toISOString().slice(0,16):'';else input.value=Array.isArray(value)?value.join(', '):value===null?'':String(value);}
  function payload(form){const d={},dates={};for(const [name,raw]of new FormData(form).entries()){if(['record_id','expected_version'].includes(name))continue;const input=form.elements.namedItem(name);let value=String(raw).trim();if(input.type==='datetime-local'&&value)value+=':00+08:00';
      if(name.startsWith('date_')){const match=name.match(/^date_(followup|commitment|remediation|estimate|ai_suggestion)_(.+)$/);if(match){dates[match[1]]??={};dates[match[1]][match[2]]=value;}continue;}
      if(name==='case_ids')value=value?value.split(/[,，\s]+/).filter(Boolean):[];
      if(['minutes','excluded_minutes'].includes(name))value=value===''?0:Number(value);
      d[name]=value;}
    if(form.dataset.kind==='case')d.dates=Object.fromEntries(Object.entries(dates).filter(([,v])=>v.at||v.evidence));return d;}
  async function freshSession(){const res=await fetch('/api/session',{cache:'no-store'});if(!res.ok)throw Error('本機保存服務無法更新驗證');session=(await res.json()).session;return session;}
  async function load(){if(!editable)return;const res=await fetch('/api/state',{cache:'no-store'});if(!res.ok)throw Error('無法讀取本機紀錄（'+res.status+'）');const x=await res.json();session=x.session;data=x.projection;render();return {run_id:data.run_id,latest:x.latest};}
  if(editable)window.PSIRT_VIEW={canApply:()=>!saving&&forms.every(f=>!f.dataset.dirty&&!f.dataset.request),apply:load};
  forms.forEach(form=>{
    form.addEventListener('input',()=>{form.dataset.dirty='1';});
    if(form.dataset.kind==='case')form.elements.stage_event.addEventListener('change',()=>{if(form.elements.stage_event.value==='reenter')for(const name of ['entered_at','entry_evidence','exited_at','exit_evidence'])fill(form,name,'');});
    form.querySelector('[data-reset]').addEventListener('click',()=>{if(saving)return;form.reset();delete form.dataset.operation;delete form.dataset.request;delete form.dataset.dirty;for(const n of form.elements)if(n.name)n.disabled=false;fill(form,'reviewer','');form.querySelector('.cw-form-status').textContent='';});
    form.addEventListener('submit',async event=>{
      event.preventDefault();if(saving||!editable)return;const status=form.querySelector('.cw-form-status'),kind=form.dataset.kind;
      let request;
      if(form.dataset.request)request=JSON.parse(form.dataset.request);
      else {const d=payload(form);let id=form.elements.record_id.value;if(kind==='case')id=d.case_id;else if(!id)id=kind+'-'+crypto.randomUUID();fill(form,'record_id',id);
        request={kind,id,payload:d,expected_version:Number(form.elements.expected_version.value),operation_id:'op-'+crypto.randomUUID()};form.dataset.operation=request.operation_id;form.dataset.request=JSON.stringify(request);}
      saving=true;forms.forEach(f=>f.querySelector('fieldset').disabled=true);status.textContent='保存中…';
      try{
        await freshSession();
        const res=await fetch('/api/records',{method:'POST',headers:{'Content-Type':'application/json','X-PSIRT-Token':session},body:JSON.stringify(request)}),body=await res.json();
        if(!res.ok){if(body.committed===false||res.status===403){delete form.dataset.request;delete form.dataset.operation;}status.textContent=(res.status===409?'版本／重送衝突，未覆蓋。請先查看最新紀錄，再重新選取編輯。 ':'未保存：')+(body.error||res.status);return;}
        if(!body.committed_and_read_back)throw Error('保存讀回尚未確認');
        fill(form,'expected_version',body.record.version);fill(form,'correction_reason','');
        if(kind==='case'){fill(form,'stage_visit_id',body.record.payload.stage_visit_id||'');fill(form,'stage_event','update');}
        delete form.dataset.operation;delete form.dataset.request;delete form.dataset.dirty;
        status.textContent='已保存並讀回 '+body.record.id+'，版本 '+body.record.version+'；新報告需另按產生。'+(body.current.version>body.record.version?' 注意：已有更新版本，請重新選取編輯。':'');
        try{await load();}catch(e){status.textContent+=' 清單讀取失敗，保存仍已確認；請重讀本機紀錄。';}
      }catch(error){status.textContent='保存結果未確認，重送會沿用同一操作 ID；或清空表單後讀回確認。 '+error.message;}
      finally{saving=false;forms.forEach(f=>{f.querySelector('fieldset').disabled=false;for(const n of f.elements)if(n.name)n.disabled=Boolean(f.dataset.request);});}
    });
  });
  document.getElementById('cw-search').addEventListener('input',renderRows);document.getElementById('cw-filter').addEventListener('change',()=>{selectedStage=null;dashboardFilter=null;renderRows();});document.getElementById('cw-clear').addEventListener('click',()=>{document.getElementById('cw-search').value='';setFilter('all');});
  document.getElementById('cw-refresh').addEventListener('click',()=>load().then(()=>document.getElementById('cw-status').textContent='已讀取本機紀錄；公司 API 未刷新。').catch(e=>document.getElementById('cw-status').textContent=e.message));
  if(editable)for(const action of ['rebuild','backup'])document.getElementById('cw-'+action).addEventListener('click',async event=>{const status=document.getElementById('cw-status');event.target.disabled=true;status.textContent='本機處理中；不呼叫公司 API…';try{await freshSession();const res=await fetch('/api/'+action,{method:'POST',headers:{'Content-Type':'application/json','X-PSIRT-Token':session},body:'{}'});const x=await res.json();if(!res.ok)throw Error(x.error||res.status);status.textContent=action==='backup'?'備份完成：'+x.path:'新報告完成：'+x.run_dir+'；來源仍為既有快照。';if(action==='rebuild'){const a=el('a','開啟這次新報告');a.href=x.url;a.target='_blank';status.append(a);await load();}}catch(e){status.textContent='未完成：'+e.message;}finally{event.target.disabled=false;}});
  render();if(editable)load().catch(e=>document.getElementById('cw-status').textContent=e.message);
})();
