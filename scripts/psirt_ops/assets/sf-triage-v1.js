/* Local view only: no fetch, storage, external resources, or writes. */
(() => {
 'use strict';
 const d=JSON.parse(document.getElementById('sf-data').textContent),$=id=>document.getElementById('sf-'+id);
 let page=0;const size=20;
 const text=v=>v===null||v===undefined||v===''?'Unknown':typeof v==='object'?JSON.stringify(v):String(v);
 const el=(tag,value)=>{const n=document.createElement(tag);if(value!==undefined)n.textContent=text(value);return n;};
 const time=v=>{if(!v)return 'Unknown';const n=new Date(v);return Number.isNaN(n.getTime())?text(v):n.toLocaleString('zh-TW',{timeZone:'Asia/Taipei',hour12:false})+' +08:00';};
 const labels={CaseNumber:'SF 編號',Subject:'主旨',CreatedDate:'Case.CreatedDate（建立時間）',LastModifiedDate:'Case.LastModifiedDate（來源異動時間）',Status:'來源狀態（非安全判定）',IsClosed:'來源 IsClosed（非修復證明）',source_owner:'Source Owner/Queue（非承接）',product:'產品／服務線索',version:'版本線索',product_field:'原始產品欄位 Product__c',description_field:'原始 Description 欄位',reporter_severity:'通報者評級',cvss_version:'通報者 CVSS 版本',cvss_score:'通報者 CVSS 分數',cvss_vector:'通報者 CVSS 向量',company_decision:'公司判定',company_reviewer:'公司判定者',company_decided_at:'公司判定日期',accepted_by:'實際承接者（需人工證據）',first_seen:'首次觀測時間（需歷史支持）',risk_description:'通報者問題描述／尚未證實',attack_prerequisites:'攻擊前提線索',reproduction:'重現文字線索（非已取得證據）',reproduction_verification:'重現證據待人工核實',public_status:'公開狀態主張'};
 const linkLabels={VERIFIED_REVIEW_EVIDENCE:'有核實人工證據；正式主關聯另查',CANDIDATE:'引用候選／待確認',NOT_FOUND_IN_SCOPE:'指定範圍未找到；不代表未開單',UNDETERMINED:'查詢失敗／不完整，無法判斷'};
 function btn(label,fn){const n=el('button',label);n.type='button';n.addEventListener('click',fn);return n;}
 function details(label,parent){const n=el('details');n.append(el('summary',label));parent.append(n);return n;}
 function evidence(node,parent){
   const p=details('值與來源證據 · '+(d.state_labels[node.state]||node.state),parent);
   p.append(el('pre',text(node.value)),el('p','來源狀態：'+text(node.source_status)+'；擷取時間：'+time(node.observed_at)));
   for(const r of node.evidence_refs||[])p.append(el('pre',JSON.stringify(r,null,2)));
   if(!(node.evidence_refs||[]).length)p.append(el('p','無足夠來源；不是已確認空值。'));
 }
 function detail(r,parent){
   const box=details('展開判讀、信件節錄與逐欄證據',parent);box.className='sf-detail';
   box.addEventListener('toggle',()=>{if(!box.open||box.dataset.built)return;box.dataset.built='true';
     box.append(el('p','Case ID：'+r.id+'；'+r.classification+'；'+r.deadline));
     box.append(el('p','日期窗內建立：'+text(r.case_in_window)+'；相較完整基準首次出現：'+text(r.first_in_baseline)+'（非 first_seen）'));
     const dl=el('dl');box.append(dl);
     for(const [k,n] of Object.entries(r.fields)){
       dl.append(el('dt',labels[k]||k));const dd=el('dd');dd.append(el('span',text(n.value)+' · '+(d.state_labels[n.state]||n.state)));
       if(/Date$/.test(k))dd.append(el('p','台灣顯示：'+time(n.value)+'；原值：'+text(n.value)));
       evidence(n,dd);dl.append(dd);
     }
     const jira=details('Jira 引用、核實人工證據及當前來源狀態',box);jira.append(el('pre',JSON.stringify(r.jira,null,2)));
     if(r.human_reviews.length){const human=details('人工紀錄（獨立保存；衝突需人覆核）',box);human.append(el('p',r.review_conflict_notice),el('pre',JSON.stringify(r.human_reviews,null,2)));}
     if(r.duplicate_candidates.length){const dup=details('重複候選 · 雙方 Case/Email IDs 與依據',box);dup.append(el('pre',JSON.stringify(r.duplicate_candidates,null,2)));}
     const messages=details('本輪已取 EmailMessage · '+r.messages.length+' 筆；不是全部歷史信件',box);
     for(const m of r.messages){const item=details(m.id+' · '+m.reply_nature,messages);
       item.append(el('p','EmailMessage.MessageDate（非伺服器實際收件時間）：'+time(m.message_date.value)+'；原值：'+text(m.message_date.value)),el('p','來源 LastModifiedDate：'+time(m.modified_date.value)));
       item.append(el('p','日期窗內：'+text(m.in_window)+'；基準首次出現：'+text(m.first_in_baseline)));
       evidence(m.subject,item);evidence(m.excerpt,item);item.append(el('p','節錄已移除聯絡地址、問候／簽名及加密區塊；長文可能截短。完整證據位置見 capture 路徑，未解密或執行。'));
     }
   });
 }
 function render(){
   const q=$('search').value.trim().toLocaleLowerCase(),filter=$('filter').value;
   const rows=d.rows.filter(r=>(filter==='all'||r.tags.includes(filter))&&[r.number,r.id,r.fields.Subject.value,r.fields.product.value,r.fields.version.value].join(' ').toLocaleLowerCase().includes(q));
   page=Math.min(page,Math.max(0,Math.ceil(rows.length/size)-1));$('rows').replaceChildren();
   for(const r of rows.slice(page*size,(page+1)*size)){
     const tr=el('tr');tr.dataset.caseId=r.id;
     const cells=[text(r.number)+'\n'+time(r.fields.CreatedDate.value),text(r.fields.product.value)+'\n版本：'+text(r.fields.version.value),text(r.fields.Subject.value)+'\n'+r.classification+'\n通報者節錄：'+text(r.fields.risk_description.value).replace(/\s+/g,' ').slice(0,120),
       '通報者：'+text(r.fields.reporter_severity.value)+'\n公司：'+text(r.fields.company_decision.value)+'\n來源可展開',r.gaps.join('、')||'仍須人工核對充分性',
       linkLabels[r.jira.status]+'\n當前：'+r.jira.current_status,r.next_action];
     for(const [i,value] of cells.entries()){const td=el('td');if(i===2){const brief=el('div',value);brief.className='sf-brief';td.append(brief);}else{td.textContent=value;td.style.whiteSpace='pre-line';}tr.append(td);} $('rows').append(tr);
     const dr=el('tr');const td=el('td');td.colSpan=7;detail(r,td);dr.append(td);$('rows').append(dr);
   }
   $('results').textContent='符合篩選：'+rows.length+' 筆已觀測 Case'+(d.index_count===null?'；來源不完整，總數 Unknown':'')+'。僅作業索引，不代表全部待辦或已確認漏洞。';
   $('page').textContent=(page+1)+' / '+Math.max(1,Math.ceil(rows.length/size));$('prev').disabled=page===0;$('next').disabled=(page+1)*size>=rows.length;
 }
 $('search').addEventListener('input',()=>{page=0;render();});$('filter').addEventListener('change',()=>{page=0;render();});
 $('clear').addEventListener('click',()=>{$('search').value='';$('filter').value='all';page=0;render();});
 $('prev').addEventListener('click',()=>{page--;render();});$('next').addEventListener('click',()=>{page++;render();});render();
})();
