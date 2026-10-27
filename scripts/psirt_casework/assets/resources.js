/* Local bookmarks. Links open only on explicit user click; no prefetch or company API. */
(()=>{
 'use strict';
 const $=id=>document.getElementById('res-'+id),root=document.getElementById('resources'),editable=root.dataset.editable==='true';
 let data=JSON.parse($('data').textContent),selected=null,dirty=false,pending=null,busy=false;
 const form=$('form'),fields=form.querySelector('fieldset');
 const el=(tag,text)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=String(text??'');return n;};
 const safe=url=>{try{const u=new URL(url);return ['https:','http:'].includes(u.protocol)&&!u.username&&!u.password;}catch{return false;}};
 function notify(text){$('status').textContent=text;}
 function reset(){selected=null;dirty=false;pending=null;form.reset();for(const n of form.elements)n.disabled=!editable;$('form-status').textContent='新增網址；尚未保存。';}
 function choose(row){
   if(busy)return;if(dirty){notify('表單有未保存內容，請先保存或按「清空表單／新增」。');return;}
   selected=row;pending=null;form.reset();for(const n of form.elements)if(n.name)n.value=row.payload[n.name]||'';
   form.elements.correction_reason.value='';$('edit').open=true;$('edit').scrollIntoView({behavior:'smooth'});$('form-status').textContent=row.payload.title+' · 本機版本 '+row.version;
 }
 function render(){
   const q=$('search').value.toLocaleLowerCase().trim(),cat=$('category').value,filter=$('filter').value;
   const rows=data.rows.filter(r=>(filter==='all'||r.payload.status===filter)&&(cat==='all'||r.payload.category===cat)&&[r.payload.title,r.payload.url,r.payload.note].join(' ').toLocaleLowerCase().includes(q));
   $('list').replaceChildren();
   for(const row of rows){
     const p=row.payload,card=el('article');card.className='sfi-mail res-card';card.dataset.linkId=row.id;
     if(safe(p.url)){const a=el('a',p.title+' ↗');a.href=p.url;a.target='_blank';a.rel='noopener noreferrer';a.referrerPolicy='no-referrer';card.append(a);}else card.append(el('strong',p.title+'（網址不可開啟）'));
     card.append(el('p',data.categories[p.category]+' · '+row.origin+(p.status==='archived'?' · 已封存':'')),el('p',p.note||'用途未填'));
     const urlDetail=el('details');urlDetail.append(el('summary','完整網址'),el('p',p.url));card.append(urlDetail);
     const edit=el('button','編輯／封存');edit.type='button';edit.disabled=!editable||busy;edit.addEventListener('click',()=>choose(row));card.append(edit);
     if(row.revisions.length){const d=el('details');d.append(el('summary','保存歷程'),el('pre',JSON.stringify(row.revisions,null,2)));card.append(d);}
     $('list').append(card);
   }
   $('count').textContent='符合篩選 '+rows.length+' 個網址。點連結另開分頁；開頁不代表整合或登入成功。';
   $('meta').textContent=JSON.stringify({source_at:data.source_at,generated_at:data.generated_at,manual_sha256:data.manual_sha256},null,2);
 }
 async function request(path,body,token){
   const r=await fetch(path,{method:body?'POST':'GET',cache:'no-store',headers:body?{'Content-Type':'application/json','X-PSIRT-Token':token}:{},body:body?JSON.stringify(body):undefined});
   const x=await r.json();if(!r.ok){const err=Error(x.error||'HTTP '+r.status);err.committed=x.committed;throw err;}return x;
 }
 async function read(){const x=await request('/api/resources');data=x.resources;render();return {run_id:data.run_id,latest:x.latest};}
 if(editable)window.PSIRT_VIEW={canApply:()=>!dirty&&!pending&&!busy,apply:read};
 for(const [key,title] of Object.entries(data.categories))for(const target of [$('category'),form.elements.category]){const o=el('option',title);o.value=key;target.append(o);}
 form.addEventListener('input',()=>{dirty=true;pending=null;});
 $('clear').addEventListener('click',()=>{if(!busy)reset();});
 form.addEventListener('submit',async e=>{
   e.preventDefault();if(!editable||busy)return;
   const payload=Object.fromEntries(new FormData(form));payload.reviewer=data.synthetic?'DEMO Vance':'Vance';
   pending=pending||{kind:'bookmark',id:selected?.id||'link-'+crypto.randomUUID(),payload,expected_version:selected?.version||0,operation_id:crypto.randomUUID()};
   const submitted=pending;busy=true;fields.disabled=true;$('read').disabled=true;render();
   try{
     const token=(await request('/api/resources')).session,result=await request('/api/records',submitted,token);
     if(!result.committed_and_read_back)throw Error('保存尚未讀回確認');
     selected={id:result.current.id,version:result.current.version,payload:result.current.payload};dirty=false;pending=null;
     for(const n of form.elements)if(n.name)n.value=result.current.payload[n.name]||'';
     $('form-status').textContent='已保存並讀回：'+result.current.payload.title+' · v'+result.current.version+(result.current.version!==result.record.version?'（其他視窗已有後續修改，表單已讀回較新版本）':'');
     notify('本機網址已保存；未連公司系統。');form.elements.correction_reason.value='';
     try{await read();}catch(err){notify('本機保存及讀回已確認；網址清單更新失敗，請按「讀回本機網址」：'+err.message);}
   }catch(err){if(err.committed===false)pending=null;$('form-status').textContent='未確認保存：'+err.message+'。輸入保留；結果不明可重送原操作，或清空後讀回。';}
   finally{busy=false;fields.disabled=false;$('read').disabled=false;for(const n of form.elements)if(n.name)n.disabled=Boolean(pending);render();}
 });
 $('read').addEventListener('click',async()=>{if(busy)return;try{await read();notify('已讀回本機網址；未保存表單仍保留。');}catch(err){notify('讀回失敗：'+err.message);}});
 for(const id of ['search','category','filter'])$(id).addEventListener(id==='search'?'input':'change',render);
 render();
})();
