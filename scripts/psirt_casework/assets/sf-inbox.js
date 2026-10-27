/* Local mail review only. Evidence stays separate from rule suggestions and human decisions. */
(()=>{
 'use strict';
 const box=document.getElementById('sfi');if(!box)return;
 let data=JSON.parse(document.getElementById('sf-data').textContent).inbox;
 if(!data){box.hidden=true;return;}
 const editable=box.dataset.editable==='true',$=id=>document.getElementById('sfi-'+id);
 const labels={unreviewed:'尚未檢視',pending:'待處理',following:'待追蹤',done:'已完成（本機）'};
 const categories={vulnerability:'漏洞通報',inquiry:'詢問／追蹤',notification:'通知',other:'其他',unknown:'待確認'};
 const attentions={priority:'優先處理',normal:'一般待辦',reference:'參考資訊（人工覆核）'};
 const answers={unchecked:'尚未核對',unanswered:'尚未回答',partial:'部分回答',answered:'已回答（人工覆核）',not_required:'不需回答（人工覆核）'};
 const replyFacts={unknown:'寄送狀態待確認',sent_human:'已寄出人工回信（已核對）',automated:'自動通知／自動回信',draft_or_failed:'草稿或寄送失敗',internal:'內部往來',not_found:'目前未找到對應回信'};
 const readStates={text_available:'文字正文已取得',html_text_available:'HTML 安全轉文字',converted_to_safe_text:'已安全轉成文字',available_not_needed:'HTML 已取得；本次使用文字正文',not_fetched:'未取得',empty:'空白',unreadable:'無法讀取',conversion_failed:'轉換失敗',unknown:'待確認',unread:'尚未讀取',read:'已讀取（依來源欄位）',verified_text:'文字已核對（依來源欄位）'};
 const flagLabels={html_only:'只有 HTML 正文，已轉安全文字',encrypted_unread:'PGP／加密正文尚未解密，不能視為已讀',attachment_unread:'附件內容尚未讀取，不能推論附件內容',body_unavailable:'未取得可讀正文',new_body_unavailable:'未取得可用的新正文',quoted_content:'包含引用舊信',body_split_uncertain:'新正文與引用切分仍有不確定',signature_removed:'規則判讀已排除簽名檔',full_source_unavailable:'完整來源未取得'};
 const el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=String(text??'Unknown');if(cls)n.className=cls;return n;};
 const time=x=>{if(!x)return 'Unknown';const v=new Date(x);return Number.isNaN(v.getTime())?'Unknown':v.toLocaleString('zh-TW',{timeZone:'Asia/Taipei',hour12:false})+' +08:00';};
 const localTime=x=>{if(!x)return '';const v=new Date(x);return Number.isNaN(v.getTime())?'':new Date(v.getTime()+8*3600000).toISOString().slice(0,16);};
 const count=x=>x===null||x===undefined?'Unknown':String(x);
 let token='',page=0,saving=false,retrying=false;const size=15,drafts=new Map(),openMail=new Set(),disabledBefore=new WeakMap();
 function context(row){return data.triage_contexts?.[row.triage?.context_id]||{timeline:[],limits:[]};}
 function currentReview(row){const p=row.record?.payload,t=row.triage;return Boolean(p&&t?.input_digest&&p.review_version==='1'&&p.analysis_digest===t.input_digest);}
 function view(row){
   const t=row.triage||{},p=currentReview(row)?row.record.payload:{};
   return {category:p.reviewed_category||t.category||'unknown',summary:p.reviewed_summary||t.summary||'資料不足，請查看原始來信並登錄一句重點。',attention:p.reviewed_attention||t.attention||'normal',answer:p.answer_assessment||t.answer_assessment||'unchecked',next:p.next_action||row.record?.payload.next_action||t.suggested_next_action||'下一步待確認',reviewed:currentReview(row)};
 }
 const recheck=row=>Boolean(row.needs_recheck||row.triage?.needs_recheck);
 const needsAttention=row=>typeof row.triage?.needs_attention==='boolean'?row.triage.needs_attention:row.state!=='done'||recheck(row);
 const brief=row=>{const v=view(row);return [row.source.case_number,row.source.email_id,row.source.subject,v.summary,v.next,categories[v.category],answers[v.answer],row.record?.payload.outcome,row.record?.payload.answer_note].join(' ');};
 function lock(yes){box.querySelectorAll('.sfi-controls input,.sfi-controls select,.sfi-controls button,.sfi-local-actions button,fieldset,[data-discard],#sfi-retry').forEach(n=>{if(yes){if(!disabledBefore.has(n))disabledBefore.set(n,n.disabled);n.disabled=true;}else if(disabledBefore.has(n)){n.disabled=disabledBefore.get(n);disabledBefore.delete(n);}});}
 function notice(s){$('status').textContent=s;}
 async function request(path,body){
   const response=await fetch(path,{method:body?'POST':'GET',cache:'no-store',credentials:'same-origin',headers:body?{'Content-Type':'application/json','X-PSIRT-Token':token}:{},body:body?JSON.stringify(body):undefined});
   const x=await response.json();if(!response.ok){const err=Error(x.error_code||x.error||'HTTP '+response.status);err.status=response.status;err.committed=x.committed;throw err;}return x;
 }
 async function read(){const x=await request('/api/sf-inbox');token=x.session;data=x.inbox;render();return {run_id:data.run_id};}
 if(editable)window.PSIRT_VIEW={canApply:()=>!saving&&!retrying&&drafts.size===0&&Boolean(window.PSIRT_REFRESH?.canReload()),apply:()=>window.PSIRT_REFRESH?.reload()??false};
 function input(parent,label,name,value,type='text'){
   const l=el('label',label),n=el(type==='textarea'?'textarea':'input');n.name=name;if(type!=='textarea')n.type=type;n.value=value??'';l.append(n);parent.append(l);return n;
 }
 function select(parent,label,name,choices,value){
   const l=el('label',label),node=el('select');node.name=name;
   for(const [key,text] of Object.entries(choices)){const option=el('option',text);option.value=key;node.append(option);}node.value=Object.hasOwn(choices,value)?value:Object.keys(choices)[0];l.append(node);parent.append(l);return node;
 }
 function safeCaseLink(row){
   const id=row.source.case_id;if(typeof id!=='string'||!/^[a-zA-Z0-9_-]+$/.test(id))return null;
   try{const base=new URL(row.source.instance);if(!['http:','https:'].includes(base.protocol)||base.username||base.password)return null;const a=el('a','到 Salesforce 查看原案');a.href=base.origin+'/'+encodeURIComponent(id);a.target='_blank';a.rel='noopener noreferrer';a.referrerPolicy='no-referrer';return a;}catch(_){return null;}
 }
 function evidenceTimeline(row,parent){
   const details=el('details',undefined,'sfi-history'),items=context(row).timeline||[];
   details.append(el('summary','本案收發信時間線與證據 · 已觀測 '+items.length+' 筆'));
   let built=false;
   details.addEventListener('toggle',()=>{if(!details.open||built)return;built=true;
     details.append(el('p','僅顯示已觀測記錄；寄出候選、已寄送與已回答是不同事實。Status 原值不直接當作寄送成功。','sfi-note'));
     const list=el('ol',undefined,'sfi-timeline');
     for(const message of items){
       const item=el('li'),direction=message.incoming===true?'來信':message.incoming===false?'寄出方向紀錄':'方向待確認';
       item.append(el('strong',direction+' · '+time(message.message_date)),el('p',message.subject||'主旨未提供'),el('p','ID '+message.email_id+' · Status '+count(message.status)+' · 寄送狀態 '+(message.sending_state||'unknown')+' · 性質 '+(message.reply_nature||'待確認'),'sfi-note'),el('pre',message.excerpt||'未取得內文節錄'));
       if(message.flags?.length)item.append(el('p','提示：'+message.flags.join('／'),'sfi-warning'));
       item.append(el('p','來源：'+(message.evidence_ref||'待確認'),'sfi-note'));list.append(item);
     }
     if(!items.length)list.append(el('li','沒有可用時間線；不能據此認定未寄信。'));
     details.append(list);for(const limit of context(row).limits||[])details.append(el('p',limit,'sfi-note'));
   });parent.append(details);
 }
 function editor(latestRow,parent){
   const draft=drafts.get(latestRow.id),row=draft?.row||latestRow,record=row.record,t=row.triage||{};
   const p=draft?.values||record?.payload||{},canReview=editable&&Boolean(t.input_digest),f=el('form'),fieldset=el('fieldset');
   f.dataset.mailReview=row.id;fieldset.disabled=!canReview;f.append(fieldset);
   fieldset.append(el('h4','人工覆核與處理紀錄'));
   if(!t.input_digest)fieldset.append(el('p','本份資料沒有新版判讀依據；請從 Launcher 開啟目前工作頁並讀回，再保存。','sfi-warning'));
   if(draft&&latestRow.triage?.input_digest!==row.triage?.input_digest)fieldset.append(el('p','這份草稿仍依據較舊來源。輸入保留；請先核對新證據，放棄草稿並讀回後再覆核，避免把舊判讀套到新資料。','sfi-warning'));
   else if(recheck(latestRow))fieldset.append(el('p','來源或同案回信內容有變動；下列舊人工內容保留供比對，保存前請重新核對。','sfi-warning'));
   const grid=el('div',undefined,'sfi-form');fieldset.append(grid);
   select(grid,'覆核後分類','reviewed_category',categories,p.reviewed_category??t.category??'unknown');
   select(grid,'注意等級（參考資訊必須人工確認）','reviewed_attention',attentions,p.reviewed_attention??t.attention??'normal');
   input(grid,'一句重點（請核對規則草稿後保存）','reviewed_summary',p.reviewed_summary??t.summary??'','textarea');
   select(grid,'本機處理狀態','state',labels,p.state||row.state||'unreviewed');
   select(grid,'寄送事實覆核','reviewed_reply_fact',replyFacts,p.reviewed_reply_fact||'unknown');
   input(grid,'寄送依據（已寄出人工回信必填）','reply_note',p.reply_note||'','textarea');
   select(grid,'是否已回答這封信的問題','answer_assessment',answers,p.answer_assessment||'unchecked');
   input(grid,'回答判斷依據／仍缺哪些回答','answer_note',p.answer_note||'','textarea');
   input(grid,'下一步（待處理／待追蹤必填）','next_action',p.next_action??t.suggested_next_action??'','textarea');
   input(grid,'處理結果（完成必填）','outcome',p.outcome||'','textarea');
   input(grid,'本人追蹤時間（台灣時間，選填；不是公司期限）','followup_at',draft?p.followup_at:localTime(p.followup_at),'datetime-local');
   input(grid,'登錄者','reviewer',p.reviewer||(data.synthetic?'DEMO Vance':'Vance'));
   input(grid,'更新原因（修改既有紀錄必填）','correction_reason',draft?.values.correction_reason||'');
   const replyIds=el('input');replyIds.type='hidden';replyIds.name='reply_ids';replyIds.value=p.reply_ids||'';fieldset.append(replyIds);
   for(const [name,value] of [['review_version','1'],['analysis_digest',t.input_digest||'']]){const n=el('input');n.type='hidden';n.name=name;n.value=value;fieldset.append(n);}
   const candidates=el('details',undefined,'sfi-reply-picker'),candidateIds=t.reply_candidate_ids||t.reply_fact?.candidate_ids||[];
   candidates.append(el('summary','選擇回答所依據的回信 · '+candidateIds.length+' 筆候選'));
   candidates.append(el('p','候選不是寄出成功證明。已回答／部分回答須選回信，並確認是已寄出的人工回信；自動通知或草稿不能當作人工回答。','sfi-note'));
   const selected=new Set(replyIds.value.split(',').map(x=>x.trim()).filter(Boolean)),messages=context(latestRow).timeline||[],checks=[];
   for(const id of candidateIds){
     const message=messages.find(m=>m.email_id===id),l=el('label',undefined,'sfi-reply-choice'),check=el('input');check.type='checkbox';check.dataset.replyId=id;check.checked=selected.has(id);checks.push(check);
     const text=el('span');text.append(el('strong',(message?.subject||'回信候選')+' · '+time(message?.message_date)),el('small','ID '+id+' · Status '+count(message?.status)+' · '+(message?.reply_nature||'性質待確認')));
     l.append(check,text);candidates.append(l);if(message?.excerpt)candidates.append(el('pre',message.excerpt,'sfi-candidate-excerpt'));
   }
   const missing=[...selected].filter(id=>!candidateIds.includes(id));
   if(missing.length)candidates.append(el('p','原選回信已不在目前候選：'+missing.join('、')+'。原紀錄保留；核對後可清空重選。','sfi-warning'));
   if(!candidateIds.length)candidates.append(el('p','未找到可選回信候選；不代表沒寄信，也不能確認已回答。','sfi-note'));
   const clearReplies=el('button','清空回信選擇');clearReplies.type='button';candidates.append(clearReplies);fieldset.append(candidates);
   fieldset.append(el('p','回答狀態與本機完成分開記錄：案件 Closed、有寄出方向記錄、你已讀過，都不等於這封問題已被回答。','sfi-note'));
   const submit=el('button','保存判讀與處理狀態');submit.type='submit';submit.disabled=!canReview;fieldset.append(submit);
   const status=el('p');status.setAttribute('role','status');status.className='sfi-form-status';fieldset.append(status);parent.append(f);
   let pending=draft?.pending||null,busy=false;
   const values=()=>Object.fromEntries(new FormData(f));
   const remember=()=>drafts.set(row.id,{row,values:values(),pending});
   function changed(){pending=null;remember();status.textContent='未保存草稿；清除篩選會保留輸入。';const state=f.closest('.sfi-mail')?.querySelector('.sfi-summary-state');if(state&&!state.querySelector('.sfi-draft'))state.append(el('strong','未保存草稿','sfi-warning sfi-draft'));}
   f.addEventListener('input',changed);f.addEventListener('change',changed);
   checks.forEach(check=>check.addEventListener('change',()=>{replyIds.value=[...new Set([...missing,...checks.filter(n=>n.checked).map(n=>n.dataset.replyId)])].join(',');changed();}));
   clearReplies.addEventListener('click',()=>{if(saving)return;missing.length=0;checks.forEach(n=>n.checked=false);replyIds.value='';changed();});
   const discard=el('button','放棄這封未保存草稿／讀回');discard.type='button';discard.dataset.discard='true';discard.disabled=!editable;parent.append(discard);
   discard.addEventListener('click',async()=>{if(saving)return;drafts.delete(row.id);try{await read();notice('已放棄本封草稿並讀回；未修改保存紀錄。');}catch(err){notice('讀回失敗：'+err.message);}});
   if(pending){status.textContent='上次結果尚未確認；可重送原操作，或放棄草稿後讀回確認。';fieldset.querySelectorAll('input,select,textarea,.sfi-reply-picker button').forEach(n=>n.disabled=true);}
   f.addEventListener('submit',async event=>{
     event.preventDefault();if(!canReview||busy||saving)return;busy=true;saving=true;
     const edited=values(),payload={...edited,instance:row.source.instance,email_id:row.source.email_id,source_digest:row.source.evidence_sha256,followup_at:edited.followup_at?edited.followup_at+':00+08:00':''};
     pending=pending||{kind:'sf_email',id:row.id,payload,expected_version:record?.version||0,operation_id:crypto.randomUUID()};
     const submitted=pending;if(!drafts.has(row.id))remember();drafts.get(row.id).pending=submitted;lock(true);discard.disabled=true;
     try{
       const session=await request('/api/sf-inbox');token=session.session;
       const saved=await request('/api/records',submitted);
       if(!saved.committed_and_read_back)throw Error('保存讀回尚未確認');
       drafts.delete(row.id);pending=null;
       const current=data.rows.find(r=>r.id===row.id);if(current){current.record=saved.current;current.state=saved.current.payload.state;current.needs_recheck=saved.current.payload.source_digest!==current.source.evidence_sha256||saved.current.payload.analysis_digest!==current.triage?.input_digest;if(current.triage){current.triage.needs_recheck=current.needs_recheck;current.triage.needs_attention=true;}}
       render();notice('已保存並讀回：'+row.source.email_id+' · '+labels[saved.current.payload.state]+' · v'+saved.current.version);
       try{await read();}catch(err){notice('已保存並讀回；判讀清單更新失敗，請重讀本機狀態：'+err.message);}
     }catch(err){
       if(err.committed===false||err.status===403){pending=null;const savedDraft=drafts.get(row.id);if(savedDraft)savedDraft.pending=null;}
       status.textContent='未確認保存：'+err.message+'。輸入保留；衝突可放棄本封草稿後讀回，結果不明可重送原操作。';
     }finally{busy=false;saving=false;lock(false);submit.disabled=!canReview;discard.disabled=!editable;fieldset.querySelectorAll('input,select,textarea,.sfi-reply-picker button').forEach(n=>n.disabled=Boolean(pending));}
   });
 }
 function sourceHealth(){
   const s=data.source||{},complete=data.coverage==='COMPLETE_IN_CONFIGURED_WINDOW';
   $('health').className='sfi-health'+(complete?'':' sfi-health-warning');
   const result=complete?'已設定範圍內取得完整':s.status==='FAILED'?'更新失敗 / FAILED':s.status==='PARTIAL'?'資料不完整 / PARTIAL':'完整性待確認 / Unknown';
   $('coverage').textContent='Salesforce · '+result+'；保留 '+count(data.known_total)+' 封已觀測來信。';
   const observed=complete?'郵件完整觀測：'+time(s.observed_at):'來源最後成功（非郵件完整證明）：'+time(s.last_successful_at);
   $('currentness').textContent=observed+(s.attempted===false?' · 本輪未重新連線':'')+'；本輪新增 '+count(data.new_incoming)+'。';
   $('source-warning').textContent=(s.auth_blocked?'授權失敗，Salesforce 自動嘗試已暫停。請先確認公司登入／既有授權。 ':'')+(!complete?'本輪新來信數 Unknown；已觀測待辦保留，可繼續本機覆核。':'');
   $('times').textContent=observed+'｜最近嘗試：'+time(s.attempted_at||s.observed_at)+(s.attempted===false?'（本輪未重新連線）':'')+'\n查詢：'+time(data.window?.window_start)+' ～ '+time(data.window?.cutoff)+'｜本頁產生：'+time(data.generated_at);
   const codes=[s.auth_error_code,...(Array.isArray(s.errors)?s.errors:[]).map(e=>typeof e==='string'?e:e?.error_code||e?.code||e?.type)].filter(Boolean);
   $('source-error').textContent='來源狀態：'+(s.status||'Unknown')+'；完整性：'+(data.coverage||'Unknown')+(codes.length?'；錯誤代碼：'+[...new Set(codes)].join('、'):'；未提供錯誤代碼。');
   $('retry').disabled=!editable||data.can_retry_source!==true||retrying||saving;
   $('retry-note').textContent=editable&&data.can_retry_source===true?'此按鈕會啟動既有四來源唯讀更新：重試 Salesforce，同輪 KEV、DT、Jira 也會更新；沿用既定範圍與憑證。':'離線快照或唯讀報告不會呼叫公司來源；請從 Launcher 開啟 live 工作頁。';
 }
 function summary(row){
   const v=view(row),s=el('summary'),grid=el('span',undefined,'sfi-summary-grid');
   const identity=el('span',undefined,'sfi-summary-case');identity.append(el('strong',row.source.case_number||row.source.case_id||'案件待確認'),el('span',row.source.subject||'主旨未提供','sfi-subject'),el('small','本封來信 '+time(row.source.message_date)));
   const state=el('span',undefined,'sfi-summary-state');state.append(el('strong',answers[v.answer]||answers.unchecked,'sfi-answer-label'),el('small',labels[row.state]||'狀態待確認'),el('small',attentions[v.attention]||'一般待辦',v.attention==='priority'?'sfi-warning':''));
   if(recheck(row))state.append(el('strong','來源更新待覆核','sfi-warning'));
   if(drafts.has(row.id))state.append(el('strong','未保存草稿','sfi-warning sfi-draft'));
   const next=el('span',undefined,'sfi-summary-next');next.append(el('span',v.next,'sfi-next-action'),el('small','追蹤日：'+time(row.record?.payload.followup_at)),el('small',v.reviewed?'人工覆核 · 同版來源':'規則建議 · 待人工覆核'));
   grid.append(identity,state,next);s.append(grid,el('span','查看證據與覆核 ▾','sfi-expand'));return s;
 }
 function render(){
   window.PSIRT_REPORT_VERSION?.render(data.report_version);
   sourceHealth();$('counts').replaceChildren();
   for(const [label,value] of [['累積已觀測來信',data.known_total],['相較完整基準新增',data.new_incoming],...Object.entries(labels).map(([k,v])=>[v,data.counts?.[k]]),['來源更新待覆核',data.needs_recheck]]){
     const n=el('div',undefined,'sfi-card');n.append(el('span',label),el('strong',count(value)));$('counts').append(n);
   }
   const q=$('search').value.trim().toLocaleLowerCase(),filter=$('filter').value,category=$('category').value,answer=$('answer').value;
   const rows=data.rows.filter(row=>{const v=view(row);return (filter==='all'||(filter==='attention'?needsAttention(row):row.state===filter))&&(category==='all'||v.category===category)&&(answer==='all'||v.answer===answer)&&brief(row).toLocaleLowerCase().includes(q);});
   page=Math.min(page,Math.max(0,Math.ceil(rows.length/size)-1));$('rows').replaceChildren();
   for(const row of rows.slice(page*size,(page+1)*size)){
     const mail=el('details',undefined,'sfi-mail');mail.dataset.mailId=row.id;mail.dataset.category=view(row).category;mail.dataset.answer=view(row).answer;mail.open=openMail.has(row.id)||drafts.has(row.id);mail.append(summary(row));
     mail.addEventListener('toggle',()=>{if(mail.open)openMail.add(row.id);else openMail.delete(row.id);});
     const content=el('div',undefined,'sfi-mail-body');mail.append(content);
     const latestIncoming=(context(row).timeline||[]).filter(m=>m.incoming===true&&m.message_date&&Number.isFinite(Date.parse(m.message_date))).map(m=>m.message_date).sort((a,b)=>Date.parse(a)-Date.parse(b)).at(-1);
     content.append(el('p','郵件日期：'+time(row.source.message_date)+'（MessageDate，非實際伺服器收件時間）\n本案已觀測最新來信：'+time(latestIncoming||row.source.message_date)+'｜首次本機觀測：'+time(row.source.first_observed_at)+'\n'+(row.in_current_capture?'本輪已觀測':'本輪未觀測；保留歷史待辦')+'｜'+(row.record?'人工 v'+row.record.version:'尚無本機處理紀錄；不是判定你從未讀過'),'sfi-meta'));
     const link=safeCaseLink(row);if(link)content.append(link);
     if(recheck(row))content.append(el('p','來源內容或同案回信已變更，原人工紀錄保留；請重新覆核分類、寄送事實及回答狀態。','sfi-warning'));
     content.append(el('h4',row.source.subject||'主旨未提供'));
     const v=view(row);content.append(el('p',v.summary,'sfi-one-line'),el('p','分類：'+(categories[v.category]||'待確認')+'；'+(v.reviewed?'人工覆核 · 同版來源':'規則初判 · 待人工覆核'),'sfi-note'),el('p',row.triage?.reply_fact?.label||'寄送事實待確認'));
     if(v.reviewed&&row.record?.payload.reviewed_reply_fact)content.append(el('p','覆核寄送事實：'+replyFacts[row.record.payload.reviewed_reply_fact],'sfi-note'));
     const states=row.triage||{};
     content.append(el('p','正文：'+(readStates[states.body_read_state]||'待確認')+'｜HTML：'+(readStates[states.html_read_state]||'待確認')+'｜附件：'+(readStates[states.attachment_read_state]||'待確認'),'sfi-meta'));
     if(states.flags?.length)content.append(el('p',states.flags.map(flag=>flagLabels[flag]||flag).join('；'),'sfi-warning'));
     content.append(el('pre',states.body_excerpt||row.source.excerpt||'沒有可讀節錄；原始內容待確認'));
     const rule=el('details');rule.append(el('summary','規則初判與原始提示（非人工結論）'),el('p','分類建議：'+(categories[row.triage?.suggested_category]||'待確認')+'｜注意等級：'+(attentions[row.triage?.suggested_attention]||'待確認')),el('p',row.triage?.suggested_summary||'規則原摘要未提供，請核對來源節錄。'),el('p',row.triage?.attention_reason||'注意原因待確認'),el('p','建議下一步：'+(row.triage?.suggested_next_action||'待確認')));content.append(rule);
     evidenceTimeline(row,content);
     const evidence=el('details');evidence.append(el('summary','來源證據與人工修訂歷程'),el('pre',JSON.stringify({source:row.source,triage_input_digest:row.triage?.input_digest,triage_rule_version:data.triage_rule_version,evidence_refs:row.triage?.evidence_refs,revisions:row.revisions},null,2)));content.append(evidence);
     editor(row,content);$('rows').append(mail);
   }
   $('results').textContent='符合篩選 '+rows.length+' 封／累積已觀測 '+count(data.known_total)+' 封 · 搜尋與各篩選取交集。'+(drafts.size?' 未保存草稿 '+drafts.size+' 封；清除篩選不會清除草稿。':'');
   $('page').textContent=(page+1)+' / '+Math.max(1,Math.ceil(rows.length/size));$('prev').disabled=page===0;$('next').disabled=(page+1)*size>=rows.length;
   $('provenance').textContent=JSON.stringify({source:data.source,comparison:data.comparison,triage_rule_version:data.triage_rule_version,manual_sha256:data.manual_sha256,limits:data.limits},null,2);
   if(saving)lock(true);
 }
 for(const id of ['search','filter','category','answer'])$(id).addEventListener(id==='search'?'input':'change',()=>{page=0;render();});
 $('clear').addEventListener('click',()=>{if(saving)return;$('search').value='';$('filter').value='attention';$('category').value='all';$('answer').value='all';page=0;render();notice('已恢復待辦預設範圍；草稿及處理紀錄保留。');});
 $('prev').addEventListener('click',()=>{page--;render();});$('next').addEventListener('click',()=>{page++;render();});
 $('refresh').addEventListener('click',async()=>{if(saving)return;try{await read();notice('已讀回本機狀態；未刷新 Salesforce。');}catch(err){notice('讀回失敗：'+err.message);}});
 $('retry').addEventListener('click',async()=>{
   if(!editable||data.can_retry_source!==true||retrying||saving)return;retrying=true;$('retry').disabled=true;
   try{const session=await request('/api/refresh');token=session.session;const result=await request('/api/refresh',{action:'retry_salesforce'});notice('已提出 Salesforce 重試；同輪其他來源也會更新。工作狀態：'+(result.refresh?.phase||'待確認')+'。請查看頁頂來源進度，未保存草稿保留。');}
   catch(err){notice('重試未確認：'+err.message+'。保留目前資料與草稿。');}finally{retrying=false;sourceHealth();}
 });
 $('rebuild').addEventListener('click',async()=>{
   if(saving)return;$('rebuild').disabled=true;
   try{const session=await request('/api/sf-inbox');token=session.session;const r=await request('/api/rebuild',{});await read();notice('新報告已產生；來源未刷新。');const a=el('a','開啟本次唯讀報告');a.href='/runs/'+r.run_dir.split('/').pop()+'/sf-triage.html';$('status').append(el('br'),a);}
   catch(err){notice('產報失敗：'+err.message);}finally{$('rebuild').disabled=!editable;}
 });
 render();
})();
