/* Bind report downloads to the displayed immutable run; no network or writes. */
(()=>{
 'use strict';
 const labels={CHANGED:'有較新的本機紀錄；下載仍是最近已產生的固定報告。請使用既有快照產生新報告。',MATCH:'目前人工紀錄與這份報告一致；停留時間仍依各自計算時間顯示。',UNKNOWN:'此報告未提供足夠人工版本資訊，是否一致待確認。',HISTORICAL:'固定歷史報告；後續人工修改不會改寫這份檔案。'};
 function render(meta){
   const box=document.getElementById('report-version');if(!box||!meta)return;
   document.getElementById('report-version-state').textContent=labels[meta.matches_report]||labels.UNKNOWN;
   document.getElementById('report-version-run').textContent=meta.report_run_id||'待確認';
   document.getElementById('report-version-time').textContent=meta.report_generated_at||'待確認';
   document.getElementById('report-version-evidence').textContent=JSON.stringify(meta,null,2);
   if(box.dataset.editable==='true'&&/^[A-Za-z0-9_+.-]+$/.test(meta.report_run_id||'')&&!['.','..'].includes(meta.report_run_id)){
     document.querySelectorAll('a[data-report-artifact]').forEach(a=>{a.href='/runs/'+meta.report_run_id+'/'+encodeURIComponent(a.dataset.reportArtifact);});
   }
 }
 window.PSIRT_REPORT_VERSION={render};
})();
