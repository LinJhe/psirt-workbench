(() => {
  'use strict';
  const bar = document.getElementById('psirt-refresh');
  if (!bar || bar.dataset.bound) return;
  bar.dataset.bound = 'true';
  const $ = name => document.getElementById('psirt-refresh-' + name);
  const initial = JSON.parse($('config').textContent);
  let shown = initial.latest || {}, loadedRun = bar.dataset.runId || '';
  let state = null, timer = null, inFlight = false, applying = false, closed = false, navigating = false, applyError = '';
  const names = {kev: 'KEV', dt: 'DT', salesforce: 'Salesforce', jira: 'Jira'};
  const phaseText = {IDLE: '等待下次更新', RUNNING: '正在更新', SUCCESS: '本輪更新成功', PARTIAL: '本輪部分完成（PARTIAL），請查看各來源', FAILED: '本輪結果未確認；本頁保留原資料，請查看來源狀態', BUSY: '其他更新佔用中，本輪未啟動；可稍後重試'};
  const triggerText = {'page-manual': '手動更新', 'page-auto': '工作頁到期自動觸發', 'salesforce-retry': '手動重試 Salesforce（同輪四來源）', 'page-rebuild': '使用快照產生新報告', cli: 'CLI', direct: '程式呼叫'};
  const text = value => value == null || value === '' ? '未提供' : String(value);
  const stamp = value => {
    if (!value) return '未知';
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? text(value) : parsed.toLocaleString('zh-TW', {hour12: false});
  };
  const offline = latest => latest && (latest.offline || latest.synthetic || ['snapshot-replay', 'synthetic'].includes(latest.mode));
  function editableView() {
    return document.querySelector('[data-editable="true"]');
  }
  function focusedInput() {
    const active = document.activeElement;
    return Boolean(active && (active.matches('input, textarea, select') || active.isContentEditable));
  }
  function analysisOpen() {
    if (!document.getElementById('dt-statistics')) return false;
    const view = document.querySelector('[data-dt-view][aria-pressed="true"]');
    const detail = document.getElementById('dt-detail');
    const page = document.getElementById('dt-page');
    // The older DT renderer keeps drill-down and exact-CVE state in a closure.
    // Conservatively defer unless its DOM confirms the default first-page view.
    return !view || view.dataset.dtView !== 'components' || !page || !/^1\s*\//.test(page.textContent.trim()) || Boolean(detail && !detail.hidden);
  }
  // Only navigation/search controls outside editors may survive a reload.
  // No textarea, contenteditable, case fields, credentials or form body is stored.
  function filterControls() {
    return [...document.querySelectorAll('input[type="search"], .dt-controls select, .cw-controls select, .sfi-controls select')].filter(node =>
      (node.id || node.name) && !node.closest('form, #psirt-refresh') && !node.isContentEditable && !node.disabled);
  }
  const viewPath = location.pathname + location.search;
  const filterKey = 'psirt.refresh.filters.v1:' + viewPath;
  function restoreFilters() {
    let saved;
    try {
      const raw = sessionStorage.getItem(filterKey);
      if (!raw) return;
      sessionStorage.removeItem(filterKey);
      saved = JSON.parse(raw);
    } catch (_) { return; }
    if (saved?.path !== viewPath || !Number.isFinite(saved.at) || Date.now() - saved.at < 0 || Date.now() - saved.at > 600000 || !Array.isArray(saved.controls)) return;
    for (const entry of saved.controls.slice(0, 100)) {
      if (!entry || typeof entry.value !== 'string' || entry.value.length > 4096) continue;
      const matches = filterControls().filter(node => entry.id ? node.id === entry.id : node.name === entry.name);
      if (matches.length !== 1) continue;
      const node = matches[0];
      if (node.tagName === 'SELECT' && ![...node.options].some(option => option.value === entry.value)) {
        applyError = '部分篩選選項已不在新資料，已使用該欄預設值。';
        continue;
      }
      node.value = entry.value;
      node.dispatchEvent(new Event('input', {bubbles: true}));
      node.dispatchEvent(new Event('change', {bubbles: true}));
    }
  }
  function reloadView() {
    if (navigating || focusedInput() || analysisOpen()) return false;
    const controls = filterControls().slice(0, 100).map(node => ({id: node.id, name: node.name, value: node.value.slice(0, 4096)}));
    try { sessionStorage.setItem(filterKey, JSON.stringify({path: viewPath, at: Date.now(), controls})); }
    catch (_) {
      applyError = '瀏覽器無法暫存篩選條件；本頁保留，請先完成目前操作再自行重新整理。';
      return false;
    }
    navigating = true;
    try { location.reload(); }
    catch (error) { navigating = false; throw error; }
    // A requested navigation is not evidence that the new page finished loading.
    return false;
  }
  window.PSIRT_REFRESH = {reload: reloadView, canReload: () => !focusedInput() && !navigating && !analysisOpen()};
  restoreFilters();
  const safeFilters = new Set(filterControls());
  const editingRisk = document.querySelector('form') || [...document.querySelectorAll('input, textarea, select, [contenteditable]')].some(node =>
    node.isContentEditable || (!node.closest('#psirt-refresh') && !node.disabled && !safeFilters.has(node) && !['hidden', 'button', 'submit', 'reset'].includes(node.type)));
  if (!window.PSIRT_VIEW && !editableView() && !editingRisk) {
    window.PSIRT_VIEW = {canApply: () => !focusedInput() && !navigating && !analysisOpen(), apply: reloadView};
  }
  function canApply() {
    try { return Boolean(window.PSIRT_VIEW && typeof window.PSIRT_VIEW.apply === 'function' && window.PSIRT_VIEW.canApply()); }
    catch (_) { return false; }
  }
  function render() {
    const refresh = state?.refresh || {}, latest = state?.latest || shown;
    const active = refresh.phase === 'RUNNING';
    $('now').disabled = inFlight || applying || active;
    $('auto').disabled = inFlight;
    if (typeof refresh.auto_enabled === 'boolean') $('auto').checked = refresh.auto_enabled;
    const seconds = Number(refresh.seconds_until_next);
    $('clock').textContent = refresh.auto_enabled === false ? '自動更新已暫停' : active ? '同一時間只執行一輪' : Number.isFinite(seconds) && refresh.seconds_until_next != null ? '下次約 ' + Math.max(0, Math.ceil(seconds / 60)) + ' 分鐘後' : '每 15 分鐘檢查';
    const mode = offline(latest) ? '離線快照重建；不會取得最新公司 API。' : latest.mode === 'report-rebuild' ? '目前為既有快照重建；來源時間如下。' : '';
    $('now').textContent = offline(latest) ? '立即重建離線資料' : '立即更新';
    $('state').textContent = (phaseText[refresh.phase] || '正在確認更新狀態') + (refresh.error_code ? '（' + text(refresh.error_code) + '）' : '') + (mode ? ' · ' + mode : '') + (applyError ? ' · ' + applyError : '');
    $('shown').textContent = '本頁顯示：' + (loadedRun || '批次未知') + ' · 擷取 ' + stamp(shown.captured_at) + (offline(shown) ? ' · 離線快照' : '');
    $('attempt').textContent = '觸發方式：' + (triggerText[refresh.trigger] || '尚未執行／未記錄') + ' · 本次開始：' + stamp(refresh.started_at) + ' · 完成：' + stamp(refresh.finished_at) + (refresh.job_id ? ' · 工作 ' + refresh.job_id : '');
    $('sources').replaceChildren();
    const sources = latest.sources || {}, displayed = shown.sources || {}, progress = refresh.progress || {}, result = refresh.result?.statuses || {};
    const keys = [...new Set([...Object.keys(sources), ...Object.keys(displayed), ...Object.keys(progress), ...Object.keys(result)])];
    for (const key of keys) {
      const source = sources[key] || {}, displayedSource = displayed[key] || {}, current = progress[key];
      const status = typeof source === 'string' ? source : source.status;
      const displayedStatus = typeof displayedSource === 'string' ? displayedSource : displayedSource.status;
      const attempt = typeof current === 'object' && current ? current.status : current;
      const node = document.createElement('li');
      node.textContent = (names[key] || key) + '：本次 ' + text(attempt || result[key] || (refresh.phase === 'IDLE' ? '尚未執行' : '未知')) + '；本頁顯示 ' + text(displayedStatus) + '／擷取 ' + stamp(displayedSource.observed_at || displayedSource.captured_at) + '；服務端最新 ' + text(status) + '／擷取 ' + stamp(source.observed_at || source.captured_at);
      $('sources').append(node);
    }
    const pending = Boolean(latest.run_id && latest.run_id !== loadedRun);
    $('pending').hidden = !pending;
    $('apply').hidden = !window.PSIRT_VIEW || analysisOpen();
    $('apply').disabled = applying || active;
    $('open').hidden = (Boolean(window.PSIRT_VIEW) && !analysisOpen()) || Boolean(editableView());
    $('open').href = location.pathname + location.search;
    if (pending) $('pending-text').textContent = refresh.phase === 'FAILED' ? '本輪結果未確認，服務端可能已有較新批次。原畫面與輸入保留；請查看來源狀態後重試。' : analysisOpen() ? 'DT 深入分析或翻頁中，保留目前現場。可另開更新頁面，或回到元件與版本第一頁並關閉明細後套用。' : focusedInput() ? '有新資料；正在輸入或選取條件，離開輸入欄位後再套用。' : editableView() && !canApply() ? '新資料已完成；請先保存或清空未保存內容，再套用更新。' : '有較新的資料批次可查看。';
    if (pending && refresh.phase === 'FAILED') { $('apply').disabled = true; $('open').hidden = true; }
  }
  async function request(method = 'GET', body, token) {
    const options = {method, credentials: 'same-origin', cache: 'no-store'};
    if (method === 'POST') { options.headers = {'Content-Type': 'application/json', 'X-PSIRT-Token': token}; options.body = JSON.stringify(body); }
    const response = await fetch('/api/refresh', options);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error_code || data.error || 'HTTP ' + response.status);
    return data;
  }
  async function applyLatest(automatic) {
    const candidate = state?.latest;
    if (applying || navigating || !candidate?.run_id || candidate.run_id === loadedRun || !['SUCCESS', 'PARTIAL', 'IDLE'].includes(state?.refresh?.phase)) return;
    if (!canApply()) {
      if (!automatic) $('pending-text').textContent = analysisOpen() ? 'DT 分析現場保留；請另開更新頁面，或回到元件與版本第一頁並關閉明細。' : focusedInput() ? '正在輸入或選取條件；離開欄位後再套用。' : '請先保存或清空未保存內容；目前輸入會保留。';
      return;
    }
    applying = true; applyError = ''; render();
    try {
      const applied = await window.PSIRT_VIEW.apply();
      if (applied === false) return;
      loadedRun = applied?.run_id || candidate.run_id;
      shown = {...candidate, ...(applied?.latest || {})};
      bar.dataset.runId = loadedRun;
    } catch (_) { applyError = '新資料已完成，但套用畫面失敗；現有內容保留，請稍後重試。'; }
    finally { applying = false; render(); }
  }
  function schedule() {
    clearTimeout(timer);
    if (!closed && !navigating) timer = setTimeout(() => update(), state?.refresh?.phase === 'RUNNING' ? 3000 : 15000);
  }
  async function update(action, enabled) {
    if (closed || inFlight) return;
    inFlight = true; render();
    let error = null;
    try {
      state = await request();
      let body = action ? {action} : null;
      if (action === 'auto') body.enabled = enabled;
      if (!action && state.refresh?.auto_enabled && state.refresh.phase !== 'RUNNING') body = {action: 'tick'};
      if (body) state = await request('POST', body, state.session?.token || state.session);
      render();
      if (['SUCCESS', 'PARTIAL', 'IDLE'].includes(state.refresh?.phase)) await applyLatest(true);
    } catch (err) { error = '無法確認更新狀態；保留本頁資料與輸入。' + (err.message ? '（' + err.message + '）' : ''); }
    finally { inFlight = false; render(); if (error) $('state').textContent = error; schedule(); }
  }
  $('now').addEventListener('click', () => update('manual'));
  $('auto').addEventListener('change', event => update('auto', event.target.checked));
  $('apply').addEventListener('click', () => applyLatest(false));
  window.addEventListener('pagehide', () => { closed = true; clearTimeout(timer); });
  window.addEventListener('pageshow', event => { if (event.persisted) { closed = false; navigating = false; update(); } });
  render(); update();
})();
