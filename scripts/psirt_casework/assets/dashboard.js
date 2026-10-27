/* Evidence-bound dashboard. Rendering only; no network, storage or verdicts. */
(() => {
  'use strict';
  const METRICS = ['total', 'active', 'waiting', 'overdue', 'jira_done', 'stage_unknown'];
  const SHORT = {intake:'登錄',handoff:'承接',analysis:'分析',planning:'規劃',development:'開發',verification:'驗證',release:'交付',closure:'覆核',monitoring:'監控'};
  const TONES = new Set(['neutral', 'info', 'success', 'warning', 'danger']);
  const STATES = {unknown: '缺證據', current: '目前', completed: '已離開'};
  const SVG = 'http://www.w3.org/2000/svg';
  const number = value => typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;
  const count = value => number(value) === null ? 'Unknown' : value.toLocaleString('zh-TW');
  const tone = value => TONES.has(value) ? value : 'neutral';
  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }
  function svg(tag, attrs) {
    const node = document.createElementNS(SVG, tag);
    for (const [key, value] of Object.entries(attrs || {})) node.setAttribute(key, String(value));
    return node;
  }
  function stamp(value) {
    if (!value) return '待確認';
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString('zh-TW', {hour12: false});
  }
  function icon(name) {
    const paths = {
      total: ['M4 5h16v14H4z', 'M8 5v14M4 10h16'],
      active: ['M5 12h13M13 6l6 6-6 6', 'M5 6v12'],
      waiting: ['M8 6v12M16 6v12', 'M3 12a9 9 0 1 0 18 0 9 9 0 1 0-18 0'],
      overdue: ['M12 3 2 21h20L12 3z', 'M12 9v5M12 17h.01'],
      jira_done: ['M5 12l4 4L19 6', 'M20 13v6H4V4h10'],
      stage_unknown: ['M9 8a3 3 0 0 1 6 0c0 3-3 2-3 5', 'M12 17h.01', 'M3 12a9 9 0 1 0 18 0 9 9 0 1 0-18 0']
    };
    const root = svg('svg', {viewBox: '0 0 24 24', 'aria-hidden': 'true', focusable: 'false'});
    for (const d of paths[name] || paths.total) root.append(svg('path', {d, fill: 'none', stroke: 'currentColor', 'stroke-width': 1.5, 'stroke-linecap': 'round', 'stroke-linejoin': 'round'}));
    return root;
  }
  function button(label, action, className) {
    const node = el('button', undefined, className);
    node.type = 'button'; node.setAttribute('aria-label', label);
    node.addEventListener('click', action);
    return node;
  }
  function badge(label, color) { return el('span', label, 'cwd-badge cwd-tone-' + tone(color)); }
  function filterButton(key, label, onFilter, className) {
    const node = button(label, () => { if (typeof onFilter === 'function') onFilter(key); }, className);
    node.dataset.dashboardFilter = key;
    if (typeof onFilter !== 'function') node.disabled = true;
    return node;
  }
  function metricCard(metric, key, onFilter) {
    const title = metric.label || key;
    const unknown = number(metric.value) === null;
    const total = count(metric.value);
    const card = filterButton('metric:' + key, title + '：' + total + '。篩選對應案件', onFilter, 'cwd-kpi cwd-tone-' + tone(metric.tone));
    const top = el('span', undefined, 'cwd-kpi-top');
    top.append(el('span', title), icon(key));
    card.append(top, el('strong', total, 'cwd-kpi-value' + (unknown ? ' cwd-unknown' : '')));
    const description = unknown ? '來源不完整 · 已觀測 ' + count(metric.observed_count) + ' 案' : key === 'jira_done' ? 'Jira 狀態完成 · 非修補驗收' : key === 'stage_unknown' ? '先登錄階段與來源證據' : key === 'overdue' ? '已確認日期及依據' : key === 'waiting' ? '已有等待或卡點紀錄' : key === 'active' ? '已確認主要階段' : '目前工作台同範圍';
    card.append(el('span', description, 'cwd-kpi-note'), el('span', '查看案件 ↗', 'cwd-kpi-action'));
    return card;
  }
  function stageChart(data, onFilter) {
    const panel = el('section', undefined, 'cwd-panel cwd-stages');
    const heading = el('div', undefined, 'cwd-panel-heading');
    heading.append(el('h3', '案件在哪一關'), el('span', '點數字或橫條查看案件', 'cwd-muted'));
    panel.append(heading, el('p', '柱長比較已觀測案件數，並非工作完成比例。', 'cwd-panel-note'));
    const stages = Array.isArray(data.stages) ? data.stages : [];
    const maximum = Math.max(1, ...stages.map(item => number(item.observed_count) || 0));
    const list = el('ul', undefined, 'cwd-stage-list');
    for (const stage of stages) {
      const incomplete = number(stage.count) === null;
      const observed = number(stage.observed_count);
      const row = el('li');
      const control = filterButton('stage:' + stage.key, (stage.label || stage.key) + '：' + count(stage.count) + (incomplete ? '，已觀測 ' + count(observed) : '') + '。篩選案件', onFilter, 'cwd-stage-row' + (stage.key === 'unknown' ? ' cwd-is-unknown' : ''));
      const rail = el('span', undefined, 'cwd-bar-track');
      rail.setAttribute('aria-hidden', 'true');
      const fill = el('span', undefined, 'cwd-bar-fill' + (incomplete ? ' cwd-partial' : ''));
      // Width is a bounded visualization of an explicit count, never a stage %.
      fill.style.width = (observed === null ? 0 : Math.min(100, observed / maximum * 100)) + '%';
      rail.append(fill);
      const total = el('span', count(stage.count), 'cwd-stage-value' + (incomplete ? ' cwd-unknown' : ''));
      if (incomplete) total.append(el('small', '已觀測 ' + count(observed)));
      control.append(el('span', stage.label || stage.key, 'cwd-stage-name'), rail, total);
      row.append(control); list.append(row);
    }
    if (!stages.length) list.append(el('li', '尚無可用的階段資料；先確認來源與登錄紀錄。', 'cwd-empty'));
    panel.append(list);
    return panel;
  }
  function deliveryGauge(deliveries) {
    const value = deliveries || {}, received = number(value.received), accepted = number(value.accepted);
    const percent = received !== null && received > 0 && accepted !== null && accepted <= received ? accepted / received * 100 : null;
    const box = el('div', undefined, 'cwd-delivery');
    const ring = el('div', undefined, 'cwd-ring');
    const drawing = svg('svg', {viewBox: '0 0 120 120', 'aria-hidden': 'true', focusable: 'false'});
    drawing.append(svg('circle', {cx: 60, cy: 60, r: 49, fill: 'none', 'stroke-width': 8, class: 'cwd-ring-track'}));
    if (percent !== null) drawing.append(svg('circle', {cx: 60, cy: 60, r: 49, fill: 'none', 'stroke-width': 8, class: 'cwd-ring-value', pathLength: 100, 'stroke-dasharray': percent + ' 100', transform: 'rotate(-90 60 60)', 'stroke-linecap': 'round'}));
    const label = el('div', undefined, 'cwd-ring-label');
    label.append(el('strong', percent === null ? '—' : Math.round(percent) + '%'), el('span', percent === null ? '尚無接受比例' : '交付接受'));
    ring.append(drawing, label);
    const text = el('div', undefined, 'cwd-delivery-copy');
    text.append(el('h4', '交付有沒有被接下來'), el('p', '已接受 ' + count(accepted) + '／已取得 ' + count(received) + ' 份', 'cwd-delivery-numbers'), el('p', '待接受 ' + count(value.pending) + ' 份', 'cwd-muted'));
    box.append(ring, text);
    return box;
  }
  function workPanel(data, onFilter) {
    const panel = el('section', undefined, 'cwd-panel cwd-work');
    const heading = el('div', undefined, 'cwd-panel-heading');
    heading.append(el('h3', '本機成果與投入'), badge('累積登錄', 'info'));
    panel.append(heading, deliveryGauge(data.deliveries), el('p', '接受比例＝已接受／已取得交付；不是整案完成率，也不是所有應交付項目的涵蓋率。', 'cwd-panel-note'));
    const work = data.work || {};
    const stats = el('dl', undefined, 'cwd-work-stats');
    for (const [label, value, suffix] of [['實際投入', work.actual_minutes, ' 分鐘'], ['實際工時紀錄', work.measured_record_count, ' 筆'], ['共用工作', Array.isArray(work.shared_record_ids) ? work.shared_record_ids.length : null, ' 筆']]) {
      const row = el('div'); row.append(el('dt', label), el('dd', count(value) + (number(value) === null ? '' : suffix))); stats.append(row);
    }
    panel.append(stats, el('p', '截至本次計算時間，僅計本機已登錄成果；未登錄工時不當作零。', 'cwd-panel-note'));
    const followup = data.followup_due;
    if (followup) {
      const link = filterButton('followup_due', '本人待追蹤：' + count(followup.value) + ' 案。篩選案件', onFilter, 'cwd-followup');
      link.append(el('span', '本人待追蹤'), el('strong', count(followup.value) + ' 案'), el('span', '查看 →'));
      panel.append(link, el('p', '本人追蹤日另列，不混入已確認承諾或正式期限逾期。', 'cwd-panel-note'));
    }
    return panel;
  }
  function render(host, data, onFilter) {
    if (!host) return;
    host.classList.add('cw-dashboard');
    host.replaceChildren();
    if (!data || data.schema !== 'case-dashboard/1') {
      host.append(el('p', '案件儀表板尚無可用資料；下方原案件與證據仍可查閱。', 'cwd-empty'));
      return;
    }
    const top = el('header', undefined, 'cwd-heading');
    const heading = el('div'); heading.append(el('p', 'CASE OPERATIONS / EVIDENCE', 'cwd-eyebrow'), el('h2', '案件掌握'), el('p', '先看需要承接的工作，再回查每一個數字。', 'cwd-subtitle'));
    const scope = data.scope || {}, meta = el('div', undefined, 'cwd-source');
    meta.append(badge(scope.complete ? '來源完整 · 同範圍' : '來源 ' + (scope.status || 'Unknown') + ' · 不完整', scope.complete ? 'success' : 'warning'), el('span', '計算 ' + stamp(data.as_of)), el('span', scope.label || '範圍待確認'));
    if (scope.historical) meta.append(badge('顯示含歷史資料', 'warning'));
    top.append(heading, meta); host.append(top);
    const grid = el('div', undefined, 'cwd-kpis');
    for (const key of METRICS) grid.append(metricCard(data.metrics?.[key] || {label: key}, key, onFilter));
    host.append(grid);
    const chartGrid = el('div', undefined, 'cwd-charts'); chartGrid.append(stageChart(data, onFilter), workPanel(data, onFilter)); host.append(chartGrid);
    const unknown = data.metrics?.stage_unknown;
    if (!unknown || number(unknown.value) === null || number(unknown.observed_count) > 0) {
      const note = el('div', undefined, 'cwd-evidence-note');
      note.append(el('strong', '灰色是證據缺口'), el('span', '先登錄主要階段、承接人與來源。系統不從 Jira 狀態猜測技術進度，也不把前面的節點畫成已完成。'));
      host.append(note);
    }
    const limits = el('details', undefined, 'cwd-limits'); limits.append(el('summary', '數字口徑與限制'));
    const list = el('ul'); for (const label of data.limits || []) list.append(el('li', label));
    if (!(data.limits || []).length) list.append(el('li', '資料口徑待確認，請先查看案件來源與人工紀錄。'));
    limits.append(list); host.append(limits);
  }
  function timeline(caseData) {
    const data = caseData || {}, root = el('div', undefined, 'cw-dashboard cwd-timeline');
    const header = el('div', undefined, 'cwd-timeline-heading');
    header.append(badge(data.label || '階段待確認', data.tone));
    if (data.flags?.waiting && data.state !== 'waiting') header.append(badge('等待／卡點', 'warning'));
    if (data.flags?.jira_done && data.state !== 'jira_done') header.append(badge('Jira 完成', 'success'));
    root.append(header);
    const stages = Array.isArray(data.timeline) ? data.timeline : [];
    const track = el('ol', undefined, 'cwd-timeline-track');
    track.setAttribute('aria-label', '有證據的案件階段；不是完成百分比');
    for (const stage of stages) {
      const state = Object.hasOwn(STATES, stage.state) ? stage.state : 'unknown';
      const color = state === 'completed' ? 'success' : state === 'current' ? data.flags?.overdue ? 'danger' : data.flags?.waiting ? 'warning' : 'info' : 'neutral';
      const label = state === 'current' && data.flags?.overdue ? '逾期' : state === 'current' && data.flags?.waiting ? '等待' : STATES[state];
      const node = el('li', undefined, 'cwd-step cwd-tone-' + color + ' cwd-step-' + state);
      node.dataset.dashboardStage = stage.key || stage.stage || '';
      node.dataset.stageState = state;
      const full = (stage.label || stage.stage || '階段待確認') + '：' + label + (stage.note ? '；' + stage.note : '');
      node.title = full; node.setAttribute('aria-label', full);
      const dot = el('span', state === 'completed' ? '✓' : state === 'current' ? '●' : '·', 'cwd-step-dot'); dot.setAttribute('aria-hidden', 'true');
      node.append(dot, el('span', SHORT[stage.key || stage.stage] || stage.label || '未知', 'cwd-step-label'), el('small', label, 'cwd-step-state'));
      track.append(node);
    }
    root.append(track);
    if (!stages.length || data.flags?.stage_unknown) root.append(el('p', '未確認主要階段；灰色不表示尚未開始。', 'cwd-timeline-note'));
    else root.append(el('p', '綠色僅代表有離開該階段的證據；不表示整案修復完成。', 'cwd-timeline-note'));
    const deliveries = data.deliveries || {}, received = number(deliveries.received), accepted = number(deliveries.accepted);
    if (received !== null && received > 0) root.append(el('p', '本機交付接受：' + count(accepted) + '／' + count(received) + ' 份 · 非整案完成率', 'cwd-timeline-delivery'));
    return root;
  }
  window.PSIRT_DASHBOARD = {render, timeline};
})();
