/* Local PP mini decoration only; no storage, network requests, or work records. */
(() => {
  'use strict';
  const host = document.getElementById('psirt-companion');
  if (!host) return;
  const image = host.querySelector('img');
  const button = document.getElementById('psirt-companion-toggle');
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  let wanted = true;
  let failed = false;

  function sync() {
    const playing = wanted && !reduced.matches && !document.hidden && !failed;
    const mode = playing ? 'animated' : 'static';
    const source = image.dataset[mode];
    if (image.getAttribute('src') !== source) image.src = source;
    image.dataset.mode = mode;
    host.dataset.mode = mode;
    button.hidden = false;
    button.disabled = reduced.matches || failed;
    button.textContent = failed ? '動畫無法播放' : reduced.matches ? '減少動態效果已開啟' : wanted ? '暫停企鵝' : '播放企鵝';
    button.setAttribute('aria-pressed', String(playing));
  }

  button.addEventListener('click', () => { wanted = !wanted; sync(); });
  document.addEventListener('visibilitychange', sync);
  reduced.addEventListener('change', sync);
  image.addEventListener('error', () => {
    if (image.dataset.mode === 'animated') { failed = true; sync(); }
    else host.hidden = true;
  });
  sync();
})();
