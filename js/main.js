// ═══════════════════════════════════════════════════════════════
//  THREATWATCH — start-up. Loaded last, after core.js, app.js and
//  cloudctl.js, so every function and global is defined by now.
// ═══════════════════════════════════════════════════════════════

loadCompanyProfile();
addLog('SYNC', 'THREATWATCH initialized — loading security feeds...');

// ── Delegated listeners (rows and tiles are re-rendered constantly) ──
['click', 'keydown'].forEach(type => {
  document.getElementById('cve-feed').addEventListener(type, onCveListActivate);
  document.getElementById('prio-list').addEventListener(type, onCveListActivate);
  document.getElementById('modal-body').addEventListener(type, onCveListActivate);
  document.getElementById('vendor-chart').addEventListener(type, onVendorActivate);
  document.getElementById('attack-grid').addEventListener(type, onCategoryActivate);
});
document.getElementById('detail-body').addEventListener('click', onDetailAction);
document.getElementById('company-suggestions').addEventListener('click', e => {
  const b = e.target.closest('[data-suggest]');
  if (b) addSuggestTag(b.dataset.suggest);
});
const timelineEl = document.getElementById('timeline-chart');
timelineEl.addEventListener('mousemove', onTimelineHover);
timelineEl.addEventListener('mouseleave', () => { document.getElementById('chart-tip').style.display = 'none'; });

let _resizeTimer = null;
window.addEventListener('resize', () => {
  clearTimeout(_resizeTimer);
  _resizeTimer = setTimeout(() => { renderTimeline(); if (window.innerWidth > 900) closeSidebar(); }, 150);
});

// ── Apply the shareable URL state, then load ──
const initialState = parseHashState(location.hash);
applyHashState(initialState);
renderAll();
if (initialState.view !== 'priority') showView(initialState.view);
else setSuggestionsForView('priority');
if (initialState.cve) openCveDetail(initialState.cve);
loadHighEpss();
refreshAll();

// Back/forward or a pasted link: re-apply the state
window.addEventListener('hashchange', () => {
  const s = parseHashState(location.hash);
  const rangeChanged = applyHashState(s);
  if (s.view !== currentView) showView(s.view);
  if (s.cve && s.cve !== _openCveId) openCveDetail(s.cve);
  else if (!s.cve) closeCveDetail();
  if (rangeChanged) {
    allCves = allCves.filter(v => v._source === 'nvd');
    refreshAll();
  } else {
    renderAll();
  }
});

// Auto-refresh every 5 minutes — skip when a custom range or keyword search is active
setInterval(() => {
  if (currentRangeDays === -1 || _currentLoadKeyword) return;
  addLog('SYNC', 'Auto-refresh triggered (5 min interval)');
  refreshAll();
}, 5 * 60 * 1000);

// ── Floating info tooltips ──
(function () {
  const tip = document.getElementById('info-tip-floating');
  document.querySelectorAll('.info-tip').forEach(function (el) {
    const show = function () {
      tip.textContent = '';
      (el.dataset.tip || '').split('\n').forEach(function (line, i) {
        if (i) tip.appendChild(document.createElement('br'));
        tip.appendChild(document.createTextNode(line));
      });
      tip.style.display = 'block';
      const r = el.getBoundingClientRect();
      tip.style.left = '0px'; tip.style.top = '0px';
      const tw = tip.offsetWidth;
      let left = r.left + r.width / 2 - tw / 2;
      const top = r.top - tip.offsetHeight - 8;
      if (left < 4) left = 4;
      if (left + tw > window.innerWidth - 4) left = window.innerWidth - tw - 4;
      tip.style.left = left + 'px';
      tip.style.top = top + 'px';
    };
    const hide = function () { tip.style.display = 'none'; };
    el.addEventListener('mouseenter', show);
    el.addEventListener('mouseleave', hide);
    el.addEventListener('focus', show);
    el.addEventListener('blur', hide);
  });
})();
