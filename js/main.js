// ── INIT ──────────────────────────────────────────────
renderAttackGrid();
renderEmergingThreats();
simulateActivity();
addLog('SYNC', 'THREATWATCH initialized — loading security feeds...');

// Load data — NVD first, then external sources merge in
loadNVD().then(() => {
  loadKEV();
  loadGitHub();
  loadPaloAlto();
  loadOSV();
  loadUbuntu();
  loadMSRC();
  loadRedHat();
});

// Auto-refresh every 5 minutes — skip when user has a custom range or keyword search active
setInterval(() => {
  if (currentRangeDays === -1 || _currentLoadKeyword) return;
  addLog('SYNC', 'Auto-refresh triggered (5 min interval)');
  loadNVD().then(() => {
    loadKEV();
    loadGitHub();
    loadPaloAlto();
    loadOSV();
    loadUbuntu();
    loadMSRC();
    loadRedHat();
  });
}, 5 * 60 * 1000);

// ── Floating info tooltips ──
(function(){
  const tip = document.getElementById('info-tip-floating');
  document.querySelectorAll('.info-tip').forEach(function(el){
    el.addEventListener('mouseenter', function(e){
      tip.innerHTML = (el.dataset.tip || '').split('&#10;').join('<br>');
      tip.style.display = 'block';
      var r = el.getBoundingClientRect();
      tip.style.left = '0px'; tip.style.top = '0px';
      var tw = tip.offsetWidth;
      var left = r.left + r.width/2 - tw/2;
      var top = r.top - tip.offsetHeight - 8;
      if (left < 4) left = 4;
      if (left + tw > window.innerWidth - 4) left = window.innerWidth - tw - 4;
      tip.style.left = left + 'px';
      tip.style.top = top + 'px';
    });
    el.addEventListener('mouseleave', function(){ tip.style.display = 'none'; });
  });
})();
