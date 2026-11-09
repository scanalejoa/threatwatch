// ═══════════════════════════════════════════════════════════════
//  THREATWATCH — threat-intel dashboard
//  Pure helpers (getCvss, getSeverity, escapeHtml, mergeCves, sortCves,
//  toCsv, hash state, …) live in js/core.js, loaded before this file.
//  Every value that comes from a feed is untrusted: escape it with
//  escapeHtml() before it goes into innerHTML.
// ═══════════════════════════════════════════════════════════════

let allCves = [];
let kevData = [];
let currentFilter = 'ALL';          // ALL | CRITICAL | HIGH | MEDIUM | LOW | UNSCORED
let currentSourceFilter = 'ALL';    // ALL | nvd | kev | github | paloalto | osv | ubuntu | msrc | redhat
let currentSort = 'cvss';           // cvss | date | epss | kev
let currentPage = 1;
const PAGE_SIZE = 50;
let newOnly = false;
let watchOnly = false;
let logCount = 0;
const sourceStats = {};             // src -> { ok, fetched, inRange }
const _extraCves = new Map();       // search results not in allCves, so the detail panel can open them
let _openCveId = '';
let _seenCriticalIds = null;        // for "new critical CVEs since last refresh"

// ── Company profile + watchlist (localStorage: tw_company_profile) ──
let companyName = '';
let companyTechStack = [];          // lowercase keywords; filters the dashboard when company mode is on
let companyModeActive = false;
let watchlist = [];                 // lowercase keywords; highlighted, never filtered out
let notifyEnabled = false;
let coreWatch = { disabled: [], extra: [] };   // localStorage tw_core_watch — built-ins switched off + own keywords
let _coreVer = 1;                              // bump to invalidate the per-entry core-software memo
let exploitIds = new Set();                    // CVE ids with a public Nuclei exploit template
let _exploitState = 'idle';                    // idle | loading | ok | failed
let upstreamNotices = { upcoming: [], noCve: [] }; // announced security releases / advisories without a CVE yet

// ── Safe storage (private windows can throw) ──
function lsGet(key, fallback = null) {
  try { const v = localStorage.getItem(key); return v === null ? fallback : v; } catch { return fallback; }
}
function lsSet(key, value) { try { localStorage.setItem(key, value); } catch { /* ignore */ } }
function lsGetJson(key, fallback) { try { return JSON.parse(lsGet(key, '')) ?? fallback; } catch { return fallback; } }

// Previous visit time, read once. Entries published (or added to KEV) after it get a NEW badge.
const PREV_VISIT_MS = Number(lsGet('tw_last_visit', '0')) || 0;
function markVisit() { lsSet('tw_last_visit', String(Date.now())); }

// ── Live Clock ──────────────────────────────────────
function updateClock() {
  document.getElementById('live-time').textContent = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
}
setInterval(updateClock, 1000);
updateClock();

// ── Activity log (real events only) ─────────────────
function addLog(type, msg) {
  const feed = document.getElementById('log-feed');
  if (!feed) return;
  const line = document.createElement('div');
  line.className = 'log-line';
  const time = document.createElement('span');
  time.className = 'time';
  time.textContent = new Date().toISOString().substring(11, 23);
  const tag = document.createElement('span');
  tag.className = 'event-type ' + ({ CVE: 'et-cve', KEV: 'et-kev', SYNC: 'et-sync', ALERT: 'et-alert' }[type] || 'et-sync');
  tag.textContent = `[${type}]`;
  line.append(time, tag, document.createTextNode(String(msg)));
  feed.insertBefore(line, feed.firstChild);
  logCount++;
  document.getElementById('log-count').textContent = `${logCount} EVENTS`;
  while (feed.children.length > 80) feed.removeChild(feed.lastChild);
}

// ── Notice banner (NVD outage, demo mode) ───────────
function showNotice(html) {
  const el = document.getElementById('notice-banner');
  if (!el) return;
  el.innerHTML = html;
  el.hidden = false;
}
function hideNotice() { const el = document.getElementById('notice-banner'); if (el) el.hidden = true; }

// ── Date Range ─────────────────────────────────────────
let currentRangeDays = 7;
let _currentLoadKeyword = '';
let _nvdLoading = false;
let _rangeNote = '';

/** The range the dashboard is showing: { start, end, label }. */
function getSelectedRange() {
  if (currentRangeDays === -1) {
    const s = document.getElementById('date-start').value;
    const e = document.getElementById('date-end').value;
    if (s && e) {
      return { start: new Date(s + 'T00:00:00Z'), end: new Date(e + 'T23:59:59Z'),
        label: `${s} to ${e}${_currentLoadKeyword ? ` [${_currentLoadKeyword}]` : ''}` };
    }
  }
  const days = currentRangeDays > 0 ? currentRangeDays : 7;
  const end = new Date();
  return { start: new Date(end.getTime() - days * 86400000), end, label: `last ${days} days` };
}

/** External feeds return entries of any age; keep only those dated inside the selected range. */
function inSelectedRange(v) {
  if (v._source === 'nvd') return true;
  const t = parseFeedDate(v._kev?.dateAdded || v.cve.published);
  if (!t) return false;
  const { start, end } = getSelectedRange();
  const slack = 86400000; // date-only fields and time zones
  return t >= start.getTime() - slack && t <= end.getTime() + slack;
}

function setActiveIn(containerSel, attr, value) {
  document.querySelectorAll(`${containerSel} [${attr}]`).forEach(b => {
    const on = b.getAttribute(attr) === String(value);
    b.classList.toggle('active', on);
    if (b.hasAttribute('aria-pressed')) b.setAttribute('aria-pressed', on ? 'true' : 'false');
  });
}

function setRange(days, btn) {
  currentRangeDays = days;
  _currentLoadKeyword = '';
  document.querySelectorAll('.rtab').forEach(t => t.classList.toggle('active', t.dataset.range === String(days)));
  document.getElementById('custom-dates').classList.remove('visible');
  allCves = allCves.filter(v => v._source === 'nvd'); // external feeds are re-fetched for the new range
  currentPage = 1;
  syncHash();
  refreshAll();
}

function _todayStr() { return new Date().toISOString().split('T')[0]; }

function _setNvdProgress(pct, done) {
  const bar   = document.getElementById('nvd-progress-bar');
  const fill  = document.getElementById('nvd-progress-fill');
  const label = document.getElementById('nvd-progress-label');
  if (!bar) return;
  if (pct === null) {
    bar.classList.remove('active');
    fill.style.width = '0%';
    fill.classList.remove('loading', 'complete');
    if (label) label.textContent = '';
    return;
  }
  bar.classList.add('active');
  fill.style.width = pct + '%';
  if (done) {
    fill.classList.remove('loading');
    fill.classList.add('complete');
    if (label) label.textContent = 'COMPLETE';
  } else {
    fill.classList.add('loading');
    fill.classList.remove('complete');
    if (label) label.textContent = `LOADING  ${pct}%`;
  }
}

function toggleCustomRange(btn) {
  document.querySelectorAll('.rtab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  const cd = document.getElementById('custom-dates');
  cd.classList.add('visible');
  // Cap both inputs to today — no future dates
  const today = _todayStr();
  document.getElementById('date-start').max = today;
  document.getElementById('date-end').max = today;
  // Default to last 30 days
  const ago = new Date();
  ago.setDate(ago.getDate() - 30);
  document.getElementById('date-end').value = today;
  document.getElementById('date-start').value = ago.toISOString().split('T')[0];
  checkCustomRangeLength();
}

function checkCustomRangeLength() {
  const startInput = document.getElementById('date-start');
  const endInput = document.getElementById('date-end');
  let startVal = startInput.value;
  let endVal = endInput.value;
  const kwRow = document.getElementById('custom-keyword-row');
  if (!startVal || !endVal) { kwRow.classList.remove('visible'); return; }
  // Clamp end date to today if user typed a future date
  const today = _todayStr();
  if (endVal > today) { endInput.value = today; endVal = today; }
  if (startVal > today) { startInput.value = today; startVal = today; }
  const diffDays = (new Date(endVal) - new Date(startVal)) / (1000 * 60 * 60 * 24);
  if (diffDays > 90) {
    kwRow.classList.add('visible');
    document.getElementById('load-btn-dates').style.display = 'none';
    document.getElementById('load-btn-kw').style.display = '';
  } else {
    kwRow.classList.remove('visible');
    document.getElementById('custom-keyword').value = '';
    document.getElementById('load-btn-dates').style.display = '';
    document.getElementById('load-btn-kw').style.display = 'none';
  }
}


function loadCustomRange() {
  const startVal = document.getElementById('date-start').value;
  const endVal = document.getElementById('date-end').value;
  if (!startVal || !endVal) return;
  const diffDays = (new Date(endVal) - new Date(startVal)) / 86400000;
  if (diffDays > 90) {
    const kw = document.getElementById('custom-keyword').value.trim();
    if (!kw) {
      const inp = document.getElementById('custom-keyword');
      inp.classList.add('error');
      inp.focus();
      setTimeout(() => inp.classList.remove('error'), 600);
      return;
    }
    _currentLoadKeyword = kw;
  } else {
    _currentLoadKeyword = '';
  }
  currentRangeDays = -1;
  allCves = allCves.filter(v => v._source === 'nvd');
  currentPage = 1;
  syncHash();
  refreshAll(new Date(startVal), new Date(endVal + 'T23:59:59'));
}

/** Load NVD, then every external feed. Used at start-up, on range changes and by auto-refresh. */
// Each refresh gets a generation number; a load that is no longer the latest
// stops writing state (switching range mid-load used to let the old load win).
let _loadGen = 0;
let _feedsLoading = false;
function refreshAll(customStart, customEnd) {
  const gen = ++_loadGen;
  resetSourcePills();
  _feedsLoading = true;
  return loadNVD(customStart, customEnd, gen)
    .then(() => { if (gen === _loadGen) return loadExternalSources(); })
    .finally(() => { if (gen === _loadGen) { _feedsLoading = false; renderPriority(); } });
}

/** Show every source as "loading" so counts from the previous range don't linger. */
function resetSourcePills() {
  document.querySelectorAll('.source-pill').forEach(el => {
    const label = el.dataset.label || (el.dataset.label = el.textContent.split('—')[0].trim());
    el.classList.remove('ok', 'fail');
    el.childNodes[el.childNodes.length - 1].textContent = label;
    el.title = 'Loading…';
  });
}

async function loadExternalSources() {
  await Promise.allSettled([loadKEV(), loadGitHub(), loadPaloAlto(), loadOSV(), loadUbuntu(), loadMSRC(), loadRedHat(), loadCveOrg(), loadUpstream()]);
  updateRangeInfo();
  queueEpssBackground();
  checkAlerts();
  markVisit();
}

function updateRangeInfo() {
  const el = document.getElementById('range-info');
  if (!el || _nvdLoading) return;
  const nvd = allCves.filter(v => v._source === 'nvd').length;
  const other = allCves.length - nvd;
  el.textContent = `${nvd.toLocaleString()} NVD + ${other.toLocaleString()} other sources = ${allCves.length.toLocaleString()} total (${getSelectedRange().label})${_rangeNote}`;
}

// ── Rendering ────────────────────────────────────────
// Feeds merge in bursts; coalesce them into one render.
let _renderTimer = null;
function renderAll() {
  if (_renderTimer) return;
  _renderTimer = setTimeout(() => { _renderTimer = null; renderNow(); }, 30);
}
function renderNow() {
  renderPriority();
  renderCves();
  renderStats();
  renderTimeline();
  renderVendorChart();
  renderDonut();
  renderAttackGrid();
  renderEmergingThreats();
  updateRangeInfo();
  if (_openCveId) renderCveDetail(_openCveId);
}

// ── NVD API ──────────────────────────────────────────
let _nvdCancelFlag = false;
const NVD_PER_PAGE = 2000;
const NVD_RATE_DELAY_MS = 6500; // 5 req/30s → ~6s between requests
const NVD_MAX_PAGES = 50;       // safety cap: 50 pages = 100K CVEs max

async function loadNVD(customStart, customEnd, gen = ++_loadGen) {
  const superseded = () => gen !== _loadGen;
  const stopped = () => _nvdCancelFlag || superseded();
  // Cancel any in-progress load (it notices via superseded())
  _nvdCancelFlag = false;
  await new Promise(r => setTimeout(r, 100));
  if (superseded()) return;

  const btn = document.getElementById('refresh-nvd');
  btn.disabled = false;
  btn.textContent = '⏹ CANCEL';
  btn.onclick = () => { _nvdCancelFlag = true; };
  document.getElementById('sync-status').textContent = 'SYNCING NVD...';
  document.getElementById('sync-status').style.color = 'var(--warn)';
  _setNvdProgress(0);
  _nvdLoading = true;
  _rangeNote = '';
  hideNotice();

  // For auto-refresh when a custom range is active, re-read the date inputs and keyword
  if (!customStart && currentRangeDays === -1) {
    const startVal = document.getElementById('date-start').value;
    const endVal = document.getElementById('date-end').value;
    if (startVal && endVal) {
      customStart = new Date(startVal);
      customEnd = new Date(endVal + 'T23:59:59');
      // Recover keyword for long ranges
      if (!_currentLoadKeyword) {
        _currentLoadKeyword = document.getElementById('custom-keyword').value.trim();
      }
    } else {
      currentRangeDays = 7;
    }
  }

  const endDate = customEnd || new Date();
  const startDate = customStart || new Date();
  if (!customStart) startDate.setDate(endDate.getDate() - currentRangeDays);

  const rangeLabel = customStart
    ? `${startDate.toISOString().split('T')[0]} to ${endDate.toISOString().split('T')[0]}${_currentLoadKeyword ? ` [${_currentLoadKeyword}]` : ''}`
    : `last ${currentRangeDays} days`;

  addLog('SYNC', `Fetching NVD data (${rangeLabel})...`);
  document.getElementById('range-info').textContent = `Loading ${rangeLabel}...`;

  try {
    // Pre-filter external source entries when a keyword is active.
    // Removes unrelated KEV/GitHub/PaloAlto entries that were loaded without a keyword at page init.
    if (_currentLoadKeyword) {
      const kw = _currentLoadKeyword.toLowerCase();
      allCves = allCves.filter(v => {
        if (v._source === 'nvd') return false;
        const id = (v.cve.id || '').toLowerCase();
        const desc = (v.cve.descriptions?.find(d => d.lang === 'en')?.value || '').toLowerCase();
        const vendor = getVendor(v).toLowerCase();
        return id.includes(kw) || desc.includes(kw) || vendor.includes(kw);
      });
      renderAll();
    }

    // CVE ID direct lookup — bypasses chunking, date range, and keyword search entirely.
    // Accepts "CVE-2021-23017", "cve-2021-23017", or bare "2021-23017".
    const cveIdMatch = _currentLoadKeyword && _currentLoadKeyword.match(/^(?:CVE-)?(\d{4}-\d+)$/i);
    if (cveIdMatch) {
      const cveId = `CVE-${cveIdMatch[1].toUpperCase()}`;
      addLog('SYNC', `CVE ID detected — direct lookup: ${cveId}`);
      document.getElementById('range-info').textContent = `Looking up ${cveId}...`;
      const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`;
      const resp = await fetch(url);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      if (superseded()) return;
      const found = (data.vulnerabilities || []).map(v => ({ ...v, _source: 'nvd' }));
      allCves = mergeCves(found, allCves.filter(v => v._source && v._source !== 'nvd')).list;
      if (found.length > 0) {
        const score = getCvss(found[0]);
        addLog('CVE', `${cveId} — CVSS ${score > 0 ? score : 'N/A'} (${getSeverity(score)})`);
        document.getElementById('range-info').textContent = `${cveId} — CVSS ${score > 0 ? score : 'N/A'}`;
        document.getElementById('sync-status').textContent = '✓ NVD SYNCED';
        document.getElementById('sync-status').style.color = 'var(--low)';
        setSourceStatus('nvd', true, 1);
      } else {
        addLog('ALERT', `${cveId} not found in NVD`);
        document.getElementById('range-info').textContent = `${cveId} not found in NVD`;
        document.getElementById('sync-status').textContent = 'NOT FOUND';
        document.getElementById('sync-status').style.color = 'var(--warn)';
        setSourceStatus('nvd', false);
      }
      renderAll();
      _setNvdProgress(100, found.length > 0);
      return;
    }

    // NVD API enforces a 120-day maximum date range per request.
    // Split larger ranges into sequential 119-day chunks.
    const NVD_CHUNK_DAYS = 119;
    const chunks = [];
    let cs = new Date(startDate);
    while (cs <= endDate) {
      const ce = new Date(cs);
      ce.setDate(ce.getDate() + NVD_CHUNK_DAYS);
      chunks.push({
        start: cs.toISOString().split('.')[0] + '.000',
        end: (ce > endDate ? endDate : ce).toISOString().split('.')[0] + '.000'
      });
      cs = new Date(ce);
      cs.setDate(cs.getDate() + 1);
    }
    if (chunks.length > 1) {
      addLog('SYNC', `Date range split into ${chunks.length} chunks (NVD API max: 120 days/request)`);
    }

    let allNvdResults = [];
    let grandTotal = 0;
    let isFirstRequest = true;

    for (let ci = 0; ci < chunks.length; ci++) {
      if (stopped()) {
        if (!superseded()) addLog('SYNC', `NVD load cancelled after ${allNvdResults.length} CVEs`);
        break;
      }

      const chunk = chunks[ci];
      const kwParam = _currentLoadKeyword ? `&keywordSearch=${encodeURIComponent(_currentLoadKeyword)}&keywordExactMatch` : '';
      const baseUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${chunk.start}&pubEndDate=${chunk.end}${kwParam}&resultsPerPage=${NVD_PER_PAGE}`;
      const chunkLabel = chunks.length > 1 ? `Chunk ${ci + 1}/${chunks.length} · ` : '';

      let startIndex = 0;
      let totalResults = null;
      let page = 0;

      while (true) {
        if (stopped()) {
          if (!superseded()) addLog('SYNC', `NVD load cancelled after ${allNvdResults.length} CVEs`);
          break;
        }

        // Rate limit: delay before every request except the very first
        if (!isFirstRequest) {
          addLog('SYNC', `Rate limit pause (${(NVD_RATE_DELAY_MS / 1000).toFixed(1)}s)...`);
          await new Promise(r => setTimeout(r, NVD_RATE_DELAY_MS));
          if (stopped()) break;
        }
        isFirstRequest = false;

        const url = `${baseUrl}&startIndex=${startIndex}`;
        const resp = await fetch(url);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();
        if (superseded()) return;

        if (totalResults === null) {
          totalResults = data.totalResults || 0;
          grandTotal += totalResults;
          const totalPages = Math.min(Math.ceil(totalResults / NVD_PER_PAGE), NVD_MAX_PAGES);
          addLog('SYNC', `${chunkLabel}${totalResults.toLocaleString()} CVEs found — fetching ${totalPages} page(s)`);
        }

        const batch = (data.vulnerabilities || []).filter(v => {
          const desc = getDescription(v);
          return !desc.startsWith('** REJECT') && !desc.startsWith('Rejected reason:');
        }).map(v => ({ ...v, _source: 'nvd' }));
        allNvdResults = [...allNvdResults, ...batch];
        page++;

        const totalPages = Math.min(Math.ceil((totalResults || 0) / NVD_PER_PAGE), NVD_MAX_PAGES);
        // Global progress: (chunks done + fraction of current chunk) / total chunks
        const globalPct = Math.round(((ci + (totalPages > 0 ? page / totalPages : 1)) / chunks.length) * 100);
        document.getElementById('range-info').textContent = `${chunkLabel}Page ${page}/${totalPages} · ${allNvdResults.length.toLocaleString()} CVEs loaded`;
        btn.textContent = 'SEARCHING';
        _setNvdProgress(globalPct);

        // Update the display incrementally every page
        // Merge rather than concatenate, so an NVD entry absorbs KEV status / extra sources
        allCves = mergeCves(allNvdResults, allCves.filter(v => v._source && v._source !== 'nvd')).list;
        renderAll();

        startIndex += NVD_PER_PAGE;
        if (startIndex >= (totalResults || 0) || page >= NVD_MAX_PAGES) break;
        if (batch.length === 0) break;
      }
    }

    if (superseded()) return;
    // Final state
    allCves = mergeCves(allNvdResults, allCves.filter(v => v._source && v._source !== 'nvd')).list;
    const loaded = allNvdResults.length;

    // Retroactively enrich KEV entries: copy real NVD CVSS into any KEV entries now in allCves
    const nvdById = {};
    allNvdResults.forEach(v => { nvdById[v.cve.id] = v; });
    allCves.forEach(v => {
      if (v._source === 'kev' && v._kevExploited) {
        const nvdMatch = nvdById[v.cve.id];
        if (nvdMatch && nvdMatch.cve.metrics && Object.keys(nvdMatch.cve.metrics).length > 0) {
          v.cve.metrics = nvdMatch.cve.metrics;
        }
      }
    });

    if (_nvdCancelFlag) {
      document.getElementById('sync-status').textContent = `⏹ CANCELLED (${loaded.toLocaleString()})`;
      document.getElementById('sync-status').style.color = 'var(--warn)';
      _setNvdProgress(null);
    } else {
      addLog('SYNC', `NVD sync complete — ${loaded.toLocaleString()} CVEs loaded (${rangeLabel})`);
      addLog('CVE', `Highest CVSS: ${getTopCvss(allCves)}`);
      document.getElementById('sync-status').textContent = '✓ NVD SYNCED';
      document.getElementById('sync-status').style.color = 'var(--low)';
      _setNvdProgress(100, true);
    }

    renderAll();
    setSourceStatus('nvd', true, loaded);
  } catch (e) {
    if (superseded()) return;
    _setNvdProgress(null);
    setSourceStatus('nvd', false);
    if (_currentLoadKeyword) {
      // Keyword-filtered load — don't inject demo data; it would show unrelated fake CVEs.
      // Clear any partial NVD results accumulated before the error.
      allCves = allCves.filter(v => v._source !== 'nvd');
      addLog('ALERT', `NVD API error: ${e.message}`);
      document.getElementById('sync-status').textContent = 'NVD OFFLINE';
      document.getElementById('sync-status').style.color = 'var(--warn)';
      _rangeNote = ' · NVD unreachable';
      renderAll();
    } else {
      allCves = allCves.filter(v => v._source !== 'nvd');
      addLog('ALERT', `NVD API error: ${e.message} — showing the other sources only`);
      document.getElementById('sync-status').textContent = 'NVD OFFLINE';
      document.getElementById('sync-status').style.color = 'var(--warn)';
      _rangeNote = ' · NVD unreachable';
      showNotice(`<strong>NVD is unreachable</strong> (${escapeHtml(e.message)}). Showing the other sources only. <button class="notice-btn" onclick="refreshAll()">RETRY</button> <button class="notice-btn" onclick="loadDemoData()">LOAD DEMO DATA</button>`);
      renderAll();
    }
  } finally {
    if (!superseded()) {
    _nvdLoading = false;
    updateRangeInfo();
    btn.disabled = false;
    btn.textContent = '↻ REFRESH';
    btn.onclick = () => refreshAll();
    }
  }
}


function getTopCvss(cves) {
  let top = 0, topId = '';
  cves.forEach(v => {
    const score = getCvss(v);
    if (score > top) { top = score; topId = v.cve.id; }
  });
  return `${topId} (${top})`;
}


// ── CISA KEV ────────────────────────────────────────────
async function loadKEV() {
  addLog('SYNC', 'Fetching CISA Known Exploited Vulnerabilities catalog...');
  try {
    const kevUrl = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
    const resp = await fetchViaProxy(kevUrl);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    const all = data.vulnerabilities || [];
    const kevCves = all.map(k => ({
      _source: 'kev',
      _kevExploited: true,
      _kev: {
        dateAdded: k.dateAdded || '', dueDate: k.dueDate || '', requiredAction: k.requiredAction || '',
        knownRansomwareCampaignUse: k.knownRansomwareCampaignUse || '', notes: k.notes || '',
        vendorProject: k.vendorProject || '', product: k.product || '', vulnerabilityName: k.vulnerabilityName || '',
      },
      cve: {
        id: k.cveID,
        published: k.dateAdded || '',
        descriptions: [{ lang: 'en', value: k.shortDescription || k.vulnerabilityName || 'Known exploited vulnerability' }],
        metrics: {},
        configurations: k.vendorProject ? [{
          nodes: [{ cpeMatch: [{ criteria: `cpe:2.3:a:${k.vendorProject.toLowerCase().replace(/[^a-z0-9]/g, '_')}:${(k.product || '').toLowerCase().replace(/[^a-z0-9]/g, '_')}:*:*:*` }] }]
        }] : []
      }
    }));
    // Entries added to KEV inside the selected range (the KEV card counts these)
    const inRange = kevCves.filter(inSelectedRange);
    kevData = inRange.map(v => ({ cveID: v.cve.id, ...v._kev, shortDescription: getDescription(v) }));
    // mergeCves marks matching NVD entries as exploited and attaches the KEV record
    mergeExternalCves(inRange, 'kev', all.length);
    addLog('KEV', `CISA KEV loaded — ${inRange.length} entries added in ${getSelectedRange().label} (${all.length.toLocaleString()} in catalog)`);
  } catch (e) {
    kevData = [];
    addLog('ALERT', `CISA KEV fetch error: ${e.message}`);
    setSourceStatus('kev', false);
    renderAll();
  }
}

// ── Source Status Helper ──────────────────────────────
function setSourceStatus(src, ok, count, fetched) {
  const el = document.getElementById(`src-${src}`);
  sourceStats[src] = { ...(sourceStats[src] || {}), ok, inRange: count, fetched };
  if (!el) return;
  el.classList.remove('ok', 'fail');
  el.classList.add(ok ? 'ok' : 'fail');
  const label = el.dataset.label || (el.dataset.label = el.textContent.split('—')[0].trim());
  el.childNodes[el.childNodes.length - 1].textContent = ok ? `${label} — ${count ?? 0}` : `${label} — ERR`;
  el.title = ok
    ? (fetched !== undefined && fetched !== count ? `${count} in selected range (${fetched} fetched)` : `${count} entries`)
    : 'Feed unavailable — see the activity log';
}

// ── CORS Proxy ───────────────────────────────────────
// ❗ Update this with YOUR worker URL after deploying cors-proxy/worker.js
const CORS_PROXY = 'https://threatwatch-cors-proxy.scanalejoa.workers.dev';
function proxyUrl(target) {
  return `${CORS_PROXY}?url=${encodeURIComponent(target)}`;
}
/** Fetch through the CORS proxy, retrying once on network errors and 5xx. */
async function fetchViaProxy(target, init) {
  for (let attempt = 0; ; attempt++) {
    try {
      const resp = await fetch(proxyUrl(target), init);
      if (resp.status < 500 || attempt >= 1) return resp;
    } catch (e) {
      if (attempt >= 1) throw e;
    }
    await new Promise(r => setTimeout(r, 1500));
  }
}

// ── Intel worker (intel-worker/): CVE.org early feed + upstream advisories ──
// Override for local testing: localStorage.setItem('tw_intel_url', 'http://localhost:8787')
const INTEL_API = lsGet('tw_intel_url', '') || 'https://threatwatch-intel.scanalejoa.workers.dev';

async function loadCveOrg() {
  const days = currentRangeDays > 0 ? Math.min(14, currentRangeDays) : 14;
  addLog('SYNC', 'Fetching new CVEs from CVE.org (intel worker)...');
  try {
    const r = await fetch(`${INTEL_API}/v1/recent?days=${days}`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const data = await r.json();
    const entries = (data.cves || []).map(cveOrgToEntry);
    addLog('CVE', `CVE.org loaded — ${entries.length} CVEs published in the last ${days} days${data.lastRun ? ` (worker ran ${new Date(data.lastRun).toLocaleTimeString()})` : ''}`);
    mergeExternalCves(entries, 'cveorg');
  } catch (e) {
    addLog('ALERT', `CVE.org early-warning feed unavailable (${e.message}) — deploy intel-worker/ (see its README)`);
    setSourceStatus('cveorg', false);
  }
}

/** Same jobs as the worker's refreshAdvisories(), run in the browser when the worker is unreachable. */
async function fetchAdvisoriesDirect() {
  const out = {};
  const text = async (url, viaProxy) => {
    const r = viaProxy ? await fetchViaProxy(url) : await fetch(url);
    if (!r.ok) throw new Error(`${new URL(url).hostname} HTTP ${r.status}`);
    return r.text();
  };
  const settle = async (key, fn) => {
    try { out[key] = { ok: true, ...(await fn()) }; } catch (e) { out[key] = { ok: false, error: e.message, items: [] }; }
  };
  const cutoff = Date.now() - 120 * 86400000;
  const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
  await Promise.all([
    settle('node', async () => {
      const items = parseNodeRss(await text('https://nodejs.org/en/feed/vulnerability.xml', true)).filter(i => parseFeedDate(i.date) > cutoff).slice(0, 3);
      const posts = await Promise.all(items.map(async i => ({ i, p: parseNodePost(await text(i.link, true), i) })));
      return {
        items: posts.flatMap(({ i, p }) => p.cves.map(c => ({ ...c, date: i.date, link: i.link }))),
        upcoming: posts.map(x => x.p.upcoming).filter(u => u && u.releaseDate >= yesterday),
      };
    }),
    settle('openssh', async () => ({ items: parseOpensshSecurity(await text('https://www.openssh.com/security.html', true)).slice(0, 10) })),
    settle('php', async () => ({ items: parsePhpAdvisories(JSON.parse(await text('https://api.github.com/repos/php/php-src/security-advisories?per_page=30', false))) })),
  ]);
  return out;
}

async function loadUpstream() {
  addLog('SYNC', 'Fetching upstream advisories (Node.js, OpenSSH, PHP)...');
  let adv = null, via = 'intel worker';
  try {
    const r = await fetch(`${INTEL_API}/v1/advisories`);
    if (r.ok) { adv = await r.json(); if (!adv.updated) adv = null; }
  } catch { /* fall back below */ }
  if (!adv) { via = 'direct'; adv = await fetchAdvisoriesDirect(); }

  const entries = [], failed = [];
  for (const [key, product] of [['node', 'Node.js'], ['openssh', 'OpenSSH'], ['php', 'PHP']]) {
    const src = adv[key];
    if (!src) continue;
    if (src.ok === false) failed.push(`${product}: ${src.error}`);
    for (const a of src.items || []) {
      if (key === 'openssh') (a.cves || []).forEach(id => entries.push(upstreamToEntry({ id, title: a.title, desc: `${a.versions}. ${a.text}`, date: a.date, link: a.link }, product)));
      else entries.push(upstreamToEntry(a, product));
    }
  }
  upstreamNotices = {
    upcoming: adv.node?.upcoming || [],
    noCve: (adv.openssh?.items || []).filter(a => !(a.cves || []).length && parseFeedDate(a.date) > Date.now() - 30 * 86400000),
  };
  if (failed.length) addLog('ALERT', `Upstream advisories partly unavailable — ${failed.join('; ')}`);
  upstreamNotices.upcoming.forEach(u => addLog('ALERT', `Upcoming ${u.product} security release on ${u.releaseDate} — highest severity ${u.severity || 'unknown'} (${u.lines.join(', ')})`));
  if (failed.length >= 3) { setSourceStatus('upstream', false); renderPriority(); return; }
  addLog('CVE', `Upstream advisories loaded via ${via} — ${entries.length} CVEs`);
  mergeExternalCves(entries, 'upstream');
}

/** Public exploit index: CVEs with a ProjectDiscovery Nuclei template (cached 12 h). */
async function loadExploitIntel() {
  const cached = lsGetJson('tw_exploit_ids', null);
  if (cached && Array.isArray(cached.ids) && Date.now() - cached.t < 12 * 3600000) {
    exploitIds = new Set(cached.ids); _exploitState = 'ok'; renderAll(); return;
  }
  _exploitState = 'loading';
  try {
    const r = await fetch('https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json');
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const ids = parseNucleiIds(await r.text());
    if (!ids.length) throw new Error('empty list');
    exploitIds = new Set(ids);
    _exploitState = 'ok';
    lsSet('tw_exploit_ids', JSON.stringify({ t: Date.now(), ids }));
    addLog('SYNC', `Exploit intel: ${ids.length.toLocaleString()} CVEs have a public Nuclei exploit template`);
  } catch (e) {
    _exploitState = 'failed';
    if (cached?.ids) exploitIds = new Set(cached.ids);
    addLog('ALERT', `Exploit intel unavailable (${e.message})${cached?.ids ? ' — using the cached list' : ''}`);
  }
  renderAll();
}

// ── GitHub Security Advisories ─────────────────────────
let githubCves = [];
async function loadGitHub() {
  addLog('SYNC', 'Fetching GitHub Security Advisories...');
  try {
    // GitHub public advisories API — no auth needed, CORS-friendly
    const resp = await fetch('https://api.github.com/advisories?per_page=100&type=reviewed', {
      headers: { 'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' }
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();

    // Normalize to NVD-like structure for seamless merging
    // Filter to last 3 years for actionable threat intelligence
    const ghCutoff = new Date();
    ghCutoff.setFullYear(ghCutoff.getFullYear() - 3);
    githubCves = data
      .filter(a => {
        if (!a.cve_id) return false;
        const d = new Date(a.published_at || '');
        return !isNaN(d) && d >= ghCutoff;
      })
      .map(a => ({
        _source: 'github',
        cve: {
          id: a.cve_id,
          published: a.published_at,
          descriptions: [{ lang: 'en', value: a.description || a.summary || 'No description' }],
          metrics: a.cvss ? {
            cvssMetricV31: [{ cvssData: { baseScore: a.cvss.score || 0 } }]
          } : {},
          configurations: a.vulnerabilities?.map(v => ({
            nodes: [{ cpeMatch: [{ criteria: `cpe:2.3:a:${v.package?.ecosystem?.toLowerCase() || 'unknown'}:${v.package?.name?.toLowerCase() || 'unknown'}:*:*:*` }] }]
          })) || []
        }
      }));

    addLog('CVE', `GitHub Advisories loaded — ${githubCves.length} CVEs`);

    // Merge into allCves (avoid duplicates)
    mergeExternalCves(githubCves, 'github');
  } catch (e) {
    addLog('ALERT', `GitHub Advisories error: ${e.message}`);
    setSourceStatus('github', false);
  }
}

// ── Red Hat Security Data API ───────────────────────────
async function loadRedHat() {
  addLog('SYNC', 'Fetching Red Hat Security advisories...');
  try {
    const after = new Date(Date.now() - 90 * 86400000).toISOString().split('T')[0];
    // Correct endpoint: /hydra/rest/securitydata/ (the old /labs/securitydataapi/ path is 404)
    const url = `https://access.redhat.com/hydra/rest/securitydata/cve.json?after=${after}&per_page=100`;
    // Try direct first — Red Hat Security Data API supports CORS
    let resp;
    try {
      resp = await fetch(url, { headers: { Accept: 'application/json' } });
      if (!resp.ok) throw new Error('direct failed');
    } catch {
      resp = await fetchViaProxy(url);
    }
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();

    // API returns an array of CVE summary objects.
    // Top-level fields: CVE, severity, public_date, cvss3_score, cvss_score,
    //                   bugzilla_description, affected_packages
    const cves = (Array.isArray(data) ? data : [])
      .filter(c => c.CVE && /^CVE-/i.test(c.CVE))
      .map(c => {
        const score = parseFloat(c.cvss3_score || c.cvss_score || 0);
        const desc = c.bugzilla_description || 'No description';
        return {
          _source: 'redhat',
          cve: {
            id: c.CVE,
            published: c.public_date || '',
            descriptions: [{ lang: 'en', value: desc }],
            metrics: score > 0 ? { cvssMetricV31: [{ cvssData: { baseScore: score } }] } : {},
            configurations: (c.affected_packages || []).slice(0, 3).map(pkg => ({
              nodes: [{ cpeMatch: [{ criteria: `cpe:2.3:a:redhat:${pkg.toLowerCase().replace(/[^a-z0-9]/g, '_')}:*:*:*` }] }]
            })),
          },
        };
      });
    addLog('CVE', `Red Hat Security loaded — ${cves.length} CVEs`);
    mergeExternalCves(cves, 'redhat');
  } catch (e) {
    addLog('ALERT', `Red Hat Security error: ${e.message}`);
    setSourceStatus('redhat', false);
  }
}

// ── Palo Alto PSIRT (direct JSON API) ─────────────────
async function loadPaloAlto() {
  addLog('SYNC', 'Fetching Palo Alto PSIRT advisories...');
  try {
    const url = 'https://security.paloaltonetworks.com/json';
    // No CORS headers on this endpoint — go straight to the proxy
    const resp = await fetchViaProxy(url);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();

    // API returns array with CVE-* and PAN-SA-* entries.
    // Include both: CVE-* are standard CVEs, PAN-SA-* are Palo Alto security advisories.
    // Filter to last 3 years to exclude ancient/deferred entries.
    const advisories = Array.isArray(data) ? data : [];
    const threeYearsAgo = new Date();
    threeYearsAgo.setFullYear(threeYearsAgo.getFullYear() - 3);
    const cves = advisories
      .filter(a => {
        if (!/^(CVE-\d|PAN-SA-)/i.test(a.ID || '')) return false;
        const d = new Date(a.date || a.updated || '');
        return !isNaN(d) && d >= threeYearsAgo;
      })
      .map(a => ({
        _source: 'paloalto',
        cve: {
          id: a.ID.toUpperCase(),
          published: a.date || a.updated || '',
          descriptions: [{ lang: 'en', value: a.title || 'No description' }],
          metrics: a.baseScore ? {
            cvssMetricV31: [{ cvssData: { baseScore: parseFloat(a.baseScore) || 0 } }]
          } : {},
          configurations: (Array.isArray(a.product) ? a.product : []).map(p => ({
            nodes: [{ cpeMatch: [{ criteria: `cpe:2.3:a:paloaltonetworks:${p.toLowerCase().replace(/[^a-z0-9]/g, '_')}:*:*:*` }] }]
          }))
        }
      }));
    addLog('CVE', `Palo Alto PSIRT loaded — ${cves.length} advisories (CVEs + PAN-SA)`);
    mergeExternalCves(cves, 'paloalto');
  } catch (e) {
    addLog('ALERT', `Palo Alto PSIRT error: ${e.message}`);
    setSourceStatus('paloalto', false);
  }
}

// ── OWASP API Top 10 Classifier (client-side) ──────────
// Enriches existing CVEs with OWASP API Security Top 10 categories (2023)
// based on description keyword matching — no API calls.
function classifyOwaspApi(vuln) {
  const desc = (vuln.cve.descriptions?.find(d => d.lang === 'en')?.value || '').toLowerCase();
  if (!desc) return null;
  // Only classify if the vuln looks API-related
  if (!/\bapi\b|rest(ful)?|graphql|oauth|jwt|json.web.token|openapi|swagger|endpoint|ssrf/.test(desc)) return null;
  if (/\bidor\b|object.level.auth|broken.object.level|bola\b/.test(desc))           return 'API1';
  if (/broken.auth|auth.*bypass|jwt\b|json.web.token|oauth\b|bearer.token|session.fix|credential.stuff/.test(desc)) return 'API2';
  if (/mass.assign|over.post|excess.*data.expos|property.level.auth/.test(desc))   return 'API3';
  if (/rate.limit|throttl|resource.*exhaust|unrestricted.*resource|dos\b|denial.of.service/.test(desc)) return 'API4';
  if (/function.level.auth|privilege.escal|admin.*endpoint|unauthorized.*function/.test(desc)) return 'API5';
  if (/business.logic|workflow.*bypass|purchase.*manipul|inventory.*manipul/.test(desc)) return 'API6';
  if (/\bssrf\b|server.side.request.forgery/.test(desc))                            return 'API7';
  if (/misconfigur|default.cred|cors.*misconfig|security.header|tls.*misconfig/.test(desc)) return 'API8';
  if (/undocumented.api|deprecated.endpoint|shadow.api|unknown.*endpoint/.test(desc)) return 'API9';
  if (/third.party.api|upstream.*service|supply.chain.*api|api.*trust/.test(desc)) return 'API10';
  return null;
}

// ── OSV (Open Source Vulnerabilities) ──────────────────
async function loadOSV() {
  addLog('SYNC', 'Fetching OSV supply chain advisories...');
  try {
    // Query OSV batch for popular open-source packages across ecosystems
    const popularPackages = [
      { name: 'express',                               ecosystem: 'npm' },
      { name: 'lodash',                                ecosystem: 'npm' },
      { name: 'axios',                                 ecosystem: 'npm' },
      { name: 'minimist',                              ecosystem: 'npm' },
      { name: 'node-fetch',                            ecosystem: 'npm' },
      { name: 'vm2',                                   ecosystem: 'npm' },
      { name: 'got',                                   ecosystem: 'npm' },
      { name: 'semver',                                ecosystem: 'npm' },
      { name: 'django',                                ecosystem: 'PyPI' },
      { name: 'flask',                                 ecosystem: 'PyPI' },
      { name: 'requests',                              ecosystem: 'PyPI' },
      { name: 'Pillow',                                ecosystem: 'PyPI' },
      { name: 'cryptography',                          ecosystem: 'PyPI' },
      { name: 'PyYAML',                                ecosystem: 'PyPI' },
      { name: 'paramiko',                              ecosystem: 'PyPI' },
      { name: 'Jinja2',                                ecosystem: 'PyPI' },
      { name: 'github.com/gin-gonic/gin',              ecosystem: 'Go' },
      { name: 'github.com/opencontainers/runc',        ecosystem: 'Go' },
      { name: 'github.com/containerd/containerd',      ecosystem: 'Go' },
      { name: 'org.springframework:spring-core',       ecosystem: 'Maven' },
      { name: 'org.apache.logging.log4j:log4j-core',  ecosystem: 'Maven' },
      { name: 'org.apache.struts:struts2-core',        ecosystem: 'Maven' },
      { name: 'rails',                                 ecosystem: 'RubyGems' },
      { name: 'nokogiri',                              ecosystem: 'RubyGems' },
      { name: 'openssl',                               ecosystem: 'crates.io' },
      { name: 'hyper',                                 ecosystem: 'crates.io' },
    ];
    const osvBody = JSON.stringify({ queries: popularPackages.map(p => ({ package: p })) });
    const osvFetchOpts = { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: osvBody };
    // Try direct CORS first; fall back to proxy if browser blocks the cross-origin POST
    let resp;
    try {
      resp = await fetch('https://api.osv.dev/v1/querybatch', osvFetchOpts);
      if (!resp.ok) throw new Error('direct failed');
    } catch {
      resp = await fetchViaProxy('https://api.osv.dev/v1/querybatch', osvFetchOpts);
    }
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();

    const seenIds = new Set();
    const osvCves = [];
    (data.results || []).forEach(result => {
      (result.vulns || []).forEach(vuln => {
        if (seenIds.has(vuln.id)) return;
        seenIds.add(vuln.id);
        // Prefer CVE alias; fall back to OSV ID (GHSA-xxx / PYSEC-xxx etc.)
        const cveId = (vuln.aliases || []).find(a => /^CVE-/i.test(a)) || vuln.id;
        if (!cveId) return;
        const affectedPkg = vuln.affected?.[0]?.package;
        // Parse base score from severity vector or database_specific
        let baseScore = 0;
        if (vuln.severity && Array.isArray(vuln.severity)) {
          for (const sev of vuln.severity) {
            const m = (sev.score || '').match(/\/(\d+(?:\.\d+)?)$/);
            if (m) { baseScore = parseFloat(m[1]); break; }
          }
        }
        if (!baseScore && vuln.database_specific?.cvss_score) {
          baseScore = parseFloat(vuln.database_specific.cvss_score) || 0;
        }
        if (!baseScore && vuln.database_specific?.severity) {
          const s = vuln.database_specific.severity.toUpperCase();
          baseScore = s === 'CRITICAL' ? 9.5 : s === 'HIGH' ? 7.5 : s === 'MODERATE' || s === 'MEDIUM' ? 5.5 : s === 'LOW' ? 2.5 : 0;
        }
        osvCves.push({
          _source: 'osv',
          cve: {
            id: cveId,
            published: vuln.published || vuln.modified || '',
            descriptions: [{ lang: 'en', value: vuln.details || vuln.summary || 'No description' }],
            metrics: baseScore > 0 ? { cvssMetricV31: [{ cvssData: { baseScore } }] } : {},
            configurations: affectedPkg ? [{
              nodes: [{ cpeMatch: [{ criteria: `cpe:2.3:a:${(affectedPkg.ecosystem || 'unknown').toLowerCase()}:${(affectedPkg.name || 'unknown').toLowerCase()}:*:*:*` }] }]
            }] : [],
          },
        });
      });
    });
    addLog('CVE', `OSV supply chain advisories loaded — ${osvCves.length} entries`);
    mergeExternalCves(osvCves, 'osv');
  } catch (e) {
    addLog('ALERT', `OSV error: ${e.constructor.name}: ${e.message}`);
    setSourceStatus('osv', false);
  }
}

// ── Ubuntu Security Notices ────────────────────────────
async function loadUbuntu() {
  addLog('SYNC', 'Fetching Ubuntu Security Notices...');
  try {
    // Ubuntu API max limit is 20 — fetch 4 pages (80 notices total)
    const allNotices = [];
    for (let page = 0; page < 4; page++) {
      const url = `https://ubuntu.com/security/notices.json?limit=20&offset=${page * 20}`;
      const resp = await fetchViaProxy(url); // no CORS headers on ubuntu.com
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      const page_notices = data.notices || data.results || [];
      allNotices.push(...page_notices);
      if (page_notices.length < 20) break; // last page
    }

    const notices = allNotices;
    const seenCves = new Set();
    const cves = [];
    for (const notice of notices) {
      // Ubuntu notices have no dedicated cves[] field — CVE IDs appear in description text
      const text = (notice.description || '') + ' ' + (notice.summary || '');
      const cveMatches = text.match(/CVE-\d{4}-\d+/g) || [];
      for (const cveId of cveMatches) {
        if (seenCves.has(cveId)) continue;
        seenCves.add(cveId);
        cves.push({
          _source: 'ubuntu',
          cve: {
            id: cveId,
            published: notice.published || '',
            descriptions: [{ lang: 'en', value: notice.title || notice.summary || 'No description' }],
            metrics: {},
            configurations: Object.keys(notice.release_packages || {}).slice(0, 1).flatMap(rel =>
              (notice.release_packages[rel] || []).filter(p => p.is_source && p.name).slice(0, 2).map(p => ({
                nodes: [{ cpeMatch: [{ criteria: `cpe:2.3:a:ubuntu:${p.name.toLowerCase().replace(/[^a-z0-9]/g, '_')}:*:*:*` }] }]
              }))
            ),
          },
        });
      }
    }
    addLog('CVE', `Ubuntu Security loaded — ${cves.length} CVEs`);
    mergeExternalCves(cves, 'ubuntu');
  } catch (e) {
    addLog('ALERT', `Ubuntu Security error: ${e.constructor.name}: ${e.message}`);
    setSourceStatus('ubuntu', false);
  }
}

// ── Microsoft MSRC (Security Update Guide) ────────────
async function loadMSRC() {
  addLog('SYNC', 'Fetching Microsoft MSRC advisories...');
  try {
    // Step 1: list available CVRF documents
    const updatesResp = await fetchViaProxy('https://api.msrc.microsoft.com/cvrf/v3.0/Updates');
    if (!updatesResp.ok) throw new Error(`HTTP ${updatesResp.status}`);
    const updatesData = await updatesResp.json();
    const updates = (updatesData.value || []).sort((a, b) =>
      new Date(b.CurrentReleaseDate || 0) - new Date(a.CurrentReleaseDate || 0)
    );
    if (!updates.length) throw new Error('No MSRC updates found');

    // Step 2: fetch the most recent monthly CVRF
    const latest = updates[0];
    const cvrfResp = await fetchViaProxy(`https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/${encodeURIComponent(latest.ID)}`);
    if (!cvrfResp.ok) throw new Error(`HTTP ${cvrfResp.status}`);
    const cvrf = await cvrfResp.json();

    const cves = (cvrf.Vulnerability || [])
      .filter(v => v.CVE && /^CVE-/i.test(v.CVE))
      .map(v => {
        const score = parseFloat(v.CVSSScoreSets?.[0]?.BaseScore || 0);
        const desc = v.Notes?.find(n => n.Type === 1 || n.Type === 'Description')?.Value
          || v.Title?.Value || 'No description';
        return {
          _source: 'msrc',
          cve: {
            id: v.CVE,
            published: v.RevisionHistory?.[v.RevisionHistory.length - 1]?.Date
              || latest.CurrentReleaseDate || '',
            descriptions: [{ lang: 'en', value: desc }],
            metrics: score > 0 ? { cvssMetricV31: [{ cvssData: { baseScore: score } }] } : {},
            configurations: [],
          },
        };
      });
    addLog('CVE', `MSRC loaded — ${cves.length} CVEs (${latest.ID})`);
    mergeExternalCves(cves, 'msrc');
  } catch (e) {
    addLog('ALERT', `MSRC error: ${e.message}`);
    setSourceStatus('msrc', false);
  }
}


// ── Merge external CVEs into allCves ───────────────────
function mergeExternalCves(incoming, src, fetchedTotal) {
  const r = mergeCves(allCves, incoming, {
    keyword: _currentLoadKeyword,
    inRange: _currentLoadKeyword ? null : inSelectedRange, // keyword searches already scope by date in NVD
  });
  allCves = r.list;
  if (r.enriched || r.list.length !== r.added.length) _coreVer++; // merged fields can change the core-software match
  // Pill count = this source's entries in range, including ones merged into an existing CVE
  const inRangeCount = incoming.filter(v => _currentLoadKeyword ? matchesKeyword(v, _currentLoadKeyword) : inSelectedRange(v)).length;
  if (src) setSourceStatus(src, true, inRangeCount, fetchedTotal ?? incoming.length);
  if (r.added.length || r.enriched) {
    if (r.added.length) addLog('SYNC', `Merged ${r.added.length} new entries from ${String(src || 'external source').toUpperCase()}`);
    if (r.enriched) addLog('SYNC', `${r.enriched} unscored CVEs got a CVSS score from ${String(src || 'another source').toUpperCase()}`);
  }
  renderAll();
  return r;
}

function getCveLink(id) {
  if (/^PAN-SA-/i.test(id)) return `https://security.paloaltonetworks.com/${encodeURIComponent(id)}`;
  if (/^GHSA-/i.test(id)) return `https://github.com/advisories/${encodeURIComponent(id)}`;
  if (/^CVE-/i.test(id)) return `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`;
  return `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
}

function getSourceLabel(v) {
  return (v._source || 'nvd').toLowerCase();
}

const SEV_COLOR = { CRITICAL: 'var(--critical)', HIGH: 'var(--high)', MEDIUM: 'var(--medium)', LOW: 'var(--low)', UNSCORED: 'var(--muted)' };
// Chart marks: validated with the dataviz palette checker (CVD ΔE ≥ 10, normal-vision ΔE ≥ 15 between neighbours)
const CHART_COLOR = { ...SEV_COLOR, UNSCORED: 'var(--unscored)' };

// ── Feed filters, sorting, paging ─────────────────────
function filterSeverity(sev, btn) {
  currentFilter = sev;
  setActiveIn('#severity-tabs', 'data-sev', sev);
  currentPage = 1;
  syncHash();
  renderCves();
}

function filterSource(src, btn) {
  currentSourceFilter = src;
  setActiveIn('#source-tabs', 'data-src', src);
  currentPage = 1;
  syncHash();
  renderCves();
}

function setSort(mode) {
  currentSort = mode;
  const sel = document.getElementById('sort-select');
  if (sel && sel.value !== mode) sel.value = mode;
  currentPage = 1;
  if (mode === 'epss') queueEpssFor(getFilteredCves().slice(0, 2000));
  syncHash();
  renderCves();
}

function toggleNewOnly(force) {
  newOnly = typeof force === 'boolean' ? force : !newOnly;
  const b = document.getElementById('toggle-new');
  if (b) { b.classList.toggle('active', newOnly); b.setAttribute('aria-pressed', String(newOnly)); }
  currentPage = 1;
  syncHash();
  renderCves();
}

function toggleWatchOnly(force) {
  watchOnly = typeof force === 'boolean' ? force : !watchOnly;
  const b = document.getElementById('toggle-watch');
  if (b) { b.classList.toggle('active', watchOnly); b.setAttribute('aria-pressed', String(watchOnly)); }
  currentPage = 1;
  syncHash();
  renderCves();
}

function goToPage(p) {
  currentPage = p;
  syncHash();
  renderCves();
  document.getElementById('cve-feed').scrollTop = 0;
}

/** allCves narrowed by company mode (if on). Every chart and card reads this. */
function getActiveCves() {
  if (companyModeActive && companyTechStack.length > 0) return allCves.filter(matchesCompanyStack);
  return allCves;
}

/** What the feed shows (all pages) — also what CSV/PDF export. */
function getFilteredCves() {
  let list = getActiveCves();
  if (currentFilter !== 'ALL') list = list.filter(v => getSeverity(getCvss(v)) === currentFilter);
  if (currentSourceFilter === 'kev') list = list.filter(v => v._kevExploited);
  else if (currentSourceFilter !== 'ALL') list = list.filter(v => getSourceLabel(v) === currentSourceFilter);
  if (newOnly) list = list.filter(v => isNewSince(v, PREV_VISIT_MS));
  if (watchOnly) list = list.filter(v => matchesAnyKeyword(v, watchlist));
  return sortCves(list, currentSort, id => epssCache.get(id)?.epss);
}

function fmtEpss(p) {
  if (p === undefined || p === null) return '';
  return p >= 0.1 ? (p * 100).toFixed(0) + '%' : p >= 0.01 ? (p * 100).toFixed(1) + '%' : '<1%';
}

function badgesHtml(v) {
  const owasp = classifyOwaspApi(v);
  const core = coreOf(v);
  const exploit = publicExploitSource(v, exploitIds);
  return (v._kevExploited ? '<span class="kev-tag" title="Listed in CISA Known Exploited Vulnerabilities">⚡EXPLOITED</span>' : '')
    + (!v._kevExploited && ssvcOf(v)?.e === 'active' ? '<span class="kev-tag" title="CISA SSVC: exploitation active">⚡CISA: ACTIVE</span>' : '')
    + (exploit ? `<span class="exploit-tag" title="${escapeHtml(EXPLOIT_LABEL[exploit])}">PUBLIC EXPLOIT</span>` : '')
    + (core ? `<span class="core-tag" title="Core software watch">CORE · ${escapeHtml(core)}</span>` : '')
    + (isNewSince(v, PREV_VISIT_MS) ? '<span class="new-tag" title="Published or added to KEV since your last visit">NEW</span>' : '')
    + (watchlist.length && matchesAnyKeyword(v, watchlist) ? '<span class="watch-tag" title="Matches your watchlist">WATCH</span>' : '')
    + (v._demo ? '<span class="demo-tag">DEMO</span>' : '')
    + (owasp ? `<span class="owasp-tag">OWASP ${owasp}</span>` : '');
}

function epssHtml(v) {
  const e = epssCache.get(v.cve.id);
  if (!e) return '';
  return `<span class="epss-tag" title="EPSS: ${(e.epss * 100).toFixed(2)}% chance of exploitation in the next 30 days (percentile ${(e.percentile * 100).toFixed(0)})">EPSS ${fmtEpss(e.epss)}</span>`;
}

function feedRowHtml(v) {
  const score = getCvss(v);
  const sev = getSeverity(score);
  const desc = getDescription(v) || 'No description';
  const short = desc.length > 140 ? desc.slice(0, 140) + '…' : desc;
  const src = getSourceLabel(v);
  const id = escapeHtml(v.cve.id);
  return `
  <div class="cve-item" tabindex="0" role="button" data-cve-id="${id}" aria-label="Open details for ${id}">
    <div>
      <a class="cve-id" href="${escapeHtml(getCveLink(v.cve.id))}" target="_blank" rel="noopener">${id}</a>${badgesHtml(v)}
      <div class="cve-vendor">${escapeHtml((v.cve.published || '').slice(0, 10))}</div>
    </div>
    <div><div class="cve-desc">${escapeHtml(short)}</div></div>
    <div class="cve-src-cell"><span class="cve-source src-${escapeHtml(src)}">${escapeHtml(src.toUpperCase())}</span>${epssHtml(v)}</div>
    <div><span class="severity-badge sev-${sev}">${sev}</span></div>
    <div class="cvss-score" style="color:${SEV_COLOR[sev]}">${score > 0 ? score.toFixed(1) : '—'}</div>
  </div>`;
}

let _lastRenderedPage = 1;
function renderCves() {
  const feed = document.getElementById('cve-feed');
  const pager = document.getElementById('cve-pager');
  const countLabel = document.getElementById('cve-count-label');
  const list = getFilteredCves();
  const pages = Math.max(1, Math.ceil(list.length / PAGE_SIZE));
  if (currentPage > pages) currentPage = pages;
  renderNewSinceChip();

  if (list.length === 0) {
    const hints = [];
    if (companyModeActive && companyTechStack.length) hints.push(`company mode (${companyTechStack.join(', ')})`);
    if (newOnly) hints.push('NEW only');
    if (watchOnly) hints.push(watchlist.length ? 'watchlist only' : 'watchlist only — your watchlist is empty');
    feed.innerHTML = `<div class="error-msg">NO VULNERABILITIES MATCH FILTERS${hints.length ? ' — ' + escapeHtml(hints.join(' · ')) : ''}</div>`;
    if (countLabel) countLabel.textContent = '0 matching';
    if (pager) pager.innerHTML = '';
    return;
  }

  const start = (currentPage - 1) * PAGE_SIZE;
  const pageItems = list.slice(start, start + PAGE_SIZE);
  const keepScroll = _lastRenderedPage === currentPage ? feed.scrollTop : 0;
  feed.innerHTML = pageItems.map(feedRowHtml).join('');
  feed.scrollTop = keepScroll;
  _lastRenderedPage = currentPage;

  const sortName = { cvss: 'CVSS', date: 'newest', epss: 'EPSS', kev: 'KEV first' }[currentSort];
  if (countLabel) countLabel.textContent = `${list.length.toLocaleString()} matching · sorted by ${sortName}`;
  if (pager) {
    pager.innerHTML = pages <= 1 ? '' : `
      <button class="ftab" ${currentPage <= 1 ? 'disabled' : ''} onclick="goToPage(${currentPage - 1})" aria-label="Previous page">‹ PREV</button>
      <span>Page ${currentPage} of ${pages} · ${(start + 1).toLocaleString()}–${(start + pageItems.length).toLocaleString()} of ${list.length.toLocaleString()}</span>
      <button class="ftab" ${currentPage >= pages ? 'disabled' : ''} onclick="goToPage(${currentPage + 1})" aria-label="Next page">NEXT ›</button>`;
  }
  queueEpssFor(pageItems);
}

function renderNewSinceChip() {
  const chip = document.getElementById('new-since-chip');
  if (!chip) return;
  if (!PREV_VISIT_MS) { chip.hidden = true; return; }
  const n = getActiveCves().filter(v => isNewSince(v, PREV_VISIT_MS)).length;
  chip.hidden = false;
  chip.textContent = `★ ${n.toLocaleString()} new since ${new Date(PREV_VISIT_MS).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}`;
}

// Row click / Enter opens the detail panel (links inside rows keep working).
function onCveListActivate(e) {
  if (e.type === 'keydown' && e.key !== 'Enter' && e.key !== ' ') return;
  if (e.target.closest('a, button')) return;
  const row = e.target.closest('[data-cve-id]');
  if (!row) return;
  e.preventDefault();
  openCveDetail(row.dataset.cveId);
}

// ── Stat cards ────────────────────────────────────────
function renderStats() {
  const active = getActiveCves();
  const counts = countsBySeverity(active);
  document.getElementById('cnt-critical').textContent = counts.CRITICAL.toLocaleString();
  document.getElementById('cnt-high').textContent = counts.HIGH.toLocaleString();
  document.getElementById('cnt-medium').textContent = counts.MEDIUM.toLocaleString();
  document.getElementById('cnt-low').textContent = counts.LOW.toLocaleString();
  document.getElementById('cnt-unscored').textContent = counts.UNSCORED.toLocaleString();
  const kev = active.filter(v => v._kevExploited).length;
  const kevFailed = sourceStats.kev && sourceStats.kev.ok === false;
  document.getElementById('cnt-kev').textContent = kevFailed ? 'ERR' : kev.toLocaleString();
}

// ── Timeline: new CVEs per day by severity ─────────────
const TIMELINE_SERIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNSCORED'];
let _timelineData = null;

function renderTimeline() {
  const wrap = document.getElementById('timeline-chart');
  if (!wrap) return;
  const range = getSelectedRange();
  const { weekly, buckets } = dailyCounts(getActiveCves(), range.start, range.end);
  _timelineData = { weekly, buckets };
  const title = document.getElementById('timeline-title');
  if (title) title.textContent = weekly ? 'New CVEs per week' : 'New CVEs per day';
  const W = Math.max(300, wrap.clientWidth || 800), H = 150, padL = 44, padR = 8, padT = 8, padB = 22;
  const max = Math.max(1, ...buckets.map(b => b.total));
  const niceMax = (() => { const p = Math.pow(10, Math.floor(Math.log10(max))); return Math.ceil(max / p) * p; })();
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const slot = plotW / buckets.length;
  const bw = Math.max(1, Math.min(28, slot * 0.72));
  const y = v => padT + plotH - (v / niceMax) * plotH;
  let bars = '';
  buckets.forEach((b, i) => {
    const x = padL + i * slot + (slot - bw) / 2;
    let acc = 0;
    const segs = TIMELINE_SERIES.filter(k => b.counts[k] > 0);
    segs.forEach((k, si) => {
      const y0 = y(acc), y1 = y(acc + b.counts[k]);
      acc += b.counts[k];
      const gap = si < segs.length - 1 && (y0 - y1) > 3 ? 1 : 0; // surface gap between stacked segments
      const h = Math.max(1, y0 - y1 - gap);
      const top = y1 + gap * 0;
      if (si === segs.length - 1) {
        const r = Math.min(3, bw / 2, h);
        bars += `<path d="M${x},${top + h} V${top + r} Q${x},${top} ${x + r},${top} H${x + bw - r} Q${x + bw},${top} ${x + bw},${top + r} V${top + h} Z" fill="${CHART_COLOR[k]}"/>`;
      } else {
        bars += `<rect x="${x}" y="${top}" width="${bw}" height="${h}" fill="${CHART_COLOR[k]}"/>`;
      }
    });
    bars += `<rect class="tl-hit" data-i="${i}" x="${padL + i * slot}" y="${padT}" width="${slot}" height="${plotH}" fill="transparent"/>`;
  });
  const fmt = k => new Date(k + 'T00:00:00Z').toLocaleDateString([], { month: 'short', day: 'numeric', timeZone: 'UTC' });
  const labelIdx = [...new Set([0, Math.floor((buckets.length - 1) / 2), buckets.length - 1])];
  const xLabels = labelIdx.map(i => `<text x="${padL + i * slot + slot / 2}" y="${H - 6}" text-anchor="${i === 0 ? 'start' : i === buckets.length - 1 ? 'end' : 'middle'}" class="tl-axis">${fmt(buckets[i].key)}</text>`).join('');
  const grid = [0.5, 1].map(f => `<line x1="${padL}" x2="${W - padR}" y1="${y(niceMax * f)}" y2="${y(niceMax * f)}" class="tl-grid"/><text x="${padL - 6}" y="${y(niceMax * f) + 3}" text-anchor="end" class="tl-axis">${Math.round(niceMax * f).toLocaleString()}</text>`).join('');
  wrap.innerHTML = `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="${escapeHtml(title ? title.textContent : 'CVE timeline')}">
      ${grid}<line x1="${padL}" x2="${W - padR}" y1="${y(0)}" y2="${y(0)}" class="tl-base"/>${bars}${xLabels}
    </svg>`;
}

function onTimelineHover(e) {
  const tip = document.getElementById('chart-tip');
  const hit = e.target.closest && e.target.closest('.tl-hit');
  if (!tip) return;
  if (!hit || !_timelineData) { tip.style.display = 'none'; return; }
  const b = _timelineData.buckets[+hit.dataset.i];
  const d = new Date(b.key + 'T00:00:00Z').toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' });
  tip.innerHTML = `<div class="tip-title">${_timelineData.weekly ? 'Week of ' : ''}${escapeHtml(d)} · ${b.total.toLocaleString()} CVEs</div>`
    + TIMELINE_SERIES.map(k => `<div class="tip-row"><span class="tip-swatch" style="background:${CHART_COLOR[k]}"></span>${k}<span class="tip-val">${b.counts[k].toLocaleString()}</span></div>`).join('');
  tip.style.display = 'block';
  const r = hit.getBoundingClientRect();
  const tw = tip.offsetWidth;
  let left = r.left + r.width / 2 - tw / 2;
  left = Math.max(8, Math.min(left, window.innerWidth - tw - 8));
  tip.style.left = left + 'px';
  tip.style.top = Math.max(8, r.top - tip.offsetHeight - 8) + 'px';
}

// ── Vendor Chart ──────────────────────────────────────
function renderVendorChart() {
  const vendorMap = {};
  getActiveCves().forEach(v => {
    const vendor = getChartVendor(v);
    if (vendor) vendorMap[vendor] = (vendorMap[vendor] || 0) + 1;
  });
  const sorted = Object.entries(vendorMap).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const max = sorted[0]?.[1] || 1;
  document.getElementById('vendor-chart').innerHTML = sorted.map(([vendor, count]) => `
    <div class="bar-row" role="button" tabindex="0" data-vendor="${escapeHtml(vendor)}" title="${escapeHtml(vendor)} — ${count} CVEs">
      <div class="bar-label">${escapeHtml(vendor.toUpperCase().substring(0, 14))}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${(count / max * 100).toFixed(1)}%"></div></div>
      <div class="bar-count">${count.toLocaleString()}</div>
    </div>`).join('')
    || '<div class="chart-empty">No vendor data yet — vendors come from CPE data, which NVD often adds a few days after publication.</div>';
}

function onVendorActivate(e) {
  if (e.type === 'keydown' && e.key !== 'Enter' && e.key !== ' ') return;
  const row = e.target.closest('[data-vendor]');
  if (!row) return;
  e.preventDefault();
  openVendorModal(row.dataset.vendor);
}

function openVendorModal(vendor) {
  const list = sortCves(getActiveCves().filter(v => getChartVendor(v) === vendor), 'cvss');
  openListModal(`📊 ${vendor.toUpperCase()} — ${list.length} vulnerabilities`, 'var(--amber)', list);
}

// ── Donut Chart ───────────────────────────────────────
function renderDonut() {
  const active = getActiveCves();
  const counts = countsBySeverity(active);
  const total = active.length || 1;
  const cfg = TIMELINE_SERIES.map(k => ({ key: k, label: k, color: CHART_COLOR[k] }));
  const r = 60, cx = 75, cy = 75, stroke = 18;
  const circumference = 2 * Math.PI * r;
  let offset = 0;
  const svgSegments = cfg.map(c => {
    const pct = counts[c.key] / total;
    const dash = pct * circumference;
    const seg = `<circle r="${r}" cx="${cx}" cy="${cy}" fill="none" stroke="${c.color}" stroke-width="${stroke}"
      stroke-dasharray="${dash} ${circumference - dash}" stroke-dashoffset="${-offset + circumference * 0.25}" opacity="${pct > 0 ? 0.9 : 0}"><title>${c.label}: ${counts[c.key].toLocaleString()}</title></circle>`;
    offset += dash;
    return seg;
  }).join('');
  document.getElementById('donut-wrap').innerHTML = `
    <svg class="donut" width="150" height="150" viewBox="0 0 150 150" role="img" aria-label="Severity distribution">
      <circle r="${r}" cx="${cx}" cy="${cy}" fill="none" stroke="var(--surface2)" stroke-width="${stroke}"/>
      ${svgSegments}
      <text x="${cx}" y="${cy - 6}" text-anchor="middle" fill="var(--amber)" font-family="Bebas Neue" font-size="18">${active.length.toLocaleString()}</text>
      <text x="${cx}" y="${cy + 12}" text-anchor="middle" fill="var(--muted)" font-family="JetBrains Mono" font-size="9">CVEs</text>
    </svg>
    <div class="donut-legend">
      ${cfg.map(c => `
        <div class="legend-item">
          <div class="legend-dot" style="background:${c.color}"></div>
          <div class="legend-label">${c.label}</div>
          <div class="legend-pct">${counts[c.key].toLocaleString()} · ${((counts[c.key] / total) * 100).toFixed(1)}%</div>
        </div>`).join('')}
    </div>`;
}

// ── Attack categories (keyword match on descriptions) ──
const ATTACK_DEFS = [
  { icon: '💉', name: 'SQL INJECTION',     keys: /sql.?inject|\bsqli\b/i },
  { icon: '⚡',     name: 'REMOTE CODE EXEC',  keys: /remote.code.exec|arbitrary.code|\brce\b|code.execution/i },
  { icon: '🎯', name: 'XSS',               keys: /cross.site.script|\bxss\b/i },
  { icon: '💣', name: 'BUFFER OVERFLOW',   keys: /buffer.overflow|stack.overflow|heap.overflow|out.of.bounds.write/i },
  { icon: '📁', name: 'PATH TRAVERSAL',    keys: /path.travers|directory.travers|\blfi\b|local.file.incl/i },
  { icon: '🔓', name: 'AUTH BYPASS',       keys: /auth(?:entication)?.bypass|bypass.auth|credential.bypass/i },
  { icon: '🔺', name: 'PRIV ESCALATION',   keys: /privilege.escal|elevation.of.priv|local.privilege/i },
  { icon: '🚫', name: 'DENIAL OF SERVICE', keys: /denial.of.service|\bddos\b|resource.exhaustion/i },
];


function renderAttackGrid() {
  const active = getActiveCves();
  const total = active.length || 1;
  const counts = ATTACK_DEFS.map(def => ({
    ...def,
    count: active.filter(v => def.keys.test(getDescription(v))).length,
  })).sort((a, b) => b.count - a.count);
  document.getElementById('attack-grid').innerHTML = counts.map(a => `
    <div class="attack-tile" role="button" tabindex="0" data-category="${escapeHtml(a.name)}" title="Show ${escapeHtml(a.name)} CVEs">
      <div class="attack-icon">${a.icon}</div>
      <div class="attack-name">${a.name}</div>
      <div class="attack-count">${a.count.toLocaleString()}</div>
      <div class="attack-trend"><span class="trend-pct">${((a.count / total) * 100).toFixed(1)}%</span><span class="trend-label">of loaded CVEs</span></div>
    </div>`).join('');
}

function onCategoryActivate(e) {
  if (e.type === 'keydown' && e.key !== 'Enter' && e.key !== ' ') return;
  const tile = e.target.closest('[data-category]');
  if (!tile) return;
  e.preventDefault();
  const def = ATTACK_DEFS.find(d => d.name === tile.dataset.category);
  if (!def) return;
  const list = sortCves(getActiveCves().filter(v => def.keys.test(getDescription(v))), 'cvss');
  openListModal(`${def.icon} ${def.name} — ${list.length.toLocaleString()} CVEs`, 'var(--amber)', list);
}

// ── Threat themes (curated context + live keyword counts) ──
const EMERGING_DEFS = [
  {
    icon: '🔐', name: 'Ransomware', level: 'CRITICAL', cls: 'tl-critical',
    keys: /ransomware|ransom(?:ware)?/i,
    desc: 'Active campaigns targeting critical infrastructure, healthcare &amp; finance sectors',
    src: 'SRC: CISA Advisories 2024'
  },
  {
    icon: '🤖', name: 'AI-Powered Attacks', level: 'HIGH', cls: 'tl-high',
    keys: /llm|large.language.model|deepfake|ai.assisted|ai.powered/i,
    desc: 'LLM-assisted phishing, deepfake impersonation &amp; automated vulnerability recon',
    src: 'SRC: CrowdStrike Global Threat Report 2024'
  },
  {
    icon: '🎣', name: 'Phishing / BEC', level: 'HIGH', cls: 'tl-high',
    keys: /phish|spear.phish|vish(?:ing)?|business.email.compromise|bec/i,
    desc: 'Business email compromise, spear phishing &amp; voice phishing (vishing) campaigns',
    src: 'SRC: Verizon DBIR 2024 — 36% of breaches'
  },
  {
    icon: '🔗', name: 'Supply Chain', level: 'HIGH', cls: 'tl-high',
    keys: /supply.chain|dependency.confusion|typosquat|malicious.package/i,
    desc: 'Dependency confusion, typosquatting &amp; malicious package injection in open source',
    src: 'SRC: OpenSSF / GitHub Advisory DB'
  },
  {
    icon: '⛓️', name: 'Blockchain / Web3', level: 'MEDIUM', cls: 'tl-medium',
    keys: /blockchain|smart.contract|web3|defi|cross.chain|flash.loan|cryptocurrency/i,
    desc: 'Smart contract exploits, cross-chain bridge attacks &amp; flash loan manipulation',
    src: 'SRC: Chainalysis Crypto Crime Report 2024'
  },
  {
    icon: '👤', name: 'Insider Threats', level: 'MEDIUM', cls: 'tl-medium',
    keys: /insider.threat|privilege.abus|credential.abus|data.exfiltrat|unauthorized.access/i,
    desc: 'Credential abuse, data exfiltration &amp; privilege misuse by malicious or negligent insiders',
    src: 'SRC: CISA Insider Threat Mitigation Guide'
  }
];


function renderEmergingThreats() {
  const active = getActiveCves();
  const total = active.length;
  document.getElementById('emerging-grid').innerHTML = EMERGING_DEFS.map(def => {
    const count = total ? active.filter(v => def.keys.test(getDescription(v))).length : 0;
    const pct = total ? ((count / total) * 100).toFixed(1) : '0.0';
    return '<div class="emerging-tile ' + def.cls + '">'
      + '<div class="emerging-icon">' + def.icon + '</div>'
      + '<div class="emerging-body">'
      + '<div class="emerging-header">'
      + '<div class="emerging-name">' + def.name + '</div>'
      + '<span class="threat-level">' + def.level + '</span>'
      + '<span class="' + (count === 0 ? 'emerging-count zero' : 'emerging-count') + '">' + (total ? count.toLocaleString() + ' CVEs · ' + pct + '%' : 'NO DATA') + '</span>'
      + '</div>'
      + '<div class="emerging-desc">' + def.desc + '</div>'
      + '<div class="emerging-source">' + def.src + '</div>'
      + '</div></div>';
  }).join('');
}

// ── Demo data (only on request, clearly labelled) ─────
function loadDemoData() {
  allCves = generateDemoCves(80);
  _rangeNote = ' · DEMO DATA';
  showNotice('<strong>DEMO DATA</strong> — these 80 entries are randomly generated, not real vulnerabilities. <button class="notice-btn" onclick="exitDemo()">BACK TO LIVE DATA</button>');
  addLog('SYNC', 'Demo data loaded at your request — these are not real CVEs');
  renderAll();
}
function exitDemo() {
  allCves = allCves.filter(v => !v._demo);
  _rangeNote = '';
  hideNotice();
  refreshAll();
}

function generateDemoCves(n) {
  const vendors = ['microsoft', 'apache', 'linux', 'cisco', 'google', 'oracle', 'adobe', 'mozilla', 'openssl', 'wordpress'];
  const types = ['Buffer Overflow in', 'Remote Code Execution in', 'SQL Injection vulnerability in', 'Authentication Bypass in', 'Memory Corruption in', 'Improper Input Validation in', 'Use After Free vulnerability in', 'Out-of-bounds Write in'];
  const products = ['Windows Kernel', 'Apache HTTP Server', 'Linux Kernel', 'Cisco IOS', 'Chrome Browser', 'Oracle Database', 'Adobe Acrobat', 'Firefox', 'OpenSSL', 'WP Core'];
  const now = new Date();
  return Array.from({ length: n }, (_, i) => {
    const vi = i % vendors.length;
    return {
      _source: 'nvd',
      _demo: true,
      cve: {
        id: `DEMO-${String(i + 1).padStart(4, '0')}`,
        published: new Date(now - Math.random() * 7 * 86400000).toISOString(),
        descriptions: [{ lang: 'en', value: `[DEMO] ${types[i % types.length]} ${products[vi]}: allows remote attackers to execute arbitrary code via crafted input.` }],
        metrics: { cvssMetricV31: [{ cvssData: { baseScore: parseFloat((Math.random() * 10).toFixed(1)) } }] },
        configurations: [{ nodes: [{ cpeMatch: [{ criteria: `cpe:2.3:a:${vendors[vi]}:product:*:*:*` }] }] }]
      }
    };
  });
}

// ── Alerts: real events for the activity log + browser notifications ──
function checkAlerts() {
  const active = allCves.filter(v => !v._demo);
  // New critical CVEs since the previous refresh in this session
  const crit = new Set(active.filter(v => getCvss(v) >= 9).map(v => v.cve.id));
  if (_seenCriticalIds) {
    const fresh = [...crit].filter(id => !_seenCriticalIds.has(id));
    if (fresh.length) addLog('CVE', `${fresh.length} new critical CVE${fresh.length !== 1 ? 's' : ''} since the last refresh: ${fresh.slice(0, 5).join(', ')}${fresh.length > 5 ? '…' : ''}`);
  }
  _seenCriticalIds = crit;

  if (!PREV_VISIT_MS) return;
  const freshKev = active.filter(v => v._kevExploited && v._kev && isNewSince(v, PREV_VISIT_MS));
  if (freshKev.length) addLog('KEV', `${freshKev.length} KEV entr${freshKev.length !== 1 ? 'ies' : 'y'} added since your last visit`);
  const keywords = [...new Set([...companyTechStack, ...watchlist])];
  const hits = freshKev.filter(v => matchesAnyKeyword(v, keywords));
  hits.forEach(v => addLog('ALERT', `New exploited vulnerability matches your stack/watchlist: ${v.cve.id} — ${getDescription(v).slice(0, 90)}`));
  if (!hits.length || !notifyEnabled || !('Notification' in window) || Notification.permission !== 'granted') return;
  const notified = new Set(lsGetJson('tw_notified_kev', []));
  hits.filter(v => !notified.has(v.cve.id)).slice(0, 5).forEach(v => {
    try {
      const n = new Notification('ThreatWatch: exploited vulnerability on your stack', { body: `${v.cve.id} — ${getDescription(v).slice(0, 140)}`, tag: v.cve.id });
      n.onclick = () => { window.focus(); openCveDetail(v.cve.id); };
    } catch { /* some browsers only allow notifications from a service worker */ }
    notified.add(v.cve.id);
  });
  lsSet('tw_notified_kev', JSON.stringify([...notified].slice(-500)));
}

// ── EPSS (FIRST.org exploit prediction scores) ────────
const epssCache = new Map();   // id -> { epss, percentile } | null (looked up, no score)
const _epssPending = new Set();
let _epssTimer = null;
let _epssFailed = false;

function queueEpssFor(cves) {
  if (_epssFailed) return;
  let added = false;
  for (const v of cves) {
    const id = v.cve.id;
    if (/^CVE-\d{4}-\d{4,}$/.test(id) && !epssCache.has(id) && !_epssPending.has(id)) { _epssPending.add(id); added = true; }
  }
  if (added) { clearTimeout(_epssTimer); _epssTimer = setTimeout(flushEpss, 300); }
}

/** After a full load, score what matters most: KEV, critical and high. */
function queueEpssBackground() {
  const rank = v => v._kevExploited ? 0 : getCvss(v) >= 9 ? 1 : 2;
  const date = v => parseFeedDate(v.cve.published);
  queueEpssFor(allCves.filter(v => v._kevExploited || getCvss(v) >= 7)
    .sort((a, b) => (rank(a) - rank(b)) || (date(b) - date(a)))
    .slice(0, 3000));
}

/**
 * Bulk-load every CVE FIRST scores at EPSS ≥ 10% (~17k), so the Fix First
 * view finds likely-exploited CVEs even when they are unscored or medium.
 * Anything absent from this set is known to be below the P2 threshold.
 */
let _epssBulkState = 'idle'; // idle | loading | ok | failed
let _epssBulkCount = 0;
async function loadHighEpss() {
  if (_epssBulkState === 'loading' || _epssBulkState === 'ok') return;
  _epssBulkState = 'loading';
  renderPriority();
  const base = `https://api.first.org/data/v1/epss?epss-gt=${EPSS_URGENT - 0.000001}&limit=5000`;
  const get = async offset => {
    const url = `${base}&offset=${offset}`;
    let r;
    try { r = await fetch(url); if (!r.ok) throw new Error(); } catch { r = await fetchViaProxy(url); }
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  };
  try {
    const first = await get(0);
    const pages = [first];
    const offsets = [];
    for (let o = 5000; o < Math.min(first.total || 0, 50000); o += 5000) offsets.push(o);
    pages.push(...await Promise.all(offsets.map(get)));
    let n = 0;
    pages.forEach(pg => (pg.data || []).forEach(d => { epssCache.set(d.cve, { epss: +d.epss, percentile: +d.percentile }); n++; }));
    _epssBulkCount = n;
    _epssBulkState = 'ok';
    addLog('SYNC', `EPSS: ${n.toLocaleString()} CVEs with ≥10% exploitation probability loaded from FIRST`);
  } catch (e) {
    _epssBulkState = 'failed';
    addLog('ALERT', `EPSS bulk load failed (${e.message}) — Fix First falls back to per-CVE EPSS lookups`);
  }
  renderAll();
}

async function flushEpss() {
  const ids = [..._epssPending].slice(0, 300);
  if (!ids.length) return;
  ids.forEach(id => _epssPending.delete(id));
  let changed = false;
  for (let i = 0; i < ids.length; i += 100) {
    const batch = ids.slice(i, i + 100);
    const url = `https://api.first.org/data/v1/epss?cve=${batch.join(',')}&limit=100`;
    try {
      let resp;
      try { resp = await fetch(url); if (!resp.ok) throw new Error(); } catch { resp = await fetchViaProxy(url); }
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      batch.forEach(id => { if (!epssCache.has(id)) epssCache.set(id, null); });
      (data.data || []).forEach(d => { epssCache.set(d.cve, { epss: +d.epss, percentile: +d.percentile }); changed = true; });
    } catch (e) {
      _epssFailed = true;
      addLog('ALERT', `EPSS lookup failed (${e.message}) — exploit scores unavailable this session`);
      break;
    }
  }
  if (changed) {
    renderCves();
    renderPriority();
    if (_openCveId) renderCveDetail(_openCveId);
  }
  if (_epssPending.size && !_epssFailed) setTimeout(flushEpss, 800);
}

// ── Fix First: remediation priority view ──────────────
let prioTierFilter = 'ALL';   // ALL | '1'..'4'
let _prioLimit = 25;
const PRIO_STEP = 25;
const TIER_COLOR = { 1: 'var(--critical)', 2: 'var(--high)', 3: 'var(--medium)', 4: 'var(--info)' };

/** Ranked rows for the active data set (company mode respected). */
function getPriorityRows() {
  return rankByPriority(getActiveCves(), id => epssCache.get(id)?.epss, prioCtx());
}

/** Core-software label for an entry, memoised until the watch list or data changes. */
function coreOf(v) {
  if (v._coreVer !== _coreVer) { v._core = coreSoftwareOf(v, coreWatch.disabled, coreWatch.extra); v._coreVer = _coreVer; }
  return v._core;
}
function prioCtx() { return { core: coreOf, exploitIds, now: Date.now() }; }
const EXPLOIT_LABEL = { nuclei: 'Public exploit (Nuclei template)', ssvc: 'CISA SSVC: proof of concept public', nvd: 'Exploit referenced by NVD' };

function setPrioTier(t) {
  prioTierFilter = prioTierFilter === String(t) ? 'ALL' : String(t);
  _prioLimit = PRIO_STEP;
  syncHash();
  renderPriority();
}
function showMorePriority() { _prioLimit += PRIO_STEP * 2; renderPriority(); }

function fmtAge(ms) {
  if (!ms) return '—';
  const d = Math.floor((Date.now() - ms) / 86400000);
  return d <= 0 ? 'today' : d === 1 ? '1d' : d + 'd';
}

function prioEpssCell(r) {
  const e = epssCache.get(r.v.cve.id);
  if (e) {
    const pct = Math.max(2, Math.round(e.epss * 100));
    return `<div class="prio-epss" title="${(e.epss * 100).toFixed(2)}% chance of exploitation in the next 30 days · percentile ${(e.percentile * 100).toFixed(0)}">
      <span class="prio-epss-val${e.epss >= EPSS_URGENT ? ' hot' : ''}">${fmtEpss(e.epss)}</span>
      <span class="prio-bar"><i style="width:${pct}%"></i></span></div>`;
  }
  if (epssCache.has(r.v.cve.id)) return '<span class="prio-dim" title="FIRST has no EPSS score for this CVE yet">n/a</span>';
  if (_epssBulkState === 'ok') return '<span class="prio-dim" title="Below 10% — not in FIRST\'s high-probability set; exact value still loading">&lt;10%</span>';
  return '<span class="prio-dim">…</span>';
}

function prioKevCell(v) {
  if (!v._kevExploited && ssvcOf(v)?.e === 'active') return '<span class="kev-tag" title="CISA SSVC: exploitation active (not yet in KEV)">⚡CISA: ACTIVE</span>';
  if (!v._kevExploited) return '<span class="prio-dim">—</span>';
  const k = v._kev || {};
  const due = daysUntil(k.dueDate);
  let dueHtml = '';
  if (due !== null) {
    dueHtml = due < 0 ? `<span class="prio-due overdue" title="CISA due date ${escapeHtml(k.dueDate)}">${-due}d overdue</span>`
      : `<span class="prio-due" title="CISA due date ${escapeHtml(k.dueDate)}">due ${due === 0 ? 'today' : 'in ' + due + 'd'}</span>`;
  }
  return `<span class="kev-tag">⚡EXPLOITED</span>${k.knownRansomwareCampaignUse === 'Known' ? '<span class="ransom-tag" title="CISA: known use in ransomware campaigns">RANSOMWARE</span>' : ''}${dueHtml}`;
}

function prioVendorText(v) {
  const k = v._kev;
  if (k && (k.vendorProject || k.product)) return [k.vendorProject, k.product].filter(Boolean).join(' · ');
  const prods = getAffectedProducts(v, 2).join(', ');
  if (prods) return prods;
  const vendor = getVendor(v);
  return vendor && vendor.toLowerCase() !== 'unknown' ? vendor : '';
}

function prioRowHtml(r, rank) {
  const v = r.v;
  const t = PRIORITY_TIERS[r.tier - 1];
  const sev = getSeverity(r.cvss);
  const id = escapeHtml(v.cve.id);
  const desc = getDescription(v) || 'No description';
  const short = desc.length > 130 ? desc.slice(0, 130) + '…' : desc;
  const vendor = prioVendorText(v);
  const tags = (r.early ? '<span class="early-tag" title="Remote, no-auth bug in core software, under 72 h old">EARLY WARNING</span>' : '')
    + (r.core ? `<span class="core-tag" title="Core software watch">CORE · ${escapeHtml(r.core)}</span>` : '')
    + (r.exploit ? `<span class="exploit-tag" title="${escapeHtml(EXPLOIT_LABEL[r.exploit])}">PUBLIC EXPLOIT</span>` : '')
    + (isNewSince(v, PREV_VISIT_MS) ? '<span class="new-tag">NEW</span>' : '')
    + (watchlist.length && matchesAnyKeyword(v, watchlist) ? '<span class="watch-tag">WATCH</span>' : '')
    + (v._demo ? '<span class="demo-tag">DEMO</span>' : '');
  return `
  <div class="prio-row tier-${r.tier}" role="row" tabindex="0" data-cve-id="${id}" aria-label="Rank ${rank}, ${t.key} ${t.label}: ${id}">
    <span class="prio-rank" role="cell">${rank}</span>
    <span role="cell"><span class="prio-pill" style="--tier:${TIER_COLOR[r.tier]}">${t.key} · ${t.label}</span></span>
    <span class="prio-vuln" role="cell">
      <span class="prio-id">${id}</span>${tags}
      ${vendor ? `<span class="prio-vendor">${escapeHtml(vendor)}</span>` : ''}
      <span class="prio-desc">${escapeHtml(short)}</span>
      <span class="prio-why">Why: ${escapeHtml(r.reasons.join(' · '))}</span>
    </span>
    <span class="prio-kev" role="cell"><span class="prio-mlabel">KEV</span>${prioKevCell(v)}</span>
    <span role="cell"><span class="prio-mlabel">EPSS</span>${prioEpssCell(r)}</span>
    <span class="prio-cvss" role="cell"><span class="prio-mlabel">CVSS</span><b style="color:${SEV_COLOR[sev]}">${r.cvss > 0 ? r.cvss.toFixed(1) : '—'}</b><small>${sev === 'UNSCORED' ? (v._upstream?.severity ? 'vendor: ' + escapeHtml(v._upstream.severity) : 'no score') : sev}</small></span>
    <span class="prio-age" role="cell" title="${v._kev?.dateAdded ? 'Added to KEV ' + escapeHtml(v._kev.dateAdded) : 'Published ' + escapeHtml((v.cve.published || '').slice(0, 10))}"><span class="prio-mlabel">AGE</span>${fmtAge(r.t)}</span>
  </div>`;
}

function renderPriority() {
  const list = document.getElementById('prio-list');
  if (!list) return;
  const rows = getPriorityRows();
  const counts = { 1: 0, 2: 0, 3: 0, 4: 0 };
  rows.forEach(r => counts[r.tier]++);

  const badge = document.getElementById('prio-nav-badge');
  if (badge) badge.textContent = allCves.length ? counts[1].toLocaleString() : '—';

  // Tier tiles (also the filter)
  document.getElementById('prio-tiers').innerHTML = PRIORITY_TIERS.map(t => `
    <button class="prio-tile${prioTierFilter === String(t.tier) ? ' active' : ''}" style="--tier:${TIER_COLOR[t.tier]}"
      aria-pressed="${prioTierFilter === String(t.tier)}" onclick="setPrioTier(${t.tier})">
      <span class="prio-tile-key">${t.key} · ${t.label}</span>
      <span class="prio-tile-num">${allCves.length ? counts[t.tier].toLocaleString() : '--'}</span>
      <span class="prio-tile-rule">${escapeHtml(t.rule)}</span>
      <span class="prio-tile-sla">${escapeHtml(t.sla)}</span>
    </button>`).join('');

  const range = getSelectedRange().label;
  const total = rows.length;
  const urgent = counts[1] + counts[2];
  const sub = document.getElementById('prio-sub');
  if (!allCves.length) {
    sub.textContent = _nvdLoading ? 'Loading vulnerability feeds…' : 'No data loaded yet.';
  } else {
    sub.innerHTML = `<b>${urgent.toLocaleString()}</b> to fix this week (exploited or likely) · <b>${total.toLocaleString()}</b> in the remediation queue · from ${getActiveCves().length.toLocaleString()} CVEs, ${escapeHtml(range)}`
      + (_feedsLoading ? ' · <span class="prio-loading">still loading feeds — counts will grow</span>' : '')
      + (companyModeActive && companyTechStack.length ? ` · <span class="prio-company">company stack only (${escapeHtml(companyTechStack.slice(0, 4).join(', '))}${companyTechStack.length > 4 ? '…' : ''})</span>` : '');
  }

  const st = document.getElementById('prio-epss-status');
  const parts = [{
    idle: '', loading: 'EPSS loading…',
    ok: `EPSS: ${_epssBulkCount.toLocaleString()} high-probability CVEs.`,
    failed: 'EPSS bulk load failed — P2 may be incomplete.',
  }[_epssBulkState], {
    idle: '', loading: 'Exploit intel loading…',
    ok: `Public exploits: ${exploitIds.size.toLocaleString()} known.`,
    failed: exploitIds.size ? `Public exploits: ${exploitIds.size.toLocaleString()} (cached).` : 'Exploit intel unavailable.',
  }[_exploitState]];
  if (sourceStats.cveorg) parts.push(sourceStats.cveorg.ok ? 'CVE.org early feed: live.' : 'CVE.org early feed: unavailable (intel worker).');
  st.textContent = parts.filter(Boolean).join(' ');
  st.classList.toggle('warn', _epssBulkState === 'failed' || (sourceStats.cveorg && !sourceStats.cveorg.ok));
  renderEarlyPanel(rows);

  const shown = prioritySelection(rows);
  const tierInfo = /^[1-4]$/.test(prioTierFilter) ? PRIORITY_TIERS[Number(prioTierFilter) - 1] : null;
  document.getElementById('prio-list-title').textContent = tierInfo ? `Remediation queue — ${tierInfo.key} ${tierInfo.label}`
    : prioTierFilter === 'early' ? 'Remediation queue — early warnings' : 'Remediation queue';
  document.getElementById('prio-count').textContent = shown.length ? `${Math.min(_prioLimit, shown.length).toLocaleString()} of ${shown.length.toLocaleString()}` : '';

  if (!shown.length) {
    list.innerHTML = `<div class="error-msg">${!allCves.length ? 'LOADING…' : tierInfo ? `NOTHING IN ${tierInfo.key} FOR THIS RANGE` : prioTierFilter === 'early' ? 'NO EARLY WARNINGS RIGHT NOW' : 'NO CVE IN THIS RANGE NEEDS SCHEDULED ACTION'}</div>`;
    document.getElementById('prio-more').innerHTML = '';
    return;
  }
  const page = shown.slice(0, _prioLimit);
  // Rank is the position in the full queue, so filtering a tier keeps the real order number
  const rankOf = new Map(rows.map((r, i) => [r, i + 1]));
  list.innerHTML = page.map(r => prioRowHtml(r, rankOf.get(r))).join('');
  document.getElementById('prio-more').innerHTML = shown.length > _prioLimit
    ? `<button class="ftab" onclick="showMorePriority()">SHOW ${Math.min(PRIO_STEP * 2, shown.length - _prioLimit)} MORE</button>`
    : '';
  queueEpssFor(page.map(r => r.v));
}

function fmtHoursAgo(ms) {
  const h = Math.max(0, Math.round((Date.now() - ms) / 3600000));
  return h < 1 ? 'just now' : h < 48 ? `${h}h ago` : `${Math.round(h / 24)}d ago`;
}

/** Banner above the tiers: early-warning CVEs and announced upstream security releases. */
function renderEarlyPanel(rows) {
  const el = document.getElementById('prio-early');
  if (!el) return;
  const early = rows.filter(r => r.early);
  const up = upstreamNotices.upcoming || [];
  const noCve = upstreamNotices.noCve || [];
  if (!early.length && !up.length && !noCve.length) { el.hidden = true; el.innerHTML = ''; return; }
  el.hidden = false;
  const fmtDay = d => new Date(d + 'T12:00:00Z').toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' });
  const items = [
    ...up.map(u => `<div class="early-item upcoming">
        <span class="early-kind">UPCOMING RELEASE</span>
        <span><b>${escapeHtml(u.product)} security release ${escapeHtml(fmtDay(u.releaseDate))}</b> — highest severity <b>${escapeHtml(u.severity || '?')}</b>, lines ${escapeHtml((u.lines || []).join(', '))}. CVE details are published on release day: plan the patch window now.
        <a href="${escapeHtml(safeUrl(u.link))}" target="_blank" rel="noopener">advisory ↗</a></span></div>`),
    ...noCve.map(a => `<div class="early-item upcoming">
        <span class="early-kind">OPENSSH ADVISORY</span>
        <span><b>${escapeHtml(a.title)}</b> — ${escapeHtml(a.versions)} (${escapeHtml(a.date.slice(0, 10))}, no CVE yet)
        <a href="${escapeHtml(safeUrl(a.link))}" target="_blank" rel="noopener">release notes ↗</a></span></div>`),
    ...early.slice(0, 5).map(r => `<div class="early-item cve" role="button" tabindex="0" data-cve-id="${escapeHtml(r.v.cve.id)}">
        <span class="early-kind">EARLY WARNING</span>
        <span><b class="prio-id">${escapeHtml(r.v.cve.id)}</b> <span class="core-tag">CORE · ${escapeHtml(r.core)}</span>
        ${escapeHtml(r.reasons.join(' · '))} · published ${escapeHtml(fmtHoursAgo(parseFeedDate(r.v.cve.published)))}</span></div>`),
  ];
  el.innerHTML = `
    <div class="prio-early-head">
      <span class="prio-early-title">⚠ EARLY WARNING</span>
      <span class="prio-early-sub">Remote, no-login bugs in core software from the last ${EARLY_WARNING_HOURS} h, and announced security releases. EPSS and KEV take days to react; AI-assisted attackers do not.</span>
      ${early.length ? `<button class="ftab${prioTierFilter === 'early' ? ' active' : ''}" onclick="setPrioTier('early')">${prioTierFilter === 'early' ? 'SHOW FULL QUEUE' : `SHOW ALL ${early.length} EARLY WARNING${early.length !== 1 ? 'S' : ''}`}</button>` : ''}
    </div>
    ${items.join('')}`;
}

function prioritySelection(all = getPriorityRows()) {
  if (prioTierFilter === 'ALL') return all;
  if (prioTierFilter === 'early') return all.filter(r => r.early);
  return all.filter(r => String(r.tier) === prioTierFilter);
}

function exportPriorityCSV() {
  const all = getPriorityRows();
  const rows = prioritySelection(all);
  if (!rows.length) return;
  const rankOf = new Map(all.map((r, i) => [r, i + 1]));
  const header = ['Rank', 'Priority', 'Suggested SLA', 'Why', 'CVE ID', 'Vendor / product', 'Core software', 'Early warning', 'Public exploit', 'KEV', 'KEV due date', 'Ransomware use', 'CISA SSVC exploitation', 'EPSS', 'EPSS percentile', 'CVSS', 'Severity', 'Published', 'Description'];
  const data = rows.map(r => {
    const t = PRIORITY_TIERS[r.tier - 1];
    const e = epssCache.get(r.v.cve.id);
    const k = r.v._kev || {};
    return [rankOf.get(r), `${t.key} ${t.label}`, t.sla, r.reasons.join(' · '), r.v.cve.id, prioVendorText(r.v), r.core || '', r.early ? 'Yes' : '', r.exploit ? EXPLOIT_LABEL[r.exploit] : '',
      r.v._kevExploited ? 'Yes' : 'No', k.dueDate || '', k.knownRansomwareCampaignUse || '', ssvcOf(r.v)?.e || '',
      e ? e.epss.toFixed(4) : '', e ? e.percentile.toFixed(3) : '', r.cvss || '', getSeverity(r.cvss), (r.v.cve.published || '').slice(0, 10), getDescription(r.v)];
  });
  downloadCsv([header, ...data], `threatwatch-fix-first-${_todayStr()}.csv`);
  addLog('SYNC', `Exported ${rows.length.toLocaleString()} prioritized CVEs to CSV`);
}

function exportPriorityPDF() {
  const rows = prioritySelection();
  if (!rows.length) return;
  const early = rows.filter(r => r.early).map(r => r.v);
  const sections = [{ heading: `EARLY WARNING — remote no-auth bugs in core software, last ${EARLY_WARNING_HOURS} h`, items: early }].concat(PRIORITY_TIERS.map(t => ({
    heading: `${t.key} ${t.label} — ${t.rule} · ${t.sla}`,
    items: rows.filter(r => r.tier === t.tier).slice(0, 50).map(r => r.v),
  })));
  printReport('THREATWATCH — Fix First (remediation priority)', sections);
}

/** Compact summary for the AI system prompt. */
function priorityContextForAi() {
  const rows = getPriorityRows();
  if (!rows.length) return 'none in range';
  const c = [1, 2, 3, 4].map(n => `P${n}: ${rows.filter(r => r.tier === n).length}`).join(', ');
  const top = rows.slice(0, 10).map((r, i) => `${i + 1}. ${r.v.cve.id} (P${r.tier}: ${r.reasons.join(', ')}${r.early ? ', EARLY WARNING' : ''}${r.cvss ? ', CVSS ' + r.cvss : ''}${prioVendorText(r.v) ? ', ' + prioVendorText(r.v).slice(0, 40) : ''})`).join('; ');
  const early = rows.filter(r => r.early).length;
  const up = (upstreamNotices.upcoming || []).map(u => `${u.product} security release ${u.releaseDate} (highest ${u.severity})`).join('; ');
  return `${c}. Early warnings (remote no-auth core-software bugs < ${EARLY_WARNING_HOURS} h): ${early}.${up ? ' Upcoming: ' + up + '.' : ''} Top 10: ${top}`;
}

// ── CVE detail panel ──────────────────────────────────
function findCve(id) {
  return allCves.find(v => v.cve.id === id) || _extraCves.get(id) || null;
}

async function openCveDetail(id) {
  _openCveId = id;
  const panel = document.getElementById('cve-detail');
  panel.classList.add('open');
  panel.setAttribute('aria-hidden', 'false');
  document.getElementById('detail-backdrop').classList.add('open');
  syncHash();
  if (!findCve(id) && /^CVE-\d{4}-\d+$/i.test(id)) {
    document.getElementById('detail-title').textContent = id;
    document.getElementById('detail-body').innerHTML = '<div class="modal-empty">Loading from NVD…</div>';
    try {
      const r = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(id)}`);
      const data = r.ok ? await r.json() : null;
      const v = data?.vulnerabilities?.[0];
      if (v) _extraCves.set(id, { ...v, _source: 'nvd' });
    } catch { /* handled below */ }
  }
  if (_openCveId !== id) return;
  renderCveDetail(id);
  queueEpssFor([{ cve: { id } }]);
  document.querySelector('#cve-detail .modal-close')?.focus();
}

function closeCveDetail() {
  if (!_openCveId) return false;
  _openCveId = '';
  const panel = document.getElementById('cve-detail');
  panel.classList.remove('open');
  panel.setAttribute('aria-hidden', 'true');
  document.getElementById('detail-backdrop').classList.remove('open');
  syncHash();
  return true;
}

function renderCveDetail(id) {
  const v = findCve(id);
  const title = document.getElementById('detail-title');
  const body = document.getElementById('detail-body');
  title.textContent = id;
  if (!v) {
    body.innerHTML = `<div class="modal-empty">${escapeHtml(id)} is not in the loaded data and could not be fetched from NVD.</div>`;
    return;
  }
  const cvss = getCvssDetail(v);
  const sev = getSeverity(cvss.score);
  const epss = epssCache.get(id);
  const kev = v._kev || (v._kevExploited ? {} : null);
  const cwes = [...new Set((v.cve.weaknesses || []).flatMap(w => (w.description || []).map(d => d.value)).filter(x => x && !/^NVD-CWE/.test(x)))];
  const products = getAffectedProducts(v, 0);
  const refs = (v.cve.references || []).slice(0, 15);
  const sources = [getSourceLabel(v), ...(v._alsoIn || [])].map(s => s.toUpperCase());
  const vendor = getChartVendor(v);
  const fact = (label, value) => value ? `<div class="fact"><div class="fact-label">${label}</div><div class="fact-value">${value}</div></div>` : '';

  let wafHtml = '<div class="detail-muted">Connect Cloudflare and run <a href="#" onclick="closeCveDetail();showView(\'waf-coverage\');return false;">WAF Coverage</a> to see matching rules.</div>';
  if (typeof _lastWafRules !== 'undefined' && _lastWafRules && typeof extractCveKeywords === 'function') {
    const kws = extractCveKeywords(v);
    const matches = _lastWafRules.filter(r => kws.some(k => k && ruleSearchSurface(r).includes(k)));
    wafHtml = matches.length
      ? `<div class="detail-muted">${matches.length} rule${matches.length !== 1 ? 's' : ''} mention ${escapeHtml(kws.slice(0, 3).join(', '))} (keyword match, not a guarantee):</div><ul class="detail-list">${matches.slice(0, 5).map(m => `<li>${escapeHtml((m.description || m.filter?.expression || m.expression || 'rule').slice(0, 90))}</li>`).join('')}</ul>`
      : `<div class="detail-muted">No deployed WAF rule mentions ${escapeHtml(kws.slice(0, 3).join(', ') || 'this product')}.</div>
         <button class="action-btn primary" data-suggest-cve="${escapeHtml(id)}" data-suggest-kws="${escapeHtml(JSON.stringify(kws))}">SUGGEST A WAF RULE (AI)</button>`;
  }

  body.innerHTML = `
    <div class="detail-badges">${badgesHtml(v)}</div>
    ${(() => {
      const sig = prioritySignals(v, { ...prioCtx(), epss: epss?.epss });
      if (!sig.tier) return '<div class="detail-prio dim">Fix First: no scheduled action (no exploitation signal, CVSS below 7)</div>';
      const t = PRIORITY_TIERS[sig.tier - 1];
      return `<div class="detail-prio" style="--tier:${TIER_COLOR[sig.tier]}"><b>${t.key} · ${t.label}</b> — ${escapeHtml(sig.reasons.join(' · '))}${sig.early ? ' · <b>EARLY WARNING</b>' : ''} <span>${escapeHtml(t.sla)}</span></div>`;
    })()}
    <div class="detail-scores">
      <div class="score-box" style="border-color:${SEV_COLOR[sev]}">
        <div class="score-label">CVSS ${escapeHtml(cvss.version)}</div>
        <div class="score-value" style="color:${SEV_COLOR[sev]}">${cvss.score ? cvss.score.toFixed(1) : '—'}</div>
        <div class="score-sub">${sev}</div>
      </div>
      <div class="score-box">
        <div class="score-label">EPSS · 30-day exploit probability</div>
        <div class="score-value">${epss ? fmtEpss(epss.epss) : epssCache.has(id) ? 'n/a' : '…'}</div>
        <div class="score-sub">${epss ? 'percentile ' + (epss.percentile * 100).toFixed(0) : epssCache.has(id) ? 'not scored by FIRST' : 'loading'}</div>
      </div>
      <div class="score-box" style="${kev ? 'border-color:var(--critical)' : ''}">
        <div class="score-label">CISA KEV</div>
        <div class="score-value" style="color:${kev ? 'var(--critical)' : 'var(--muted)'}">${kev ? 'YES' : 'NO'}</div>
        <div class="score-sub">${kev && kev.dateAdded ? 'added ' + escapeHtml(kev.dateAdded) : kev ? 'known exploited' : 'no known exploitation'}</div>
      </div>
    </div>
    ${cvss.vector ? `<div class="detail-vector" title="CVSS vector">${escapeHtml(cvss.vector)}</div>` : ''}
    <div class="detail-section">DESCRIPTION</div>
    <p class="detail-desc">${escapeHtml(getDescription(v) || 'No description')}</p>
    ${kev && (kev.requiredAction || kev.dueDate) ? `
      <div class="detail-section">CISA REQUIRED ACTION</div>
      <div class="detail-kev">
        ${kev.requiredAction ? `<p>${escapeHtml(kev.requiredAction)}</p>` : ''}
        <div class="facts">${fact('Due date (US federal)', escapeHtml(kev.dueDate))}${fact('Used in ransomware', escapeHtml(kev.knownRansomwareCampaignUse))}${fact('Vendor / product', escapeHtml([kev.vendorProject, kev.product].filter(Boolean).join(' ')))}</div>
      </div>` : ''}
    <div class="detail-section">DETAILS</div>
    <div class="facts">
      ${fact('Published', escapeHtml((v.cve.published || '').slice(0, 10)))}
      ${fact('Last modified', escapeHtml((v.cve.lastModified || '').slice(0, 10)))}
      ${fact('Reported by', escapeHtml(sources.join(', ')))}
      ${fact('Weakness (CWE)', escapeHtml(cwes.join(', ')))}
      ${fact('Affected', escapeHtml(products.slice(0, 12).join(', ') + (products.length > 12 ? ` +${products.length - 12} more` : '')))}
      ${fact('Core software', escapeHtml(coreOf(v) || ''))}
      ${fact('Public exploit', escapeHtml(EXPLOIT_LABEL[publicExploitSource(v, exploitIds)] || ''))}
      ${fact('CISA SSVC', ssvcOf(v) ? escapeHtml(`exploitation: ${ssvcOf(v).e || '?'} · automatable: ${ssvcOf(v).a || '?'} · impact: ${ssvcOf(v).t || '?'}`) : '')}
      ${fact('Vendor advisory', v._upstream ? `<a href="${escapeHtml(safeUrl(v._upstream.link))}" target="_blank" rel="noopener">${escapeHtml(v._upstream.product)}${v._upstream.severity ? ' — ' + escapeHtml(v._upstream.severity) : ''} ↗</a>` : '')}
      ${fact('Assigned by (CNA)', escapeHtml(v.cve._cna || ''))}
    </div>
    <div class="detail-section">CLOUDFLARE WAF</div>
    ${wafHtml}
    ${refs.length ? `<div class="detail-section">REFERENCES</div><ul class="detail-list refs">${refs.map(r => {
      const href = safeUrl(r.url);
      let host = '';
      try { host = new URL(href).hostname; } catch { host = ''; }
      return `<li><a href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer">${escapeHtml(host || r.url)}</a>${(r.tags || []).length ? ` <span class="ref-tags">${escapeHtml(r.tags.join(', '))}</span>` : ''}</li>`;
    }).join('')}</ul>` : ''}
    <div class="detail-actions">
      <a class="action-btn" href="${escapeHtml(getCveLink(id))}" target="_blank" rel="noopener">OPEN SOURCE ↗</a>
      <button class="action-btn primary" data-ask-ai="${escapeHtml(id)}">ASK AI ABOUT THIS</button>
      <button class="action-btn" data-copy="${escapeHtml(id)}">COPY ID</button>
      ${vendor ? `<button class="action-btn" data-watch="${escapeHtml(vendor)}">${watchlist.includes(vendor) ? '✓ WATCHING ' : '+ WATCH '}${escapeHtml(vendor.toUpperCase())}</button>` : ''}
    </div>`;
}

function onDetailAction(e) {
  const t = e.target.closest('button[data-ask-ai], button[data-copy], button[data-watch], button[data-suggest-cve]');
  if (!t) return;
  if (t.dataset.askAi) {
    const v = findCve(t.dataset.askAi);
    const score = v ? getCvss(v) : 0;
    const facts = [score ? `CVSS ${score}` : 'no CVSS yet', v?._kevExploited ? 'in CISA KEV' : 'not in KEV', v && getChartVendor(v) ? `vendor ${getChartVendor(v)}` : ''].filter(Boolean).join(', ');
    const input = document.getElementById('cmd-input');
    input.value = `Analyze ${t.dataset.askAi} (${facts}): what is affected, how likely is exploitation, and what should we do first? If it is web-exploitable, suggest a Cloudflare WAF mitigation.`;
    closeCveDetail();
    openAiDrawer();
    input.focus();
  } else if (t.dataset.copy) {
    navigator.clipboard?.writeText(t.dataset.copy).then(() => { t.textContent = '✓ COPIED'; }, () => { t.textContent = 'COPY FAILED'; });
  } else if (t.dataset.watch) {
    const w = t.dataset.watch;
    if (watchlist.includes(w)) watchlist = watchlist.filter(x => x !== w); else watchlist.push(w);
    persistProfile();
    addLog('SYNC', `${watchlist.includes(w) ? 'Watching' : 'Stopped watching'} "${w}"`);
    renderAll();
  } else if (t.dataset.suggestCve) {
    let kws = [];
    try { kws = JSON.parse(t.dataset.suggestKws || '[]'); } catch { /* ignore */ }
    closeCveDetail();
    suggestWafRuleFor(t.dataset.suggestCve, kws);
  }
}

// ── Mobile navigation ─────────────────────────────────
function toggleSidebar(force) {
  const sb = document.getElementById('sidebar');
  const open = typeof force === 'boolean' ? force : !sb.classList.contains('open');
  sb.classList.toggle('open', open);
  document.getElementById('sidebar-backdrop').classList.toggle('open', open);
  document.getElementById('menu-btn')?.setAttribute('aria-expanded', String(open));
}
function closeSidebar() { if (document.getElementById('sidebar')?.classList.contains('open')) toggleSidebar(false); }

// ── Shareable URL state (#range=30&sev=CRITICAL&…) ────
let _applyingHash = false;
function currentHashState() {
  const custom = currentRangeDays === -1;
  return {
    range: custom ? 'custom' : String(currentRangeDays),
    from: custom ? document.getElementById('date-start').value : undefined,
    to: custom ? document.getElementById('date-end').value : undefined,
    kw: custom ? _currentLoadKeyword : undefined,
    sev: currentFilter, src: currentSourceFilter, sort: currentSort, page: currentPage,
    new: newOnly, watch: watchOnly,
    view: typeof currentView !== 'undefined' ? currentView : 'priority',
    pt: prioTierFilter,
    cve: _openCveId || undefined,
  };
}
function syncHash() {
  if (_applyingHash) return;
  const hash = buildHashState(currentHashState());
  if (hash !== location.hash && !(hash === '' && location.hash === '')) {
    history.replaceState(null, '', location.pathname + location.search + hash);
  }
}

/** Apply a parsed hash state to the UI. Returns true when the date range changed. */
function applyHashState(s) {
  _applyingHash = true;
  const before = JSON.stringify([currentRangeDays, document.getElementById('date-start').value, document.getElementById('date-end').value, _currentLoadKeyword]);
  currentFilter = s.sev; setActiveIn('#severity-tabs', 'data-sev', s.sev);
  currentSourceFilter = s.src; setActiveIn('#source-tabs', 'data-src', s.src);
  currentSort = s.sort; const sel = document.getElementById('sort-select'); if (sel) sel.value = s.sort;
  currentPage = s.page;
  prioTierFilter = s.pt;
  toggleNewOnly(s.new); toggleWatchOnly(s.watch);
  document.querySelectorAll('.rtab').forEach(t => t.classList.remove('active'));
  if (s.range === 'custom') {
    currentRangeDays = -1;
    document.getElementById('rtab-custom').classList.add('active');
    document.getElementById('custom-dates').classList.add('visible');
    const today = _todayStr();
    document.getElementById('date-start').max = today;
    document.getElementById('date-end').max = today;
    document.getElementById('date-start').value = s.from;
    document.getElementById('date-end').value = s.to;
    document.getElementById('custom-keyword').value = s.kw || '';
    checkCustomRangeLength();
    _currentLoadKeyword = (new Date(s.to) - new Date(s.from)) / 86400000 > 90 ? (s.kw || '') : '';
  } else {
    currentRangeDays = Number(s.range);
    _currentLoadKeyword = '';
    document.getElementById('custom-dates').classList.remove('visible');
    document.querySelectorAll(`.rtab[data-range="${s.range}"]`).forEach(t => t.classList.add('active'));
  }
  const after = JSON.stringify([currentRangeDays, document.getElementById('date-start').value, document.getElementById('date-end').value, _currentLoadKeyword]);
  _applyingHash = false;
  return before !== after;
}

// ── Modals (stat cards, vendors, categories, search) ───
function modalItemHtml(v) {
  const score = getCvss(v);
  const sev = getSeverity(score);
  const desc = getDescription(v) || 'No description';
  const short = desc.length > 220 ? desc.substring(0, 220) + '…' : desc;
  const affected = getAffectedProducts(v);
  const id = escapeHtml(v.cve.id);
  return `
    <div class="modal-item" tabindex="0" role="button" data-cve-id="${id}" aria-label="Open details for ${id}">
      <div class="modal-item-header">
        <a href="${escapeHtml(getCveLink(v.cve.id))}" target="_blank" rel="noopener">${id}</a>
        <span class="severity-badge sev-${sev}">${sev}</span>
        <span class="modal-item-score" style="color:${SEV_COLOR[sev]}">${score > 0 ? score.toFixed(1) : '—'}</span>
        ${badgesHtml(v)}${epssHtml(v)}
        <span class="modal-item-date">${escapeHtml((v._kev?.dateAdded || v.cve.published || '').slice(0, 10))}</span>
      </div>
      <div class="modal-item-desc">${escapeHtml(short)}</div>
      ${affected.length ? `<div class="modal-item-affected">⚠ Affected: ${escapeHtml(affected.join(', '))}</div>` : ''}
    </div>`;
}

function openListModal(titleText, color, list, limit = 50) {
  const title = document.getElementById('modal-title');
  title.textContent = titleText;
  title.style.color = color;
  document.getElementById('export-csv-btn').style.display = 'none';
  document.getElementById('export-pdf-btn').style.display = 'none';
  document.getElementById('modal-body').innerHTML = list.length
    ? list.slice(0, limit).map(modalItemHtml).join('') + (list.length > limit ? `<div class="modal-empty">Showing ${limit} of ${list.length.toLocaleString()} — use the feed filters to see all.</div>` : '')
    : '<div class="modal-empty">NOTHING TO SHOW</div>';
  document.getElementById('modal-overlay').classList.add('active');
  queueEpssFor(list.slice(0, limit));
}

function openModal(type) {
  const active = getActiveCves();
  if (type === 'KEV') {
    const list = active.filter(v => v._kevExploited)
      .sort((a, b) => parseFeedDate(b._kev?.dateAdded) - parseFeedDate(a._kev?.dateAdded) || getCvss(b) - getCvss(a));
    const failed = sourceStats.kev && sourceStats.kev.ok === false;
    openListModal(`🔴 CISA KEV — ${list.length} actively exploited`, 'var(--critical)', list);
    if (failed) document.getElementById('modal-body').innerHTML = '<div class="modal-empty">The CISA KEV feed could not be loaded — see the activity log.</div>';
    return;
  }
  const list = sortCves(active.filter(v => getSeverity(getCvss(v)) === type), type === 'UNSCORED' ? 'date' : 'cvss');
  const label = type === 'UNSCORED' ? 'Unscored CVEs (no CVSS yet)' : `${type} severity CVEs`;
  openListModal(`⚡ ${label} — ${list.length.toLocaleString()}`, SEV_COLOR[type] || 'var(--amber)', list);
}

function closeModal() {
  document.getElementById('modal-overlay').classList.remove('active');
  document.getElementById('export-csv-btn').style.display = 'none';
  document.getElementById('export-pdf-btn').style.display = 'none';
}

// Escape closes the detail panel first, then a modal, then the mobile menu.
document.addEventListener('keydown', e => {
  if (e.key !== 'Escape') return;
  if (closeCveDetail()) return;
  if (document.getElementById('modal-overlay').classList.contains('active')) { closeModal(); return; }
  closeSidebar();
});

// ── Exports ─────────────────────────────────────────────
const CSV_HEADER = ['CVE ID', 'Severity', 'CVSS Score', 'EPSS', 'Published', 'Source', 'KEV Exploited', 'KEV Date Added', 'Affected Products', 'Description'];
function csvRow(v) {
  const score = getCvss(v);
  const e = epssCache.get(v.cve.id);
  return [
    v.cve.id || '', getSeverity(score), score > 0 ? score.toFixed(1) : '', e ? e.epss.toFixed(4) : '',
    (v.cve.published || '').substring(0, 10), getSourceLabel(v).toUpperCase(), v._kevExploited ? 'YES' : 'NO',
    v._kev?.dateAdded || '', getAffectedProducts(v).join('; '), getDescription(v).replace(/\r?\n/g, ' '),
  ];
}
function downloadCsv(rows, filename) {
  const blob = new Blob(['﻿' + toCsv(rows)], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function exportPanelCSV() {
  const cvs = getFilteredCves();
  if (!cvs.length) { addLog('ALERT', 'No CVEs to export'); return; }
  const parts = [currentSourceFilter !== 'ALL' ? currentSourceFilter.toUpperCase() : '', currentFilter !== 'ALL' ? currentFilter : '',
    newOnly ? 'NEW' : '', watchOnly ? 'WATCH' : '', companyModeActive ? 'COMPANY' : ''].filter(Boolean);
  const range = getSelectedRange().label.replace(/[^a-z0-9]+/gi, '_');
  downloadCsv([CSV_HEADER, ...cvs.map(csvRow)], `threatwatch-${cvs.length}_rows${parts.length ? '_' + parts.join('_') : ''}-${range}-${_todayStr()}.csv`);
}

function printReport(titleText, sections) {
  let html = `<h1>${escapeHtml(titleText)}</h1>`;
  html += `<div class="pr-meta">${escapeHtml(new Date().toISOString().replace('T', ' ').substring(0, 19))} UTC · ${escapeHtml(getSelectedRange().label)}</div>`;
  sections.forEach(({ heading, items }) => {
    if (!items.length) return;
    html += `<div class="pr-section">${escapeHtml(heading)} (${items.length.toLocaleString()})</div>`;
    items.forEach(v => {
      const score = getCvss(v);
      const affected = getAffectedProducts(v);
      html += `<div class="pr-item">
        <div class="pr-id">${escapeHtml(v.cve.id)} &nbsp; ${getSeverity(score)}${score > 0 ? ` — CVSS ${score.toFixed(1)}` : ''}${v._kevExploited ? ' · ⚡ KEV EXPLOITED' : ''}${epssCache.get(v.cve.id) ? ' · EPSS ' + fmtEpss(epssCache.get(v.cve.id).epss) : ''}</div>
        <div class="pr-sub">${escapeHtml((v.cve.published || '').substring(0, 10))} · ${escapeHtml(getSourceLabel(v).toUpperCase())}${affected.length ? ' · ' + escapeHtml(affected.join(', ')) : ''}</div>
        <div class="pr-desc">${escapeHtml(getDescription(v) || 'No description')}</div>
      </div>`;
    });
  });
  const printArea = document.getElementById('print-area');
  printArea.innerHTML = html;
  printArea.style.display = 'block';
  window.addEventListener('afterprint', () => { printArea.style.display = 'none'; printArea.innerHTML = ''; }, { once: true });
  window.print();
}

function exportPanelPDF() {
  const cvs = getFilteredCves();
  if (!cvs.length) { addLog('ALERT', 'No CVEs to export'); return; }
  printReport('ThreatWatch — Vulnerability Report', [{ heading: 'CVEs', items: cvs }]);
}

let _lastSearchResults = null; // { query, results }
function exportSearchCSV() {
  if (!_lastSearchResults) return;
  const { query, results } = _lastSearchResults;
  downloadCsv([CSV_HEADER, ...results.map(csvRow)], `threatwatch-${query.replace(/[^a-z0-9]/gi, '_')}-${_todayStr()}.csv`);
}
function exportSearchPDF() {
  if (!_lastSearchResults) return;
  const { query, results } = _lastSearchResults;
  printReport(`ThreatWatch — Search: "${query}"`, [{ heading: 'Results', items: results }]);
}

// ── Search ──────────────────────────────────────────────
async function runSearch() {
  const query = document.getElementById('search-input').value.trim();
  if (!query) return;
  const q = query.toLowerCase();
  const title = document.getElementById('modal-title');
  const body = document.getElementById('modal-body');
  title.textContent = `🔍 Search: "${query}"`;
  title.style.color = 'var(--amber)';
  document.getElementById('export-csv-btn').style.display = 'none';
  document.getElementById('export-pdf-btn').style.display = 'none';
  body.innerHTML = '<div class="modal-empty" style="color:var(--amber)">SEARCHING LOCAL DATA + NVD API…</div>';
  document.getElementById('modal-overlay').classList.add('active');

  // 1) Local data (includes KEV entries, which carry vendor/product in their CPE)
  const local = allCves.filter(v =>
    (v.cve.id || '').toLowerCase().includes(q) || getDescription(v).toLowerCase().includes(q)
    || getVendor(v).toLowerCase().includes(q) || getAffectedProducts(v, 0).join(' ').toLowerCase().includes(q));
  const byId = new Map(local.map(v => [v.cve.id, v]));
  const isPanSA = /^PAN-SA-/i.test(query);
  const isCveId = /^CVE-\d{4}-\d+$/i.test(query);

  // 2) Live NVD search (all time unless a custom range is active)
  if (!isPanSA) {
    addLog('SYNC', `Querying NVD API for "${query}"...`);
    try {
      let apiUrl;
      if (isCveId) {
        apiUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(query.toUpperCase())}`;
      } else {
        const from = currentRangeDays === -1 && document.getElementById('date-start').value ? new Date(document.getElementById('date-start').value) : null;
        apiUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(query)}&resultsPerPage=2000${from ? `&pubStartDate=${from.toISOString().split('.')[0]}.000&pubEndDate=${new Date().toISOString().split('.')[0]}.000` : ''}`;
      }
      const resp = await fetch(apiUrl);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      let fresh = 0;
      (data.vulnerabilities || []).forEach(apiV => {
        const cur = byId.get(apiV.cve.id) || allCves.find(v => v.cve.id === apiV.cve.id);
        if (cur) {
          if (getCvss(cur) === 0 && getCvss(apiV) > 0) cur.cve.metrics = apiV.cve.metrics;
          if (!byId.has(cur.cve.id)) byId.set(cur.cve.id, cur);
        } else {
          const entry = { ...apiV, _source: 'nvd' };
          byId.set(entry.cve.id, entry);
          _extraCves.set(entry.cve.id, entry);
          fresh++;
        }
      });
      addLog('SYNC', `NVD API returned ${(data.vulnerabilities || []).length} results (${fresh} not in the loaded range)`);
    } catch (e) {
      addLog('ALERT', `Live NVD search failed: ${e.message}`);
    }
  }

  // 3) Palo Alto PSIRT for PAN-SA IDs or Palo Alto queries
  if (isPanSA || q.includes('palo alto') || q.includes('paloalto') || q.includes('pan-os')) {
    try {
      const paResp = await fetchViaProxy('https://security.paloaltonetworks.com/json');
      if (paResp.ok) {
        const advisories = await paResp.json();
        (Array.isArray(advisories) ? advisories : []).filter(a => {
          const id = (a.ID || '').toUpperCase();
          return id && !byId.has(id) && (id.includes(query.toUpperCase()) || (a.title || '').toLowerCase().includes(q));
        }).forEach(a => {
          const entry = {
            _source: 'paloalto',
            cve: {
              id: a.ID.toUpperCase(), published: a.date || a.updated || '',
              descriptions: [{ lang: 'en', value: a.title || 'No description' }],
              metrics: a.baseScore ? { cvssMetricV31: [{ cvssData: { baseScore: parseFloat(a.baseScore) || 0 } }] } : {},
              configurations: (Array.isArray(a.product) ? a.product : []).map(p => ({ nodes: [{ cpeMatch: [{ criteria: `cpe:2.3:a:paloaltonetworks:${String(p).toLowerCase().replace(/[^a-z0-9]/g, '_')}:*:*:*` }] }] })),
            },
          };
          byId.set(entry.cve.id, entry);
          _extraCves.set(entry.cve.id, entry);
        });
      }
    } catch (e) {
      addLog('ALERT', `Palo Alto PSIRT search failed: ${e.message}`);
    }
  }

  // 4) Fill in missing CVSS for up to 10 results
  const results = sortCves([...byId.values()], 'cvss');
  const needsScore = results.filter(v => getCvss(v) === 0 && /^CVE-/i.test(v.cve.id)).slice(0, 10);
  if (needsScore.length) {
    await Promise.all(needsScore.map(v =>
      fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(v.cve.id)}`)
        .then(r => r.ok ? r.json() : null)
        .then(d => { const f = d?.vulnerabilities?.[0]; if (f && getCvss(f) > 0) v.cve.metrics = f.cve.metrics; })
        .catch(() => { })));
  }
  const sorted = sortCves(results, 'cvss');
  const kevCount = sorted.filter(v => v._kevExploited).length;
  body.innerHTML = sorted.length
    ? `<div class="modal-subhead">${sorted.length.toLocaleString()} matches${kevCount ? ` · ${kevCount} actively exploited (KEV)` : ''} — sorted by severity</div>`
      + sorted.slice(0, 60).map(modalItemHtml).join('')
      + (sorted.length > 60 ? `<div class="modal-empty">Showing 60 of ${sorted.length.toLocaleString()} — export CSV for all.</div>` : '')
    : '<div class="modal-empty">NO RESULTS FOUND</div>';
  queueEpssFor(sorted.slice(0, 60));
  addLog('SYNC', `Search complete: "${query}" — ${sorted.length} results, ${kevCount} KEV`);
  _lastSearchResults = { query, results: sorted };
  document.getElementById('export-csv-btn').style.display = 'inline-flex';
  document.getElementById('export-pdf-btn').style.display = 'inline-flex';
}

// ── Company profile + watchlist ───────────────────────
const COMMON_VENDORS = [
  'microsoft', 'cisco', 'apache', 'linux', 'google', 'apple', 'oracle',
  'adobe', 'fortinet', 'palo alto', 'vmware', 'nginx', 'openssl', 'wordpress',
  'jenkins', 'docker', 'kubernetes', 'python', 'php', 'node', 'java', 'log4j',
  'atlassian', 'citrix', 'sap', 'ibm', 'juniper', 'f5', 'gitlab', 'confluence'
];

// In-modal working copies (committed on save)
let _modalTechStack = [];
let _modalWatchlist = [];

function loadCompanyProfile() {
  const p = lsGetJson('tw_company_profile', null);
  if (p) {
    companyName = p.companyName || '';
    companyTechStack = Array.isArray(p.companyTechStack) ? p.companyTechStack : [];
    companyModeActive = !!p.companyModeActive;
    watchlist = Array.isArray(p.watchlist) ? p.watchlist : [];
    notifyEnabled = !!p.notifyEnabled;
  }
  const cw = lsGetJson('tw_core_watch', null);
  if (cw) coreWatch = { disabled: Array.isArray(cw.disabled) ? cw.disabled : [], extra: Array.isArray(cw.extra) ? cw.extra : [] };
  updateCompanyModeUI();
}

function persistProfile() {
  lsSet('tw_company_profile', JSON.stringify({ companyName, companyTechStack, companyModeActive, watchlist, notifyEnabled }));
}

async function saveCompanyProfile() {
  companyName = (document.getElementById('company-name-input').value || '').trim();
  companyTechStack = [..._modalTechStack];
  watchlist = [..._modalWatchlist];
  companyModeActive = document.getElementById('company-mode-toggle').checked;
  const wantNotify = document.getElementById('notify-toggle').checked;
  if (wantNotify && 'Notification' in window && Notification.permission === 'default') {
    try { await Notification.requestPermission(); } catch { /* ignore */ }
  }
  notifyEnabled = wantNotify && 'Notification' in window && Notification.permission === 'granted';
  coreWatch = {
    disabled: CORE_SOFTWARE.map(d => d.key).filter(k => !document.querySelector(`#core-grid input[value="${k}"]`)?.checked),
    extra: [..._modalCoreExtra],
  };
  lsSet('tw_core_watch', JSON.stringify(coreWatch));
  _coreVer++;
  if (wantNotify && !notifyEnabled) addLog('ALERT', 'Browser notifications are blocked for this site — alerts will appear in this log only');
  persistProfile();
  closeCompanyModal();
  updateCompanyModeUI();
  currentPage = 1;
  renderAll();
  addLog('SYNC', `Profile saved: "${companyName || 'unnamed'}" — ${companyTechStack.length} tech(s), ${watchlist.length} watched, company mode ${companyModeActive ? 'ON' : 'OFF'}`);
}

function openCompanyModal() {
  _modalTechStack = [...companyTechStack];
  _modalWatchlist = [...watchlist];
  document.getElementById('company-name-input').value = companyName;
  document.getElementById('company-mode-toggle').checked = companyModeActive;
  const nt = document.getElementById('notify-toggle');
  nt.checked = notifyEnabled;
  nt.disabled = !('Notification' in window);
  renderTechTags();
  renderWatchTags();
  _modalCoreExtra = [...coreWatch.extra];
  document.getElementById('core-grid').innerHTML = CORE_SOFTWARE.map(d => `
    <label class="core-check"><input type="checkbox" value="${d.key}" ${coreWatch.disabled.includes(d.key) ? '' : 'checked'}> ${escapeHtml(d.label)}</label>`).join('');
  renderCoreTags();
  document.getElementById('company-suggestions').innerHTML = COMMON_VENDORS.map(v =>
    `<button class="suggest-tag" data-suggest="${escapeHtml(v)}">${escapeHtml(v)}</button>`).join('');
  document.getElementById('company-modal-overlay').classList.add('active');
}

function closeCompanyModal() {
  document.getElementById('company-modal-overlay').classList.remove('active');
}

function renderTagList(elId, list, removeFn, emptyText) {
  const el = document.getElementById(elId);
  if (!el) return;
  el.innerHTML = list.length
    ? list.map((tag, i) => `<span class="tech-tag">${escapeHtml(tag)}<button class="remove-tag" onclick="${removeFn}(${i})" title="Remove" aria-label="Remove ${escapeHtml(tag)}">✕</button></span>`).join('')
    : `<span class="tag-empty">${emptyText}</span>`;
}
function renderTechTags() { renderTagList('company-tags', _modalTechStack, 'removeTechTag', 'No technologies added yet'); }
function renderWatchTags() { renderTagList('watch-tags', _modalWatchlist, 'removeWatchTag', 'Nothing watched yet'); }

function addTagFromInput(inputId, list, render, event) {
  if (event) event.preventDefault();
  const input = document.getElementById(inputId);
  input.value.split(',').map(s => s.trim().toLowerCase()).filter(Boolean).forEach(raw => {
    if (!list.includes(raw)) list.push(raw);
  });
  render();
  input.value = '';
  input.focus();
}
function addTechTag(event) { addTagFromInput('company-tag-input', _modalTechStack, renderTechTags, event); }
function addWatchTag(event) { addTagFromInput('watch-tag-input', _modalWatchlist, renderWatchTags, event); }
let _modalCoreExtra = [];
function renderCoreTags() { renderTagList('core-tags', _modalCoreExtra, 'removeCoreTag', 'No extra core software'); }
function addCoreTag(event) { addTagFromInput('core-tag-input', _modalCoreExtra, renderCoreTags, event); }
function removeCoreTag(index) { _modalCoreExtra.splice(index, 1); renderCoreTags(); }
function addSuggestTag(vendor) { if (!_modalTechStack.includes(vendor)) { _modalTechStack.push(vendor); renderTechTags(); } }
function removeTechTag(index) { _modalTechStack.splice(index, 1); renderTechTags(); }
function removeWatchTag(index) { _modalWatchlist.splice(index, 1); renderWatchTags(); }

function matchesCompanyStack(vuln) {
  if (!companyTechStack.length) return true;
  return matchesAnyKeyword(vuln, companyTechStack);
}

function updateCompanyModeUI() {
  const header = document.querySelector('header');
  const badge = document.getElementById('company-mode-badge');
  const banner = document.getElementById('profile-active-banner');
  if (companyName) {
    document.getElementById('pab-name').textContent = companyName.toUpperCase();
    const parts = [];
    if (companyTechStack.length) parts.push(companyTechStack.length + ' TECH' + (companyTechStack.length !== 1 ? 'S' : ''));
    if (companyModeActive) parts.push('FILTERED');
    document.getElementById('pab-meta').textContent = parts.join(' · ');
    banner.style.display = 'flex';
  } else {
    banner.style.display = 'none';
  }
  header.classList.toggle('company-mode-active', companyModeActive);
  badge.style.display = companyModeActive ? '' : 'none';
}

// ── Inventory file import (company profile) ───────────
const INV_VENDOR_COLS = ['vendor','manufacturer','brand','make','publisher','developer','company','provider','supplier','mfr','mfg'];
const INV_PRODUCT_COLS = ['software','application','product','app','program','title','model','solution','tool','package'];
const INV_SKIP = new Set(['n/a','na','none','unknown','other','yes','no','true','false','null','undefined','','-','any']);
function invDragOver(e){e.preventDefault();document.getElementById('inv-drop-zone').classList.add('inv-dragover');}
function invDragLeave(){document.getElementById('inv-drop-zone').classList.remove('inv-dragover');}
function invDrop(e){e.preventDefault();document.getElementById('inv-drop-zone').classList.remove('inv-dragover');var f=e.dataTransfer&&e.dataTransfer.files&&e.dataTransfer.files[0];if(f)parseInventoryFile(f);}
function parseInventoryFile(file){if(!file)return;var ext=file.name.split('.').pop().toLowerCase();showInvResult('','Parsing '+file.name+'...');var reader=new FileReader();reader.onload=function(ev){try{var rows=[];if(ext==='csv'){rows=invCsvToRows(ev.target.result);}else if(ext==='xls'||ext==='xlsx'){if(typeof XLSX==='undefined'){showInvResult('err','XLS parser not loaded. Try again or use CSV.');return;}var wb=XLSX.read(ev.target.result,{type:'binary'});var ws=wb.Sheets[wb.SheetNames[0]];rows=XLSX.utils.sheet_to_json(ws,{defval:''});}else{showInvResult('err','Unsupported format. Use .csv, .xls or .xlsx');return;}processInventoryRows(rows);}catch(err){showInvResult('err','Parse error: '+err.message);}};if(ext==='csv')reader.readAsText(file);else reader.readAsBinaryString(file);}
function invCsvToRows(text){var lines=text.replace(/\r\n/g,'\n').replace(/\r/g,'\n').trim().split('\n');if(lines.length<2)return[];function splitLine(line){var out=[],cur='',inQ=false;for(var i=0;i<line.length;i++){var c=line[i];if(c==='"'){inQ=!inQ;}else if(c===','&&!inQ){out.push(cur.trim());cur='';}else cur+=c;}out.push(cur.trim());return out;}var headers=splitLine(lines[0]).map(function(h){return h.replace(/^"|"$/g,'').trim();});return lines.slice(1).map(function(line){var vals=splitLine(line),row={};headers.forEach(function(h,i){row[h]=(vals[i]||'').replace(/^"|"$/g,'').trim();});return row;}).filter(function(row){return Object.values(row).some(function(v){return v;});});}
function processInventoryRows(rows){if(!rows.length){showInvResult('err','File is empty or unreadable');return;}var allKeys=Object.keys(rows[0]);var scored=allKeys.map(function(k){var lk=k.toLowerCase();var vs=INV_VENDOR_COLS.some(function(c){return lk.includes(c);})?2:0;var ps=INV_PRODUCT_COLS.some(function(c){return lk.includes(c);})?1:0;return{key:k,score:vs+ps,isVendor:vs>0};}).filter(function(c){return c.score>0;}).sort(function(a,b){return b.score-a.score;});var usedCols=scored;if(!usedCols.length){usedCols=allKeys.filter(function(k){var samples=rows.slice(0,10).map(function(r){return String(r[k]||'').trim();}).filter(Boolean);return samples.length>0&&samples.every(function(s){return isNaN(s)&&s.length>=2&&s.length<=40;});}).slice(0,4).map(function(k){return{key:k,isVendor:false};});}if(!usedCols.length){showInvResult('warn','No vendor/brand columns detected. Rename columns to: vendor, manufacturer, software, product');return;}var keywords=new Set();rows.forEach(function(row){usedCols.forEach(function(col){var raw=String(row[col.key]||'').trim().toLowerCase();if(!raw||INV_SKIP.has(raw)||raw.length<2)return;raw.split(/[,;|\/]+/).forEach(function(part){part=part.trim().replace(/[^a-z0-9 .\-_]/g,'').trim();if(!part||part.length<2)return;var fw=part.split(/\s+/)[0].trim();var ml=col.isVendor?2:3;if(fw.length>=ml&&!INV_SKIP.has(fw))keywords.add(fw);});});});var newKws=Array.from(keywords).filter(function(k){return!_modalTechStack.includes(k);}).sort();var dup=keywords.size-newKws.length;if(!newKws.length&&!keywords.size){showInvResult('warn','No keywords extracted. Ensure file has text in labeled columns.');return;}newKws.forEach(function(k){_modalTechStack.push(k);});renderTechTags();var cols=usedCols.map(function(c){return c.key;}).join(', ');var dupNote=dup?' ('+dup+' already in stack)':'';showInvResult('ok',newKws.length+' keyword'+(newKws.length!==1?'s':'')+' imported from '+rows.length+' rows'+dupNote+'|Columns: '+cols,newKws.slice(0,20),newKws.length>20);}
function showInvResult(type, msg, previewTags, hasMore) {
  const el = document.getElementById('inv-result');
  if (!el) return;
  el.className = 'inv-result' + (type ? ' ' + type : '');
  el.style.display = 'block';
  if (!type) { el.textContent = msg; return; }
  el.innerHTML = msg.split('|').map(l => '<div>' + escapeHtml(l) + '</div>').join('')
    + (previewTags && previewTags.length
      ? '<div class="inv-preview">' + previewTags.map(t => '<span class="inv-preview-tag">' + escapeHtml(t) + '</span>').join('')
        + (hasMore ? '<span class="inv-preview-tag" style="color:var(--muted)">+more</span>' : '') + '</div>'
      : '');
}
