// options.js — DLP Guard advanced settings page.
// Reads/writes chrome.storage.local. No network. Custom regexes are the user's
// own config; they run in the content-script isolated world, never in pages.
'use strict';

const $ = (id) => document.getElementById(id);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const CAT_DEFAULTS = { token: true, assignment: true, privatekey: true, custom: true, user: true, pii: false, infra: false, generic: false };

const DEFAULTS = {
  dlp_enabled: true,
  dlp_maskOnPage: true,
  dlp_redactPaste: true,
  dlp_revealOnClick: true,
  dlp_exfilShield: true,
  dlp_exfilThreshold: 10,
  dlp_guardPasswordField: true,
  dlp_guardAuthUrl: true,
  dlp_redactInPasswordFields: false,
  dlp_skipCloudEditors: true,
  dlp_fileScanEnabled: true,
  dlp_fileMaxSizeKB: 1024,
  dlp_fileExtensions: (typeof DlpEngine !== 'undefined' && DlpEngine.FILE_EXTENSIONS_DEFAULT) ? [...DlpEngine.FILE_EXTENSIONS_DEFAULT] : [],
  dlp_cats: { ...CAT_DEFAULTS },
  dlp_customTerms: [],
  dlp_userPatterns: [],
  dlp_builtinOverrides: [],
  dlp_disabledSites: [],
};

// Config keys that Export/Import round-trips (not counters or the audit log).
const CONFIG_KEYS = Object.keys(DEFAULTS);

function banner(msg) {
  const b = $('savedBanner');
  b.textContent = msg || 'Saved.';
  b.style.display = 'block';
  clearTimeout(banner._t);
  banner._t = setTimeout(() => { b.style.display = 'none'; }, 1400);
}

// ── Tabs ──────────────────────────────────────────────────────────────────────
$('tabs').addEventListener('click', (e) => {
  const btn = e.target.closest('button[data-tab]');
  if (!btn) return;
  $$('#tabs button').forEach((b) => b.classList.toggle('active', b === btn));
  $$('.tab').forEach((t) => t.classList.toggle('active', t.id === `tab-${btn.dataset.tab}`));
});

// ── Load everything ───────────────────────────────────────────────────────────
function loadAll() {
  chrome.storage.local.get(DEFAULTS, (items) => {
    $$('[data-setting]').forEach((el) => {
      const key = el.dataset.setting;
      if (el.type === 'checkbox') el.checked = items[key] !== false;
      else el.value = items[key];
    });
    currentCats = { ...CAT_DEFAULTS, ...(items.dlp_cats || {}) };
    $$('[data-cat]').forEach((el) => { el.checked = Boolean(currentCats[el.dataset.cat]); });
    if (document.activeElement !== $('termsArea')) {
      $('termsArea').value = (items.dlp_customTerms || []).join('\n');
    }
    if (document.activeElement !== $('fileExts')) {
      $('fileExts').value = (items.dlp_fileExtensions || []).join(' ');
    }
    renderSites(items.dlp_disabledSites || []);
    builtinOverrides = Array.isArray(items.dlp_builtinOverrides) ? items.dlp_builtinOverrides : [];
    userPatterns = Array.isArray(items.dlp_userPatterns) ? items.dlp_userPatterns : [];
    renderAllPatterns();
    renderCustomCats();
  });
  loadStats();
  renderCategoryCounts();
}

function renderCategoryCounts() {
  const all = [...(typeof DLP_PATTERNS !== 'undefined' ? DLP_PATTERNS : []),
    ...(typeof DLP_EXTRA_PATTERNS !== 'undefined' ? DLP_EXTRA_PATTERNS : [])];
  const counts = {};
  for (const p of all) counts[p.category] = (counts[p.category] || 0) + 1;
  for (const c of ['token', 'assignment', 'privatekey', 'pii', 'infra', 'generic']) {
    const el = $(`cnt-${c}`);
    if (el) el.textContent = `${counts[c] || 0}`;
  }
}

// ── General settings persist on change ────────────────────────────────────────
$$('[data-setting]').forEach((el) => {
  el.addEventListener('change', () => {
    const key = el.dataset.setting;
    let val;
    if (el.type === 'checkbox') val = el.checked;
    else if (el.type === 'number') val = Math.max(1, Math.min(1000, Number(el.value) || 10));
    else val = el.value;
    if (el.type === 'number') el.value = val;
    chrome.storage.local.set({ [key]: val }, () => banner());
  });
});

$$('[data-cat]').forEach((el) => {
  el.addEventListener('change', () => {
    // merge onto existing cats so custom-category flags aren't wiped
    const cats = { ...currentCats };
    $$('[data-cat]').forEach((c) => { cats[c.dataset.cat] = c.checked; });
    cats.custom = true; cats.user = true; // always honored; managed per-item
    currentCats = cats;
    chrome.storage.local.set({ dlp_cats: cats }, () => banner());
  });
});

// ── Pattern engine: built-in library + user patterns, unified ─────────────────
const ALL_BUILTINS = (typeof DlpEngine !== 'undefined' && DlpEngine.builtins) ? DlpEngine.builtins() : [];
const BUILTIN_CATS = ['token', 'assignment', 'privatekey', 'pii', 'infra', 'generic'];
let builtinOverrides = [];   // [{id, disabled?, source?, flags?}]
let userPatterns = [];       // [{id,label,category,source,flags,valueGroup,mask,enabled}]
let currentCats = { ...CAT_DEFAULTS };
let editMode = null;         // null | {type:'custom', id} | {type:'builtin', id}

function ovFor(id) { return builtinOverrides.find((o) => o.id === id); }

// A single catastrophic regex can't be interrupted once exec() starts, so the
// guard is STATIC first (reject dangerous structure before running anything),
// then a short bounded timing probe as a secondary net.
function redosLint(source) {
  if (/\([^)]*[+*][^)]*\)\s*[+*]/.test(source)) return 'a group containing + or * is itself repeated (nested quantifier, classic ReDoS)';
  if (/\([^)]*[+*][^)]*\)\s*\{\d*,\d*\}/.test(source) || /\([^)]*[+*][^)]*\)\s*\{\d+,\}/.test(source)) return 'a group containing + or * is repeated with a {..,} count (nested quantifier)';
  const braceWrap = source.match(/\([^)]*[.][*+][^)]*\)\{(\d+),?\d*\}/);
  if (braceWrap && Number(braceWrap[1]) >= 8) return 'a wildcard group repeated many times risks polynomial blowup';
  return null;
}

function compileTest(source, flags) {
  let re;
  try { re = new RegExp(source, flags.includes('g') ? flags : flags + 'g'); }
  catch (e) { return { ok: false, msg: `Invalid regex: ${e.message}` }; }
  if (re.test('')) return { ok: false, msg: 'Rejected: matches empty string (would loop over any text).' };
  const lint = redosLint(source);
  if (lint) return { ok: false, msg: `Rejected: ${lint}. Rewrite to avoid catastrophic backtracking.` };
  const runs = ['a', 'A', '0', 'a1', 'aA', 'a-', '=', '/', ' a'];
  const t0 = performance.now();
  for (const c of runs) {
    for (const probe of [c.repeat(22) + '!# ', 'x ' + c.repeat(18) + ' y']) {
      try { re.lastIndex = 0; let n = 0; while (re.exec(probe) && ++n < 3000) {} } catch (_e) { /* ignore */ }
    }
    if (performance.now() - t0 > 50) {
      return { ok: false, msg: 'Rejected: too slow (possible catastrophic backtracking).' };
    }
  }
  return { ok: true, re };
}

// Distinct categories currently in play: built-ins + any the user invented.
function allCategories() {
  const set = new Set(BUILTIN_CATS);
  for (const p of userPatterns) if (p.category) set.add(String(p.category).trim());
  return [...set];
}

// One flat, filterable list of rows describing every pattern (built-in + custom).
function patternRows() {
  const rows = [];
  for (const p of ALL_BUILTINS) {
    const ov = ovFor(p.id);
    rows.push({
      type: 'builtin', id: p.id, label: p.label, category: p.category,
      source: ov && ov.source ? ov.source : p.source,
      flags: ov && ov.flags ? ov.flags : p.flags,
      valueGroup: p.valueGroup, mask: '(by category)',
      enabled: !(ov && ov.disabled),
      changed: Boolean(ov && (ov.source || ov.disabled)),
      hasValidator: p.hasValidator, orig: p,
    });
  }
  for (const p of userPatterns) {
    rows.push({
      type: 'custom', id: p.id, label: p.label, category: (p.category && String(p.category).trim()) || 'user',
      source: p.source, flags: p.flags, valueGroup: p.valueGroup || 0,
      mask: p.mask === 'affix' ? 'prefix/suffix' : 'stars',
      enabled: p.enabled !== false, changed: false, custom: p,
    });
  }
  return rows;
}

function renderAllPatterns() {
  // filter select options
  const fc = $('pxFilterCat');
  const prev = fc.value;
  fc.innerHTML = '<option value="">All categories</option>' +
    allCategories().sort().map((c) => `<option value="${c}">${c}</option>`).join('');
  fc.value = prev;
  // datalist for the category input
  $('pxCatList').innerHTML = allCategories().sort().map((c) => `<option value="${c}">`).join('');

  const q = ($('pxSearch').value || '').toLowerCase();
  const cat = $('pxFilterCat').value;
  const typeF = $('pxFilterType').value;
  const tbody = $('pxTable').querySelector('tbody');
  tbody.innerHTML = '';
  const CAP = 300;
  let matched = 0, shown = 0;
  for (const r of patternRows()) {
    if (cat && r.category !== cat) continue;
    if (typeF === 'custom' && r.type !== 'custom') continue;
    if (typeF === 'builtin' && r.type !== 'builtin') continue;
    if (typeF === 'changed' && !r.changed && r.type !== 'custom') continue;
    if (q && !(r.label.toLowerCase().includes(q) || r.source.toLowerCase().includes(q) || r.category.toLowerCase().includes(q))) continue;
    matched++;
    if (shown >= CAP) continue;
    shown++;

    const tr = document.createElement('tr');
    const tdOn = document.createElement('td');
    const cb = document.createElement('input');
    cb.type = 'checkbox'; cb.checked = r.enabled;
    cb.addEventListener('change', () => {
      if (r.type === 'builtin') setOverride(r.id, { disabled: !cb.checked });
      else toggleCustom(r.id, cb.checked);
    });
    tdOn.appendChild(cb);

    const tdLabel = document.createElement('td');
    tdLabel.textContent = r.label;
    if (r.changed) { const b = document.createElement('span'); b.className = 'pill'; b.textContent = 'changed'; b.style.marginLeft = '6px'; tdLabel.appendChild(b); }

    const tdCat = document.createElement('td'); tdCat.textContent = r.category;
    const tdSrc = document.createElement('td'); tdSrc.className = 'mono';
    tdSrc.textContent = `/${r.source}/${r.flags}` + (r.valueGroup ? ` (g${r.valueGroup})` : '');
    const tdType = document.createElement('td');
    tdType.innerHTML = r.type === 'custom' ? '<span class="pill">custom</span>' : 'built-in';

    const tdA = document.createElement('td');
    const edit = document.createElement('button');
    edit.className = 'btn secondary small'; edit.textContent = 'Edit';
    edit.addEventListener('click', () => openEditor(r));
    tdA.appendChild(edit);
    if (r.type === 'custom') {
      const del = document.createElement('button');
      del.className = 'btn small'; del.textContent = 'Delete'; del.style.marginLeft = '6px';
      del.addEventListener('click', () => deleteCustom(r.id));
      tdA.appendChild(del);
    } else if (r.changed) {
      const reset = document.createElement('button');
      reset.className = 'btn small'; reset.textContent = 'Reset'; reset.style.marginLeft = '6px';
      reset.addEventListener('click', () => clearOverride(r.id));
      tdA.appendChild(reset);
    }

    tr.append(tdOn, tdLabel, tdCat, tdSrc, tdType, tdA);
    tbody.appendChild(tr);
  }
  $('pxCount').textContent = `${matched} pattern${matched === 1 ? '' : 's'}` +
    (matched > CAP ? ` — showing first ${CAP}, narrow the search` : '') +
    ` · ${userPatterns.length} custom · ${builtinOverrides.length} override${builtinOverrides.length === 1 ? '' : 's'}`;
}

// ── Built-in overrides ────────────────────────────────────────────────────────
function setOverride(id, patch) {
  let ov = ovFor(id);
  if (!ov) { ov = { id }; builtinOverrides.push(ov); }
  Object.assign(ov, patch);
  if (!ov.disabled && !ov.source && !ov.flags) builtinOverrides = builtinOverrides.filter((o) => o.id !== id);
  chrome.storage.local.set({ dlp_builtinOverrides: builtinOverrides }, () => { renderAllPatterns(); banner(); });
}
function clearOverride(id) {
  builtinOverrides = builtinOverrides.filter((o) => o.id !== id);
  chrome.storage.local.set({ dlp_builtinOverrides: builtinOverrides }, () => {
    if (editMode && editMode.type === 'builtin' && editMode.id === id) resetForm();
    renderAllPatterns(); banner('Override removed.');
  });
}

// ── Custom user patterns ──────────────────────────────────────────────────────
function toggleCustom(id, enabled) {
  userPatterns = userPatterns.map((p) => (p.id === id ? { ...p, enabled } : p));
  chrome.storage.local.set({ dlp_userPatterns: userPatterns }, () => banner());
}
function deleteCustom(id) {
  userPatterns = userPatterns.filter((p) => p.id !== id);
  chrome.storage.local.set({ dlp_userPatterns: userPatterns }, () => {
    if (editMode && editMode.type === 'custom' && editMode.id === id) resetForm();
    renderAllPatterns(); renderCustomCats(); banner('Pattern deleted.');
  });
}

// ── The unified editor form ───────────────────────────────────────────────────
function setFormEnabled(builtin) {
  // built-ins: only source/flags editable (they become an override); label,
  // category, mask, value-group are fixed by the shipped pattern.
  for (const id of ['pxLabel', 'pxCategory', 'pxMask', 'pxGroup']) $(id).disabled = builtin;
}

function openEditor(r) {
  editMode = { type: r.type, id: r.id };
  $('pxFormTitle').textContent = r.type === 'builtin' ? `Edit built-in: ${r.label}` : `Edit pattern: ${r.label}`;
  $('pxLabel').value = r.label;
  $('pxCategory').value = r.category;
  $('pxSource').value = r.source;
  $('pxFlags').value = r.flags;
  $('pxGroup').value = String(r.valueGroup || 0);
  $('pxMask').value = (r.custom && r.custom.mask === 'affix') ? 'affix' : 'stars';
  $('pxTest').value = '';
  $('pxStatus').className = 'status';
  $('pxStatus').textContent = (r.type === 'builtin' && r.hasValidator) ? 'Note: this pattern also has a built-in validator that still applies.' : '';
  setFormEnabled(r.type === 'builtin');
  $('pxSaveBtn').textContent = 'Save changes';
  $('pxResetBtn').style.display = (r.type === 'builtin' && r.changed) ? 'inline-block' : 'none';
  $('pxCancelBtn').style.display = 'inline-block';
  $('pxSource').scrollIntoView({ behavior: 'smooth', block: 'center' });
}

function resetForm() {
  editMode = null;
  $('pxFormTitle').textContent = 'Add a pattern';
  for (const id of ['pxLabel', 'pxCategory', 'pxSource', 'pxTest']) $(id).value = '';
  $('pxFlags').value = 'g'; $('pxGroup').value = '0'; $('pxMask').value = 'stars';
  $('pxStatus').textContent = '';
  setFormEnabled(false);
  $('pxSaveBtn').textContent = 'Add pattern';
  $('pxResetBtn').style.display = 'none';
  $('pxCancelBtn').style.display = 'none';
}

$('pxTestBtn').addEventListener('click', () => {
  const r = compileTest($('pxSource').value, $('pxFlags').value || 'g');
  const s = $('pxStatus');
  if (!$('pxSource').value) { s.className = 'status err'; s.textContent = 'Enter a regex.'; return; }
  if (!r.ok) { s.className = 'status err'; s.textContent = r.msg; return; }
  const sample = $('pxTest').value;
  if (!sample) { s.className = 'status ok'; s.textContent = 'Compiles and looks safe.'; return; }
  const m = sample.match(r.re);
  s.className = 'status ok';
  s.textContent = m ? `${m.length} match(es): ${m.slice(0, 5).join(' , ').slice(0, 120)}` : 'Compiles, but no match in the sample.';
});

$('pxSaveBtn').addEventListener('click', () => {
  const source = $('pxSource').value;
  const flags = ($('pxFlags').value || 'g').replace(/[^gimsuy]/g, '') || 'g';
  const s = $('pxStatus');
  if (!source) { s.className = 'status err'; s.textContent = 'A regex is required.'; return; }
  const r = compileTest(source, flags);
  if (!r.ok) { s.className = 'status err'; s.textContent = r.msg; return; }

  if (editMode && editMode.type === 'builtin') {
    const p = ALL_BUILTINS.find((x) => x.id === editMode.id);
    const patch = { source: source === p.source ? undefined : source, flags: flags === p.flags ? undefined : flags };
    if (patch.source === undefined && patch.flags === undefined) { clearOverride(editMode.id); resetForm(); return; }
    setOverride(editMode.id, patch);
    resetForm();
    return;
  }

  const label = ($('pxLabel').value || '').trim();
  if (!label) { s.className = 'status err'; s.textContent = 'A label is required.'; return; }
  const category = ($('pxCategory').value || '').trim().toLowerCase().replace(/[^a-z0-9_-]+/g, '_') || 'user';
  const entry = {
    id: (editMode && editMode.id) || `u${Date.now().toString(36)}${Math.floor(performance.now() % 1000)}`,
    label, category, source, flags,
    valueGroup: Math.max(0, Math.min(9, Number($('pxGroup').value) || 0)),
    mask: $('pxMask').value === 'affix' ? 'affix' : 'stars',
    enabled: true,
  };
  const idx = userPatterns.findIndex((p) => p.id === entry.id);
  if (idx >= 0) { entry.enabled = userPatterns[idx].enabled !== false; userPatterns[idx] = entry; }
  else userPatterns.push(entry);
  chrome.storage.local.set({ dlp_userPatterns: userPatterns }, () => {
    resetForm(); renderAllPatterns(); renderCustomCats();
    banner(idx >= 0 ? 'Pattern updated.' : 'Pattern added.');
  });
});

$('pxResetBtn').addEventListener('click', () => { if (editMode && editMode.type === 'builtin') clearOverride(editMode.id); });
$('pxCancelBtn').addEventListener('click', resetForm);
$('pxSearch').addEventListener('input', renderAllPatterns);
$('pxFilterCat').addEventListener('change', renderAllPatterns);
$('pxFilterType').addEventListener('change', renderAllPatterns);

// ── Custom-category master toggles (shown in the Categories tab) ──────────────
function renderCustomCats() {
  const custom = [...new Set(userPatterns.map((p) => (p.category && String(p.category).trim()) || 'user'))]
    .filter((c) => !BUILTIN_CATS.includes(c) && c !== 'custom');
  const card = $('customCatsCard');
  const host = $('customCatsRows');
  host.innerHTML = '';
  if (custom.length === 0) { card.style.display = 'none'; return; }
  card.style.display = 'block';
  for (const c of custom.sort()) {
    const n = userPatterns.filter((p) => ((p.category && String(p.category).trim()) || 'user') === c).length;
    const row = document.createElement('div');
    row.className = 'row';
    const label = document.createElement('label');
    label.innerHTML = `${c} <span class="pill">${n}</span>`;
    const cb = document.createElement('input');
    cb.type = 'checkbox'; cb.checked = currentCats[c] !== false;
    cb.addEventListener('change', () => {
      currentCats = { ...currentCats, [c]: cb.checked };
      chrome.storage.local.set({ dlp_cats: currentCats }, () => banner());
    });
    row.append(label, cb);
    host.appendChild(row);
  }
}

// ── File-scan extensions ──────────────────────────────────────────────────────
function parseExts(raw) {
  return [...new Set(raw.split(/[\s,]+/).map((e) => e.trim().toLowerCase().replace(/^\./, '')).filter(Boolean))];
}
$('saveExtsBtn').addEventListener('click', () => {
  const exts = parseExts($('fileExts').value);
  chrome.storage.local.set({ dlp_fileExtensions: exts }, () => {
    const s = $('extsStatus'); s.className = 'status ok';
    s.textContent = `Saved ${exts.length} type${exts.length === 1 ? '' : 's'}.`;
    setTimeout(() => { s.textContent = ''; }, 1600);
  });
});
$('resetExtsBtn').addEventListener('click', () => {
  const def = (typeof DlpEngine !== 'undefined' && DlpEngine.FILE_EXTENSIONS_DEFAULT) ? [...DlpEngine.FILE_EXTENSIONS_DEFAULT] : [];
  chrome.storage.local.set({ dlp_fileExtensions: def }, () => { $('fileExts').value = def.join(' '); banner('Defaults restored.'); });
});

// ── Protected terms ───────────────────────────────────────────────────────────
$('saveTermsBtn').addEventListener('click', () => {
  const terms = [...new Set($('termsArea').value.split('\n').map((t) => t.trim()).filter((t) => t.length >= 2))];
  chrome.storage.local.set({ dlp_customTerms: terms }, () => {
    const s = $('termsStatus'); s.className = 'status ok';
    s.textContent = `Saved ${terms.length} term${terms.length === 1 ? '' : 's'}.`;
    setTimeout(() => { s.textContent = ''; }, 1600);
  });
});

// ── Disabled sites ────────────────────────────────────────────────────────────
function renderSites(sites) {
  const tbody = $('sitesTable').querySelector('tbody');
  tbody.innerHTML = '';
  $('sitesEmpty').style.display = sites.length ? 'none' : 'block';
  $('sitesTable').style.display = sites.length ? 'table' : 'none';
  for (const host of sites) {
    const tr = document.createElement('tr');
    const td = document.createElement('td'); td.textContent = host; td.className = 'mono';
    const tdA = document.createElement('td'); tdA.style.textAlign = 'right';
    const rm = document.createElement('button');
    rm.className = 'btn small'; rm.textContent = 'Remove';
    rm.addEventListener('click', () => {
      const next = sites.filter((h) => h !== host);
      chrome.storage.local.set({ dlp_disabledSites: next }, () => { renderSites(next); banner(); });
    });
    tdA.appendChild(rm);
    tr.append(td, tdA); tbody.appendChild(tr);
  }
}

$('addSiteBtn').addEventListener('click', () => {
  let host = $('siteInput').value.trim();
  if (!host) return;
  try { if (/^https?:\/\//i.test(host)) host = new URL(host).hostname; } catch (_e) { /* keep raw */ }
  host = host.replace(/\/.*$/, '');
  chrome.storage.local.get({ dlp_disabledSites: [] }, ({ dlp_disabledSites }) => {
    const set = new Set(dlp_disabledSites || []); set.add(host);
    const list = [...set];
    chrome.storage.local.set({ dlp_disabledSites: list }, () => { $('siteInput').value = ''; renderSites(list); banner(); });
  });
});

// ── Stats & log ───────────────────────────────────────────────────────────────
let chartGrouping = 'day';

function loadStats() {
  chrome.storage.local.get({ dlp_bypassCount: 0, dlp_revealCount: 0, dlp_exfilBlocked: 0, dlp_fileUploadedAnyway: 0, dlp_fileRemoved: 0, dlp_bypassLog: [], dlp_dailyStats: {} }, (s) => {
    $('stBypass').textContent = String(s.dlp_bypassCount);
    $('stReveal').textContent = String(s.dlp_revealCount);
    $('stExfil').textContent = String(s.dlp_exfilBlocked);
    $('stFileAnyway').textContent = String(s.dlp_fileUploadedAnyway);
    $('stFileRemoved').textContent = String(s.dlp_fileRemoved);
    renderLog(Array.isArray(s.dlp_bypassLog) ? s.dlp_bypassLog : []);
    renderChart(s.dlp_dailyStats && typeof s.dlp_dailyStats === 'object' ? s.dlp_dailyStats : {});
  });
}

// Aggregate the per-day map into buckets (day or month) and draw a grouped
// bar chart as inline SVG (no external chart library — CSP-safe).
function renderChart(daily) {
  const days = Object.keys(daily).sort();
  const host = $('chart');
  if (days.length === 0) { host.innerHTML = ''; $('chartEmpty').style.display = 'block'; return; }
  $('chartEmpty').style.display = 'none';

  const KINDS = ['paste', 'reveal', 'exfil', 'file'];
  const buckets = new Map(); // key → {paste,reveal,exfil,file}
  for (const d of days) {
    const key = chartGrouping === 'month' ? d.slice(0, 7) : d;
    const b = buckets.get(key) || { paste: 0, reveal: 0, exfil: 0, file: 0 };
    const v = daily[d] || {};
    for (const k of KINDS) b[k] += v[k] || 0;
    buckets.set(key, b);
  }
  // keep the most recent N buckets so the chart stays readable
  const N = chartGrouping === 'month' ? 18 : 30;
  const keys = [...buckets.keys()].sort().slice(-N);
  const data = keys.map((k) => ({ key: k, ...buckets.get(k) }));
  const max = Math.max(1, ...data.map((d) => Math.max(...KINDS.map((k) => d[k]))));

  const W = Math.max(560, data.length * 52);
  const H = 240, padL = 34, padB = 46, padT = 10;
  const plotH = H - padB - padT;
  const groupW = (W - padL - 8) / data.length;
  const barW = Math.max(2.5, (groupW - 8) / KINDS.length);
  const COLORS = { paste: '#e02424', reveal: '#c27803', exfil: '#1f6feb', file: '#059669' };
  const y = (v) => padT + plotH - (v / max) * plotH;

  const parts = [];
  parts.push(`<svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" font-family="system-ui,sans-serif" font-size="10">`);
  // y gridlines + labels (0, mid, max)
  for (const frac of [0, 0.5, 1]) {
    const val = Math.round(max * frac);
    const yy = y(val);
    parts.push(`<line x1="${padL}" y1="${yy}" x2="${W - 4}" y2="${yy}" stroke="var(--border)" stroke-width="1"/>`);
    parts.push(`<text x="${padL - 5}" y="${yy + 3}" text-anchor="end" fill="var(--muted)">${val}</text>`);
  }
  data.forEach((d, i) => {
    const gx = padL + i * groupW + 4;
    KINDS.forEach((kind, j) => {
      const v = d[kind];
      if (v <= 0) return;
      const bx = gx + j * barW;
      const by = y(v);
      parts.push(`<rect x="${bx.toFixed(1)}" y="${by.toFixed(1)}" width="${barW.toFixed(1)}" height="${(padT + plotH - by).toFixed(1)}" fill="${COLORS[kind]}"><title>${d.key} ${kind}: ${v}</title></rect>`);
    });
    const label = chartGrouping === 'month' ? d.key : d.key.slice(5); // MM-DD
    parts.push(`<text x="${(gx + groupW / 2 - 4).toFixed(1)}" y="${H - padB + 14}" text-anchor="middle" fill="var(--muted)" transform="rotate(35 ${(gx + groupW / 2 - 4).toFixed(1)} ${H - padB + 14})">${label}</text>`);
  });
  parts.push('</svg>');
  host.innerHTML = parts.join('');
}

$('grpDay').addEventListener('click', () => { chartGrouping = 'day'; loadStats(); });
$('grpMonth').addEventListener('click', () => { chartGrouping = 'month'; loadStats(); });

function renderLog(log) {
  const tbody = $('logTable').querySelector('tbody');
  tbody.innerHTML = '';
  $('logCount').textContent = String(log.length);
  $('logEmpty').style.display = log.length ? 'none' : 'block';
  $('logTable').style.display = log.length ? 'table' : 'none';
  const KIND = { paste: 'Paste original', reveal: 'Mask revealed', exfil: 'Copy blocked' };
  for (const e of [...log].reverse()) {
    const tr = document.createElement('tr');
    const when = document.createElement('td');
    when.textContent = e.t ? new Date(e.t).toLocaleString() : '—';
    const kind = document.createElement('td'); kind.textContent = KIND[e.kind] || e.kind;
    const host = document.createElement('td'); host.textContent = e.host || '—'; host.className = 'mono';
    const sec = document.createElement('td'); sec.textContent = String(e.secrets ?? '');
    tr.append(when, kind, host, sec); tbody.appendChild(tr);
  }
}

$('clearStatsBtn').addEventListener('click', () => {
  // clear the graph history too, so it stays consistent with the counters
  chrome.storage.local.set({ dlp_bypassCount: 0, dlp_revealCount: 0, dlp_exfilBlocked: 0, dlp_fileWithSecrets: 0, dlp_fileUploadedAnyway: 0, dlp_fileRemoved: 0, dlp_dailyStats: {} }, () => { loadStats(); banner('Counters reset.'); });
});
$('clearLogBtn').addEventListener('click', () => {
  chrome.storage.local.set({ dlp_bypassLog: [] }, () => { loadStats(); banner('Log cleared.'); });
});

// ── Export / Import (YAML) ────────────────────────────────────────────────────
// The exported file is a COMPLETE snapshot: settings, custom patterns, terms,
// AND the full built-in library with any edits/disables applied (dlp_builtins).
// On import the built-in section is diffed against the current shipped library
// to reconstruct the overrides, so a backup restores the exact effective state.
function effectiveBuiltins(overrides) {
  const map = new Map((overrides || []).filter((o) => o && o.id).map((o) => [o.id, o]));
  return ALL_BUILTINS.map((p) => {
    const ov = map.get(p.id);
    return {
      id: p.id, label: p.label, category: p.category,
      source: ov && ov.source ? ov.source : p.source,
      flags: ov && ov.flags ? ov.flags : p.flags,
      valueGroup: p.valueGroup || 0,
      enabled: !(ov && ov.disabled),
    };
  });
}

function buildConfigYaml(items) {
  const config = {};
  for (const k of CONFIG_KEYS) {
    if (k === 'dlp_builtinOverrides') continue; // superseded by the full list below
    config[k] = items[k];
  }
  config.dlp_builtins = effectiveBuiltins(items.dlp_builtinOverrides);
  return DlpYaml.stringify(config);
}

// Rebuild the compact override list by diffing an exported dlp_builtins array
// against the current shipped built-ins (matched by id). Unknown ids (version
// drift) are ignored; unsafe regexes are dropped.
function overridesFromBuiltins(list) {
  const shipped = new Map(ALL_BUILTINS.map((p) => [p.id, p]));
  const overrides = [];
  for (const b of list) {
    if (!b || !b.id) continue;
    const p = shipped.get(b.id);
    if (!p) continue;
    const ov = { id: b.id };
    let changed = false;
    if (b.enabled === false) { ov.disabled = true; changed = true; }
    const srcChanged = b.source && b.source !== p.source;
    if (srcChanged) {
      try { new RegExp(b.source, b.flags || 'g'); } catch (_e) { continue; }
      if (redosLint(b.source)) continue;
      ov.source = b.source; changed = true;
    }
    // capture a flags change independently of the source change — a flags-only
    // edit (e.g. adding 'i') must survive an export→import round-trip too
    if (b.flags && b.flags !== p.flags) {
      const effSrc = srcChanged ? b.source : p.source;
      try { new RegExp(effSrc, b.flags); ov.flags = b.flags; changed = true; } catch (_e) { /* keep original flags */ }
    }
    if (changed) overrides.push(ov);
  }
  return overrides;
}

$('exportBtn').addEventListener('click', () => {
  chrome.storage.local.get(DEFAULTS, (items) => {
    const yaml = `# DLP Guard configuration\n# exported ${new Date().toISOString()}\n${buildConfigYaml(items)}`;
    const blob = new Blob([yaml], { type: 'text/yaml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'dlp-guard-config.yaml';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
});

$('copyYamlBtn').addEventListener('click', () => {
  chrome.storage.local.get(DEFAULTS, (items) => {
    const yaml = buildConfigYaml(items);
    navigator.clipboard.writeText(yaml).then(() => banner('YAML copied.'), () => banner('Copy failed.'));
  });
});

$('importBtn').addEventListener('click', () => {
  const status = $('importStatus');
  let config;
  try { config = DlpYaml.parse($('importArea').value); }
  catch (e) { status.className = 'status err'; status.textContent = `Invalid YAML: ${e.message}`; return; }
  // tolerate an exported wrapper shape { config: {...} } too
  if (config && config.config && typeof config.config === 'object') config = config.config;
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    status.className = 'status err'; status.textContent = 'No config mapping found.'; return;
  }
  const clean = {};
  for (const k of CONFIG_KEYS) if (k in config) clean[k] = config[k];
  // sanitize custom + built-in override regexes: drop any that don't compile or look catastrophic
  if (Array.isArray(clean.dlp_userPatterns)) {
    clean.dlp_userPatterns = clean.dlp_userPatterns.filter((p) => {
      if (!p || !p.source) return false;
      try { new RegExp(p.source, (p.flags || 'g')); } catch (_e) { return false; }
      return !redosLint(p.source);
    });
  }
  // The full built-in library (dlp_builtins) is authoritative when present:
  // reconstruct the override list from it. Otherwise accept a compact
  // dlp_builtinOverrides list directly.
  if (Array.isArray(config.dlp_builtins)) {
    clean.dlp_builtinOverrides = overridesFromBuiltins(config.dlp_builtins);
  } else if (Array.isArray(clean.dlp_builtinOverrides)) {
    clean.dlp_builtinOverrides = clean.dlp_builtinOverrides.filter((o) => {
      if (!o || !o.id) return false;
      if (!o.source) return true; // disable-only override is fine
      try { new RegExp(o.source, (o.flags || 'g')); } catch (_e) { return false; }
      return !redosLint(o.source);
    });
  }
  if (Object.keys(clean).length === 0) { status.className = 'status err'; status.textContent = 'No recognized settings in that YAML.'; return; }
  chrome.storage.local.set(clean, () => {
    status.className = 'status ok';
    status.textContent = `Imported ${Object.keys(clean).length} setting group(s).`;
    $('importArea').value = '';
    loadAll();
    banner('Configuration imported.');
  });
});

$('resetBtn').addEventListener('click', () => {
  chrome.storage.local.set({ ...DEFAULTS, dlp_cats: { ...CAT_DEFAULTS }, dlp_customTerms: [], dlp_userPatterns: [], dlp_builtinOverrides: [], dlp_disabledSites: [] }, () => {
    builtinOverrides = [];
    loadAll();
    banner('Reset to defaults.');
  });
});

// Keep the page live if another surface (popup) changes settings.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local') return;
  if (Object.keys(changes).some((k) => k.startsWith('dlp_'))) {
    // don't reload while the user is typing in an editor field (ids: px*, terms*, import*, site*)
    if (!/^(px|terms|import|site)/i.test(document.activeElement?.id || '')) loadAll();
    else loadStats();
  }
});

loadAll();
