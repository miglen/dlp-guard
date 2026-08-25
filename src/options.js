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
  dlp_cats: { ...CAT_DEFAULTS },
  dlp_customTerms: [],
  dlp_userPatterns: [],
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
    const cats = { ...CAT_DEFAULTS, ...(items.dlp_cats || {}) };
    $$('[data-cat]').forEach((el) => { el.checked = Boolean(cats[el.dataset.cat]); });
    if (document.activeElement !== $('termsArea')) {
      $('termsArea').value = (items.dlp_customTerms || []).join('\n');
    }
    renderPatterns(items.dlp_userPatterns || []);
    renderSites(items.dlp_disabledSites || []);
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
    const cats = {};
    $$('[data-cat]').forEach((c) => { cats[c.dataset.cat] = c.checked; });
    cats.custom = true; cats.user = true; // always honored; managed per-item
    chrome.storage.local.set({ dlp_cats: cats }, () => banner());
  });
});

// ── Custom regex management ───────────────────────────────────────────────────
let editingId = null;

// A single catastrophic regex can't be interrupted once exec() starts, so the
// guard is STATIC first (reject dangerous structure before running anything),
// then a short bounded timing probe as a secondary net.
function redosLint(source) {
  // nested unbounded quantifiers: a group with +/* inside, itself repeated
  if (/\([^)]*[+*][^)]*\)\s*[+*]/.test(source)) return 'a group containing + or * is itself repeated (nested quantifier, classic ReDoS)';
  if (/\([^)]*[+*][^)]*\)\s*\{\d*,\d*\}/.test(source) || /\([^)]*[+*][^)]*\)\s*\{\d+,\}/.test(source)) return 'a group containing + or * is repeated with a {..,} count (nested quantifier)';
  // repeated wildcard group like (.*x){8,} — polynomial degree n
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
  // Secondary net: SHORT probes so even a missed exponential case completes one
  // exec quickly enough to trip the budget rather than hang the page.
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

$('rxTestBtn').addEventListener('click', () => {
  const src = $('rxSource').value;
  const flags = $('rxFlags').value || 'g';
  const status = $('rxStatus');
  if (!src) { status.className = 'status err'; status.textContent = 'Enter a regex.'; return; }
  const r = compileTest(src, flags);
  if (!r.ok) { status.className = 'status err'; status.textContent = r.msg; return; }
  const sample = $('rxTest').value;
  if (!sample) { status.className = 'status ok'; status.textContent = 'Regex compiles and looks safe.'; return; }
  const matches = sample.match(r.re);
  status.className = 'status ok';
  status.textContent = matches ? `${matches.length} match(es): ${matches.slice(0, 5).join(' , ').slice(0, 120)}` : 'Compiles, but no match in the sample.';
});

$('rxAddBtn').addEventListener('click', () => {
  const label = ($('rxLabel').value || '').trim();
  const source = $('rxSource').value;
  const flags = ($('rxFlags').value || 'g').replace(/[^gimsuy]/g, '') || 'g';
  const status = $('rxStatus');
  if (!label) { status.className = 'status err'; status.textContent = 'A label is required.'; return; }
  if (!source) { status.className = 'status err'; status.textContent = 'A regex is required.'; return; }
  const r = compileTest(source, flags);
  if (!r.ok) { status.className = 'status err'; status.textContent = r.msg; return; }
  const entry = {
    id: editingId || `u${Date.now().toString(36)}${Math.floor(performance.now() % 1000)}`,
    label, source, flags,
    valueGroup: Math.max(0, Math.min(9, Number($('rxGroup').value) || 0)),
    mask: $('rxMask').value === 'affix' ? 'affix' : 'stars',
    enabled: true,
  };
  chrome.storage.local.get({ dlp_userPatterns: [] }, ({ dlp_userPatterns }) => {
    const list = Array.isArray(dlp_userPatterns) ? dlp_userPatterns : [];
    const idx = list.findIndex((p) => p.id === entry.id);
    if (idx >= 0) { entry.enabled = list[idx].enabled; list[idx] = entry; }
    else list.push(entry);
    chrome.storage.local.set({ dlp_userPatterns: list }, () => {
      resetRxForm();
      renderPatterns(list);
      banner(idx >= 0 ? 'Pattern updated.' : 'Pattern added.');
    });
  });
});

$('rxCancelBtn').addEventListener('click', resetRxForm);

function resetRxForm() {
  editingId = null;
  $('rxLabel').value = ''; $('rxSource').value = ''; $('rxFlags').value = 'g';
  $('rxGroup').value = '0'; $('rxMask').value = 'stars'; $('rxTest').value = '';
  $('rxStatus').textContent = '';
  $('rxAddBtn').textContent = 'Add pattern';
  $('rxCancelBtn').style.display = 'none';
}

function renderPatterns(list) {
  const tbody = $('rxTable').querySelector('tbody');
  tbody.innerHTML = '';
  $('rxCount').textContent = String(list.length);
  $('rxEmpty').style.display = list.length ? 'none' : 'block';
  $('rxTable').style.display = list.length ? 'table' : 'none';
  for (const p of list) {
    const tr = document.createElement('tr');

    const tdOn = document.createElement('td');
    const cb = document.createElement('input');
    cb.type = 'checkbox'; cb.checked = p.enabled !== false;
    cb.addEventListener('change', () => togglePattern(p.id, cb.checked));
    tdOn.appendChild(cb);

    const tdLabel = document.createElement('td');
    tdLabel.textContent = p.label;

    const tdSrc = document.createElement('td');
    tdSrc.className = 'mono';
    tdSrc.textContent = `/${p.source}/${p.flags}` + (p.valueGroup ? ` (g${p.valueGroup})` : '');

    const tdMask = document.createElement('td');
    tdMask.textContent = p.mask === 'affix' ? 'prefix/suffix' : 'stars';

    const tdActions = document.createElement('td');
    const edit = document.createElement('button');
    edit.className = 'btn secondary small'; edit.textContent = 'Edit';
    edit.addEventListener('click', () => startEdit(p));
    const del = document.createElement('button');
    del.className = 'btn small'; del.textContent = 'Delete'; del.style.marginLeft = '6px';
    del.addEventListener('click', () => deletePattern(p.id));
    tdActions.appendChild(edit); tdActions.appendChild(del);

    tr.append(tdOn, tdLabel, tdSrc, tdMask, tdActions);
    tbody.appendChild(tr);
  }
}

function startEdit(p) {
  editingId = p.id;
  $('rxLabel').value = p.label; $('rxSource').value = p.source; $('rxFlags').value = p.flags;
  $('rxGroup').value = String(p.valueGroup || 0); $('rxMask').value = p.mask || 'stars';
  $('rxAddBtn').textContent = 'Save changes';
  $('rxCancelBtn').style.display = 'inline-block';
  $('rxSource').scrollIntoView({ behavior: 'smooth', block: 'center' });
}

function togglePattern(id, enabled) {
  chrome.storage.local.get({ dlp_userPatterns: [] }, ({ dlp_userPatterns }) => {
    const list = (dlp_userPatterns || []).map((p) => (p.id === id ? { ...p, enabled } : p));
    chrome.storage.local.set({ dlp_userPatterns: list }, () => banner());
  });
}

function deletePattern(id) {
  chrome.storage.local.get({ dlp_userPatterns: [] }, ({ dlp_userPatterns }) => {
    const list = (dlp_userPatterns || []).filter((p) => p.id !== id);
    chrome.storage.local.set({ dlp_userPatterns: list }, () => { renderPatterns(list); banner('Pattern deleted.'); });
  });
}

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
function loadStats() {
  chrome.storage.local.get({ dlp_bypassCount: 0, dlp_revealCount: 0, dlp_exfilBlocked: 0, dlp_bypassLog: [] }, (s) => {
    $('stBypass').textContent = String(s.dlp_bypassCount);
    $('stReveal').textContent = String(s.dlp_revealCount);
    $('stExfil').textContent = String(s.dlp_exfilBlocked);
    renderLog(Array.isArray(s.dlp_bypassLog) ? s.dlp_bypassLog : []);
  });
}

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
  chrome.storage.local.set({ dlp_bypassCount: 0, dlp_revealCount: 0, dlp_exfilBlocked: 0 }, () => { loadStats(); banner('Counters reset.'); });
});
$('clearLogBtn').addEventListener('click', () => {
  chrome.storage.local.set({ dlp_bypassLog: [] }, () => { loadStats(); banner('Log cleared.'); });
});

// ── Export / Import ───────────────────────────────────────────────────────────
$('exportBtn').addEventListener('click', () => {
  chrome.storage.local.get(DEFAULTS, (items) => {
    const config = {};
    for (const k of CONFIG_KEYS) config[k] = items[k];
    const payload = { _dlpGuardConfig: 1, exportedAt: new Date().toISOString(), config };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'dlp-guard-config.json';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
});

$('importBtn').addEventListener('click', () => {
  const status = $('importStatus');
  let parsed;
  try { parsed = JSON.parse($('importArea').value); }
  catch (e) { status.className = 'status err'; status.textContent = `Invalid JSON: ${e.message}`; return; }
  const config = parsed && parsed.config ? parsed.config : parsed;
  if (!config || typeof config !== 'object') { status.className = 'status err'; status.textContent = 'No config object found.'; return; }
  const clean = {};
  for (const k of CONFIG_KEYS) if (k in config) clean[k] = config[k];
  // sanitize user patterns: drop any that don't compile or look catastrophic
  if (Array.isArray(clean.dlp_userPatterns)) {
    clean.dlp_userPatterns = clean.dlp_userPatterns.filter((p) => {
      if (!p || !p.source) return false;
      try { new RegExp(p.source, (p.flags || 'g')); } catch (_e) { return false; }
      return !redosLint(p.source);
    });
  }
  if (Object.keys(clean).length === 0) { status.className = 'status err'; status.textContent = 'No recognized settings in that config.'; return; }
  chrome.storage.local.set(clean, () => {
    status.className = 'status ok';
    status.textContent = `Imported ${Object.keys(clean).length} setting group(s).`;
    $('importArea').value = '';
    loadAll();
    banner('Configuration imported.');
  });
});

$('resetBtn').addEventListener('click', () => {
  chrome.storage.local.set({ ...DEFAULTS, dlp_customTerms: [], dlp_userPatterns: [], dlp_disabledSites: [] }, () => {
    loadAll();
    banner('Reset to defaults.');
  });
});

// Keep the page live if another surface (popup) changes settings.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local') return;
  if (Object.keys(changes).some((k) => k.startsWith('dlp_'))) {
    if (!/rx|terms|import|site/i.test(document.activeElement?.id || '')) loadAll();
    else loadStats();
  }
});

loadAll();
