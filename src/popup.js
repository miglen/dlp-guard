// popup.js — DLP Guard popup. Reads/writes settings in chrome.storage.local;
// asks the active tab's content script for live status.
'use strict';

const DEFAULTS = {
  dlp_enabled: true,
  dlp_maskOnPage: true,
  dlp_redactPaste: true,
  dlp_revealOnClick: true,
  dlp_cats: { token: true, assignment: true, privatekey: true, infra: false, generic: false },
  dlp_disabledSites: [],
};

const $ = (id) => document.getElementById(id);
let currentHostname = null;
let disabledSites = [];

function setStatus(cls, text) {
  const el = $('status');
  el.className = `status ${cls}`;
  el.textContent = text;
}

function loadSettings() {
  chrome.storage.local.get(DEFAULTS, (items) => {
    $('enabled').checked = items.dlp_enabled !== false;
    $('maskOnPage').checked = items.dlp_maskOnPage !== false;
    $('redactPaste').checked = items.dlp_redactPaste !== false;
    $('revealOnClick').checked = items.dlp_revealOnClick !== false;
    const cats = { ...DEFAULTS.dlp_cats, ...(items.dlp_cats || {}) };
    $('catToken').checked = cats.token;
    $('catAssignment').checked = cats.assignment;
    $('catPrivatekey').checked = cats.privatekey;
    $('catInfra').checked = cats.infra;
    $('catGeneric').checked = cats.generic;
    disabledSites = Array.isArray(items.dlp_disabledSites) ? items.dlp_disabledSites : [];
    if (currentHostname) {
      $('site').checked = !disabledSites.includes(currentHostname);
    }
  });
  chrome.storage.local.get({ dlp_bypassCount: 0, dlp_revealCount: 0 }, (s) => {
    $('bypassCount').textContent = String(s.dlp_bypassCount);
    $('revealCount').textContent = String(s.dlp_revealCount);
  });
}

function queryTab() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs && tabs[0];
    if (!tab || tab.id == null) {
      setStatus('off', 'No active tab');
      $('site').disabled = true;
      return;
    }
    // Badge-accurate count (summed across all frames) comes from the background.
    chrome.runtime.sendMessage({ type: 'DLP_GET_TAB_COUNT', tabId: tab.id }, (r) => {
      if (!chrome.runtime.lastError && r) $('count').textContent = String(r.total);
    });
    chrome.tabs.sendMessage(tab.id, { type: 'DLP_GET_STATUS' }, { frameId: 0 }, (resp) => {
      if (chrome.runtime.lastError || !resp) {
        setStatus('off', 'Not active on this page (browser page or no content script)');
        $('site').disabled = true;
        $('siteLabel').textContent = 'Enable on this site';
        return;
      }
      $('site').disabled = false; // a transient failure must not stick
      currentHostname = resp.hostname;
      $('siteLabel').textContent = `Enable on ${resp.hostname || 'this site'}`;
      $('site').checked = !resp.siteDisabled;
      if (resp.suspended) {
        setStatus('warn', `Suspended — ${resp.reason}. DLP Guard never runs on login or registration pages.`);
      } else if (resp.siteDisabled) {
        setStatus('off', 'Disabled on this site');
      } else {
        setStatus('ok', `Protected — ${resp.maskCount} hidden on page, ${resp.pasteCount} redacted from pastes`);
      }
      loadSettings(); // refresh site checkbox now that hostname is known
    });
  });
}

// ── Wire up controls ──────────────────────────────────────────────────────────

$('enabled').addEventListener('change', (e) =>
  chrome.storage.local.set({ dlp_enabled: e.target.checked }));
$('maskOnPage').addEventListener('change', (e) =>
  chrome.storage.local.set({ dlp_maskOnPage: e.target.checked }));
$('redactPaste').addEventListener('change', (e) =>
  chrome.storage.local.set({ dlp_redactPaste: e.target.checked }));
$('revealOnClick').addEventListener('change', (e) =>
  chrome.storage.local.set({ dlp_revealOnClick: e.target.checked }));

for (const cat of ['token', 'assignment', 'privatekey', 'infra', 'generic']) {
  const id = 'cat' + cat[0].toUpperCase() + cat.slice(1);
  $(id).addEventListener('change', () => {
    const cats = {
      token: $('catToken').checked,
      assignment: $('catAssignment').checked,
      privatekey: $('catPrivatekey').checked,
      infra: $('catInfra').checked,
      generic: $('catGeneric').checked,
    };
    chrome.storage.local.set({ dlp_cats: cats });
  });
}

$('site').addEventListener('change', (e) => {
  if (!currentHostname) return;
  const set = new Set(disabledSites);
  if (e.target.checked) set.delete(currentHostname);
  else set.add(currentHostname);
  disabledSites = [...set];
  chrome.storage.local.set({ dlp_disabledSites: disabledSites });
});

loadSettings();
queryTab();
setInterval(queryTab, 1500); // keep count/status live while popup is open
