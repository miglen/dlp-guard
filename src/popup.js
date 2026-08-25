// popup.js — DLP Guard popup (compact). Everyday toggles + live status;
// everything else lives in the Advanced settings (options) page.
'use strict';

const DEFAULTS = {
  dlp_enabled: true,
  dlp_maskOnPage: true,
  dlp_redactPaste: true,
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
    disabledSites = Array.isArray(items.dlp_disabledSites) ? items.dlp_disabledSites : [];
    if (currentHostname) $('site').checked = !disabledSites.includes(currentHostname);
  });
  chrome.storage.local.get({ dlp_bypassCount: 0, dlp_revealCount: 0, dlp_exfilBlocked: 0 }, (s) => {
    const total = s.dlp_bypassCount + s.dlp_revealCount + s.dlp_exfilBlocked;
    $('statsLine').textContent = total === 0 ? 'No bypasses yet'
      : `${s.dlp_bypassCount} bypassed · ${s.dlp_revealCount} revealed · ${s.dlp_exfilBlocked} blocked`;
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
    chrome.runtime.sendMessage({ type: 'DLP_GET_TAB_COUNT', tabId: tab.id }, (r) => {
      if (!chrome.runtime.lastError && r) $('count').textContent = String(r.total);
    });
    chrome.tabs.sendMessage(tab.id, { type: 'DLP_GET_STATUS' }, { frameId: 0 }, (resp) => {
      if (chrome.runtime.lastError || !resp) {
        setStatus('off', 'Not active on this page');
        $('site').disabled = true;
        $('siteLabel').textContent = 'Enable on this site';
        return;
      }
      $('site').disabled = false;
      currentHostname = resp.hostname;
      $('siteLabel').textContent = `Enable on ${resp.hostname || 'this site'}`;
      $('site').checked = !resp.siteDisabled;
      if (resp.suspended) {
        const isAuth = /password|login|registration/i.test(resp.reason || '');
        setStatus('warn', `Suspended — ${resp.reason}.` +
          (isAuth ? ' Never runs on login pages.' : ''));
      } else if (resp.siteDisabled) {
        setStatus('off', 'Disabled on this site');
      } else {
        setStatus('ok', `Protected — ${resp.maskCount} hidden, ${resp.pasteCount} redacted`);
      }
    });
  });
}

// ── Controls ──────────────────────────────────────────────────────────────────
$('enabled').addEventListener('change', (e) =>
  chrome.storage.local.set({ dlp_enabled: e.target.checked }));
$('maskOnPage').addEventListener('change', (e) =>
  chrome.storage.local.set({ dlp_maskOnPage: e.target.checked }));
$('redactPaste').addEventListener('change', (e) =>
  chrome.storage.local.set({ dlp_redactPaste: e.target.checked }));

$('site').addEventListener('change', (e) => {
  if (!currentHostname) return;
  const set = new Set(disabledSites);
  if (e.target.checked) set.delete(currentHostname);
  else set.add(currentHostname);
  disabledSites = [...set];
  chrome.storage.local.set({ dlp_disabledSites: disabledSites });
});

$('openOptions').addEventListener('click', () => {
  if (chrome.runtime.openOptionsPage) chrome.runtime.openOptionsPage();
  else window.open(chrome.runtime.getURL('options.html'));
});

loadSettings();
queryTab();
setInterval(queryTab, 1500);
setInterval(loadSettings, 1500);
