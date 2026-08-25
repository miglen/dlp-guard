// background.js — DLP Guard service worker.
// Keeps the per-tab badge count (summed across frames). Counts are persisted
// in chrome.storage.session so they survive MV3 worker idle-termination.
// No network. No logging of secret values — content scripts only send counts.

const COUNTS_KEY = 'dlp_tab_counts'; // { [tabId]: { [frameId]: count } }

// Serialize read-modify-write cycles so rapid messages can't clobber each other.
let queue = Promise.resolve();
function withCounts(mutator) {
  queue = queue.then(async () => {
    const data = await chrome.storage.session.get({ [COUNTS_KEY]: {} });
    const counts = data[COUNTS_KEY];
    const result = mutator(counts);
    await chrome.storage.session.set({ [COUNTS_KEY]: counts });
    return result;
  }).catch(() => {});
  return queue;
}

function tabTotal(counts, tabId) {
  const frames = counts[tabId];
  let total = 0;
  if (frames) for (const c of Object.values(frames)) total += c;
  return total;
}

function paintBadge(tabId, total) {
  chrome.action.setBadgeText({ tabId, text: total > 0 ? String(total) : '' });
  if (total > 0) chrome.action.setBadgeBackgroundColor({ tabId, color: '#e02424' });
}

// Bypass bookkeeping: every deliberate bypass (paste-original or chip reveal)
// increments a persistent counter and appends to a rolling audit log.
// Only kind/host/count/time are recorded — never the secret values.
const MAX_BYPASS_LOG = 200;
let bypassQueue = Promise.resolve();
function recordBypass(kind, host, secrets) {
  bypassQueue = bypassQueue.then(async () => {
    const items = await chrome.storage.local.get({
      dlp_bypassCount: 0,
      dlp_revealCount: 0,
      dlp_exfilBlocked: 0,
      dlp_bypassLog: [],
    });
    const update = {};
    if (kind === 'paste') update.dlp_bypassCount = items.dlp_bypassCount + 1;
    else if (kind === 'exfil') update.dlp_exfilBlocked = items.dlp_exfilBlocked + 1;
    else update.dlp_revealCount = items.dlp_revealCount + 1;
    const log = Array.isArray(items.dlp_bypassLog) ? items.dlp_bypassLog : [];
    log.push({ t: Date.now(), kind, host: String(host || ''), secrets: secrets | 0 });
    if (log.length > MAX_BYPASS_LOG) log.splice(0, log.length - MAX_BYPASS_LOG);
    update.dlp_bypassLog = log;
    await chrome.storage.local.set(update);
  }).catch(() => {});
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === 'DLP_BADGE' && sender.tab?.id != null) {
    const tabId = sender.tab.id;
    withCounts((counts) => {
      if (!counts[tabId]) counts[tabId] = {};
      counts[tabId][sender.frameId ?? 0] = message.count | 0;
      paintBadge(tabId, tabTotal(counts, tabId));
    });
    return false;
  }
  if (message?.type === 'DLP_GET_TAB_COUNT' && typeof message.tabId === 'number') {
    withCounts((counts) => tabTotal(counts, message.tabId))
      .then((total) => sendResponse({ total: total ?? 0 }));
    return true; // async sendResponse
  }
  if (message?.type === 'DLP_BYPASS' && sender.tab?.id != null) {
    recordBypass(message.kind === 'paste' ? 'paste' : 'reveal', message.host, message.secrets);
    return false;
  }
  if (message?.type === 'DLP_EXFIL_BLOCK' && sender.tab?.id != null) {
    recordBypass('exfil', message.host, message.secrets);
    return false;
  }
  return false;
});

// Reset the count when a tab navigates or closes.
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading') {
    withCounts((counts) => { delete counts[tabId]; });
    chrome.action.setBadgeText({ tabId, text: '' });
  }
});
chrome.tabs.onRemoved.addListener((tabId) => {
  withCounts((counts) => { delete counts[tabId]; });
});

// First-run defaults.
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(null, (items) => {
    const defaults = {
      dlp_enabled: true,
      dlp_maskOnPage: true,
      dlp_redactPaste: true,
      dlp_revealOnClick: true,
      dlp_exfilShield: true,
      dlp_exfilThreshold: 10,
      dlp_cats: { token: true, assignment: true, privatekey: true, custom: true, user: true, pii: false, infra: false, generic: false },
      dlp_customTerms: [],
      dlp_userPatterns: [],
      dlp_disabledSites: [],
    };
    const missing = {};
    for (const [k, v] of Object.entries(defaults)) {
      if (!(k in items)) missing[k] = v;
    }
    if (Object.keys(missing).length) chrome.storage.local.set(missing);
  });
});
