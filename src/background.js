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
      dlp_cats: { token: true, assignment: true, privatekey: true, infra: false, generic: false },
      dlp_disabledSites: [],
    };
    const missing = {};
    for (const [k, v] of Object.entries(defaults)) {
      if (!(k in items)) missing[k] = v;
    }
    if (Object.keys(missing).length) chrome.storage.local.set(missing);
  });
});
