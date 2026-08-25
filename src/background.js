// background.js — DLP Guard service worker.
// Keeps the per-tab badge count (sum across frames). No network. No logging
// of secret values — content scripts only ever send counts.

const tabCounts = new Map(); // tabId → Map(frameId → count)

function updateBadge(tabId) {
  const frames = tabCounts.get(tabId);
  let total = 0;
  if (frames) for (const c of frames.values()) total += c;
  chrome.action.setBadgeText({ tabId, text: total > 0 ? String(total) : '' });
  if (total > 0) chrome.action.setBadgeBackgroundColor({ tabId, color: '#e02424' });
}

chrome.runtime.onMessage.addListener((message, sender) => {
  if (message?.type === 'DLP_BADGE' && sender.tab?.id != null) {
    const tabId = sender.tab.id;
    if (!tabCounts.has(tabId)) tabCounts.set(tabId, new Map());
    tabCounts.get(tabId).set(sender.frameId ?? 0, message.count | 0);
    updateBadge(tabId);
  }
});

// Reset the count when a tab navigates or closes.
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading') {
    tabCounts.delete(tabId);
    chrome.action.setBadgeText({ tabId, text: '' });
  }
});
chrome.tabs.onRemoved.addListener((tabId) => tabCounts.delete(tabId));

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
