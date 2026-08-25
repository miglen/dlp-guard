// content.js — DLP Guard content script.
// Detects secrets in rendered page text and hides them behind mask chips;
// redacts secrets on paste before they reach chat inputs.
// Runs at document_start after engine.js + pageguard.js + patterns.generated.js
// (same isolated world), so the paste listener is registered before any page
// script can add its own.
'use strict';

(() => {
  if (window.__dlpGuardLoaded) return;
  window.__dlpGuardLoaded = true;

  const MASK_ATTR = 'data-dlpg-mask';
  const LOG_PREFIX = '🛡️ DLP Guard:';

  const DEFAULTS = Object.freeze({
    dlp_enabled: true,
    dlp_maskOnPage: true,
    dlp_redactPaste: true,
    dlp_revealOnClick: true,
    dlp_cats: DlpEngine.CATEGORY_DEFAULTS,
    dlp_disabledSites: [],
  });

  const STATE = {
    ready: false,
    enabled: true,
    maskOnPage: true,
    redactPaste: true,
    revealOnClick: true,
    cats: { ...DlpEngine.CATEGORY_DEFAULTS },
    disabledSites: [],
    suspendReason: null, // non-null → login/registration page, do nothing
    maskCount: 0,        // secrets currently hidden on this page
    pasteCount: 0,       // total secrets redacted from pastes
  };

  /** Real values for masked spans — closure-held, never written into the DOM. */
  const originals = new WeakMap();
  /** Text nodes we created ourselves (post-mask segments). Skipped by the
   *  observer path to avoid feedback loops; full scans deliberately ignore
   *  this set so nothing is ever permanently exempt from scanning. */
  const ourTextNodes = new WeakSet();
  /** Invalidates in-flight chunked scans when settings/guard state change. */
  let scanGeneration = 0;

  // ── Settings ───────────────────────────────────────────────────────────────

  function applySettings(items) {
    STATE.enabled = items.dlp_enabled !== false;
    STATE.maskOnPage = items.dlp_maskOnPage !== false;
    STATE.redactPaste = items.dlp_redactPaste !== false;
    STATE.revealOnClick = items.dlp_revealOnClick !== false;
    STATE.cats = { ...DlpEngine.CATEGORY_DEFAULTS, ...(items.dlp_cats || {}) };
    STATE.disabledSites = Array.isArray(items.dlp_disabledSites) ? items.dlp_disabledSites : [];
    DlpEngine.compile(STATE.cats);
    scanGeneration++;
  }

  function siteDisabled() {
    return STATE.disabledSites.includes(location.hostname);
  }

  function isActive() {
    return STATE.ready && STATE.enabled && !STATE.suspendReason && !siteDisabled();
  }

  chrome.storage.local.get(DEFAULTS, (items) => {
    applySettings(items);
    STATE.ready = true;
    evaluateGuard(true);
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => scheduleFullScan());
    } else {
      scheduleFullScan();
    }
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local') return;
    chrome.storage.local.get(DEFAULTS, (items) => {
      applySettings(items);
      // Settings changed: start from a clean slate, then re-mask if active.
      unmaskAll();
      scheduleFullScan();
    });
  });

  // ── Login/registration page guard ──────────────────────────────────────────

  function evaluateGuard(initial) {
    const reason = PageGuard.suspendReason();
    if (reason && !STATE.suspendReason) {
      STATE.suspendReason = reason;
      scanGeneration++; // kill in-flight scans immediately
      unmaskAll();
      if (!initial) console.info(`${LOG_PREFIX} suspended — ${reason}`);
      reportCount();
    } else if (!reason && STATE.suspendReason) {
      STATE.suspendReason = null;
      scheduleFullScan();
    }
  }

  let lastHref = location.href;
  function checkUrlChange() {
    if (location.href !== lastHref) {
      lastHref = location.href;
      evaluateGuard(false);
    }
  }
  window.addEventListener('popstate', () => checkUrlChange());
  window.addEventListener('hashchange', () => checkUrlChange());
  // history.pushState in the page world is invisible to this isolated world,
  // so poll as a backstop for SPA route changes that mutate nothing right away.
  setInterval(checkUrlChange, 1000);

  // Re-publish the badge count when a bfcache-restored page comes back.
  window.addEventListener('pageshow', (e) => {
    if (e.persisted) reportCount();
  });

  // ── Masking ────────────────────────────────────────────────────────────────

  function injectStyle() {
    if (document.getElementById('dlpg-style')) return;
    const style = document.createElement('style');
    style.id = 'dlpg-style';
    style.textContent = `
      [${MASK_ATTR}] {
        background: #fde8e8;
        border: 1px solid #e02424;
        color: #771d1d;
        border-radius: 4px;
        padding: 0 5px;
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
        font-size: 0.85em;
        cursor: pointer;
        user-select: none;
        white-space: nowrap;
      }
      [${MASK_ATTR}][data-dlpg-revealed] {
        background: #fdf6b2;
        border-color: #c27803;
        color: #633112;
        user-select: text;
        white-space: pre-wrap;
      }
    `;
    (document.head || document.documentElement).appendChild(style);
  }

  function maskChipText(label) {
    return `••••• ${label} •••••`;
  }

  function shouldSkipNode(textNode) {
    let el = textNode.parentElement;
    if (!el) return true;
    if (el.namespaceURI !== 'http://www.w3.org/1999/xhtml') return true; // svg/mathml
    while (el) {
      const tag = el.tagName;
      if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'NOSCRIPT' ||
          tag === 'TEXTAREA' || tag === 'TITLE') return true;
      if (el.isContentEditable) return true; // never rewrite what the user is editing
      if (el.hasAttribute && el.hasAttribute(MASK_ATTR)) return true;
      el = el.parentElement;
    }
    return false;
  }

  // fromFullScan: full sweeps ignore the ourTextNodes skip so that restored or
  // split segments are always re-examined; the observer path keeps the skip to
  // avoid processing our own insertions in a loop.
  function processTextNode(node, fromFullScan) {
    if (!node.isConnected) return;
    if (!fromFullScan && ourTextNodes.has(node)) return;
    const text = node.nodeValue;
    if (!text || text.length < 6) return;
    if (shouldSkipNode(node)) return;

    const ranges = DlpEngine.findRanges(text);
    if (ranges.length === 0) return;

    injectStyle();
    const frag = document.createDocumentFragment();
    let pos = 0;
    for (const r of ranges) {
      if (r.start > pos) {
        const before = document.createTextNode(text.slice(pos, r.start));
        ourTextNodes.add(before);
        frag.appendChild(before);
      }
      const span = document.createElement('span');
      span.setAttribute(MASK_ATTR, r.label);
      span.textContent = maskChipText(r.label);
      span.title = 'Secret hidden by DLP Guard' + (STATE.revealOnClick ? ' — click to reveal' : '');
      originals.set(span, text.slice(r.start, r.end));
      frag.appendChild(span);
      pos = r.end;
      STATE.maskCount++;
    }
    if (pos < text.length) {
      const after = document.createTextNode(text.slice(pos));
      ourTextNodes.add(after);
      frag.appendChild(after);
    }
    node.parentNode.replaceChild(frag, node);
    reportCount();
  }

  function unmaskAll() {
    scanGeneration++; // any in-flight scan chain is now stale
    const spans = document.querySelectorAll(`[${MASK_ATTR}]`);
    for (const span of spans) {
      const real = originals.get(span);
      // A chip whose original was lost (e.g. framework cloned the element)
      // must not "restore" its decorative chip text as if it were content.
      const textNode = document.createTextNode(real != null ? real : '');
      span.parentNode?.replaceChild(textNode, span);
    }
    STATE.maskCount = 0;
    reportCount();
  }

  // Click a chip → reveal; click again → hide. Delegated, capture phase.
  // isTrusted: page scripts must not be able to force-reveal via synthetic clicks.
  document.addEventListener('click', (ev) => {
    if (!ev.isTrusted || !STATE.revealOnClick) return;
    const span = ev.target instanceof Element ? ev.target.closest(`[${MASK_ATTR}]`) : null;
    if (!span || !originals.has(span)) return;
    ev.preventDefault();
    ev.stopPropagation();
    if (span.hasAttribute('data-dlpg-revealed')) {
      span.removeAttribute('data-dlpg-revealed');
      span.textContent = maskChipText(span.getAttribute(MASK_ATTR));
    } else {
      span.setAttribute('data-dlpg-revealed', '1');
      span.textContent = originals.get(span);
    }
  }, true);

  // ── Scanning: full sweep + mutation-driven ─────────────────────────────────

  const pendingNodes = new Set();
  let scanTimer = null;
  let fullScanQueued = false;

  function scheduleFullScan() {
    fullScanQueued = true;
    scheduleFlush();
  }

  function scheduleFlush() {
    if (scanTimer !== null) return;
    scanTimer = setTimeout(() => {
      scanTimer = null;
      flush();
    }, 150); // let SPA streaming settle a beat
  }

  function collectTextNodes(root, out) {
    if (root.nodeType === Node.TEXT_NODE) {
      out.push(root);
      return;
    }
    if (root.nodeType !== Node.ELEMENT_NODE) return;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    let n;
    while ((n = walker.nextNode())) out.push(n);
  }

  function flush() {
    checkUrlChange();
    evaluateGuard(false);
    if (!isActive() || !STATE.maskOnPage) {
      pendingNodes.clear();
      fullScanQueued = false;
      return;
    }
    const batch = [];
    let fromFullScan = false;
    if (fullScanQueued) {
      fullScanQueued = false;
      fromFullScan = true;
      pendingNodes.clear();
      if (document.body) collectTextNodes(document.body, batch);
    } else {
      for (const root of pendingNodes) collectTextNodes(root, batch);
      pendingNodes.clear();
    }
    processInChunks(batch, 0, scanGeneration, fromFullScan);
  }

  function processInChunks(nodes, offset, generation, fromFullScan) {
    // Bail out when the world changed under us: settings toggled, page
    // suspended (login modal appeared), or masking disabled mid-scan.
    if (generation !== scanGeneration || !isActive() || !STATE.maskOnPage) return;
    const CHUNK = 300;
    const end = Math.min(offset + CHUNK, nodes.length);
    for (let i = offset; i < end; i++) processTextNode(nodes[i], fromFullScan);
    if (end < nodes.length) {
      const next = () => processInChunks(nodes, end, generation, fromFullScan);
      if (typeof requestIdleCallback === 'function') requestIdleCallback(next, { timeout: 500 });
      else setTimeout(next, 30);
    }
  }

  const observer = new MutationObserver((mutations) => {
    if (!STATE.ready) return;
    let touched = false;
    for (const mut of mutations) {
      if (mut.type === 'characterData') {
        const t = mut.target;
        if (t.parentElement && t.parentElement.closest(`[${MASK_ATTR}]`)) continue;
        ourTextNodes.delete(t); // content changed → re-eligible for scanning
        pendingNodes.add(t);
        touched = true;
      } else if (mut.type === 'childList') {
        for (const n of mut.addedNodes) {
          if (n.nodeType === Node.ELEMENT_NODE && n.hasAttribute?.(MASK_ATTR)) continue;
          if (n.nodeType === Node.TEXT_NODE && ourTextNodes.has(n)) continue;
          pendingNodes.add(n);
          touched = true;
        }
      }
    }
    if (touched) scheduleFlush();
  });

  function startObserver() {
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      characterData: true,
    });
  }
  if (document.documentElement) startObserver();
  else document.addEventListener('DOMContentLoaded', startObserver);

  // ── Paste redaction ────────────────────────────────────────────────────────

  // Returns the editable root the paste lands in, or null when the paste
  // target is not editable (then we must not touch the event or the DOM).
  function getEditableRoot(target) {
    if (target instanceof HTMLTextAreaElement) return target;
    if (target instanceof HTMLInputElement) {
      return PageGuard.isPasswordInput(target) ? null : target;
    }
    let el = target instanceof Element ? target : target?.parentElement;
    let root = null;
    while (el) {
      if (el.isContentEditable) root = el;
      el = el.parentElement;
    }
    return root;
  }

  // Registered on window in the capture phase at document_start, so it runs
  // before any page-registered paste listener can read the raw clipboard.
  window.addEventListener('paste', (event) => {
    if (!STATE.ready || !STATE.enabled || !STATE.redactPaste || siteDisabled()) return;
    // Re-check the guard synchronously — a login modal may have appeared
    // within the observer debounce window, or a password field may currently
    // be toggled to type="text".
    if (STATE.suspendReason || PageGuard.suspendReason()) return;

    const target = event.target;
    const editable = getEditableRoot(target);
    if (!editable) return; // nothing will be inserted; don't touch the page
    if (PageGuard.inPasswordForm(target)) return;

    const raw = event.clipboardData?.getData('text');
    if (!raw) return;
    const { text: sanitized, count } = DlpEngine.redactString(raw);
    if (count === 0) return;

    event.preventDefault();
    event.stopImmediatePropagation();
    insertText(editable, sanitized);
    STATE.pasteCount += count;
    console.info(`${LOG_PREFIX} redacted ${count} secret(s) from paste.`);
    reportCount();
    showToast(`${count} secret${count > 1 ? 's' : ''} redacted from paste`);
  }, true);

  function insertText(editable, text) {
    // execCommand routes through the editing pipeline, so React/ProseMirror
    // editors (ChatGPT, Claude, DeepSeek, Kimi, Lovable) treat it as typing.
    let inserted = false;
    try {
      inserted = document.execCommand('insertText', false, text);
    } catch (_e) { /* fall through */ }
    if (inserted) return;

    if (typeof editable.setRangeText === 'function') {
      const start = editable.selectionStart ?? 0;
      const end = editable.selectionEnd ?? 0;
      editable.setRangeText(text, start, end, 'end');
      editable.dispatchEvent(new Event('input', { bubbles: true }));
      return;
    }
    // Selection fallback — only inside the editable root, never on page DOM.
    const sel = window.getSelection();
    if (!sel || sel.rangeCount === 0) return;
    const range = sel.getRangeAt(0);
    if (!editable.contains(range.commonAncestorContainer)) return;
    range.deleteContents();
    range.insertNode(document.createTextNode(text));
    range.collapse(false);
    sel.removeAllRanges();
    sel.addRange(range);
    editable.dispatchEvent(new InputEvent('input', { bubbles: true, cancelable: true, data: text }));
  }

  // ── Status + badge ─────────────────────────────────────────────────────────

  let badgeTimer = null;
  function reportCount() {
    if (badgeTimer !== null) return;
    badgeTimer = setTimeout(() => {
      badgeTimer = null;
      try {
        chrome.runtime.sendMessage({
          type: 'DLP_BADGE',
          count: STATE.maskCount + STATE.pasteCount,
        });
      } catch (_e) { /* extension reloaded; page refresh will fix */ }
    }, 400);
  }

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message && message.type === 'DLP_GET_STATUS') {
      sendResponse({
        hostname: location.hostname,
        suspended: Boolean(STATE.suspendReason),
        reason: STATE.suspendReason,
        siteDisabled: siteDisabled(),
        maskCount: STATE.maskCount,
        pasteCount: STATE.pasteCount,
      });
    }
    return false;
  });

  // ── Toast ──────────────────────────────────────────────────────────────────

  function showToast(message) {
    const toast = document.createElement('div');
    toast.setAttribute('role', 'status');
    toast.style.cssText = [
      'position:fixed', 'top:16px', 'right:16px', 'z-index:2147483647',
      'background:#fde8e8', 'border:1px solid #e02424', 'color:#771d1d',
      'padding:10px 14px', 'border-radius:8px',
      'font:500 13px system-ui,sans-serif', 'max-width:340px',
      'box-shadow:0 4px 12px rgba(0,0,0,.15)', 'transition:opacity .3s',
    ].join(';');
    toast.textContent = `🛡️ DLP Guard — ${message}`;
    (document.body || document.documentElement).appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      setTimeout(() => toast.remove(), 350);
    }, 3500);
  }
})();
