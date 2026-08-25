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
    dlp_exfilShield: true,
    dlp_cats: DlpEngine.CATEGORY_DEFAULTS,
    dlp_customTerms: [],
    dlp_userPatterns: [],
    dlp_exfilThreshold: 10,
    dlp_disabledSites: [],
  });

  const STATE = {
    ready: false,
    enabled: true,
    maskOnPage: true,
    redactPaste: true,
    revealOnClick: true,
    exfilShield: true,
    cats: { ...DlpEngine.CATEGORY_DEFAULTS },
    customTerms: [],
    userPatterns: [],
    exfilThreshold: 10,
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
    STATE.exfilShield = items.dlp_exfilShield !== false;
    STATE.cats = { ...DlpEngine.CATEGORY_DEFAULTS, ...(items.dlp_cats || {}) };
    STATE.customTerms = Array.isArray(items.dlp_customTerms) ? items.dlp_customTerms : [];
    STATE.userPatterns = Array.isArray(items.dlp_userPatterns) ? items.dlp_userPatterns : [];
    STATE.exfilThreshold = Number(items.dlp_exfilThreshold) > 0 ? Number(items.dlp_exfilThreshold) : 10;
    STATE.disabledSites = Array.isArray(items.dlp_disabledSites) ? items.dlp_disabledSites : [];
    DlpEngine.compile(STATE.cats, STATE.customTerms, STATE.userPatterns);
    scanGeneration++;
  }

  // Google Workspace editors do their own paste/DOM handling; rewriting their
  // editing surface breaks them (the foundation extension skipped them too).
  // The DOM-selector arm is gated on Google hostnames so an arbitrary page
  // can't disable protection by mimicking Workspace class names.
  function isWorkspaceEditor() {
    if (/(^|\.)docs\.google\.com$/.test(location.hostname)) return true;
    if (!/\.google\.com$/.test(location.hostname)) return false;
    return Boolean(document.querySelector(
      '.kix-appview-editor, .docs-texteventtarget-iframe, [id="docs-editor"]'));
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
    deliverEarlyPaste();
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => scheduleFullScan());
    } else {
      scheduleFullScan();
    }
  });

  const SETTINGS_KEYS = Object.keys(DEFAULTS);
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local') return;
    // Stats/log writes (bypass counters) must not trigger an unmask+rescan.
    if (!SETTINGS_KEYS.some((k) => k in changes)) return;
    chrome.storage.local.get(DEFAULTS, (items) => {
      applySettings(items);
      // Settings changed: start from a clean slate, then re-mask if active.
      unmaskAll();
      scheduleFullScan();
    });
  });

  // ── Login/registration page guard ──────────────────────────────────────────

  function evaluateGuard(initial) {
    const reason = PageGuard.suspendReason() ||
      (isWorkspaceEditor() ? 'Google Workspace editor (compatibility skip)' : null);
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
        border: 1px solid #f3b1b1;
        color: #9b1c1c;
        border-radius: 4px;
        padding: 0 3px;
        font-family: inherit;
        font-size: inherit;
        cursor: pointer;
        user-select: none;
        white-space: pre-wrap;
      }
      [${MASK_ATTR}]:hover { border-color: #e02424; }
      [${MASK_ATTR}][data-dlpg-revealed] {
        background: #fdf6b2;
        border-color: #c27803;
        color: #633112;
        user-select: text;
      }
    `;
    (document.head || document.documentElement).appendChild(style);
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
    if (!text || text.length < DlpEngine.minTextLen()) return;
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
      const hidden = text.slice(r.start, r.end);
      const masked = DlpEngine.maskValue(hidden, r.category);
      span.textContent = masked;
      span.title = `${r.label} hidden by DLP Guard` + (STATE.revealOnClick ? ' — click to reveal' : '');
      originals.set(span, { real: hidden, masked });
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
      const entry = originals.get(span);
      // A mask whose original was lost (e.g. framework cloned the element)
      // must not "restore" star text as if it were content.
      const textNode = document.createTextNode(entry ? entry.real : '');
      span.parentNode?.replaceChild(textNode, span);
    }
    STATE.maskCount = 0;
    reportCount();
  }

  // Click a chip → reveal; click again → hide. Delegated, capture phase.
  // isTrusted: page scripts must not be able to force-reveal via synthetic clicks.
  // Dedupe reveal counting by VALUE, not by span — rescans rebuild spans, and
  // re-revealing the same secret after a settings change is not a new bypass.
  const revealedValues = new Set();
  document.addEventListener('click', (ev) => {
    if (!ev.isTrusted || !STATE.revealOnClick) return;
    const span = ev.target instanceof Element ? ev.target.closest(`[${MASK_ATTR}]`) : null;
    if (!span || !originals.has(span)) return;
    ev.preventDefault();
    ev.stopPropagation();
    const entry = originals.get(span);
    if (span.hasAttribute('data-dlpg-revealed')) {
      span.removeAttribute('data-dlpg-revealed');
      span.textContent = entry.masked;
    } else {
      span.setAttribute('data-dlpg-revealed', '1');
      span.textContent = entry.real;
      if (!revealedValues.has(entry.real)) {
        revealedValues.add(entry.real);
        reportBypass('reveal', 1);
      }
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

  /** Last redacted paste, kept so the user can deliberately bypass it.
   *  Cleared when the offer toast goes away. */
  let lastPaste = null; // { editable, raw, sanitized, count }
  /** Armed bypass: content-bound — only a re-paste of EXACTLY this text,
   *  within the window, goes through as the original. */
  let armed = null; // { raw, count, until }
  /** A paste that arrived before settings loaded — held back (fail-closed)
   *  and delivered through the normal redaction flow once ready. */
  let earlyPaste = null; // { editable, raw }

  function deliverEarlyPaste() {
    const ep = earlyPaste;
    if (!ep) return;
    earlyPaste = null;
    if (!ep.editable.isConnected) return;
    const redact = isActive() && STATE.redactPaste &&
      !PageGuard.suspendReason() && !isWorkspaceEditor() &&
      !PageGuard.inPasswordForm(ep.editable);
    if (!redact) {
      insertText(ep.editable, ep.raw);
      return;
    }
    const { text: sanitized, count } = DlpEngine.redactString(ep.raw);
    insertText(ep.editable, count ? sanitized : ep.raw);
    if (count > 0) {
      STATE.pasteCount += count;
      reportCount();
      showToast(`${count} secret${count > 1 ? 's' : ''} redacted from paste`, {
        actionLabel: 'Paste original',
        onAction: bypassLastPaste,
      });
      lastPaste = { editable: ep.editable, raw: ep.raw, sanitized, count };
    }
  }

  // Registered on window in the capture phase at document_start, so it runs
  // before any page-registered paste listener can read the raw clipboard.
  window.addEventListener('paste', (event) => {
    // Synthetic paste events carry page-authored data and never run the
    // browser's default insertion — ignore them entirely (they must not be
    // able to consume the armed bypass or pop misleading toasts).
    if (!event.isTrusted) return;
    // Settings not loaded yet: fail CLOSED — hold the paste back and deliver
    // it through the normal redaction flow once storage arrives.
    if (!STATE.ready) {
      const editable = getEditableRoot(event.target);
      const raw = event.clipboardData?.getData('text');
      if (!editable || !raw) return;
      event.preventDefault();
      event.stopImmediatePropagation();
      earlyPaste = { editable, raw };
      return;
    }
    if (!STATE.enabled || !STATE.redactPaste || siteDisabled()) return;
    // Re-check the guard synchronously — a login modal may have appeared
    // within the observer debounce window, or a password field may currently
    // be toggled to type="text".
    if (STATE.suspendReason || PageGuard.suspendReason() || isWorkspaceEditor()) return;

    const target = event.target;
    const editable = getEditableRoot(target);
    if (!editable) return; // nothing will be inserted; don't touch the page
    if (PageGuard.inPasswordForm(target)) return;

    const raw = event.clipboardData?.getData('text');
    if (!raw) return;

    // Armed bypass consumption: same text, within the window. Even then the
    // event is cancelled and WE insert — page paste listeners never see it.
    if (armed && Date.now() < armed.until && raw === armed.raw) {
      const count = armed.count;
      armed = null;
      event.preventDefault();
      event.stopImmediatePropagation();
      insertText(editable, raw);
      reportBypass('paste', count);
      showToast('original pasted — bypass recorded');
      return;
    }

    const { text: sanitized, count } = DlpEngine.redactString(raw);
    if (count === 0) return;

    event.preventDefault();
    event.stopImmediatePropagation();
    insertText(editable, sanitized);
    STATE.pasteCount += count;
    console.info(`${LOG_PREFIX} redacted ${count} secret(s) from paste.`);
    reportCount();
    showToast(`${count} secret${count > 1 ? 's' : ''} redacted from paste`, {
      actionLabel: 'Paste original',
      onAction: bypassLastPaste,
    });
    // Set AFTER showToast — showing a new toast clears any previous offer.
    lastPaste = { editable, raw, sanitized, count };
  }, true);

  // Deliberate bypass: put the original clipboard text back in place of the
  // sanitized insertion. Counted only when it actually happens (in-place
  // replacement succeeds, or the armed re-paste is consumed).
  function bypassLastPaste() {
    const lp = lastPaste;
    if (!lp) return;
    lastPaste = null;
    const { editable, raw, sanitized, count } = lp;

    if (editable.isConnected &&
        (editable instanceof HTMLInputElement || editable instanceof HTMLTextAreaElement)) {
      try {
        const idx = editable.value.lastIndexOf(sanitized);
        if (idx !== -1) {
          editable.focus();
          editable.setSelectionRange(idx, idx + sanitized.length);
          if (!safeExecInsert(raw)) {
            editable.setRangeText(raw, idx, idx + sanitized.length, 'end');
            editable.dispatchEvent(new Event('input', { bubbles: true }));
          }
          reportBypass('paste', count);
          return;
        }
      } catch (_e) { /* email/number inputs have no selection API */ }
    } else if (editable.isConnected) {
      // contenteditable: extend the selection backwards over the sanitized
      // text. modify() steps by grapheme, not code unit, so step until the
      // selected string is long enough, then require exact equality.
      editable.focus();
      const sel = window.getSelection();
      const canWalk = sel && sel.rangeCount > 0 && sel.isCollapsed &&
        editable.contains(sel.anchorNode) &&
        typeof sel.modify === 'function' && sanitized.length <= 5000;
      if (canWalk) {
        let steps = 0;
        while (sel.toString().length < sanitized.length && steps < sanitized.length + 16) {
          sel.modify('extend', 'backward', 'character');
          steps++;
        }
        if (sel.toString() === sanitized && safeExecInsert(raw)) {
          reportBypass('paste', count);
          return;
        }
        sel.collapseToEnd();
      }
    }
    // In-place replacement not possible — arm a one-shot, content-bound
    // re-paste window instead.
    armed = { raw, count, until: Date.now() + 15000 };
    showToast('press Ctrl/Cmd+V again to paste the original (15s)');
  }

  function safeExecInsert(text) {
    try { return document.execCommand('insertText', false, text); }
    catch (_e) { return false; }
  }

  // ── Exfiltration shield ────────────────────────────────────────────────────
  // Copying a selection containing many detected secrets is blocked — the
  // clipboard gets a notice instead. Single-secret copies stay untouched;
  // this only guards against bulk exfiltration (threshold below).
  // configurable in the options page (dlp_exfilThreshold)

  function selectedTextForCopy() {
    const sel = window.getSelection();
    const text = sel ? sel.toString() : '';
    if (text.trim()) return text;
    const active = document.activeElement;
    if (active && (active instanceof HTMLTextAreaElement ||
        (active instanceof HTMLInputElement && !PageGuard.isPasswordInput(active)))) {
      const s = active.selectionStart ?? 0;
      const e = active.selectionEnd ?? 0;
      try { return active.value.substring(s, e); } catch (_e) { return ''; }
    }
    return '';
  }

  window.addEventListener('copy', (event) => {
    if (!event.isTrusted) return;
    if (!STATE.ready || !STATE.enabled || !STATE.exfilShield || siteDisabled()) return;
    if (STATE.suspendReason) return;
    const selected = selectedTextForCopy();
    if (!selected || selected.length < 60) return;
    const ranges = DlpEngine.findRanges(selected, Infinity);
    if (ranges.length < STATE.exfilThreshold) return;
    event.preventDefault();
    event.stopImmediatePropagation(); // page copy handlers must not override the block
    event.clipboardData?.setData(
      'text/plain',
      `[DLP Guard] Copy blocked: selection contained ${ranges.length} secrets.`);
    showToast(`blocked copying ${ranges.length} secrets (exfiltration shield)`);
    try {
      chrome.runtime.sendMessage({
        type: 'DLP_EXFIL_BLOCK',
        secrets: ranges.length,
        host: location.hostname,
      });
    } catch (_e) { /* extension reloaded */ }
  }, true);

  function reportBypass(kind, secrets) {
    try {
      chrome.runtime.sendMessage({
        type: 'DLP_BYPASS',
        kind,
        secrets: secrets | 0,
        host: location.hostname,
      });
    } catch (_e) { /* extension reloaded */ }
  }

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

  // The toast renders inside a CLOSED shadow root so page scripts cannot
  // reach or restyle the bypass button. Clicks are additionally verified by
  // geometry (a legit toast button is small and sits top-right) so a page
  // that moves/scales the host cannot clickjack a trusted click into a bypass.
  let activeToast = null; // { host, timer, hadAction }
  function dismissToast() {
    if (!activeToast) return;
    clearTimeout(activeToast.timer);
    activeToast.host.remove();
    if (activeToast.hadAction) lastPaste = null; // offer expired with the toast
    activeToast = null;
  }

  function showToast(message, action) {
    dismissToast();
    const host = document.createElement('div');
    host.style.cssText = 'position:fixed;top:16px;right:16px;z-index:2147483647;';
    const root = host.attachShadow({ mode: 'closed' });
    const box = document.createElement('div');
    box.setAttribute('role', 'status');
    box.style.cssText = [
      'display:flex', 'align-items:center', 'gap:10px',
      'background:#fde8e8', 'border:1px solid #e02424', 'color:#771d1d',
      'padding:10px 14px', 'border-radius:8px',
      'font:500 13px system-ui,sans-serif', 'max-width:380px',
      'box-shadow:0 4px 12px rgba(0,0,0,.15)', 'transition:opacity .3s',
    ].join(';');
    const text = document.createElement('span');
    text.textContent = `🛡️ DLP Guard — ${message}`;
    box.appendChild(text);
    if (action) {
      const btn = document.createElement('button');
      btn.textContent = action.actionLabel;
      btn.style.cssText = [
        'background:#e02424', 'color:#fff', 'border:none', 'border-radius:6px',
        'padding:5px 10px', 'font:600 12px system-ui,sans-serif',
        'cursor:pointer', 'white-space:nowrap', 'flex-shrink:0',
      ].join(';');
      // preventDefault on mousedown keeps focus (and the caret) in the
      // editable the paste went into — required for in-place replacement.
      btn.addEventListener('mousedown', (e) => e.preventDefault());
      btn.addEventListener('click', (e) => {
        if (!e.isTrusted) return;
        const r = btn.getBoundingClientRect();
        const sane = r.width > 0 && r.width <= 320 && r.height <= 60 &&
          r.top <= 120 && r.right >= window.innerWidth - 480;
        if (!sane) return; // host was moved/scaled — likely clickjacking
        const fn = action.onAction;
        // Direct removal — dismissToast would clear lastPaste before fn runs.
        clearTimeout(activeToast?.timer);
        host.remove();
        activeToast = null;
        fn();
      });
      box.appendChild(btn);
    }
    root.appendChild(box);
    (document.body || document.documentElement).appendChild(host);
    const timer = setTimeout(() => {
      box.style.opacity = '0';
      setTimeout(() => {
        // only dismiss if this toast is still the active one
        if (activeToast && activeToast.host === host) dismissToast();
        else host.remove();
      }, 350);
    }, action ? 8000 : 3500);
    activeToast = { host, timer, hadAction: Boolean(action) };
  }
})();
