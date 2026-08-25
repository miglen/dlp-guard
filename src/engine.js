// engine.js — pattern compilation + secret range detection.
// Loaded before content.js in the same isolated world. No DOM access here.
'use strict';

const DlpEngine = (() => {
  // category → settings key; infra, generic & pii ship default-off (noisy).
  // custom = user-defined protected terms, always honored when terms exist.
  const CATEGORY_DEFAULTS = Object.freeze({
    token: true,
    assignment: true,
    privatekey: true,
    custom: true,
    user: true,
    pii: false,
    infra: false,
    generic: false,
  });

  // Values that look like placeholders/docs, not real secrets.
  const PLACEHOLDER_VALUES = new Set([
    'password', 'changeme', 'change_me', 'example', 'examples', 'secret',
    'yourkey', 'your_key', 'your_api_key', 'your-api-key', 'yourtoken',
    'your_token', 'xxxxxx', 'xxxxxxxx', 'redacted', 'undefined', 'null',
    'true', 'false', 'placeholder', 'insert_key_here', 'api_key_here',
    'string', 'value', 'token_here', 'key_here', 'process.env',
  ]);

  let compiled = null; // [{re, label, category, valueGroup, lit, validate, mask}]
  let assignmentPrefilter = null;
  let minLen = 6; // shortest text worth scanning; lowered when short custom terms exist

  function escapeRegex(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  function compile(enabledCategories, customTerms = [], userPatterns = []) {
    compiled = [];
    const extra = typeof DLP_EXTRA_PATTERNS !== 'undefined' ? DLP_EXTRA_PATTERNS : [];
    for (const p of [...DLP_PATTERNS, ...extra]) {
      if (!enabledCategories[p.category]) continue;
      try {
        compiled.push({
          re: new RegExp(p.source, p.flags),
          label: p.label,
          category: p.category,
          valueGroup: p.valueGroup,
          lit: p.lit || null, // required literal word — cheap indexOf gate
          validate: typeof p.validate === 'function' ? p.validate : null,
          mask: p.mask || null, // per-pattern mask-style override ('stars')
        });
      } catch (_e) {
        // A pattern this browser build can't compile is skipped, never fatal.
      }
    }
    // User-defined protected terms (server names, client names, codenames…).
    minLen = 6;
    if (enabledCategories.custom !== false && Array.isArray(customTerms)) {
      const terms = [...new Set(customTerms.map((t) => String(t).trim()).filter((t) => t.length >= 2))]
        .sort((a, b) => b.length - a.length);
      for (const term of terms) {
        try {
          compiled.push({
            re: new RegExp(`(?<![A-Za-z0-9_])${escapeRegex(term)}(?![A-Za-z0-9_])`, 'gi'),
            label: 'CUSTOM_TERM',
            category: 'custom',
            valueGroup: 0,
            // the lit gate lowercases via toLowerCase(), which can disagree
            // with the regex 'i' flag for some Unicode pairs — ASCII only
            lit: /^[\x00-\x7f]+$/.test(term) ? term.toLowerCase() : null,
            validate: null,
            mask: 'stars',
          });
          minLen = Math.min(minLen, Math.max(2, term.length));
        } catch (_e) { /* skip unusable term */ }
      }
    }
    // User-defined patterns from the options page. category 'user' is always
    // on; a per-pattern enabled:false skips it. These are the user's own
    // config (not page content), but a pathological regex could still slow
    // pages — the options page compile-tests + time-guards them on save.
    if (Array.isArray(userPatterns)) {
      for (const up of userPatterns) {
        if (!up || up.enabled === false || !up.source) continue;
        try {
          const vg = Number(up.valueGroup) > 0 ? Number(up.valueGroup) : 0;
          let flags = String(up.flags || '').replace(/[^gimsuy]/g, '');
          if (!flags.includes('g')) flags += 'g';
          if (vg > 0 && !flags.includes('d')) flags += 'd';
          compiled.push({
            re: new RegExp(up.source, flags),
            label: String(up.label || 'CUSTOM').toUpperCase().replace(/[^A-Z0-9]+/g, '_').slice(0, 40) || 'CUSTOM',
            category: 'user',
            valueGroup: vg,
            lit: null,
            validate: null,
            mask: up.mask === 'affix' ? 'affix' : 'stars',
          });
        } catch (_e) { /* skip unusable user pattern */ }
      }
    }
    try {
      assignmentPrefilter = new RegExp(DLP_ASSIGNMENT_PREFILTER_SOURCE, 'i');
    } catch (_e) {
      assignmentPrefilter = null;
    }
    return compiled.length;
  }

  function isPlaceholderValue(v) {
    const s = v.toLowerCase().replace(/["']/g, '');
    if (PLACEHOLDER_VALUES.has(s)) return true;
    if (/^(x+|\*+|\.+|-+|_+|#+)$/.test(s)) return true;   // xxxx / **** / ----
    if (/^<[^>]+>$/.test(s) || /^\$\{[^}]+\}$/.test(s)) return true; // <KEY> / ${KEY}
    if (/^(your|my|the|insert|enter|add|paste)[-_]/.test(s)) return true;
    return false;
  }

  // Find secret ranges in a plain string.
  // Returns non-overlapping [{start, end, label}] sorted by start.
  // maxRanges bounds work on pathological page nodes; paste redaction passes
  // Infinity — it must never silently leave later secrets unredacted.
  function findRanges(text, maxRanges = 500) {
    if (!compiled || !text || text.length < minLen) return [];

    const hasAssignChar = text.indexOf('=') !== -1 || text.indexOf(':') !== -1;
    // A broken prefilter must fail open (run the patterns), never fail closed.
    const runAssignments =
      hasAssignChar && (!assignmentPrefilter || assignmentPrefilter.test(text));
    let lowerCache = null;
    const lower = () => (lowerCache ??= text.toLowerCase());

    const ranges = [];
    for (const p of compiled) {
      if (p.category === 'assignment' && !runAssignments) continue;
      // literal gate (any category): a pattern whose required literal is
      // absent can't match — indexOf is far cheaper than a regex scan
      if (p.lit && lower().indexOf(p.lit) === -1) continue;
      p.re.lastIndex = 0;
      let m;
      while ((m = p.re.exec(text)) !== null) {
        if (m[0].length === 0) { p.re.lastIndex++; continue; } // zero-width guard
        let start = m.index;
        let end = m.index + m[0].length;
        if (p.valueGroup > 0) {
          const idx = m.indices && m.indices[p.valueGroup];
          if (!idx) continue;
          if (isPlaceholderValue(m[p.valueGroup])) continue;
          [start, end] = idx;
        }
        if (p.validate && !p.validate(text.slice(start, end), text, start)) continue;
        ranges.push({ start, end, label: p.label, category: p.category, mask: p.mask });
        if (ranges.length > maxRanges) return mergeRanges(ranges);
      }
    }
    return mergeRanges(ranges);
  }

  // For identical ranges, the category decides the mask style — token wins so
  // e.g. AWS_ACCESS_KEY_ID="ASIA…" keeps its identifiable prefix rather than
  // getting the assignment pattern's full-star mask.
  const CATEGORY_PRIORITY = { user: 0, custom: 1, token: 2, privatekey: 3, assignment: 4, pii: 5, infra: 6, generic: 7 };

  // Sort by start; overlapping ranges are merged (extended), never dropped —
  // a partially-overlapping detection must not leave its tail unmasked.
  function mergeRanges(ranges) {
    ranges.sort((a, b) =>
      a.start - b.start || b.end - a.end ||
      (CATEGORY_PRIORITY[a.category] ?? 9) - (CATEGORY_PRIORITY[b.category] ?? 9));
    const out = [];
    let lastEnd = -1;
    for (const r of ranges) {
      if (r.start >= lastEnd) {
        out.push(r);
        lastEnd = r.end;
      } else if (r.end > lastEnd) {
        out[out.length - 1].end = r.end;
        lastEnd = r.end;
      }
    }
    return out;
  }

  // ── Structure-preserving masks ───────────────────────────────────────────
  // The mask mirrors the shape of what it hides, never its content:
  //   token       → ASIA****************FSPM  (identifiable prefix/suffix kept)
  //   assignment  → ***********************   (pure-entropy value: stars only)
  //   private key → BEGIN line + star lines + END line
  // Star runs are capped so the mask never leaks the value's exact length.
  const STAR_CAP = 35;
  function starRun(n) {
    return '*'.repeat(Math.max(4, Math.min(n, STAR_CAP)));
  }

  function affixMask(hidden) {
    if (hidden.includes('\n')) return starRun(hidden.length);
    // keep up to 4 chars each side, but never reveal more than half the value
    // and always leave at least 3 stars in the middle
    const keep = Math.min(4, Math.floor((hidden.length - 3) / 2));
    if (keep < 2) return starRun(hidden.length);
    return hidden.slice(0, keep) + starRun(hidden.length - 2 * keep) + hidden.slice(-keep);
  }

  function maskValue(hidden, category, maskOverride) {
    if (maskOverride === 'stars') return starRun(hidden.length);
    if (maskOverride === 'affix') return affixMask(hidden);
    if (category === 'privatekey' && hidden.includes('\n')) {
      const lines = hidden.split('\n');
      let endIdx = -1;
      for (let i = lines.length - 1; i > 0; i--) {
        if (lines[i].trimStart().startsWith('-----END')) { endIdx = i; break; }
      }
      const bodyEnd = endIdx === -1 ? lines.length : endIdx;
      const body = lines.slice(1, bodyEnd).filter((l) => l.trim() !== '');
      const out = [lines[0], ...body.slice(0, 4).map((l) => starRun(l.length))];
      if (endIdx !== -1) out.push(lines[endIdx]);
      return out.join('\n');
    }
    // Token formats carry a public, non-secret vendor prefix (they come from a
    // public pattern DB) — keep 4 chars each side so the user can tell WHICH
    // credential is hidden. Assignment values are arbitrary entropy: all stars.
    if (category === 'token' && hidden.length >= 16 && !hidden.includes('\n')) {
      return affixMask(hidden);
    }
    return starRun(hidden.length);
  }

  // Replace all detected secrets in a string with structure-preserving masks.
  // Returns {text, count}.
  function redactString(text) {
    const ranges = findRanges(text, Infinity);
    if (ranges.length === 0) return { text, count: 0 };
    let out = '';
    let pos = 0;
    for (const r of ranges) {
      out += text.slice(pos, r.start) + maskValue(text.slice(r.start, r.end), r.category, r.mask);
      pos = r.end;
    }
    out += text.slice(pos);
    return { text: out, count: ranges.length };
  }

  return Object.freeze({
    CATEGORY_DEFAULTS, compile, findRanges, redactString, maskValue,
    minTextLen: () => minLen,
  });
})();
