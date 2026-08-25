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

  // Stable id for a built-in pattern so the options page can target it for
  // enable/disable/edit overrides. category + label + occurrence index makes
  // it stable across sessions (the generated list order is deterministic).
  function builtinList() {
    const extra = typeof DLP_EXTRA_PATTERNS !== 'undefined' ? DLP_EXTRA_PATTERNS : [];
    const all = [...DLP_PATTERNS, ...extra];
    const seen = new Map();
    return all.map((p) => {
      const base = `${p.category}:${p.label}`;
      const n = (seen.get(base) || 0) + 1;
      seen.set(base, n);
      return { ...p, id: `${base}#${n}` };
    });
  }

  function compile(enabledCategories, customTerms = [], userPatterns = [], builtinOverrides = []) {
    compiled = [];
    // overrides: array of { id, disabled?, source?, flags? } → map by id
    const ovMap = new Map();
    if (Array.isArray(builtinOverrides)) {
      for (const o of builtinOverrides) if (o && o.id) ovMap.set(o.id, o);
    }
    for (const p of builtinList()) {
      if (!enabledCategories[p.category]) continue;
      const ov = ovMap.get(p.id);
      if (ov && ov.disabled) continue;
      const source = ov && ov.source ? ov.source : p.source;
      const flags = ov && ov.flags ? ov.flags : p.flags;
      // an edited source may no longer contain the original literal; keep the
      // gate only if the new source still contains it, else drop it
      const edited = Boolean(ov && ov.source);
      let lit = p.lit || null;
      if (edited) lit = (lit && source.toLowerCase().includes(lit)) ? lit : null;
      try {
        compiled.push({
          re: new RegExp(source, flags),
          label: p.label,
          category: p.category,
          valueGroup: p.valueGroup,
          lit,
          validate: typeof p.validate === 'function' ? p.validate : null,
          mask: p.mask || null, // per-pattern mask-style override ('stars')
          // edited assignment patterns must not be gated by the shared
          // shipped-keyword prefilter (their keyword may have changed)
          overridden: edited,
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
    // User-defined patterns from the options page. Each may carry its own
    // category (including a brand-new one the user names); a category is run
    // unless it is explicitly disabled, and a per-pattern enabled:false skips
    // that one. These are the user's own config (not page content), but a
    // pathological regex could still slow pages — the options page
    // compile-tests + time-guards them on save.
    if (Array.isArray(userPatterns)) {
      for (const up of userPatterns) {
        if (!up || up.enabled === false || !up.source) continue;
        const cat = (up.category && String(up.category).trim()) || 'user';
        if (enabledCategories[cat] === false) continue;
        try {
          const vg = Number(up.valueGroup) > 0 ? Number(up.valueGroup) : 0;
          let flags = String(up.flags || '').replace(/[^gimsuy]/g, '');
          if (!flags.includes('g')) flags += 'g';
          if (vg > 0 && !flags.includes('d')) flags += 'd';
          compiled.push({
            re: new RegExp(up.source, flags),
            label: String(up.label || 'CUSTOM').toUpperCase().replace(/[^A-Z0-9]+/g, '_').slice(0, 40) || 'CUSTOM',
            category: cat,
            valueGroup: vg,
            lit: null,
            validate: null,
            mask: up.mask === 'affix' ? 'affix' : 'stars',
            user: true, // never gated by the shipped-keyword assignment prefilter
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
      // The shared assignment prefilter only knows the SHIPPED keywords, so it
      // must not gate an edited assignment built-in (or a user pattern in the
      // 'assignment' category) whose keyword it never saw.
      if (p.category === 'assignment' && !runAssignments && !p.overridden && !p.user) continue;
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
  // A user-defined category the user invented isn't in the map; give it high
  // precedence (1.5, just under the built-in 'user'/'custom') so a pattern the
  // user deliberately added wins overlaps against the shipped built-ins.
  const catPriority = (c) => (c in CATEGORY_PRIORITY ? CATEGORY_PRIORITY[c] : 1.5);

  // Sort by start; overlapping ranges are merged (extended), never dropped —
  // a partially-overlapping detection must not leave its tail unmasked.
  function mergeRanges(ranges) {
    ranges.sort((a, b) =>
      a.start - b.start || b.end - a.end ||
      catPriority(a.category) - catPriority(b.category));
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

  // Default file types worth scanning before an AI-chatbot upload: text and
  // credential files. Binary office/image formats are deliberately excluded
  // (they need format-specific parsers, out of scope for a text scan).
  const FILE_EXTENSIONS_DEFAULT = Object.freeze([
    'env', 'ini', 'cfg', 'conf', 'config', 'properties', 'toml', 'yaml', 'yml',
    'json', 'json5', 'xml', 'txt', 'text', 'md', 'csv', 'tsv', 'log',
    'pem', 'key', 'ppk', 'pub', 'crt', 'cer', 'asc', 'gpg',
    'sh', 'bash', 'zsh', 'fish', 'bat', 'cmd', 'ps1',
    'py', 'js', 'mjs', 'cjs', 'ts', 'jsx', 'tsx', 'rb', 'go', 'rs', 'java',
    'kt', 'cs', 'php', 'pl', 'lua', 'sql', 'tf', 'tfvars', 'hcl',
    'npmrc', 'netrc', 'htpasswd', 'credentials', 'dockercfg', 'kubeconfig',
    'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
  ]);

  // Should this file be read+scanned given the user's config?
  // exts: array of extensions or bare filenames (empty = scan any text file).
  // maxBytes: skip files larger than this. Pure — no DOM/file access.
  // Files with NO real extension (id_rsa, cert, server-key, .netrc, …) are
  // ALWAYS scanned: private keys and credentials are routinely saved without
  // one, and binary extensionless files are caught later by looksBinary().
  function shouldScanFile(name, sizeBytes, exts, maxBytes) {
    if (typeof sizeBytes === 'number' && maxBytes > 0 && sizeBytes > maxBytes) return false;
    const n = String(name || '').toLowerCase();
    const base = n.slice(n.lastIndexOf('/') + 1);
    const dot = base.lastIndexOf('.');
    if (dot <= 0) return true; // no extension, or a leading-dot dotfile → scan
    if (!Array.isArray(exts) || exts.length === 0) return true; // scan all under size
    for (let e of exts) {
      e = String(e).toLowerCase().trim().replace(/^\./, '');
      if (!e) continue;
      if (base === e || base.endsWith('.' + e)) return true;
    }
    return false;
  }

  // Cheap binary sniff: a run of NUL bytes means it's not text worth scanning.
  function looksBinary(text) {
    const n = Math.min(text.length, 8192);
    let nul = 0;
    for (let i = 0; i < n; i++) if (text.charCodeAt(i) === 0 && ++nul > 1) return true;
    return false;
  }

  return Object.freeze({
    CATEGORY_DEFAULTS, compile, findRanges, redactString, maskValue,
    minTextLen: () => minLen,
    FILE_EXTENSIONS_DEFAULT, shouldScanFile, looksBinary,
    // Options page: the built-in patterns with stable ids, for per-regex
    // enable/disable/edit. Returns plain descriptors (no compiled RegExp).
    builtins: () => builtinList().map((p) => ({
      id: p.id, label: p.label, category: p.category,
      source: p.source, flags: p.flags, valueGroup: p.valueGroup || 0,
      hasValidator: typeof p.validate === 'function',
    })),
  });
})();
