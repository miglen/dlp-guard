// engine.js — pattern compilation + secret range detection.
// Loaded before content.js in the same isolated world. No DOM access here.
'use strict';

const DlpEngine = (() => {
  // category → settings key; infra & generic ship default-off (too noisy).
  const CATEGORY_DEFAULTS = Object.freeze({
    token: true,
    assignment: true,
    privatekey: true,
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

  let compiled = null; // [{re, label, category, valueGroup}]
  let assignmentPrefilter = null;

  function compile(enabledCategories) {
    compiled = [];
    for (const p of DLP_PATTERNS) {
      if (!enabledCategories[p.category]) continue;
      try {
        compiled.push({
          re: new RegExp(p.source, p.flags),
          label: p.label,
          category: p.category,
          valueGroup: p.valueGroup,
          lit: p.lit || null, // required literal word — cheap indexOf gate
        });
      } catch (_e) {
        // A pattern this browser build can't compile is skipped, never fatal.
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
  function findRanges(text) {
    if (!compiled || !text || text.length < 6) return [];

    const hasAssignChar = text.indexOf('=') !== -1 || text.indexOf(':') !== -1;
    const runAssignments =
      hasAssignChar && assignmentPrefilter && assignmentPrefilter.test(text);
    const lower = runAssignments ? text.toLowerCase() : '';

    const ranges = [];
    for (const p of compiled) {
      if (p.category === 'assignment') {
        if (!runAssignments) continue;
        if (p.lit && lower.indexOf(p.lit) === -1) continue;
      }
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
        ranges.push({ start, end, label: p.label });
        if (ranges.length > 500) return mergeRanges(ranges); // runaway page guard
      }
    }
    return mergeRanges(ranges);
  }

  // Sort by start; on overlap keep the earlier start, then the longer match.
  function mergeRanges(ranges) {
    ranges.sort((a, b) => a.start - b.start || b.end - a.end);
    const out = [];
    let lastEnd = -1;
    for (const r of ranges) {
      if (r.start >= lastEnd) {
        out.push(r);
        lastEnd = r.end;
      }
    }
    return out;
  }

  // Replace all detected secrets in a string with [HIDDEN_<LABEL>].
  // Returns {text, count}.
  function redactString(text) {
    const ranges = findRanges(text);
    if (ranges.length === 0) return { text, count: 0 };
    let out = '';
    let pos = 0;
    for (const r of ranges) {
      out += text.slice(pos, r.start) + `[HIDDEN_${r.label}]`;
      pos = r.end;
    }
    out += text.slice(pos);
    return { text: out, count: ranges.length };
  }

  return Object.freeze({ CATEGORY_DEFAULTS, compile, findRanges, redactString });
})();
