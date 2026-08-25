// yaml.js — a minimal YAML emitter + parser for DLP Guard's config export.
// NOT a general YAML implementation. It handles exactly the shapes the config
// uses: nested mappings, block sequences, and scalars (bool / number / null /
// string). Strings that could be ambiguous are double-quoted and escaped, so
// regex sources with backslashes, quotes, and colons round-trip safely.
// No external dependencies (MV3 CSP forbids them).
'use strict';

const DlpYaml = (() => {
  // ── Emit ────────────────────────────────────────────────────────────────────
  function needsQuote(s) {
    if (s === '') return true;
    if (/^[\s]|[\s]$/.test(s)) return true;                 // leading/trailing space
    if (/[:#\-?&*!|>'"%@`{}\[\],]/.test(s)) return true;    // YAML indicators
    if (/[\\\n\t]/.test(s)) return true;                    // escapes
    if (/^(true|false|null|yes|no|on|off|~)$/i.test(s)) return true; // reserved words
    if (/^[+-]?(\d|\.\d)/.test(s)) return true;             // looks numeric
    return false;
  }
  function quote(s) {
    return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\t/g, '\\t') + '"';
  }
  function scalar(v) {
    if (v === null || v === undefined) return 'null';
    if (typeof v === 'boolean') return v ? 'true' : 'false';
    if (typeof v === 'number') return Number.isFinite(v) ? String(v) : 'null';
    const s = String(v);
    return needsQuote(s) ? quote(s) : s;
  }
  function isPlainObject(v) {
    return v && typeof v === 'object' && !Array.isArray(v);
  }

  function emit(value, indent) {
    const pad = '  '.repeat(indent);
    if (Array.isArray(value)) {
      if (value.length === 0) return `${pad}[]\n`;
      let out = '';
      for (const item of value) {
        if (isPlainObject(item) || Array.isArray(item)) {
          const inner = emit(item, indent + 1);
          // splice the "- " onto the first emitted line
          const firstNl = inner.indexOf('\n');
          const firstLine = inner.slice(0, firstNl).replace(/^ {2}/, '');
          out += `${pad}- ${firstLine.trimStart()}\n` + inner.slice(firstNl + 1);
        } else {
          out += `${pad}- ${scalar(item)}\n`;
        }
      }
      return out;
    }
    if (isPlainObject(value)) {
      const keys = Object.keys(value);
      if (keys.length === 0) return `${pad}{}\n`;
      let out = '';
      for (const k of keys) {
        const v = value[k];
        const key = needsQuote(k) ? quote(k) : k;
        if (isPlainObject(v) && Object.keys(v).length) {
          out += `${pad}${key}:\n` + emit(v, indent + 1);
        } else if (Array.isArray(v) && v.length) {
          out += `${pad}${key}:\n` + emit(v, indent + 1);
        } else if (Array.isArray(v)) {
          out += `${pad}${key}: []\n`;
        } else if (isPlainObject(v)) {
          out += `${pad}${key}: {}\n`;
        } else {
          out += `${pad}${key}: ${scalar(v)}\n`;
        }
      }
      return out;
    }
    return `${pad}${scalar(value)}\n`;
  }

  function stringify(obj) {
    return emit(obj, 0);
  }

  // ── Parse ────────────────────────────────────────────────────────────────────
  function parseScalar(tok) {
    const t = tok.trim();
    if (t === '' || t === '~' || t === 'null') return null;
    if (t === 'true') return true;
    if (t === 'false') return false;
    if (t === '[]') return [];
    if (t === '{}') return {};
    if (t[0] === '"') return unquote(t);
    if (t[0] === "'") return t.slice(1, -1).replace(/''/g, "'");
    if (/^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$/.test(t)) return Number(t);
    return t;
  }
  function unquote(t) {
    let s = t;
    if (s[0] === '"') {
      // find the closing unescaped quote
      let end = 1, buf = '';
      while (end < s.length) {
        const c = s[end];
        if (c === '\\') {
          const n = s[end + 1];
          buf += n === 'n' ? '\n' : n === 't' ? '\t' : n;
          end += 2; continue;
        }
        if (c === '"') break;
        buf += c; end += 1;
      }
      return buf;
    }
    return s;
  }
  function splitKey(line) {
    // split "key: value" respecting a double-quoted key
    if (line[0] === '"') {
      let end = 1;
      while (end < line.length) {
        if (line[end] === '\\') { end += 2; continue; }
        if (line[end] === '"') break;
        end += 1;
      }
      const key = unquote(line.slice(0, end + 1));
      const rest = line.slice(end + 1).replace(/^\s*:\s?/, '');
      return [key, rest];
    }
    const idx = line.indexOf(':');
    if (idx === -1) return [line.trim(), undefined];
    return [line.slice(0, idx).trim(), line.slice(idx + 1).replace(/^\s/, '')];
  }

  // Tokenize into {indent, raw} lines, dropping blanks and comments.
  function tokenize(text) {
    const out = [];
    for (const rawLine of text.split('\n')) {
      const noComment = stripComment(rawLine);
      if (noComment.trim() === '') continue;
      const indent = noComment.match(/^ */)[0].length;
      out.push({ indent, raw: noComment.trim() });
    }
    return out;
  }
  function stripComment(line) {
    // remove a trailing # comment that is not inside quotes
    let inS = false, inD = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (c === '"' && !inS) inD = !inD;
      else if (c === "'" && !inD) inS = !inS;
      else if (c === '#' && !inS && !inD && (i === 0 || /\s/.test(line[i - 1]))) return line.slice(0, i);
    }
    return line;
  }

  // Does this line start a mapping (a real "key:" outside quotes)? A quoted or
  // plain scalar list item does not.
  function looksLikeMapping(s) {
    let inD = false, inS = false;
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (c === '"' && !inS) inD = !inD;
      else if (c === "'" && !inD) inS = !inS;
      else if (c === ':' && !inD && !inS && (i + 1 >= s.length || /\s/.test(s[i + 1]))) return true;
    }
    return false;
  }

  // Recursive-descent over the indented token list.
  function parseBlock(lines, start, indent) {
    // sequence?
    if (start < lines.length && lines[start].indent === indent && lines[start].raw.startsWith('- ')) {
      const arr = [];
      let i = start;
      while (i < lines.length && lines[i].indent === indent && (lines[i].raw === '-' || lines[i].raw.startsWith('- '))) {
        const rest = lines[i].raw === '-' ? '' : lines[i].raw.slice(2);
        if (rest === '' ) {
          const [val, next] = parseBlock(lines, i + 1, indent + 1);
          arr.push(val); i = next;
        } else if (looksLikeMapping(rest)) {
          // inline first mapping key on the "- key: val" line
          const synth = [{ indent: indent + 2, raw: rest }];
          // gather following deeper lines belonging to this item
          let j = i + 1;
          while (j < lines.length && lines[j].indent > indent) { synth.push({ indent: lines[j].indent, raw: lines[j].raw }); j++; }
          const [val] = parseBlock(synth, 0, indent + 2);
          arr.push(val); i = j;
        } else {
          arr.push(parseScalar(rest)); i += 1;
        }
      }
      return [arr, i];
    }
    // mapping
    const obj = {};
    let i = start;
    while (i < lines.length && lines[i].indent === indent && !lines[i].raw.startsWith('- ')) {
      const [key, rest] = splitKey(lines[i].raw);
      if (rest === undefined || rest === '') {
        // nested block follows (or empty)
        if (i + 1 < lines.length && lines[i + 1].indent > indent) {
          const [val, next] = parseBlock(lines, i + 1, lines[i + 1].indent);
          obj[key] = val; i = next;
        } else {
          obj[key] = null; i += 1;
        }
      } else {
        obj[key] = parseScalar(rest); i += 1;
      }
    }
    return [obj, i];
  }

  function parse(text) {
    const lines = tokenize(text);
    if (lines.length === 0) return {};
    const [val] = parseBlock(lines, 0, lines[0].indent);
    return val;
  }

  return Object.freeze({ stringify, parse });
})();

if (typeof module !== 'undefined' && module.exports) module.exports = DlpYaml;
