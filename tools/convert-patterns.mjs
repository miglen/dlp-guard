#!/usr/bin/env node
// convert-patterns.mjs
// Converts secrets-patterns-db "leakin-regexes.yml" into src/patterns.generated.js
//
// Source dataset:
//   https://github.com/mazen160/secrets-patterns-db/blob/master/datasets/leakin-regexes.yml
//
// Usage:
//   node tools/convert-patterns.mjs <path-to-leakin-regexes.yml>
//
// What it does:
//   1. Parses the YAML (flat, well-known structure — no yaml dependency needed).
//   2. Classifies each pattern:
//        - assignment : "api[_-]?key(=| =|:| :)" label patterns → rewritten to
//                       capture the VALUE after the label so only the value is hidden.
//        - token      : concrete secret formats (AKIA…, xox…, sk_live_…, PEM headers…)
//        - infra      : cloud endpoint hostnames (cloudfront, elb, s3…) — default OFF
//        - generic    : catch-alls (any URL, any UUID…) — default OFF
//   3. Repairs known-broken regexes and strips inline flags JS doesn't support.
//   4. Wraps bare token patterns with word-ish boundaries to cut false positives.
//   5. Compile-tests every regex in JS; anything that still fails is dropped (reported).

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT_FILE = join(__dirname, '..', 'src', 'patterns.generated.js');

const yamlPath = process.argv[2];
if (!yamlPath) {
  console.error('usage: node tools/convert-patterns.mjs <leakin-regexes.yml>');
  process.exit(1);
}

// ── 1. Minimal YAML parse ────────────────────────────────────────────────────
// Structure is strictly:  - pattern:\n  name: X\n  regex: "..."\n  confidence: low
function parseYaml(text) {
  const entries = [];
  let cur = null;
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    if (line.startsWith('- pattern:')) {
      if (cur && cur.name && cur.regex != null) entries.push(cur);
      cur = {};
      continue;
    }
    if (!cur) continue;
    let m;
    if ((m = line.match(/^name:\s*(.+)$/))) {
      cur.name = unquote(m[1].trim());
    } else if ((m = line.match(/^regex:\s*(.+)$/))) {
      cur.regex = unquote(m[1].trim());
    } else if ((m = line.match(/^confidence:\s*(.+)$/))) {
      cur.confidence = unquote(m[1].trim());
    }
  }
  if (cur && cur.name && cur.regex != null) entries.push(cur);
  return entries;
}

function unquote(s) {
  if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) {
    // YAML double-quoted: unescape \" and \\
    return s.slice(1, -1).replace(/\\(["\\])/g, '$1');
  }
  if (s.length >= 2 && s.startsWith("'") && s.endsWith("'")) {
    return s.slice(1, -1).replace(/''/g, "'");
  }
  return s;
}

// ── 2. Repairs for known-broken source regexes ───────────────────────────────
// Keyed by the exact broken source string from the dataset.
const REPAIRS = new Map([
  // Telegram bot token — missing backslash on \d, {34,34} nonstandard
  ['d{5,}:A[0-9a-z_-]{34,34}', '\\d{5,}:A[A-Za-z0-9_-]{34}'],
  // Google API key wrapped in a broken nested character class
  ["(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0-9a-z-_]{35}]['\"]",
   "(google|gcp|youtube|drive|yt)(.{0,20})?['\"]AIza[0-9A-Za-z\\-_]{35}['\"]"],
  // Braintree token — bare $ are literals in the token, must be escaped in JS
  ['access_token$production$[0-9a-z]{16}$[0-9a-f]{32}',
   'access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}'],
  ['(access_token$production$[0-9a-z]{16}$[0-9a-f]{32})',
   '(access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32})'],
  // AWS ARN — greedy ".+" would swallow all text after the ARN; cap to ARN charset
  ['arn:aws:[a-z0-9-]+:[a-z]{2}-[a-z]+-[0-9]+:[0-9]+:.+',
   'arn:aws:[a-z0-9-]+:[a-z]{2}-[a-z]+-[0-9]+:[0-9]+:[A-Za-z0-9\\-_/:.*]+'],
  // Combined BEGIN/END armor-marker pattern → BEGIN-only literal form, so it
  // classifies as privatekey and gets the whole-block extension (covers
  // EC/DSA keys the four dedicated header patterns miss). A lone END marker
  // is not a secret, so dropping the END alternative loses nothing.
  ['(?i)-----(?:(?:BEGIN|END) )(?:(?:EC|PGP|DSA|RSA|OPENSSH).)?PRIVATE.KEY(.BLOCK)?-----',
   '(?i)-----BEGIN (?:(?:EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY( BLOCK)?-----'],
]);

// Broken beyond repair, or duplicates of an already-working pattern.
const DROP_SOURCES = new Set([
  '(W(?:[a-f0-9]{32}(-us[0-9]{1,2}))a-zA-Z0-9)', // mangled Mailchimp duplicate
]);

// ── 3. Category classification ───────────────────────────────────────────────
const ASSIGNMENT_TAIL = /\(=\| =\|:\| :\)$/;

// Hostname/endpoint discovery patterns — useful for recon tools, noisy for a
// page-masking DLP. Shipped but default-disabled.
const INFRA_NAME = /\b(api gateway|cloudfront|ec2|elb|elasticcache|rds|s3 (bucket|endpoint)|aws_s3|blob|digitalocean|trello url|possible urls)\b/i;

// Catch-alls that would repaint half the internet. Default-disabled.
const GENERIC_SOURCES = new Set([
  "http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*(),]|(?:%[0-9a-fA-F][0-9a-fA-F]))[^><'\" \\n)]+",
  '([a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12})', // any UUID
  '([a-zA-Z0-9]{1,2}([a-zA-Z0-9]{50})[a-zA-Z0-9]{1,2}$)', // any 52-char blob
  '[a-zA-Z0-9]{1,2}([E][A-Z]{1}[a-zA-Z0-9_-]{78})[a-zA-Z0-9]{1,2}$',
]);

// Label-only word patterns (match a key NAME with no value) → treat as assignment.
const LABEL_ONLY_SOURCES = new Set([
  '(?i)(?:accesskeyid|secretaccesskey|aws_access_key_id|aws_secret_access_key)',
  '(?i)(?:google_client_id|google_client_secret|google_client_token)',
]);

// Value part appended to assignment/label patterns. Captures the secret value
// after ":" or "=" (optionally quoted). 6+ chars of typical secret alphabet.
const VALUE_PART = '\\s*[:=]\\s*["\']?([A-Za-z0-9_\\-/+=.]{6,})';

function classify(name, source) {
  if (ASSIGNMENT_TAIL.test(source) || LABEL_ONLY_SOURCES.has(source)) return 'assignment';
  if (GENERIC_SOURCES.has(source)) return 'generic';
  if (INFRA_NAME.test(name)) return 'infra';
  if (/-----BEGIN/.test(source)) return 'privatekey';
  return 'token';
}

// ── 4. JS-ification ──────────────────────────────────────────────────────────
function toJsRegex(source) {
  let flags = 'g';
  let src = source;
  if (src.includes('(?i)')) {
    flags += 'i';
    src = src.replaceAll('(?i)', '');
  }
  src = src.replaceAll('(?-i)', ''); // JS has no inline flag disabling
  return { src, flags };
}

// Wrap bare token patterns with boundaries so e.g. SK[0-9a-f]{32} doesn't fire
// inside longer hex blobs. Skip when the pattern itself anchors or starts with
// a non-word char.
function addBoundaries(src) {
  if (src.startsWith('^') || src.endsWith('$')) return src;
  const startsWordish = /^[[(a-zA-Z0-9\\]/.test(src) && !src.startsWith('\\b');
  if (!startsWordish) return src;
  return `(?<![A-Za-z0-9_])(?:${src})(?![A-Za-z0-9_])`;
}

// ── Main ─────────────────────────────────────────────────────────────────────
const raw = readFileSync(yamlPath, 'utf8');
const entries = parseYaml(raw);
console.log(`parsed ${entries.length} patterns from dataset`);

// Supplemental patterns the dataset lacks but real-world usage requires
// (AWS STS credentials always travel with a session token).
entries.push(
  { name: 'aws_session_token', regex: 'aws[_-]?session[_-]?token(=| =|:| :)', confidence: 'low' },
  { name: 'session_token', regex: 'session[_-]?token(=| =|:| :)', confidence: 'low' },
);

const seen = new Set();
const out = [];
const dropped = [];

// Longest literal word (≥3 chars) in an assignment label base — used as a
// cheap indexOf gate before running the full regex. null → no reliable literal.
function literalGate(base) {
  if (base.includes('|')) return null; // alternation → no single required word
  // character classes, brace counts, and escapes are not required literals
  const stripped = base
    .replace(/\[(?:[^\]\\]|\\.)*\]/g, ' ')
    .replace(/\{[0-9,]*\}/g, ' ')
    .replace(/\\./g, ' ');
  const words = [];
  for (const m of stripped.matchAll(/[a-z0-9]{3,}/gi)) {
    let w = m[0];
    // a trailing char quantified with ? or * is optional — drop it
    const next = stripped[m.index + w.length];
    if (next === '?' || next === '*') w = w.slice(0, -1);
    if (w.length >= 3) words.push(w.toLowerCase());
  }
  if (words.length === 0) return null;
  return words.reduce((a, b) => (b.length > a.length ? b : a));
}

for (const e of entries) {
  let source = e.regex;
  if (DROP_SOURCES.has(source)) { dropped.push([e.name, 'known-broken duplicate']); continue; }
  if (REPAIRS.has(source)) source = REPAIRS.get(source);
  // ".-_" inside a class is an accidental RANGE (0x2E–0x5F: includes :;=digits).
  // The dataset authors meant literal dot/dash/underscore.
  source = source.replaceAll('.-_', '._-');

  const category = classify(e.name, source);
  let valueGroup = 0;

  if (category === 'assignment') {
    // trim: a stray trailing space in the label would make 'key: value' unmatchable
    const base = source.replace(ASSIGNMENT_TAIL, '').trim();
    const { src: jsBase, flags } = toJsRegex(base);
    // group 1 = the value; label patterns contain no capture groups of their own
    const groupCount = countGroups(jsBase);
    source = `(?<![A-Za-z0-9_])(?:${jsBase})${VALUE_PART}`;
    valueGroup = groupCount + 1;
    pushPattern(e.name, category, source, flags.includes('i') ? 'gi' : 'gi', valueGroup, jsBase, literalGate(jsBase));
    continue;
  }

  let { src, flags } = toJsRegex(source);
  // Cap unbounded leading class quantifiers (any category) — an uncapped
  // leading [class]+/[class]* is O(n²) on runs of chars from that class;
  // capping makes the worst case O(n·100).
  src = src
    .replace(/^\[([^\]]+)\]\+/, '[$1]{1,100}')
    .replace(/^\[([^\]]+)\]\*/, '[$1]{0,100}');
  // extract the literal gate BEFORE the privatekey/boundary rewrites below —
  // they add alternations that would defeat extraction, but the required
  // literals are unchanged by them
  const gate = literalGate(src);
  if (category === 'privatekey') {
    // The dataset patterns match only the "-----BEGIN …-----" header line.
    // Extend them to swallow the whole block: body = anything up to the next
    // real armor marker (tempered [\s\S] — a 5-dash run that is NOT a
    // BEGIN/END marker stays inside the body), plus the END marker when
    // present. A header with no footer swallows the rest of the text node —
    // deliberate fail-closed behavior for key material.
    src = `${src}(?:(?!-----(?:BEGIN|END))[\\s\\S])*(?:-----END[A-Za-z ]*-----)?`;
  }
  const bounded = addBoundaries(src);
  // literal gate for every category — the engine skips a pattern with a
  // cheap indexOf before ever running its regex
  pushPattern(e.name, category, bounded, flags, 0, undefined, gate);
}

function countGroups(src) {
  // count capturing groups: "(" not followed by "?" and not escaped/inside class
  let n = 0, inClass = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === '\\') { i++; continue; }
    if (inClass) { if (c === ']') inClass = false; continue; }
    if (c === '[') { inClass = true; continue; }
    if (c === '(' && src[i + 1] !== '?') n++;
  }
  return n;
}

function pushPattern(name, category, source, flags, valueGroup, base, lit = null) {
  const key = `${source}\0${flags}`;
  if (seen.has(key)) { dropped.push([name, 'duplicate']); return; }
  // compile test
  let re;
  try {
    re = new RegExp(source, flags + (valueGroup ? 'd' : ''));
  } catch (err) {
    dropped.push([name, `compile error: ${err.message}`]);
    return;
  }
  // smoke test: must not match trivial prose (cheap FP sanity check)
  const prose = 'The quick brown fox jumps over the lazy dog. Hello world, this is a normal sentence about nothing in particular with numbers 12345 and http and key words.';
  re.lastIndex = 0;
  if (re.test(prose)) { dropped.push([name, 'matches plain prose — too generic']); return; }
  seen.add(key);
  out.push({ name, category, source, flags: flags + (valueGroup ? 'd' : ''), valueGroup, base, lit });
}

// label used in the mask chip / paste placeholder
function toLabel(name) {
  return name.toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 40);
}

const counts = {};
for (const p of out) counts[p.category] = (counts[p.category] || 0) + 1;
console.log('kept by category:', counts);
console.log(`dropped: ${dropped.length}`);
for (const [n, why] of dropped.slice(0, 50)) console.log(`  - ${n}: ${why}`);

const banner = `// patterns.generated.js — GENERATED FILE, do not edit by hand.
// Generated by tools/convert-patterns.mjs from secrets-patterns-db leakin-regexes.yml
// https://github.com/mazen160/secrets-patterns-db/blob/master/datasets/leakin-regexes.yml
// ${out.length} patterns. Categories: ${Object.entries(counts).map(([k, v]) => `${k}=${v}`).join(', ')}
'use strict';

// Each entry: { name, label, category, source, flags, valueGroup }
// valueGroup > 0 → only that capture group (the secret value) is hidden.
// category: token | assignment | privatekey | infra | generic
const DLP_PATTERNS = [
`;

const body = out
  .map((p) =>
    `  { name: ${JSON.stringify(p.name)}, label: ${JSON.stringify(toLabel(p.name))}, category: ${JSON.stringify(p.category)}, source: ${JSON.stringify(p.source)}, flags: ${JSON.stringify(p.flags)}, valueGroup: ${p.valueGroup}, lit: ${JSON.stringify(p.lit ?? null)} },`)
  .join('\n');

// Combined prefilter for assignment patterns: one pass over the text decides
// whether any of the ~700 individual assignment regexes need to run at all.
const assignmentBases = out.filter((p) => p.category === 'assignment' && p.base).map((p) => p.base);
const prefilterSource = `(?<![A-Za-z0-9_])(?:${assignmentBases.join('|')})\\s*[:=]`;
new RegExp(prefilterSource, 'i'); // compile test — throws if broken

const footer = `];

// One-pass prefilter over all assignment labels — run the per-pattern regexes
// only when this matches. Keeps scanning cheap on pages full of ":" and "=".
const DLP_ASSIGNMENT_PREFILTER_SOURCE = ${JSON.stringify(prefilterSource)};
`;

mkdirSync(dirname(OUT_FILE), { recursive: true });
writeFileSync(OUT_FILE, banner + body + footer);
console.log(`wrote ${OUT_FILE} (${out.length} patterns, prefilter ${prefilterSource.length} chars)`);
