#!/usr/bin/env node
// test-patterns.mjs — sanity tests for the generated pattern library + engine.
// Runs in Node (same V8 regex engine as Chrome). Exits non-zero on failure.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const src = (f) => readFileSync(join(__dirname, '..', 'src', f), 'utf8');

// Evaluate the plain content-script files in this scope.
const sandbox = {};
const code = `${src('patterns.generated.js')}\n${src('engine.js')}\n
  sandbox.DLP_PATTERNS = DLP_PATTERNS; sandbox.DlpEngine = DlpEngine;`;
new Function('sandbox', code)(sandbox);
const { DLP_PATTERNS, DlpEngine } = sandbox;

let pass = 0, fail = 0;
function expect(name, cond, detail = '') {
  if (cond) { pass++; }
  else { fail++; console.error(`  ✗ ${name} ${detail}`); }
}

// ── 1. every pattern compiles ────────────────────────────────────────────────
for (const p of DLP_PATTERNS) {
  try { new RegExp(p.source, p.flags); }
  catch (e) { expect(`compile ${p.name}`, false, e.message); }
}
console.log(`compile check: ${DLP_PATTERNS.length} patterns`);

// ── 2. ReDoS smoke test — worst-case adversarial inputs must stay fast ───────
const nasty = [
  'a'.repeat(20000),
  ('api_key: ' + 'x'.repeat(5000) + ' ').repeat(3),
  'aws '.repeat(4000) + '"' + 'a'.repeat(39),
  ':::===:::'.repeat(2000),
  ('facebook ' + '"'.repeat(30)).repeat(300),
];
DlpEngine.compile({ token: true, assignment: true, privatekey: true, infra: true, generic: true });
for (const [i, text] of nasty.entries()) {
  const t0 = performance.now();
  DlpEngine.findRanges(text);
  const ms = performance.now() - t0;
  expect(`redos-${i} under 200ms`, ms < 200, `took ${ms.toFixed(1)}ms`);
}

// ── 3. true positives ────────────────────────────────────────────────────────
DlpEngine.compile({ token: true, assignment: true, privatekey: true, infra: false, generic: false });
const positives = [
  ['AWS key',          'creds: AKIAIOSFODNN7EXAMPLE done'],
  ['Slack token',      'token xoxb-123456789012-abcdefghijkl here'],
  ['Stripe live key',  'use sk_live_abcdefghijklmnopqrstuvwx please'],
  ['Google API key',   'key AIzaSyA1234567890abcdefghijklmnopqrstuv end'],
  ['JWT',              'jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N65N65cp6GSdC1fCzX2 ok'],
  ['private key',      'oops -----BEGIN RSA PRIVATE KEY----- leaked'],
  ['assignment',       'api_key: 8f2a9c1d4e5b6a7f8091a2b3c4d5e6f7'],
  ['assignment eq',    'export DATABASE_PASSWORD=Sup3rS3cretV4lue99'.replace('DATABASE_PASSWORD', 'db_password')],
  ['github token',     "github = 'ghabcdef1234567890abcdef1234567890abc'"],
  ['heroku uuid',      'heroku_key: 12345678-ABCD-ABCD-ABCD-123456789ABC'],
  ['twilio',           'sid SKabcdef0123456789abcdef0123456789 x'],
  ['sendgrid',         'SG.abcdefghijklmnop.qrstuvwxyz0123456789abcdef x'],
  ['mailgun',          'key-abcdef0123456789abcdef0123456789 x'],
  ['telegram bot',     'bot 12345678:AAbbccddeeffgghhiijjkkllmmnnooppqqr x'],
  ['facebook token',   'EAACEdEose0cBA1234567890abcdefghijk x'],
];
for (const [name, text] of positives) {
  const r = DlpEngine.findRanges(text);
  expect(`detects ${name}`, r.length > 0, `in: ${text.slice(0, 60)}`);
}

// ── 4. true negatives — normal chat/page text must NOT match ─────────────────
const negatives = [
  ['prose',        'Hello! How can I help you today? Let me explain how transformers work.'],
  ['code sample',  'for (let i = 0; i < arr.length; i++) { sum += arr[i]; }'],
  ['css',          'body { margin: 0; padding: 10px; color: #333333; }'],
  ['json config',  '{"temperature": 0.7, "max_tokens": 4096, "stream": true}'],
  ['markdown',     '# Title\n- item one\n- item two\nSee the docs for details.'],
  ['time',         'The meeting is at 14:30 and ends around 16:00 today.'],
  ['url plain',    'Check https://example.com/docs/getting-started for more.'],
  ['placeholder',  'api_key: YOUR_API_KEY and password: ********'],
  ['placeholder2', 'secret_key: <your-key-here> token: ${API_TOKEN}'],
  ['math',         'x = 42 and y = 1337 so z = 55.5'],
];
for (const [name, text] of negatives) {
  const r = DlpEngine.findRanges(text);
  expect(`ignores ${name}`, r.length === 0,
    r.length ? `matched: ${r.map((x) => x.label).join(',')}` : '');
}

// ── 5. redactString ──────────────────────────────────────────────────────────
{
  const { text, count } = DlpEngine.redactString(
    'here AKIAIOSFODNN7EXAMPLE and sk_live_abcdefghijklmnopqrstuvwx end');
  expect('redactString count', count === 2, `count=${count}`);
  expect('redactString no leak', !text.includes('AKIAIOSFODNN7EXAMPLE') && !text.includes('sk_live_'), text);
  expect('redactString keeps rest', text.startsWith('here ') && text.endsWith(' end'), text);
}

// ── 6. value-group masking hides only the value ──────────────────────────────
{
  const s = 'config api_key: Zx9Yw8Vu7Tt6Ss5Rr4Qq3 more';
  const ranges = DlpEngine.findRanges(s);
  expect('assignment matched', ranges.length === 1, JSON.stringify(ranges));
  if (ranges.length === 1) {
    const hidden = s.slice(ranges[0].start, ranges[0].end);
    expect('only value hidden', hidden === 'Zx9Yw8Vu7Tt6Ss5Rr4Qq3', `hidden="${hidden}"`);
  }
}

// ── 7. category toggles respected ────────────────────────────────────────────
{
  DlpEngine.compile({ token: false, assignment: false, privatekey: false, infra: false, generic: false });
  const r = DlpEngine.findRanges('AKIAIOSFODNN7EXAMPLE api_key: 8f2a9c1d4e5b6a7f8091');
  expect('all-off finds nothing', r.length === 0, JSON.stringify(r));
  DlpEngine.compile({ token: true, assignment: true, privatekey: true, infra: false, generic: false });
}

// ── 8. overlapping detections merge (never drop a tail) ──────────────────────
{
  // assignment value and token pattern overlap on the same key
  const s = 'aws_key: AKIAIOSFODNN7EXAMPLE tail';
  const ranges = DlpEngine.findRanges(s);
  const covered = ranges.some((r) => s.slice(r.start, r.end).includes('AKIAIOSFODNN7EXAMPLE'));
  expect('overlap union covers full token', covered, JSON.stringify(ranges));
  const { text } = DlpEngine.redactString(s);
  expect('no partial token survives', !text.includes('AKIA'), text);
}

// ── 9. redactString is uncapped — every secret in a huge paste is redacted ───
{
  const big = 'AKIAIOSFODNN7EXAMPLE '.repeat(520);
  const { text, count } = DlpEngine.redactString(big);
  expect('uncapped redaction count', count >= 520, `count=${count}`);
  expect('uncapped redaction no leak', !text.includes('AKIA'), '');
}

// ── 10. assignment base trimming (dataset labels with stray spaces) ──────────
{
  const r = DlpEngine.findRanges('magento_auth_username: someuser1234');
  expect('trimmed assignment base matches', r.length === 1, JSON.stringify(r));
}

// ── 11. private key blocks are hidden in full, not just the header ───────────
{
  const pem = `-----BEGIN RSA PRIVATE KEY-----
MIIBOAIBAAJARsF2wfXtjllRR8nnz8+CLULn0bqgZtYktJB2BdcB5bw6OYmmDVCc
TeTC3VXZATdSqNA6WDWCkSVinC05uYEOEwIDAQABAkArUAaYmSkAeKCO54Pl7Ert
1gT+l9XU3cW+WqhEzuc0cC4Eiqe9phpdiQXNosI60a8YyeyBUjCtQGFwbJ1Kl8Hh
AiEAioOWu1s5nbB6ioOXdhbW4Ov5xfI62TYJNxdz656/njsCIQCCxRfwRVfDcC0h
aKMjV5PzfUUCIHX2s4yEERJ1K9EVwfE/5bH1E+TERb3j21UZZphjGv15AiBBs0w5
WRuPspPXIAHPKrjEHkUsgDZHW/V0fJWbIjJarw==
-----END RSA PRIVATE KEY-----`;
  const ranges = DlpEngine.findRanges(pem);
  expect('pem single merged range', ranges.length === 1, JSON.stringify(ranges));
  if (ranges.length === 1) {
    expect('pem covers whole block', ranges[0].start === 0 && ranges[0].end === pem.length,
      `covered [${ranges[0].start},${ranges[0].end}] of ${pem.length}`);
  }
  const { text } = DlpEngine.redactString('context before\n' + pem + '\nafter');
  expect('pem body never survives redaction', !/MIIBOA|AiEAio|WRuPsp/.test(text), text.slice(0, 200));
  expect('pem surroundings survive', text.startsWith('context before') && text.endsWith('after'), '');

  // other key types, including EC (covered only by the repaired generic pattern)
  for (const kind of ['OPENSSH', 'EC', 'DSA']) {
    const block = `-----BEGIN ${kind} PRIVATE KEY-----\nb3BlbnNzaEtFWWZha2U=\nZmFrZWJvZHlmYWtlYm9keQ==\n-----END ${kind} PRIVATE KEY-----`;
    const r = DlpEngine.findRanges(block);
    const full = r.length >= 1 && r[0].start === 0 && r[r.length - 1].end === block.length;
    expect(`${kind} key block fully covered`, full, JSON.stringify(r));
  }

  // adversarial: header followed by dash floods must stay fast and bounded
  const t0 = performance.now();
  DlpEngine.findRanges('-----BEGIN RSA PRIVATE KEY-----' + '-'.repeat(20000));
  expect('pem dash-flood under 200ms', performance.now() - t0 < 200, '');

  // a 5+ dash run INSIDE the body must not truncate the block
  const inner = '-----BEGIN RSA PRIVATE KEY-----\nZmFrZQ==\n------ inner dashes ------\nc2VjcmV0Ym9keQ==\n-----END RSA PRIVATE KEY-----';
  const ri = DlpEngine.findRanges(inner);
  expect('inner dash run stays inside block',
    ri.length === 1 && ri[0].start === 0 && ri[0].end === inner.length, JSON.stringify(ri));

  // two blocks in one text node: the first match must not swallow the second header
  const two = '-----BEGIN RSA PRIVATE KEY-----\nYWFh\n-----END RSA PRIVATE KEY-----\nplain text between\n-----BEGIN EC PRIVATE KEY-----\nYmJi\n-----END EC PRIVATE KEY-----';
  const rt = DlpEngine.findRanges(two);
  const covered2 = rt.length >= 1 &&
    !rt.some((r) => two.slice(r.start, r.end).includes('plain text between')) &&
    rt.some((r) => two.slice(r.start, r.end).includes('YWFh')) &&
    rt.some((r) => two.slice(r.start, r.end).includes('YmJi'));
  expect('two blocks are separate matches, text between stays visible', covered2, JSON.stringify(rt));
}

// ── 12. page guard URL matrix ─────────────────────────────────────────────────
{
  const guardCode = src('pageguard.js');
  function guardFor(hostname, pathname) {
    const sandbox2 = {};
    const stubDoc = { querySelector: () => null, querySelectorAll: () => [], title: '' };
    const stubLoc = { hostname, pathname, search: '', hash: '' };
    new Function('location', 'document', 'Node', 'HTMLInputElement', 'sandbox',
      `${guardCode}\nsandbox.PageGuard = PageGuard;`)(stubLoc, stubDoc, { TEXT_NODE: 3 }, class {}, sandbox2);
    return sandbox2.PageGuard.suspendReason();
  }
  const mustAllow = [
    ['chatgpt.com', '/c/6789abcd-1234'],
    ['claude.ai', '/chat/6789abcd-1234'],
    ['chat.deepseek.com', '/'],
    ['www.kimi.com', '/'],
    ['lovable.dev', '/projects/my-login-page-clone'],
    ['chatgpt.com', '/share/how-to-login-securely'],
    ['gemini.google.com', '/app/abc123'],
    ['github.com', '/settings/tokens'],
    ['docs.google.com', '/document/d/abc123/edit'],
    ['example.com', '/blog/authors/jane'],
  ];
  const mustSuspend = [
    ['accounts.google.com', '/'],
    ['example.com', '/login'],
    ['example.com', '/signup'],
    ['app.example.com', '/users/sign_in'],
    ['example.com', '/oauth2/authorize'],
    ['join.slack.com', '/'],
    ['example.com', '/reset-password'],
  ];
  for (const [h, p] of mustAllow) {
    expect(`guard allows ${h}${p}`, guardFor(h, p) === null, `got: ${guardFor(h, p)}`);
  }
  for (const [h, p] of mustSuspend) {
    expect(`guard suspends ${h}${p}`, guardFor(h, p) !== null, 'got: null');
  }
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
