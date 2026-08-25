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
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
