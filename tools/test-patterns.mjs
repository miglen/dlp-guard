#!/usr/bin/env node
// test-patterns.mjs — sanity tests for the generated pattern library + engine.
// Runs in Node (same V8 regex engine as Chrome). Exits non-zero on failure.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const src = (f) => readFileSync(join(__dirname, '..', 'src', f), 'utf8');

// Evaluate the plain content-script files in this scope (manifest order).
const sandbox = {};
const code = `${src('patterns.generated.js')}\n${src('patterns.extra.js')}\n${src('engine.js')}\n
  sandbox.DLP_PATTERNS = DLP_PATTERNS; sandbox.DLP_EXTRA_PATTERNS = DLP_EXTRA_PATTERNS; sandbox.DlpEngine = DlpEngine;`;
new Function('sandbox', code)(sandbox);
const { DLP_PATTERNS, DLP_EXTRA_PATTERNS, DlpEngine } = sandbox;

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

// ── 5. redactString: structure-preserving masks ──────────────────────────────
{
  const { text, count } = DlpEngine.redactString(
    'here AKIAIOSFODNN7EXAMPLE and sk_live_abcdefghijklmnopqrstuvwx end');
  expect('redactString count', count === 2, `count=${count}`);
  expect('redactString hides middles',
    !text.includes('AKIAIOSFODNN7EXAMPLE') && !text.includes('IOSFODNN') &&
    !text.includes('abcdefghijklmnopqrst'), text);
  expect('redactString keeps token prefix/suffix',
    text.includes('AKIA') && text.includes('MPLE') && text.includes('sk_l') && text.includes('uvwx'), text);
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
  expect('no full token survives', !text.includes('AKIAIOSFODNN7EXAMPLE') && !text.includes('IOSFODNN'), text);
}

// ── 9. redactString is uncapped — every secret in a huge paste is redacted ───
{
  const big = 'AKIAIOSFODNN7EXAMPLE '.repeat(520);
  const { text, count } = DlpEngine.redactString(big);
  expect('uncapped redaction count', count >= 520, `count=${count}`);
  expect('uncapped redaction no leak', !text.includes('AKIAIOSFODNN7EXAMPLE') && !text.includes('IOSFODNN'), '');
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
  expect('pem BEGIN/END lines preserved',
    text.includes('-----BEGIN RSA PRIVATE KEY-----') && text.includes('-----END RSA PRIVATE KEY-----'), text.slice(0, 250));
  expect('pem body is star lines', /-----BEGIN RSA PRIVATE KEY-----\n\*+\n/.test(text), text.slice(0, 250));

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

// ── 12. structure-preserving masks: user-reported AWS + OPENSSH examples ─────
{
  const env = [
    'export AWS_ACCESS_KEY_ID="ASIAQV76KKSL4NXIFSPM"',
    'export AWS_SECRET_ACCESS_KEY="ntkv1NJz2o7PWE55P6v+fnDCLJI1fI18hMDHKE3I"',
    'export AWS_SESSION_TOKEN="IQoJb3JpZ2luX2VjED8aDGV1LWNlbnRyYWwtMSJIMEYCIQCJnwBl4Afl4tMKs13F7WhBjiHzywYru5GTsrUz5gil7AIhAMwaPuwYR9pT3TTOusJsp46MKiD2kzk5SbAZAyofgPEx"',
  ].join('\n');
  const { text } = DlpEngine.redactString(env);
  expect('access key keeps ASIA prefix + FSPM suffix',
    /AWS_ACCESS_KEY_ID="ASIA\*+FSPM"/.test(text), text);
  expect('access key middle hidden', !text.includes('QV76KKSL4NXI'), text);
  expect('secret key all stars', /AWS_SECRET_ACCESS_KEY="\*+"/.test(text), text);
  expect('secret key gone', !text.includes('ntkv1NJz'), '');
  expect('session token all stars', /AWS_SESSION_TOKEN="\*+"/.test(text), text);
  expect('session token gone', !text.includes('IQoJb3Jp'), '');
  expect('export structure intact', text.split('\n').every((l) => l.startsWith('export AWS_')), text);
  expect('star runs capped at 35', !/\*{36}/.test(text), '');

  const ossh = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACAoPXsyQLSo/o83bwPuozFuyCeK1MdbgrqoqDPMKTNsaQAAAKjcmmPP3Jpj\nIDBAU=\n-----END OPENSSH PRIVATE KEY-----';
  const masked = DlpEngine.maskValue(ossh, 'privatekey');
  const mlines = masked.split('\n');
  expect('openssh mask keeps BEGIN line', mlines[0] === '-----BEGIN OPENSSH PRIVATE KEY-----', masked);
  expect('openssh mask keeps END line', mlines[mlines.length - 1] === '-----END OPENSSH PRIVATE KEY-----', masked);
  expect('openssh mask body is stars only', mlines.slice(1, -1).every((l) => /^\*+$/.test(l)), masked);
  expect('openssh mask leaks nothing', !masked.includes('b3Blbn'), masked);
}

// ── 13. PII supplemental category (default off, validated) ───────────────────
{
  // default settings: PII must be OFF
  DlpEngine.compile({ token: true, assignment: true, privatekey: true, custom: true, pii: false, infra: false, generic: false });
  expect('pii off by default', DlpEngine.findRanges('server at 10.50.22.18 mail jane@example.com').length === 0, '');

  const PII_ON = { token: true, assignment: true, privatekey: true, custom: true, pii: true, infra: false, generic: false };
  DlpEngine.compile(PII_ON);
  expect('detects internal IP', DlpEngine.findRanges('server at 10.50.22.18 ok').length === 1, '');
  expect('ignores loopback', DlpEngine.findRanges('local 127.0.0.1 ok').length === 0, '');
  expect('ignores invalid octets', DlpEngine.findRanges('version 999.1.2.3 ok').length === 0, '');
  expect('detects email', DlpEngine.findRanges('mail jane.doe@example.com ok').length === 1, '');
  expect('ignores asset filename', DlpEngine.findRanges('img logo@2x.png ok').length === 0, '');
  expect('detects SSN', DlpEngine.findRanges('ssn 234-56-7890 ok').length === 1, '');
  expect('detects Luhn-valid card', DlpEngine.findRanges('card 4111 1111 1111 1111 ok').length === 1, '');
  // groups start with 0/1 so the Aadhaar pattern ([2-9]…) can't fire either
  expect('ignores Luhn-invalid digits', DlpEngine.findRanges('num 1023 1023 1023 1023 ok').length === 0,
    JSON.stringify(DlpEngine.findRanges('num 1023 1023 1023 1023 ok')));
  expect('detects MAC', DlpEngine.findRanges('mac 00:1B:44:11:3A:B7 ok').length === 1, '');
  expect('detects ETH address', DlpEngine.findRanges('eth 0x89205A3A3b2A69De6Dbf7f01ED13B2108B2c43e7 ok').length === 1, '');
  const { text: piiText } = DlpEngine.redactString('server 10.50.22.18 mail jane@example.com');
  expect('pii masks are stars', /server \*+ mail \*+/.test(piiText), piiText);
  DlpEngine.compile({ token: true, assignment: true, privatekey: true, custom: true, pii: false, infra: false, generic: false });
}

// ── 14. custom protected terms ────────────────────────────────────────────────
{
  const CATS = { token: true, assignment: true, privatekey: true, custom: true, pii: false, infra: false, generic: false };
  DlpEngine.compile(CATS, ['Acme Health Partners', 'projekt-x']);
  const { text, count } = DlpEngine.redactString('Customer: Acme Health Partners uses PROJEKT-X daily.');
  expect('custom term masked', count === 2 && !text.includes('Acme') && !/projekt-x/i.test(text), text);
  expect('custom term structure kept', text.startsWith('Customer: ') && text.endsWith(' daily.'), text);
  expect('custom term partial word not masked',
    DlpEngine.findRanges('Acmeology is unrelated to projekt-xyz').length === 0, '');
  DlpEngine.compile(CATS); // reset: no custom terms
  expect('terms cleared on recompile', DlpEngine.findRanges('Acme Health Partners').length === 0, '');
}

// ── 15. modern token formats (parity-audit gaps, patterns.extra.js) ──────────
{
  const DEFAULT_CATS = { token: true, assignment: true, privatekey: true, custom: true, pii: false, infra: false, generic: false };
  DlpEngine.compile(DEFAULT_CATS);
  const modern = [
    ['OpenAI project key', 'key sk-proj-abc123DEF456ghi789JKL012mno x'],
    ['OpenAI legacy key',  'key sk-abcdefghij1234567890KLMNOP x'],
    ['Anthropic key',      'key sk-ant-api03-abcdef123456 x'],
    ['GitHub PAT',         'tok ghp_abcdefghij1234567890KLMN x'],
    ['GitHub fine PAT',    'tok github_pat_11ABCDEF0abcdefGhij1234 x'],
    ['GitHub OAuth',       'tok gho_abcdefghij1234567890KLMN x'],
    ['Google OAuth secret','sec GOCSPX-abcDEF123ghiJKL456mnoPQ x'],
    ['Docker PAT',         'tok dckr_pat_AbCd1234EfGh5678IjKl90 x'],
    ['npm token',          'tok npm_abcdefghij1234567890KLMNOPQRST12 x'],
    ['Bearer token',       'Authorization: Bearer dGhpc2lzYXRva2VuMTIzNDU2Nzg5MA x'],
    ['Slack webhook (modern)', 'https://hooks.slack.com/services/T0123456789AB/B0123456789AB/abcdEFGH1234ijkl5678 x'],
    ['conn-string password', 'postgres://admin:Sup3rSecret9@db.internal.example:5432/prod'],
    ['bare AWS secret',    'secret wJalrXUtnFEMIK7MDENGbPxRfiCYzEXAMPLEKEY1 x'],
    ['env catch-all',      'MY_INTERNAL_THING=Xy9walvbTR33Ee'],
    ['hex private key',    'wallet key 8da4ef21b864d2cc526dbdb2a120bd2874c36c9d0a1fb7f8c63d7f7a8b41de8f x'],
    ['ETH private key',    'pk 0x8da4ef21b864d2cc526dbdb2a120bd2874c36c9d0a1fb7f8c63d7f7a8b41de8f x'],
    ['BTC WIF key',        'wif 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ x'],
  ];
  for (const [name, text] of modern) {
    expect(`detects ${name}`, DlpEngine.findRanges(text).length > 0, text.slice(0, 60));
  }
  const modernNegatives = [
    ['git SHA-1 not AWS secret', 'commit 356a192b7913b04c54574d18c28d46e6395428ab done'],
    ['sha256 checksum spared',   'sha256 checksum: 8da4ef21b864d2cc526dbdb2a120bd2874c36c9d0a1fb7f8c63d7f7a8b41de8f verified'],
    ['numeric env value',        'MAX_TOKENS=40960000'],
    ['boolean env value',        'STREAM_MODE=disabled'],
    ['path env value',           'CACHE_DIR=/var/cache/app0'],
    ['plain url path 1//',       'see example.com/path1//foo for details'],
  ];
  for (const [name, text] of modernNegatives) {
    const r = DlpEngine.findRanges(text);
    expect(`ignores ${name}`, r.length === 0, r.map((x) => x.label).join(','));
  }
  // conn-string: only the password is masked, host stays visible
  const { text: conn } = DlpEngine.redactString('postgres://admin:Sup3rSecret9@db.internal.example:5432/prod');
  expect('conn-string keeps host', conn.includes('@db.internal.example') && conn.includes('postgres://admin:'), conn);
  expect('conn-string hides password', !conn.includes('Sup3rSecret9'), conn);
  // stars-forced masks never keep prefix/suffix
  const { text: envred } = DlpEngine.redactString('MY_INTERNAL_THING=Xy9walvbTR33Ee');
  expect('env value fully starred', /MY_INTERNAL_THING=\*+$/.test(envred), envred);
  // the user's ASIA example must still keep its prefix (regression guard
  // against the env catch-all overlapping the token match)
  const { text: asia } = DlpEngine.redactString('export AWS_ACCESS_KEY_ID="ASIAQV76KKSL4NXIFSPM"');
  expect('ASIA prefix still kept with env catch-all', /ASIA\*+FSPM/.test(asia), asia);
}

// ── 15b. seed phrase (pii, opt-in) ────────────────────────────────────────────
{
  DlpEngine.compile({ token: true, assignment: true, privatekey: true, custom: true, pii: true, infra: false, generic: false });
  const seed = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
  expect('detects 12-word seed phrase (pii on)', DlpEngine.findRanges(seed).length > 0, '');
  DlpEngine.compile({ token: true, assignment: true, privatekey: true, custom: true, pii: false, infra: false, generic: false });
  expect('seed phrase off by default', DlpEngine.findRanges(seed).length === 0, '');
}

// ── 15c. user-defined regex patterns (options page) ──────────────────────────
{
  const CATS = { token: true, assignment: true, privatekey: true, custom: true, user: true, pii: false, infra: false, generic: false };
  const userPatterns = [
    { id: 'u1', label: 'INTERNAL_ID', source: 'ACME-\\d{6,}', flags: 'g', valueGroup: 0, mask: 'affix', enabled: true },
    { id: 'u2', label: 'TICKET', source: 'JIRA:\\s*([A-Z]{2,}-\\d+)', flags: 'g', valueGroup: 1, mask: 'stars', enabled: true },
    { id: 'u3', label: 'DISABLED', source: 'SHOULDNOTMATCH', flags: 'g', valueGroup: 0, mask: 'stars', enabled: false },
  ];
  DlpEngine.compile(CATS, [], userPatterns);
  expect('user pattern matches', DlpEngine.findRanges('id ACME-123456 done').length === 1, '');
  expect('user value-group masks only group', (() => {
    const s = 'ref JIRA: OPS-42 end';
    const r = DlpEngine.findRanges(s);
    return r.length === 1 && s.slice(r[0].start, r[0].end) === 'OPS-42';
  })(), '');
  expect('disabled user pattern skipped', DlpEngine.findRanges('x SHOULDNOTMATCH x').length === 0, '');
  const { text } = DlpEngine.redactString('id ACME-123456 and JIRA: OPS-42');
  expect('user affix mask keeps prefix/suffix', /ACME[*-]/.test(text) && !text.includes('123456'), text);
  expect('user stars mask hides ticket', !text.includes('OPS-42'), text);
  DlpEngine.compile(CATS); // reset
  expect('user patterns cleared', DlpEngine.findRanges('ACME-123456').length === 0, '');
}

// ── 15d. built-in pattern overrides (disable / edit source) ──────────────────
{
  const CATS = { token: true, assignment: true, privatekey: true, custom: true, user: true, pii: false, infra: false, generic: false };
  DlpEngine.compile(CATS);
  const akia = 'creds AKIAIOSFODNN7EXAMPLE here';
  expect('AWS client id detected by default', DlpEngine.findRanges(akia).length === 1, '');
  // find the built-in id(s) for AKIA-matching token patterns
  const builtins = DlpEngine.builtins();
  const awsIds = builtins.filter((b) => b.category === 'token' && /AKIA/.test(b.source));
  expect('AWS client-id builtin has stable id', awsIds.length >= 1 && awsIds.every((b) => /#\d+$/.test(b.id)), JSON.stringify(awsIds.map((b) => b.id)));
  // disable them → no longer detected
  DlpEngine.compile(CATS, [], [], awsIds.map((b) => ({ id: b.id, disabled: true })));
  expect('disabled builtins no longer match', DlpEngine.findRanges(akia).length === 0, JSON.stringify(DlpEngine.findRanges(akia)));
  // edit the EMAIL builtin source and confirm the override applies
  DlpEngine.compile({ ...CATS, pii: true });
  const email = builtins.find((b) => b.category === 'pii' && b.label === 'EMAIL');
  DlpEngine.compile({ ...CATS, pii: true }, [], [], [{ id: email.id, source: 'ZZ_[a-z]+_ZZ', flags: 'g' }]);
  expect('edited builtin uses new source', DlpEngine.findRanges('x ZZ_hello_ZZ y').length === 1, '');
  expect('edited builtin drops old behavior', DlpEngine.findRanges('mail a@b.com y').length === 0, '');
  DlpEngine.compile(CATS);
}

// ── 15e. user patterns with custom categories ────────────────────────────────
{
  const CATS = { token: true, assignment: true, privatekey: true, custom: true, user: true, pii: false, infra: false, generic: false };
  const ups = [
    { id: 'c1', label: 'ACME_ID', category: 'mycompany', source: 'ACME-\\d{5,}', flags: 'g', valueGroup: 0, mask: 'stars', enabled: true },
  ];
  DlpEngine.compile(CATS, [], ups);
  expect('custom-category pattern runs by default', DlpEngine.findRanges('id ACME-12345 x').length === 1, '');
  // disabling that category via cats flag turns it off
  DlpEngine.compile({ ...CATS, mycompany: false }, [], ups);
  expect('custom category can be disabled', DlpEngine.findRanges('id ACME-12345 x').length === 0, '');
  // a custom-category pattern wins overlap against a built-in
  DlpEngine.compile(CATS, [], [
    { id: 'c2', label: 'WHOLE', category: 'mine', source: 'AKIA[0-9A-Z]{16}\\b', flags: 'g', valueGroup: 0, mask: 'stars', enabled: true },
  ]);
  const r = DlpEngine.findRanges('k AKIAIOSFODNN7EXAMPLE z');
  expect('custom-category range present', r.length >= 1, JSON.stringify(r));
  DlpEngine.compile(CATS);
}

// ── 16. exfiltration threshold sanity (engine side) ───────────────────────────
{
  const bulk = Array.from({ length: 12 }, (_, i) => `key${i}: AKIAIOSFODNN7EXAMPL${i % 10}`).join('\n');
  const n = DlpEngine.findRanges(bulk, Infinity).length;
  expect('bulk selection yields >=10 ranges', n >= 10, `n=${n}`);
}

// ── 16. page guard URL matrix ─────────────────────────────────────────────────
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
