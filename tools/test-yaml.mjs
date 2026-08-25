#!/usr/bin/env node
// test-yaml.mjs — round-trip tests for the minimal YAML lib (src/yaml.js).
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const code = readFileSync(join(__dirname, '..', 'src', 'yaml.js'), 'utf8') + '\nsandbox.DlpYaml = DlpYaml;';
const sandbox = {};
new Function('sandbox', 'module', code)(sandbox, { exports: {} });
const Y = sandbox.DlpYaml;

let pass = 0, fail = 0;
const eq = (name, a, b) => {
  const ja = JSON.stringify(a), jb = JSON.stringify(b);
  if (ja === jb) pass++;
  else { fail++; console.error(`  ✗ ${name}\n    exp ${ja}\n    got ${jb}`); }
};

const roundtrip = (name, obj) => eq(name, obj, Y.parse(Y.stringify(obj)));

roundtrip('scalars', { a: true, b: false, c: 10, d: -3.5, e: null, f: 'plain' });
roundtrip('quoted strings', { terms: ['a: b', '- x', 'true', '42', '#hash', 'has "quote"', 'back\\slash'] });
roundtrip('empty containers', { arr: [], obj: {}, s: '' });
roundtrip('nested maps', { cats: { token: true, pii: false }, deep: { a: { b: { c: 1 } } } });
roundtrip('array of objects', {
  dlp_userPatterns: [
    { id: 'u1', label: 'TICKET', source: 'JIRA:\\s*([A-Z]{2,}-\\d+)', flags: 'g', valueGroup: 1, mask: 'stars', enabled: true },
    { id: 'u2', label: 'X', source: '"quoted" and \\d+', flags: 'gi', valueGroup: 0, mask: 'affix', enabled: false },
  ],
});
roundtrip('builtin overrides', {
  dlp_builtinOverrides: [
    { id: 'token:AWS_CLIENT_ID#1', disabled: true },
    { id: 'pii:EMAIL#1', source: '\\b\\w+@\\w+\\.\\w+\\b', flags: 'g' },
  ],
});

// the full realistic config
const full = {
  dlp_enabled: true, dlp_maskOnPage: true, dlp_redactPaste: true, dlp_revealOnClick: true,
  dlp_exfilShield: true, dlp_exfilThreshold: 25,
  dlp_guardPasswordField: false, dlp_guardAuthUrl: true, dlp_redactInPasswordFields: false,
  dlp_cats: { token: true, assignment: true, privatekey: true, custom: true, user: true, pii: true, infra: false, generic: false },
  dlp_customTerms: ['Acme Health Partners', 'projekt-x', 'db:prod:07'],
  dlp_userPatterns: [{ id: 'u1', label: 'T', source: 'ACME-\\d{6,}', flags: 'gi', valueGroup: 0, mask: 'affix', enabled: true }],
  dlp_builtinOverrides: [{ id: 'pii:EMAIL#1', source: 'x', flags: 'g' }],
  dlp_disabledSites: ['example.com', 'chat.internal'],
};
roundtrip('full config', full);

// hand-edited YAML (comments, blank lines, extra spaces) parses
const edited = `# config
dlp_enabled: true      # master

dlp_cats:
  token: false
  pii: true
dlp_customTerms:
  - Foo
  - "Bar: baz"
  - projekt-x
dlp_exfilThreshold: 12
`;
const p = Y.parse(edited);
eq('edited: enabled', p.dlp_enabled, true);
eq('edited: cats', p.dlp_cats, { token: false, pii: true });
eq('edited: terms', p.dlp_customTerms, ['Foo', 'Bar: baz', 'projekt-x']);
eq('edited: number', p.dlp_exfilThreshold, 12);

// escaped quotes + '#' inside strings must not truncate (stripComment bug)
roundtrip('quote then hash', { dlp_customTerms: ['Acme "Q3 #roadmap', 'a"b"c"d #e', 'plain # x'] });
// quoted scalar containing ": " must stay a string, not become a mapping
roundtrip('colon-space in quoted scalar', { dlp_customTerms: ['label": value', 'a": b'] });
// regex source with quotes/backslash/hash
roundtrip('regex with quote-hash', { dlp_userPatterns: [{ id: 'r', label: 'X', source: '["]\\s+ #note', flags: 'g', valueGroup: 0, mask: 'stars', enabled: true }] });

// tab indentation must throw, not silently collapse
{
  let threw = false;
  try { Y.parse('dlp_cats:\n\ttoken: true\n'); } catch (_e) { threw = true; }
  eq('tab indent throws', threw, true);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
