# DLP Guard — Secret Detector & Hider

Browser extension (Manifest V3) that **detects secrets rendered on web pages and hides
them**, and **redacts secrets on paste** before they reach AI chat inputs.

Built for AI tools — ChatGPT, Claude, DeepSeek, Kimi, Lovable, Gemini, Copilot and any
other site — it runs everywhere (`<all_urls>`) **except login, password, and
registration pages**, where it always suspends itself.

Detection patterns come from
[secrets-patterns-db / leakin-regexes.yml](https://github.com/mazen160/secrets-patterns-db/blob/master/datasets/leakin-regexes.yml)
(771 patterns after conversion and repair).

## Privacy

100% local. The extension makes **no network requests**. Detected values never leave
the page: masked originals are held in a closure-scoped `WeakMap` (never written to the
DOM or to storage), and only *counts* are sent to the service worker for the badge.

## Features

- **Hide secrets on pages** — text nodes are scanned (initial sweep + MutationObserver
  for SPA/streamed content) and matches are replaced with red `••••• LABEL •••••` chips.
  Click a chip to reveal/re-hide (toggleable).
- **Redact on paste** — pasted text is scanned before insertion; secrets become
  `[HIDDEN_<TYPE>]`. Works in `<textarea>`, `<input>`, and contenteditable editors
  (ProseMirror/React chat inputs) via `execCommand('insertText')`.
- **Login-page suspension** — the extension never runs when any of these is true:
  a password field is present, the hostname starts with an auth-ish prefix
  (`login.`, `auth.`, `sso.`, `accounts.` …), the URL path/query contains auth segments
  (`/login`, `/signup`, `/oauth`, `/reset-password` …), or the title looks like an auth
  page. Paste-redaction additionally skips any form containing a password field.
- **Pattern categories** (toggle in popup):
  | Category | Count | Default | What |
  |---|---|---|---|
  | API keys & tokens | 63 | on | Concrete formats: `AKIA…`, `xox…`, `sk_live_…`, JWT, … |
  | key=value assignments | 688 | on | `api_key: <value>` — only the value is hidden |
  | Private key blocks | 4 | on | `-----BEGIN … PRIVATE KEY-----` |
  | Cloud endpoints | 12 | off | `*.cloudfront.net`, `*.elb.amazonaws.com`, … (noisy) |
  | Generic URLs/UUIDs | 4 | off | catch-alls (very noisy) |
- **Per-site disable** and a global kill switch in the popup; badge shows the number of
  secrets hidden/redacted on the current tab.

## Install (test it now)

1. Open `chrome://extensions`
2. Enable **Developer mode** (top right)
3. **Load unpacked** → select this folder
4. Open `test/test-page.html` — fake secrets should appear as red chips
5. Open `test/login-page.html` — nothing must be masked (popup says "Suspended")
6. Try an AI site: paste a fake key into ChatGPT/Claude/DeepSeek — it should arrive as
   `[HIDDEN_…]`

## Development

```
manifest.json                MV3 manifest
src/patterns.generated.js    generated pattern library — DO NOT edit by hand
src/engine.js                pattern compilation + range finding + redaction
src/pageguard.js             login/registration page detection
src/content.js               DOM masking, MutationObserver, paste redaction
src/background.js            badge counts, first-run defaults
popup.html, src/popup.js     settings UI
tools/convert-patterns.mjs   YAML dataset → patterns.generated.js
tools/test-patterns.mjs      test suite (compile, ReDoS, TP/FP, redaction)
tools/make-icons.mjs         icon generator
test/*.html                  manual test fixtures
```

Regenerate patterns after updating the dataset:

```bash
curl -sL https://raw.githubusercontent.com/mazen160/secrets-patterns-db/master/datasets/leakin-regexes.yml -o /tmp/leakin-regexes.yml
node tools/convert-patterns.mjs /tmp/leakin-regexes.yml
node tools/test-patterns.mjs
```

The converter repairs known-broken dataset regexes, rewrites label-only patterns
(`api_key(=|:)`) into value-capturing ones, adds boundary lookarounds, caps quantifiers
that were quadratic, and compile-tests every pattern. `tools/test-patterns.mjs` guards
against regressions including ReDoS (worst-case inputs must scan in <200 ms).

## Known limitations

- A secret split across multiple DOM text nodes (e.g. syntax-highlighted per-character)
  is not detected.
- During token-by-token streaming a secret may be masked only once its text node
  settles (scans are debounced 150 ms).
- Pattern quality is bounded by the upstream dataset (all patterns are marked
  confidence "low" there); placeholder values (`YOUR_API_KEY`, `<key>`, `****`) are
  filtered out, but expect occasional false positives — use the category toggles or
  per-site disable.
