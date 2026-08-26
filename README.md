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

- **Hide secrets on pages, structure preserved** — text nodes are scanned (initial
  sweep + MutationObserver for SPA/streamed content) and matches are replaced with
  masks that mirror the shape of what they hide, never the content:
  - identifiable tokens keep 4 chars each side: `ASIA*******FSPM` (the prefix comes
    from a public pattern DB, so it is not itself secret)
  - pure-entropy values (assignment values, secrets) become all stars, with star runs
    capped at 35 so the mask doesn't leak the value's length
  - private key blocks (RSA/EC/DSA/OPENSSH/PGP/PKCS8) keep their `-----BEGIN`/`-----END`
    lines with the body replaced by star lines
  Click a mask to reveal/re-hide (toggleable). The same masks are used for paste
  redaction, so `export AWS_ACCESS_KEY_ID="ASIA…"` arrives as
  `export AWS_ACCESS_KEY_ID="ASIA*******FSPM"`.
- **Redact on paste** — pasted text is scanned before insertion; secrets are replaced
  with the same structure-preserving masks described above.
  Works in `<textarea>`, `<input>`, and contenteditable editors
  (ProseMirror/React chat inputs) via `execCommand('insertText')`. The listener is
  registered at `document_start` on `window` (capture), so it runs before any page
  script can observe the raw clipboard. Pastes outside editable fields are never
  touched.
- **Login-page suspension** — the extension never runs when any of these is true:
  a password field is present (including open shadow DOM, `type="password"` or
  `autocomplete="current-password"/"new-password"` — so "show password" toggles are
  still covered), the hostname starts with an auth prefix (`login.`, `auth.`, `sso.`,
  `accounts.`, `join.` …), or the URL path/query contains auth segments (`/login`,
  `/signup`, `/oauth`, `/reset-password` …). Auth words are matched only between real
  URL delimiters, so content slugs like `/projects/my-login-page` don't false-suspend.
  The page title is deliberately NOT a signal — on AI chat sites the title is the
  conversation name, and chatting about passwords must not disable protection.
  The guard is re-checked synchronously on every paste, on SPA route changes
  (`popstate`, `hashchange`, and a 1s `location.href` poll for `pushState`), and on
  every DOM mutation batch. Paste-redaction additionally skips password inputs and
  any form containing one.
- **Pattern categories** (toggle in popup):
  | Category | Count | Default | What |
  |---|---|---|---|
  | API keys & tokens | 61 | on | Concrete formats: `AKIA…`, `xox…`, `sk_live_…`, JWT, … |
  | key=value assignments | 691 | on | `api_key: <value>` — only the value is hidden |
  | Private key blocks | 5 | on | whole `-----BEGIN…-----END-----` armor blocks |
  | Custom protected terms | user | on | your server/client/project names (popup textarea) |
  | PII | 8 | off | IPs (validated octets), emails, US SSN, cards (Luhn), MAC, IBAN, BTC/ETH |
  | Cloud endpoints | 12 | off | `*.cloudfront.net`, `*.s3.amazonaws.com`, … (noisy) |
  | Generic URLs/UUIDs | 4 | off | catch-alls (very noisy) |

  PII patterns live in hand-written [src/patterns.extra.js](src/patterns.extra.js)
  (ported from the SafeRelay foundation's validated set, since the leakin dataset
  has no PII patterns); everything else is generated from the dataset.
- **File-upload scanning** — when you attach a file to an AI chatbot (file picker,
  drag-and-drop, or paste), DLP Guard reads a *copy* and scans it with the same engine.
  If it finds secrets, a warning panel names the file(s) and what was found. Two modes:
  - **Warn + remove (default)** — the file attaches, then the panel's *Remove from
    upload* detaches it through the **app's own Remove control** (finding the
    attachment card by filename and clicking its Remove button, with a full
    pointer/mouse-event fallback). This is the only reliable removal on React SPAs like
    claude.ai, where clearing the file input is a no-op because the app has already read
    the file into component state. *Upload anyway* (or ignoring the panel) is recorded.
  - **Block before attach (opt-in)** — holds each upload in the capture phase, scans it,
    and stops a flagged file from attaching at all (a clean file is replayed through so
    it attaches normally). Stronger, but holding/replaying is less reliable on some
    uploaders, so it's off by default.

  Configurable in the options page: on/off,
  a max file size, and the list of extensions / filenames to scan (defaults cover text
  and credential files — `.env`, `.pem`, `id_rsa`, `credentials`, `.npmrc`, configs,
  source, etc.). **Extensionless files** (a private cert saved as `id_rsa`, `cert`,
  `server-key`, …) are always scanned, since keys and credentials are routinely saved
  without an extension. Binary office/image formats are out of scope (they'd need format
  parsers); files over the size limit or that sniff as binary are skipped. Open the
  browser DevTools console to see exactly what DLP Guard scanned or skipped and why.
- **Deliberate bypass, always counted** — the redaction toast has a **Paste original**
  button that swaps the real clipboard text back in. In-place replacement is tried
  first; when the editor makes that impossible, a one-shot re-paste window (15 s) is
  armed instead — bound to exactly the same clipboard text, and even that paste is
  cancelled and inserted by the extension so page paste listeners never see the event.
  The toast lives in a closed shadow root and bypass clicks are geometry-verified, so
  page scripts can neither press the button nor clickjack it. Revealing a mask on the
  page is also a bypass. Both kinds are recorded: persistent counters plus a rolling 200-entry log
  (`timestamp · hostname · kind · secret count` — never the values) in
  `chrome.storage.local`; totals show in the popup under **Bypass stats**.
- **Custom protected terms** — add your own server names, client names, or project
  codenames in the popup (one per line); occurrences are masked on pages and in pastes
  with word-boundary matching, case-insensitive.
- **Exfiltration shield** — copying a selection that contains 10+ detected secrets is
  blocked: the clipboard receives a notice instead and the block is counted
  (popup → Bypass stats → "Bulk copies blocked"). Toggleable; normal copies with a
  secret or two are never touched.
- **Per-site disable** and a global kill switch in the popup; badge shows the number of
  secrets hidden/redacted on the current tab.
- **Configurable login-page safety** — the suspension is on by default but can be
  relaxed in the options page: suspend-on-password-field and suspend-on-auth-URL are
  independent toggles, and *Redact secrets pasted into password fields* (off by
  default) lets you freely paste passwords and API keys into password inputs.
- **Cloud-editor compatibility** — DLP Guard suspends inside rich cloud document
  editors that manage their own editing (Google Docs/Sheets/Slides, Microsoft 365,
  SharePoint/OneDrive, Notion, Quip, Coda, Dropbox Paper, Zoho, Confluence), matched by
  hostname so pages can't spoof it. Toggleable in the options page.
- **Compact popup** — status, the two everyday toggles (hide on pages, redact on
  paste), the per-site switch, a one-line bypass summary, and a button to the full
  settings. Everything else lives in the options page.
- **Advanced settings page** (popup → *Advanced settings*, or the extension's Options)
  — a tabbed UI for everything:
  - **General** — all behavior toggles, exfiltration threshold, and login-page safety
  - **Categories** — bulk enable/disable each built-in category, with live counts;
    plus any categories you invented for your own patterns
  - **Patterns** — one unified table of *every* detector, built-in and custom. Edit any
    built-in's regex (stored as an override, Reset restores the original), toggle one
    off, or add your own — with a label, a category (including a brand-new one you
    name), flags, value-capture group, and mask style. Test against sample text. Every
    regex is compile-checked and screened for catastrophic backtracking (static
    structural lint + a bounded timing probe) before it can be saved, so a bad pattern
    can't hang your pages. All patterns run only in the isolated content-script world.
  - **Protected terms** — the custom-term editor with more room
  - **Sites** — manage the disabled-site list
  - **Stats & log** — lifetime counters (including risky files uploaded-anyway / removed),
    an activity graph (bypasses/reveals/blocks/file-uploads per day or per month,
    aggregated locally), and the full audit log, with reset/clear
  - **Backup** — export the **complete** configuration to a **YAML** file — every
    setting, custom pattern, protected term, and the full built-in regex library with
    your edits applied — and import it back (import re-screens custom and edited
    regexes and drops unsafe ones, and reconstructs built-in overrides from the file)

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
- Closed shadow roots cannot be inspected by any extension; a password field inside
  one is invisible to the login guard (the URL/host heuristics still apply).
- Suspension is deliberately fail-closed: any page containing a password field is
  left alone, so a page could disable masking by embedding a hidden password input.
  That trades adversarial-page resistance for the hard guarantee of never touching
  credential flows.
- Masking rewrites the page DOM (secrets the page already had). Revealed values and
  restored text are visible to page scripts — the extension never exposes anything
  the page didn't already have, but it cannot remove what the page server already
  received.
