# Privacy Policy — DLP Guard

_Last updated: 26 August 2026_

DLP Guard is a browser extension that detects sensitive data (secrets, API keys,
tokens, private keys, and optionally personal data) and prevents it from leaking
into web pages and AI chat tools. This policy explains exactly what the extension
does and does not do with your data.

## The short version

**DLP Guard collects nothing, sends nothing, and has no servers.** All processing
happens locally in your browser. There are no accounts, no analytics, no tracking,
and no third parties. The extension makes **no network requests** of any kind.

## What the extension processes locally

To do its job, DLP Guard inspects content on the pages you visit:

- **Text you paste** into inputs and chat boxes.
- **Files you attach or upload** to a page (read as a local copy).
- **Text already rendered on a page**, to mask secrets shown there.
- **Text you copy**, to warn about bulk copying of secrets.

This inspection happens **entirely on your device, in memory**. Detected values are
matched against local pattern rules. The extension never transmits this content
anywhere, and it does not write the sensitive values to disk.

## What is stored on your device

DLP Guard uses your browser's local extension storage (`chrome.storage.local` and
`chrome.storage.session`) to keep, **only on your own computer**:

- Your settings and configuration (which detections are on, custom patterns,
  protected terms, per-site toggles, file-scan options).
- Usage counters and a rolling activity log of events. The log records only
  **metadata** — a timestamp, the site's hostname, the type of event, and how many
  items were involved. It **never** stores the secret or personal values themselves.

This data stays in your browser profile. It is never uploaded, shared, or sold. You
can clear it at any time from the extension's settings page, or by removing the
extension.

## What the extension does NOT do

- It does **not** send any data to the developer or to any third party.
- It does **not** use analytics, telemetry, cookies, or fingerprinting.
- It does **not** require an account or any sign-in.
- It does **not** run on login, password, or registration pages, and it stays out
  of document editors such as Google Docs — by design.

## Permissions

- **storage** — to save your settings and local usage counters on your device.
- **Host access (`<all_urls>`)** — the content script must be able to run on any
  site, because you could paste, upload, or view a secret anywhere (AI chat tools,
  dashboards, webmail, internal apps). It runs locally only and makes no network
  requests.

## Open source

DLP Guard is open source. You can review exactly what it does at
<https://github.com/miglen/dlp-guard>.

## Contact

Questions about this policy: [Miglen Evlogiev](https://miglen.com).

## Changes

If this policy changes, the updated version will be published in this file with a new
"last updated" date.
