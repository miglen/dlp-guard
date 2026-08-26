# DLP Guard Privacy Policy

_Last updated: 26 August 2026_

DLP Guard is a browser extension that finds sensitive data (secrets, API keys,
tokens, private keys, and optionally personal data) and keeps it from leaking into
web pages and AI chats. This page explains what it does with your data.

## In one line

DLP Guard collects nothing and sends nothing. It has no servers, no accounts, and no
analytics, and it never makes a network request. Everything happens locally in your
browser.

## What it looks at, locally

To do its job the extension has to read some of what is on the pages you use:

* Text you paste into inputs and chat boxes.
* Files you attach or upload (it reads a local copy).
* Text already shown on a page, so it can mask secrets that are visible.
* Text you copy, so it can warn you before you copy a large block of secrets.

All of this is checked in memory, on your machine, against local pattern rules. None
of that content is uploaded anywhere, and the actual secret values are never written
to disk.

## What it saves on your device

The extension uses your browser's own storage (`chrome.storage.local` and
`chrome.storage.session`) to remember a few things, and only on your computer:

* Your settings: which detections are on, any custom patterns or protected words you
  added, your per-site on/off choices, and the file-scan options.
* Usage counters and a short activity log. The log only records metadata, meaning a
  time, the site's hostname, the type of event, and how many items were involved. It
  does not record the secret or personal values themselves.

This stays in your browser profile. It is never uploaded, shared, or sold. You can
clear it from the settings page at any time, or by removing the extension.

## What it does not do

* It does not send anything to me or to any third party.
* It does not use analytics, telemetry, cookies, or fingerprinting.
* It does not need an account or a login.
* It stays off login, password, and registration pages, and out of editors like
  Google Docs, on purpose.

## Permissions

* `storage`: to save your settings and local counters on your device.
* Host access (`<all_urls>`): the content script needs to run on any site, because you
  might paste, upload, or view a secret anywhere. It only ever works locally and makes
  no network requests.

## Open source

The full code is public at https://github.com/miglen/dlp-guard, so you can check
exactly what it does.

## Contact

If you have a question about this policy, reach me at https://miglen.com.

## Changes

If this policy changes, I will update this file and change the date at the top.
