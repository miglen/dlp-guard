// pageguard.js — decides whether this page is a login / password / registration
// page. The extension must NEVER touch those, so this errs on the side of
// flagging. Loaded before content.js in the same isolated world.
'use strict';

const PageGuard = (() => {
  // Hostname prefixes that are almost always auth portals.
  const AUTH_HOST_RE =
    /^(login|signin|sign-in|signup|sign-up|join|auth|sso|accounts?|id|idp|identity|oauth|passport)\./i;

  // Path/query segments that indicate auth flows. Boundaries are real URL
  // delimiters only (/ . ? # & =) — NOT "-" or "_" — so content slugs like
  // /projects/my-login-page or /share/how-to-login do not falsely suspend.
  // Multi-word auth routes (sign-in, reset-password) are matched as whole
  // tokens by the [-_]? parts inside each alternative.
  const AUTH_PATH_RE =
    /(?:^|[/.?#&=])(?:log[-_]?in|log[-_]?on|sign[-_]?in|sign[-_]?up|sign[-_]?on|register|registration|join|onboarding|get[-_]?started|create[-_]?(?:account|profile)|auth(?:n|entication|orize|orization)?|oauth2?|openid|sso|saml|password|passwd|pwd|forgot|reset[-_]?password|two[-_]?factor|2fa|mfa|otp|verify[-_]?(?:email|account)|session\/new|users?\/new|accounts?\/new)(?:$|[/.?#&=])/i;

  // Password fields: live type=password, plus fields that identify themselves
  // as password inputs even while a "show password" toggle has them as text.
  const PASSWORD_SELECTOR =
    'input[type="password"], input[autocomplete="current-password" i], input[autocomplete="new-password" i]';

  function urlLooksLikeAuth() {
    try {
      if (AUTH_HOST_RE.test(location.hostname)) return true;
      if (AUTH_PATH_RE.test(location.pathname + location.search + location.hash)) return true;
    } catch (_e) { /* detached frame */ }
    return false;
  }

  // Password-field search that also descends into open shadow roots.
  // (Closed shadow roots cannot be inspected by anyone — known limitation.)
  function hasPasswordField() {
    if (document.querySelector(PASSWORD_SELECTOR)) return true;
    return shadowHasPassword(document);
  }

  function shadowHasPassword(root) {
    const hosts = root.querySelectorAll('*');
    for (const el of hosts) {
      const sr = el.shadowRoot;
      if (!sr) continue;
      if (sr.querySelector(PASSWORD_SELECTOR)) return true;
      if (shadowHasPassword(sr)) return true;
    }
    return false;
  }

  function isPasswordInput(el) {
    if (!(el instanceof HTMLInputElement)) return false;
    if (el.type === 'password') return true;
    const ac = (el.getAttribute('autocomplete') || '').toLowerCase();
    return ac === 'current-password' || ac === 'new-password';
  }

  // Is this node inside a form that contains a password field? Extra layer for
  // paste-redaction; page-wide hasPasswordField() is the primary guard.
  function inPasswordForm(node) {
    let el = node && node.nodeType === Node.TEXT_NODE ? node.parentElement : node;
    while (el) {
      if (el.tagName === 'FORM' && el.querySelector(PASSWORD_SELECTOR)) return true;
      el = el.parentElement;
    }
    return false;
  }

  // Returns a reason string when the page must not be processed, else null.
  // NOTE: document.title is deliberately NOT a signal — on AI chat sites the
  // title is the conversation name, and chatting about passwords must not
  // disable protection.
  function suspendReason() {
    if (hasPasswordField()) return 'password field on page';
    if (urlLooksLikeAuth()) return 'login/registration URL';
    return null;
  }

  return Object.freeze({ suspendReason, inPasswordForm, isPasswordInput });
})();
