// pageguard.js — decides whether this page is a login / password / registration
// page. The extension must NEVER touch those, so this errs on the side of
// flagging. Loaded before content.js in the same isolated world.
'use strict';

const PageGuard = (() => {
  // Hostname prefixes that are almost always auth portals.
  const AUTH_HOST_RE =
    /^(login|signin|sign-in|signup|sign-up|auth|sso|accounts?|id|idp|identity|oauth|passport|session)\./i;

  // Path/query segments that indicate auth flows.
  const AUTH_PATH_RE =
    /(?:^|[/\-_.?#&=])(?:log[-_]?in|log[-_]?on|sign[-_]?in|sign[-_]?up|sign[-_]?on|register|registration|create[-_]?account|auth(?:n|entication|orize|orization)?|oauth2?|openid|sso|saml|password|passwd|pwd|credentials?|forgot|reset[-_]?password|two[-_]?factor|2fa|mfa|otp|verify[-_]?(?:email|account)|session\/new|users?\/new)(?:$|[/\-_.?#&=])/i;

  // Document titles typical of auth pages.
  const AUTH_TITLE_RE =
    /\b(?:log\s?in|sign\s?in|sign\s?up|register|create\s(?:an\s)?account|forgot\spassword|reset\s(?:your\s)?password|two[-\s]?factor|verify\s(?:your\s)?(?:email|identity))\b/i;

  function urlLooksLikeAuth() {
    try {
      if (AUTH_HOST_RE.test(location.hostname)) return true;
      if (AUTH_PATH_RE.test(location.pathname + location.search + location.hash)) return true;
    } catch (_e) { /* detached frame */ }
    return false;
  }

  function titleLooksLikeAuth() {
    return AUTH_TITLE_RE.test(document.title || '');
  }

  function hasPasswordField() {
    return document.querySelector('input[type="password"]') !== null;
  }

  // Is this node inside a form that contains a password field? Used to keep
  // paste-redaction away from login forms even when the rest of the page is fine.
  function inPasswordForm(node) {
    let el = node && node.nodeType === Node.TEXT_NODE ? node.parentElement : node;
    while (el) {
      if (el.tagName === 'FORM' && el.querySelector('input[type="password"]')) return true;
      el = el.parentElement;
    }
    return false;
  }

  // Returns a reason string when the page must not be processed, else null.
  function suspendReason() {
    if (hasPasswordField()) return 'password field on page';
    if (urlLooksLikeAuth()) return 'login/registration URL';
    if (titleLooksLikeAuth()) return 'login/registration page title';
    return null;
  }

  return Object.freeze({ suspendReason, inPasswordForm });
})();
