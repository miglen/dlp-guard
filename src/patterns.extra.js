// patterns.extra.js — hand-curated supplemental patterns with validators.
// These are NOT from the leakin dataset; they close the gaps a parity audit
// found against the SafeRelay foundation extension:
//   - modern AI/dev token formats the dataset predates (category 'token', ON)
//   - crypto private material (category 'token', ON)
//   - PII and national/corporate identifiers (category 'pii', default OFF)
// Deliberately NOT ported from the foundation: bare digit-run identifiers
// (NG bank 10-digit, NG NIN 11-digit, AU TFN 8-9 digit, DE tax 11-digit,
// ZA ID 13-digit, separator-less Aadhaar, bare SOL addresses) — they mask
// arbitrary numbers and would make the PII toggle unusable.
// validate(value, fullText, start) → false rejects the match.
// mask: 'stars' forces a full-star mask (no prefix/suffix kept).
// Loaded before engine.js in the same isolated world.
'use strict';

function _dlpLuhnValid(digits) {
  if (digits.length !== 15 && digits.length !== 16) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (n < 0 || n > 9) return false;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

const DLP_EXTRA_PATTERNS = [
  // ── Modern AI / developer tokens (the leakin dataset predates these) ──────
  {
    name: 'OpenAI project key', label: 'OPENAI_KEY', category: 'token',
    source: '(?<![A-Za-z0-9_])sk-proj-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])',
    flags: 'g', valueGroup: 0, lit: 'sk-proj-',
  },
  {
    name: 'OpenAI legacy key', label: 'OPENAI_KEY', category: 'token',
    source: '(?<![A-Za-z0-9_])sk-(?!proj-|ant-)[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])',
    flags: 'g', valueGroup: 0, lit: 'sk-',
  },
  {
    name: 'Anthropic key', label: 'ANTHROPIC_KEY', category: 'token',
    source: '(?<![A-Za-z0-9_])sk-ant-[A-Za-z0-9_-]{10,}(?![A-Za-z0-9_-])',
    flags: 'g', valueGroup: 0, lit: 'sk-ant-',
  },
  {
    name: 'GitHub PAT', label: 'GITHUB_PAT', category: 'token',
    source: '(?<![A-Za-z0-9_])ghp_[A-Za-z0-9]{20,}(?![A-Za-z0-9])',
    flags: 'g', valueGroup: 0, lit: 'ghp_',
  },
  {
    name: 'GitHub fine-grained PAT', label: 'GITHUB_PAT', category: 'token',
    source: '(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{20,}(?![A-Za-z0-9_])',
    flags: 'g', valueGroup: 0, lit: 'github_pat_',
  },
  {
    name: 'GitHub OAuth/app token', label: 'GITHUB_TOKEN', category: 'token',
    source: '(?<![A-Za-z0-9_])gh[osur]_[A-Za-z0-9]{20,}(?![A-Za-z0-9])',
    flags: 'g', valueGroup: 0, lit: 'gh',
  },
  {
    name: 'Google OAuth client secret', label: 'GOOGLE_OAUTH_SECRET', category: 'token',
    source: '(?<![A-Za-z0-9_])GOCSPX-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])',
    flags: 'g', valueGroup: 0, lit: 'gocspx-',
  },
  {
    name: 'Google OAuth refresh token', label: 'GOOGLE_REFRESH_TOKEN', category: 'token',
    source: '(?<![A-Za-z0-9_/])1//[A-Za-z0-9_-]{24,}(?![A-Za-z0-9_-])',
    flags: 'g', valueGroup: 0, lit: '1//',
  },
  {
    name: 'Docker PAT', label: 'DOCKER_PAT', category: 'token',
    source: '(?<![A-Za-z0-9])dckr_pat_[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])',
    flags: 'g', valueGroup: 0, lit: 'dckr_pat_',
  },
  {
    name: 'npm token', label: 'NPM_TOKEN', category: 'token',
    source: '(?<![A-Za-z0-9])npm_[A-Za-z0-9]{30,}(?![A-Za-z0-9])',
    flags: 'g', valueGroup: 0, lit: 'npm_',
  },
  {
    name: 'Bearer token', label: 'BEARER_TOKEN', category: 'token',
    source: '(?<![A-Za-z0-9_])bearer\\s+([A-Za-z0-9._~+/=-]{16,})',
    flags: 'gid', valueGroup: 1, lit: 'bearer',
  },
  {
    name: 'Slack webhook (modern IDs)', label: 'SLACK_WEBHOOK', category: 'token',
    source: 'hooks\\.slack\\.com/services/T[A-Z0-9]{6,14}/B[A-Z0-9]{6,14}/[A-Za-z0-9]{16,}',
    flags: 'g', valueGroup: 0, lit: 'hooks.slack.com',
  },
  {
    // scheme://user:PASSWORD@host — masks only the password, keeps the host
    name: 'Connection-string password', label: 'CONN_STRING', category: 'token',
    source: '(?<=\\b[a-z][a-z0-9+.\\-]*:\\/\\/[^:/\\s@]+:)[^\\s]+?(?=@[a-zA-Z0-9.\\-]+(?::\\d+)?(?:[/\\s]|$))',
    flags: 'gi', valueGroup: 0, lit: '://', mask: 'stars',
  },
  {
    // bare 40-char AWS secret (no variable name). Mixed-case + digit required;
    // pure hex excluded so git SHA-1 hashes never match.
    name: 'AWS secret (bare)', label: 'AWS_SECRET', category: 'token',
    source: '(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])',
    flags: 'g', valueGroup: 0, lit: null, mask: 'stars',
    validate(v) {
      if (/^[0-9a-fA-F]{40}$/.test(v)) return false;
      return /[a-z]/.test(v) && /[A-Z]/.test(v) && /[0-9]/.test(v);
    },
  },
  {
    // any ALLCAPS_VAR=value line (catch-all for unrecognized env names)
    name: 'ENV value', label: 'ENV_VALUE', category: 'token',
    source: '(?<=^\\s*(?:export\\s+)?[A-Z][A-Z0-9_]{2,}=["\']?)[^\\s"\']{8,}',
    flags: 'gm', valueGroup: 0, lit: null, mask: 'stars',
    validate(v) {
      if (/^\d+$/.test(v)) return false;                       // ports, sizes
      if (/^(true|false|null|none|undefined|yes|no)$/i.test(v)) return false;
      if (/^[a-z]+$/.test(v) || /^[A-Z]+$/.test(v)) return false; // config words
      if (/^[/.$~]/.test(v)) return false;                     // paths, $refs
      return true;
    },
  },
  {
    // 64-hex blob: mask unless it sits in checksum/hash context without any
    // secret-ish context (same heuristic as the foundation extension)
    name: 'Hex-encoded private key', label: 'CRYPTO_KEY', category: 'token',
    source: '(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])',
    flags: 'g', valueGroup: 0, lit: null, mask: 'stars',
    validate(_v, fullText, start) {
      const around = fullText.slice(Math.max(0, start - 60), start + 130).toLowerCase();
      const hashCtx = /sha[-_]?256|sha[-_]?512|checksum|hash|digest|integrity|etag|commit/.test(around);
      const secretCtx = /private|secret|wallet|seed|mnemonic|credential|key/.test(around);
      return !(hashCtx && !secretCtx);
    },
  },
  {
    name: 'ETH private key', label: 'ETH_PRIVATE_KEY', category: 'token',
    source: '(?<![A-Za-z0-9])0x[A-Fa-f0-9]{64}(?![A-Za-z0-9])',
    flags: 'g', valueGroup: 0, lit: '0x', mask: 'stars',
  },
  {
    name: 'Bitcoin WIF private key', label: 'BTC_WIF', category: 'token',
    source: '(?<![A-Za-z0-9])[5KL][1-9A-HJ-NP-Za-km-z]{50,51}(?![A-Za-z0-9])',
    flags: 'g', valueGroup: 0, lit: null, mask: 'stars',
  },

  // ── PII / identifiers (default OFF — enable in the popup) ─────────────────
  {
    name: 'IPv4 address', label: 'IP', category: 'pii',
    source: '(?<![0-9.])(?:\\d{1,3}\\.){3}\\d{1,3}(?![0-9.])',
    flags: 'g', valueGroup: 0, lit: '.',
    validate(m) {
      const o = m.split('.').map(Number);
      if (o.some((x) => x > 255)) return false;
      return o[0] !== 127 && o[0] !== 255 && o[0] !== 0;
    },
  },
  {
    name: 'Email address', label: 'EMAIL', category: 'pii',
    source: '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b',
    flags: 'g', valueGroup: 0, lit: '@',
    validate(m) {
      return !/\.(png|jpg|jpeg|gif|svg|webp|css|js|json|html?)$/i.test(m);
    },
  },
  {
    name: 'US SSN', label: 'US_SSN', category: 'pii',
    source: '\\b(?!000|666|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0000)\\d{4}\\b',
    flags: 'g', valueGroup: 0, lit: '-',
  },
  {
    // Phone (formatted): 3-3-4 with a separator, so bare digit runs (order
    // ids, SSNs 3-2-4) don't match. Covers 415-555-1234, 415.555.1234,
    // (415) 555-1234, +1 415 555 1234.
    name: 'Phone number (formatted)', label: 'PHONE', category: 'pii',
    source: '(?<!\\d)(?:\\+?1[ .\\-]?)?(?:\\(\\d{3}\\)|\\d{3})[ .\\-]\\d{3}[ .\\-]\\d{4}(?!\\d)',
    flags: 'g', valueGroup: 0, lit: null,
  },
  {
    // Phone (E.164 international): +<country><digits>, 8–15 digits total.
    name: 'Phone number (E.164)', label: 'PHONE', category: 'pii',
    source: '(?<![\\w+])\\+[1-9]\\d{7,14}(?!\\d)',
    flags: 'g', valueGroup: 0, lit: '+',
  },
  {
    name: 'Credit card', label: 'CREDIT_CARD', category: 'pii',
    source: '\\b(?:\\d{4}[-\\s]?){3}\\d{3,4}\\b|\\b3[47]\\d{2}[-\\s]?\\d{6}[-\\s]?\\d{5}\\b',
    flags: 'g', valueGroup: 0, lit: null,
    validate(m) {
      return _dlpLuhnValid(m.replace(/\D/g, ''));
    },
  },
  {
    name: 'MAC address', label: 'MAC', category: 'pii',
    source: '\\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\\b',
    flags: 'g', valueGroup: 0, lit: null,
  },
  {
    name: 'IBAN', label: 'IBAN', category: 'pii',
    source: '\\b[A-Z]{2}\\d{2}[A-Z0-9]{11,30}\\b',
    flags: 'g', valueGroup: 0, lit: null,
  },
  {
    name: 'BTC address', label: 'BTC_ADDRESS', category: 'pii',
    source: '(?<![A-Za-z0-9])(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{20,87})(?![A-Za-z0-9])',
    flags: 'g', valueGroup: 0, lit: null,
  },
  {
    name: 'ETH address', label: 'ETH_ADDRESS', category: 'pii',
    source: '(?<![A-Za-z0-9])0x[a-fA-F0-9]{40}(?![A-Za-z0-9])',
    flags: 'g', valueGroup: 0, lit: '0x',
  },
  {
    // BIP39 words are 3-8 lowercase letters; still noisy → pii, full stars
    name: 'Seed phrase (12/24 words)', label: 'SEED_PHRASE', category: 'pii',
    source: '\\b(?:[a-z]{3,8} ){23}[a-z]{3,8}\\b|\\b(?:[a-z]{3,8} ){11}[a-z]{3,8}\\b',
    flags: 'g', valueGroup: 0, lit: null, mask: 'stars',
  },
  {
    name: 'UK national insurance number', label: 'UK_NINO', category: 'pii',
    source: '\\b[A-Z]{2}\\d{6}[A-Z]\\b',
    flags: 'g', valueGroup: 0, lit: null,
  },
  {
    name: 'Canada SIN', label: 'CA_SIN', category: 'pii',
    source: '\\b[1-79]\\d{2}-\\d{3}-\\d{3}\\b',
    flags: 'g', valueGroup: 0, lit: '-',
  },
  {
    // separators required — the foundation's optional-separator form masks
    // arbitrary 12-digit numbers
    name: 'India Aadhaar', label: 'IN_AADHAAR', category: 'pii',
    source: '\\b[2-9]\\d{3}[\\s-]\\d{4}[\\s-]\\d{4}\\b',
    flags: 'g', valueGroup: 0, lit: null,
  },
  {
    name: 'India PAN', label: 'IN_PAN', category: 'pii',
    source: '\\b[A-Z]{5}[0-9]{4}[A-Z]\\b',
    flags: 'g', valueGroup: 0, lit: null,
  },
  {
    name: 'Brazil CPF', label: 'BR_CPF', category: 'pii',
    source: '\\b\\d{3}\\.\\d{3}\\.\\d{3}-\\d{2}\\b',
    flags: 'g', valueGroup: 0, lit: '.',
  },
  {
    name: 'Singapore NRIC', label: 'SG_NRIC', category: 'pii',
    source: '\\b[STFG]\\d{7}[A-Z]\\b',
    flags: 'g', valueGroup: 0, lit: null,
  },
  {
    name: 'Nigeria BVN (labeled)', label: 'NG_BVN', category: 'pii',
    source: '(?<=\\b(?:BVN|Bank[\\s-]?Verification(?:[\\s-]?(?:Number|No|#))?)\\s*[:#-]?\\s*)\\d{11}\\b',
    flags: 'gi', valueGroup: 0, lit: 'v',
  },
  {
    name: 'Nigeria NIN (labeled)', label: 'NG_NIN', category: 'pii',
    source: '(?<=\\b(?:NIN|National[\\s-]?(?:Identification|Identity|ID)(?:[\\s-]?(?:Number|No|#))?)\\s*[:#-]?\\s*)\\d{11}\\b',
    flags: 'gi', valueGroup: 0, lit: 'n',
  },
  {
    name: 'Nigeria phone', label: 'NG_PHONE', category: 'pii',
    source: '\\b0[789][01]\\d{8}\\b',
    flags: 'g', valueGroup: 0, lit: null,
  },
  {
    name: 'US green card / USCIS number', label: 'US_GREEN_CARD', category: 'pii',
    source: '\\b[A-Z]{2,3}\\d{9,10}\\b',
    flags: 'g', valueGroup: 0, lit: null,
    validate(m) {
      const upper = m.toUpperCase();
      if (['LIN', 'EAC', 'WAC', 'SRC', 'MSC', 'IOE'].some((p) => upper.startsWith(p))) return true;
      if (/^A\d{8,9}$/.test(upper)) return true;
      return /^[A-Z]{3}\d{10}$/.test(upper);
    },
  },
  {
    name: 'DUNS number (labeled)', label: 'DUNS', category: 'pii',
    source: '(?:D[-\\s]?U[-\\s]?N[-\\s]?S|D&B|Dun\\s*&\\s*Bradstreet)[^0-9]{0,50}(\\d{2}-\\d{3}-\\d{4}|\\d{9})',
    flags: 'gid', valueGroup: 1, lit: null,
  },
  {
    name: 'EIN (labeled)', label: 'EIN', category: 'pii',
    source: '\\b(?:EIN|Tax\\s*ID|Federal\\s*Tax\\s*ID)[^0-9]{0,20}(\\d{2}-\\d{7})\\b',
    flags: 'gid', valueGroup: 1, lit: null,
  },
  {
    name: 'EU VAT number', label: 'VAT_EU', category: 'pii',
    source: '\\b(ATU\\d{8}|BE0\\d{9}|BG\\d{9,10}|CY\\d{8}L|CZ\\d{8,10}|DE\\d{9}|DK\\d{8}|EE\\d{9}|EL\\d{9}|ES[A-Z0-9]\\d{7}[A-Z0-9]|FI\\d{8}|FR[A-Z0-9]{2}\\d{9}|HR\\d{11}|HU\\d{8}|IE\\d{7}[A-Z]{1,2}|IT\\d{11}|LT\\d{9,12}|LU\\d{8}|LV\\d{11}|MT\\d{8}|NL\\d{9}B\\d{2}|PL\\d{10}|PT\\d{9}|RO\\d{2,10}|SE\\d{12}|SI\\d{8}|SK\\d{10})\\b',
    flags: 'g', valueGroup: 0, lit: null,
  },
  {
    name: 'GPS coordinates', label: 'GPS_COORDS', category: 'pii',
    source: '\\b(-?(?:[1-8]?\\d(?:\\.\\d+)?|90(?:\\.0+)?)),\\s*(-?(?:1[0-7]\\d(?:\\.\\d+)?|(?:[1-9]?\\d(?:\\.\\d+)?)|180(?:\\.0+)?))\\b',
    flags: 'g', valueGroup: 0, lit: ',',
  },
  {
    name: 'UNHCR ID', label: 'UNHCR_ID', category: 'pii',
    source: '\\b[A-Z]{3}-\\d{2}-\\d{6,8}C?\\d?\\b',
    flags: 'g', valueGroup: 0, lit: '-',
  },
  {
    name: 'Donor/case ID (labeled)', label: 'DONOR_ID', category: 'pii',
    source: '\\b(?:Donor|Beneficiary|Bene|Case|Client|Member|Ref)[-\\s]?(?:ID|No|#|Number|Code)[-\\s:]*([A-Z0-9]{4,16})\\b',
    flags: 'gd', valueGroup: 1, lit: null,
  },
];
