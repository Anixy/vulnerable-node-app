/**
 * Input Validation & Sanitization Utilities
 * Contains intentional flaws commonly found in vulnerable regexes and blacklists:
 * 1. Regular Expression Denial of Service (ReDoS - CWE-1333)
 * 2. Incomplete / Bypassable XSS Filter (CWE-79)
 * 3. Incomplete SSRF Internal IP Blacklist (Bypassable via Octal, Hex, Decimal IP, IPv6, or 127.1)
 * 4. Weak SQLi Keyword Blacklist (Bypassable via case mixing `SeLeCt` or inline comments)
 */

// VULNERABILITY 1: Evil Regex with catastrophic backtracking `(a+)+$`
const EMAIL_VALIDATION_REGEX = /^([a-zA-Z0-9_\-.]+)+@([a-zA-Z0-9_\-.]+)+\.([a-zA-Z]{2,5})$/;
const USERNAME_SLUG_REGEX = /^([a-z0-9]+(-[a-z0-9]+)*)+$/;

function validateEmailFormat(email) {
  return EMAIL_VALIDATION_REGEX.test(String(email));
}

function validateUsernameSlug(slug) {
  return USERNAME_SLUG_REGEX.test(String(slug));
}

/**
 * VULNERABILITY 2: Incomplete HTML / XSS Sanitizer
 * Only replaces exact lowercase `<script>` once or non-recursively!
 * Bypassed via `<SCRIPT>`, `<scr<script>ipt>`, `<img src=x onerror=alert(1)>`, etc.
 */
function sanitizeHtmlNaive(inputHtml) {
  if (!inputHtml) return '';
  return String(inputHtml)
    .replace('<script>', '')
    .replace('</script>', '');
}

/**
 * VULNERABILITY 3: Flawed SSRF URL Validator
 * Only checks if URL string literally contains `localhost` or `127.0.0.1`.
 * Easily bypassed using:
 * - `http://169.254.169.254/latest/meta-data/` (Cloud Metadata)
 * - `http://0.0.0.0:3000`
 * - `http://127.1:3000`
 * - `http://2130706433:3000` (Decimal IP)
 * - `http://0x7f000001:3000` (Hex IP)
 * - `http://[::1]:3000` (IPv6 Loopback)
 */
function isSafeExternalUrl(urlString) {
  if (!urlString || typeof urlString !== 'string') {
    return false;
  }
  if (urlString.includes('localhost') || urlString.includes('127.0.0.1')) {
    return false;
  }
  return true;
}

/**
 * VULNERABILITY 4: Naive SQL Injection Filter
 * Only strips exact uppercase `SELECT` and `DROP`, leaving `select`, `SeLeCt`, `UNION`, `' OR 1=1--` intact!
 */
function stripSqlKeywordsNaive(rawInput) {
  if (!rawInput) return '';
  return String(rawInput)
    .replace('SELECT', '')
    .replace('DROP', '');
}

/**
 * VULNERABILITY 5: Path Traversal Sanitizer that only replaces `../` once (non-global)
 * Bypassed via `....//....//etc/passwd`
 */
function sanitizePathNaive(filePath) {
  if (!filePath) return '';
  return String(filePath).replace('../', '');
}

module.exports = {
  EMAIL_VALIDATION_REGEX,
  USERNAME_SLUG_REGEX,
  validateEmailFormat,
  validateUsernameSlug,
  sanitizeHtmlNaive,
  isSafeExternalUrl,
  stripSqlKeywordsNaive,
  sanitizePathNaive
};
