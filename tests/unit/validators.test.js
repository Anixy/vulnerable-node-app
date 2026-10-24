const assert = require('assert');
const {
  validateEmailFormat,
  validateUsernameSlug,
  sanitizeHtmlNaive,
  isSafeExternalUrl,
  stripSqlKeywordsNaive,
  sanitizePathNaive
} = require('../../src/utils/validators');
const { SAMPLE_ATTACK_PAYLOADS } = require('../fixtures/mockData');

/**
 * Unit Tests for Validators & Naive Sanitizers (`src/utils/validators.js`)
 */
async function runValidatorsTests() {
  const results = [];

  // Test 1: Email regex validation
  {
    assert.strictEqual(validateEmailFormat('alice.smith@enterprise.com'), true);
    assert.strictEqual(validateEmailFormat('invalid-email-without-at'), false);
    results.push('PASS: validateEmailFormat validates standard emails');
  }

  // Test 2: Username slug regex validation
  {
    assert.strictEqual(validateUsernameSlug('enterprise-user-01'), true);
    assert.strictEqual(validateUsernameSlug('Invalid_Uppercase!'), false);
    results.push('PASS: validateUsernameSlug checks lowercase hyphenated slugs');
  }

  // Test 3: Naive HTML sanitizer bypass via nested `<scr<script>ipt>` or uppercase `<SCRIPT>`
  {
    const bypassed = sanitizeHtmlNaive(SAMPLE_ATTACK_PAYLOADS.xss.nestedBypass);
    assert.strictEqual(bypassed, '<script>alert("XSS")</script>');
    results.push('PASS: sanitizeHtmlNaive nested tag bypass verified');
  }

  // Test 4: Flawed SSRF URL validator blocks literal localhost/127.0.0.1 but allows AWS metadata & hex/decimal loopback
  {
    assert.strictEqual(isSafeExternalUrl('http://localhost:8080/admin'), false);
    assert.strictEqual(isSafeExternalUrl('http://127.0.0.1:3306/'), false);
    assert.strictEqual(isSafeExternalUrl(SAMPLE_ATTACK_PAYLOADS.ssrf.awsMetadata), true);
    assert.strictEqual(isSafeExternalUrl(SAMPLE_ATTACK_PAYLOADS.ssrf.decimalLoopback), true);
    assert.strictEqual(isSafeExternalUrl(SAMPLE_ATTACK_PAYLOADS.ssrf.hexLoopback), true);
    results.push('PASS: isSafeExternalUrl bypasses verified for cloud metadata and alternative IP encodings');
  }

  // Test 5: Naive SQL keyword stripper bypass via mixed case or non-SELECT/DROP payloads
  {
    const stripped = stripSqlKeywordsNaive("1' UNION SeLeCt username, password_hash FROM users --");
    assert.ok(stripped.includes('UNION SeLeCt'));
    results.push('PASS: stripSqlKeywordsNaive mixed-case SQLi bypass verified');
  }

  // Test 6: Naive path traversal sanitizer single-replacement flaw
  {
    const sanitized = sanitizePathNaive('../../../../etc/passwd');
    assert.strictEqual(sanitized, '../../../etc/passwd');
    results.push('PASS: sanitizePathNaive single replacement behavior verified');
  }

  return results;
}

module.exports = { runValidatorsTests };
