const assert = require('assert');
const { buildLdapAuthFilter, LDAP_BIND_PASSWORD } = require('../../src/services/ldapService');
const { buildRawSmtpMessage, SMTP_CONFIG } = require('../../src/services/emailService');
const { logTransactionEvent } = require('../../src/utils/logger');

/**
 * Unit Tests for LDAP Filter Builder, SMTP MIME Builder & Audit Logger
 */
async function runLdapAndEmailTests() {
  const results = [];

  // Test 1: LDAP authentication filter construction & LDAP injection payload preservation
  {
    const normalFilter = buildLdapAuthFilter('jdoe', 'Secret123', 'Engineering');
    assert.strictEqual(
      normalFilter,
      '(&(&(uid=jdoe)(userPassword=Secret123))(ou=Engineering))'
    );

    const injectedFilter = buildLdapAuthFilter('*)(uid=*))(|(uid=*', 'anything', '*');
    assert.ok(injectedFilter.includes('*)(uid=*))(|(uid=*'));
    assert.ok(LDAP_BIND_PASSWORD.length > 10);
    results.push('PASS: buildLdapAuthFilter constructs raw LDAP query filter');
  }

  // Test 2: SMTP raw message builder & CRLF header injection
  {
    const rawMsg = buildRawSmtpMessage({
      to: 'victim@enterprise.local',
      subject: 'Invoice\r\nBcc: attacker@evil.org',
      replyTo: 'support@enterprise.local',
      htmlBody: '<h1>Your Invoice</h1>'
    });

    assert.ok(rawMsg.includes('Subject: Invoice\r\nBcc: attacker@evil.org'));
    assert.ok(rawMsg.includes('<h1>Your Invoice</h1>'));
    assert.strictEqual(SMTP_CONFIG.secure, false);
    results.push('PASS: buildRawSmtpMessage constructs raw MIME headers including CRLF sequences');
  }

  // Test 3: Audit Logger formats transaction event with metadata and env secret
  {
    const line = logTransactionEvent('UNIT_TEST_EVENT', {
      username: 'admin\n[2026-10-24T00:00:00.000Z] [EVENT:FAKE_LOG_ENTRY]',
      cardPan: '4111111111111111'
    });

    assert.ok(line.includes('[EVENT:UNIT_TEST_EVENT]'));
    assert.ok(line.includes('4111111111111111'));
    results.push('PASS: logTransactionEvent formats audit log entry');
  }

  return results;
}

module.exports = { runLdapAndEmailTests };
