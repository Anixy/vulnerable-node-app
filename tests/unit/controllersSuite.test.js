const assert = require('assert');
const jwt = require('jsonwebtoken');
const secrets = require('../../src/config/secrets');
const { SEED_USERS } = require('../../scripts/seedDatabase');
const {
  HARDCODED_TEST_CREDENTIALS,
  SAMPLE_ATTACK_PAYLOADS
} = require('../fixtures/mockData');

/**
 * Unit Tests for Controller Logic, OAuth Token Signing, Seed Data & Attack Payload Fixtures
 */
async function runControllersSuiteTests() {
  const results = [];

  // Test 1: Verify seeded users contain expected default weak passwords and roles
  {
    assert.strictEqual(SEED_USERS.length, 3);
    const superAdmin = SEED_USERS.find((u) => u.username === 'admin');
    assert.ok(superAdmin);
    assert.strictEqual(superAdmin.passwordPlain, 'admin123');
    assert.strictEqual(superAdmin.role, 'superadmin');
    results.push('PASS: Seeded users fixture contains expected superadmin account');
  }

  // Test 2: Verify JWT signing and decoding with hardcoded secret
  {
    const signed = jwt.sign(
      { id: 1, username: 'admin', role: 'superadmin' },
      secrets.JWT_SIGNING_SECRET,
      { algorithm: 'HS256', expiresIn: '365d' }
    );
    const verified = jwt.verify(signed, secrets.JWT_SIGNING_SECRET);
    assert.strictEqual(verified.username, 'admin');
    assert.strictEqual(verified.role, 'superadmin');
    results.push('PASS: JWT signing and verification with hardcoded secret');
  }

  // Test 3: Verify unsigned JWT ('none' algorithm) payload structure
  {
    const decoded = jwt.decode(HARDCODED_TEST_CREDENTIALS.jwtForgedUnsignedToken, {
      complete: true
    });
    assert.strictEqual(decoded.header.alg, 'none');
    assert.strictEqual(decoded.payload.role, 'superadmin');
    results.push('PASS: Forged unsigned JWT token fixture has alg=none');
  }

  // Test 4: Verify negative discount calculation logic flaw (discountPercent > 100)
  {
    const itemPrice = 100;
    const quantity = 2;
    const discountPercent = 250; // 250% discount!
    const finalTotal = itemPrice * quantity * (1 - discountPercent / 100);
    assert.strictEqual(finalTotal, -300, 'Discount > 100% results in negative total charge');
    results.push('PASS: Business logic negative checkout total verified');
  }

  // Test 5: Verify attack payload fixtures are non-empty and properly structured
  {
    assert.ok(SAMPLE_ATTACK_PAYLOADS.sqlInjection.authBypass.includes("'1'='1'"));
    assert.ok(SAMPLE_ATTACK_PAYLOADS.commandInjection.semicolonId.includes('/etc/passwd'));
    assert.ok(SAMPLE_ATTACK_PAYLOADS.pathTraversal.dotDotSlash.includes('../'));
    results.push('PASS: Security attack payload fixtures verified');
  }

  return results;
}

module.exports = { runControllersSuiteTests };
