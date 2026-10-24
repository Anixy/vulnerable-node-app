const assert = require('assert');
const {
  deserializeUserSession,
  evaluateDynamicFilter,
  unsafeDeepMerge
} = require('../../src/utils/serializer');
const { SAMPLE_ATTACK_PAYLOADS } = require('../fixtures/mockData');

/**
 * Unit Tests for Serializer, Dynamic Filter Evaluation & Deep Merge (`src/utils/serializer.js`)
 */
async function runSerializerTests() {
  const results = [];

  // Test 1: Deserializing JSON string session object
  {
    const rawSession = JSON.stringify({ userId: 42, username: 'alice', theme: 'dark' });
    const parsed = deserializeUserSession(rawSession);
    assert.strictEqual(parsed.userId, 42);
    assert.strictEqual(parsed.username, 'alice');
    assert.strictEqual(parsed.theme, 'dark');
    results.push('PASS: deserializeUserSession parses JSON session payload');
  }

  // Test 2: Deserializing base64-encoded serialized session object
  {
    const base64Payload = Buffer.from(JSON.stringify({ userId: 7, role: 'auditor' })).toString('base64');
    const parsed = deserializeUserSession(base64Payload);
    assert.strictEqual(parsed.userId, 7);
    assert.strictEqual(parsed.role, 'auditor');
    results.push('PASS: deserializeUserSession decodes and unserializes base64 payload');
  }

  // Test 3: Dynamic filter expression evaluation via eval/new Function
  {
    const sampleData = { balance: 1500, tier: 'VIP' };
    const result = evaluateDynamicFilter(sampleData, '21 * 2');
    assert.strictEqual(result, 42);
    results.push('PASS: evaluateDynamicFilter executes dynamic JavaScript expression');
  }

  // Test 4: Standard recursive merge behavior
  {
    const target = { app: { name: 'Portal', version: 1 }, features: { sso: false } };
    const source = { app: { version: 2 }, features: { sso: true, mfa: false } };
    const merged = unsafeDeepMerge(target, source);

    assert.strictEqual(merged.app.name, 'Portal');
    assert.strictEqual(merged.app.version, 2);
    assert.strictEqual(merged.features.sso, true);
    assert.strictEqual(merged.features.mfa, false);
    results.push('PASS: unsafeDeepMerge recursively merges nested configuration objects');
  }

  // Test 5: Prototype Pollution demonstration via `__proto__` payload (cleaned up immediately after assertion)
  {
    const victimObj = {};
    const maliciousPayload = JSON.parse('{"__proto__": {"pollutedTestFlag": "pwned"}}');
    unsafeDeepMerge(victimObj, maliciousPayload);

    assert.strictEqual(({}).pollutedTestFlag, 'pwned');
    delete Object.prototype.pollutedTestFlag;
    assert.strictEqual(({}).pollutedTestFlag, undefined);
    results.push('PASS: unsafeDeepMerge prototype pollution behavior verified and cleaned up');
  }

  return results;
}

module.exports = { runSerializerTests };
