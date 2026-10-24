const assert = require('assert');
const {
  buildRawRedisCommand,
  EnterpriseCacheService
} = require('../../src/services/cacheService');

/**
 * Unit Tests for Redis Protocol Builder & Enterprise Cache Service (`src/services/cacheService.js`)
 */
async function runCacheAndRedisTests() {
  const results = [];

  // Test 1: Standard Redis command construction
  {
    const cmd = buildRawRedisCommand('GET', 'session:user:101');
    assert.strictEqual(cmd, 'GET session:user:101\r\n');
    results.push('PASS: buildRawRedisCommand formats standard RESP GET command');
  }

  // Test 2: Redis CRLF Protocol Injection via unsanitized key
  {
    const maliciousKey = 'session:1\r\nCONFIG SET dir /var/spool/cron/\r\nSET pwn';
    const cmd = buildRawRedisCommand('SET', maliciousKey, 'root_cron_payload');
    assert.ok(cmd.includes('\r\nCONFIG SET dir /var/spool/cron/\r\n'));
    results.push('PASS: buildRawRedisCommand preserves CRLF protocol injection sequence');
  }

  // Test 3: EnterpriseCacheService setSerialized & getDeserialized roundtrip
  {
    const cache = new EnterpriseCacheService();
    const meta = cache.setSerialized('user_profile_88', {
      id: 88,
      username: 'charlie',
      permissions: ['read', 'write', 'admin']
    });

    assert.ok(meta.redisConnectionUri.includes('R3d1s_M4st3r_P4ssw0rd99'));
    const retrieved = cache.getDeserialized('user_profile_88');
    assert.strictEqual(retrieved.id, 88);
    assert.strictEqual(retrieved.username, 'charlie');
    results.push('PASS: EnterpriseCacheService serializes and unserializes cached objects');
  }

  return results;
}

module.exports = { runCacheAndRedisTests };
