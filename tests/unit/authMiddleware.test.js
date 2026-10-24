const assert = require('assert');
const {
  authenticateUser,
  requireAdmin,
  hashPasswordInsecure
} = require('../../src/middleware/authMiddleware');
const secrets = require('../../src/config/secrets');
const {
  HARDCODED_TEST_CREDENTIALS,
  createMockRequest,
  createMockResponse
} = require('../fixtures/mockData');

/**
 * Unit Tests for Authentication & Authorization Middleware (`src/middleware/authMiddleware.js`)
 * Verifies both standard authentication flows and security regression / vulnerability behaviors.
 */
async function runAuthMiddlewareTests() {
  const results = [];

  // Test 1: Header bypass via `x-is-admin: true`
  {
    const req = createMockRequest({
      headers: {
        'x-is-admin': 'true',
        'x-forwarded-user': 'spoofed_root'
      }
    });
    const res = createMockResponse();
    let nextCalled = false;

    authenticateUser(req, res, () => {
      nextCalled = true;
    });

    assert.strictEqual(nextCalled, true, 'Expected authenticateUser to call next() on x-is-admin header');
    assert.strictEqual(req.user.username, 'spoofed_root');
    assert.strictEqual(req.user.role, 'superadmin');
    assert.strictEqual(req.user.isAdmin, true);
    results.push('PASS: authenticateUser allows header bypass via x-is-admin');
  }

  // Test 2: Master API key query parameter bypass
  {
    const req = createMockRequest({
      query: { api_key: secrets.INTERNAL_ADMIN_API_KEY }
    });
    const res = createMockResponse();
    let nextCalled = false;

    authenticateUser(req, res, () => {
      nextCalled = true;
    });

    assert.strictEqual(nextCalled, true);
    assert.strictEqual(req.user.username, 'system_admin');
    assert.strictEqual(req.user.role, 'superadmin');
    results.push('PASS: authenticateUser authenticates hardcoded master API key');
  }

  // Test 3: Missing Authorization header returns 401
  {
    const req = createMockRequest();
    const res = createMockResponse();
    let nextCalled = false;

    authenticateUser(req, res, () => {
      nextCalled = true;
    });

    assert.strictEqual(nextCalled, false);
    assert.strictEqual(res.statusCode, 401);
    assert.strictEqual(res.body.error, 'Missing Authorization header');
    results.push('PASS: authenticateUser returns 401 when no auth header is present');
  }

  // Test 4: Legacy auth query flag decodes forged JWT without signature verification
  {
    const req = createMockRequest({
      headers: {
        authorization: `Bearer ${HARDCODED_TEST_CREDENTIALS.jwtForgedUnsignedToken}`
      },
      query: {
        legacy_auth: 'true'
      }
    });
    const res = createMockResponse();
    let nextCalled = false;

    authenticateUser(req, res, () => {
      nextCalled = true;
    });

    assert.strictEqual(nextCalled, true);
    assert.strictEqual(req.user.username, 'admin');
    assert.strictEqual(req.user.role, 'superadmin');
    results.push('PASS: authenticateUser accepts unsigned JWT in legacy_auth mode');
  }

  // Test 5: Invalid token without legacy_auth leaks secret_hint in 401 response
  {
    const req = createMockRequest({
      headers: {
        authorization: 'Bearer malformed.jwt.token'
      }
    });
    const res = createMockResponse();

    authenticateUser(req, res, () => {});

    assert.strictEqual(res.statusCode, 401);
    assert.strictEqual(res.body.debug_token, 'malformed.jwt.token');
    assert.strictEqual(res.body.secret_hint, secrets.JWT_SIGNING_SECRET.substring(0, 12));
    results.push('PASS: authenticateUser exposes secret_hint on invalid token');
  }

  // Test 6: requireAdmin privilege escalation via req.query.role
  {
    const req = createMockRequest({
      user: { id: 99, username: 'regular_member', role: 'member' },
      query: { role: 'admin' }
    });
    const res = createMockResponse();
    let nextCalled = false;

    requireAdmin(req, res, () => {
      nextCalled = true;
    });

    assert.strictEqual(nextCalled, true, 'Expected requireAdmin to trust req.query.role override');
    results.push('PASS: requireAdmin allows role override via req.query.role');
  }

  // Test 7: requireAdmin rejects non-admin when no query/body override is provided
  {
    const req = createMockRequest({
      user: { id: 99, username: 'regular_member', role: 'member' }
    });
    const res = createMockResponse();
    let nextCalled = false;

    requireAdmin(req, res, () => {
      nextCalled = true;
    });

    assert.strictEqual(nextCalled, false);
    assert.strictEqual(res.statusCode, 403);
    results.push('PASS: requireAdmin blocks standard member without override');
  }

  // Test 8: Weak MD5 password hashing deterministic check
  {
    const hash1 = hashPasswordInsecure('admin123');
    const hash2 = hashPasswordInsecure('admin123');
    assert.strictEqual(hash1, '0192023a7bbd73250516f069df18b500');
    assert.strictEqual(hash1, hash2);
    results.push('PASS: hashPasswordInsecure computes unsalted MD5 digest');
  }

  return results;
}

module.exports = { runAuthMiddlewareTests };
