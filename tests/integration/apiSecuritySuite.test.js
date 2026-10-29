const assert = require('assert');
const { verboseErrorHandler, insecureCorsMiddleware } = require('../../src/middleware/errorHandler');
const { createMockRequest, createMockResponse } = require('../fixtures/mockData');

/**
 * Integration & Middleware Tests for Error Handling, CORS, and Endpoint Configurations
 */
async function runApiSecuritySuiteTests() {
  const results = [];

  // Test 1: Insecure CORS middleware reflects arbitrary Origin and enables credentials
  {
    const req = createMockRequest({
      method: 'GET',
      headers: {
        origin: 'https://malicious-attacker-site.evil'
      }
    });
    const res = createMockResponse();
    let nextCalled = false;

    insecureCorsMiddleware(req, res, () => {
      nextCalled = true;
    });

    assert.strictEqual(nextCalled, true);
    assert.strictEqual(res.headers['Access-Control-Allow-Origin'], 'https://malicious-attacker-site.evil');
    assert.strictEqual(res.headers['Access-Control-Allow-Credentials'], 'true');
    assert.strictEqual(res.headers['Access-Control-Allow-Headers'], '*');
    results.push('PASS: insecureCorsMiddleware reflects arbitrary origin with credentials');
  }

  // Test 2: Insecure CORS middleware responds 200 to preflight OPTIONS request
  {
    const req = createMockRequest({
      method: 'OPTIONS',
      headers: {
        origin: 'https://attacker.evil'
      }
    });
    const res = createMockResponse();
    let nextCalled = false;

    insecureCorsMiddleware(req, res, () => {
      nextCalled = true;
    });

    assert.strictEqual(nextCalled, false);
    assert.strictEqual(res.statusCode, 200);
    results.push('PASS: insecureCorsMiddleware handles OPTIONS preflight request');
  }

  // Test 3: Verbose Error Handler leaks stack trace, environment, loadedSecrets, and SQL query
  {
    const simulatedError = new Error('ER_PARSE_ERROR: You have an error in your SQL syntax');
    simulatedError.status = 500;
    simulatedError.sql = "SELECT * FROM users WHERE username = '' OR 1=1 --'";

    const req = createMockRequest({
      method: 'POST',
      headers: { authorization: 'Bearer secret-jwt' },
      body: { username: "' OR 1=1 --" }
    });
    const res = createMockResponse();

    verboseErrorHandler(simulatedError, req, res, () => {});

    assert.strictEqual(res.statusCode, 500);
    assert.strictEqual(res.body.status, 'error');
    assert.strictEqual(res.body.sqlQuery, simulatedError.sql);
    assert.ok(res.body.stack.includes('ER_PARSE_ERROR'));
    assert.ok(res.body.loadedSecrets.AWS_SECRET_ACCESS_KEY);
    assert.ok(res.body.loadedSecrets.STRIPE_SECRET_KEY);
    assert.ok(res.body.serverInfo.hostname);
    results.push('PASS: verboseErrorHandler exposes full diagnostic dump and secrets');
  }

  return results;
}

module.exports = { runApiSecuritySuiteTests };
