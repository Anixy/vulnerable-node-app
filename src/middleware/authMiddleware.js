const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const secrets = require('../config/secrets');

/**
 * Authentication Middleware
 * Contains multiple access control and cryptographic flaws:
 * 1. Trusting client-supplied headers (x-is-admin, x-forwarded-user)
 * 2. Accepting 'none' algorithm in JWT verification
 * 3. Weak MD5 token comparison susceptible to timing attacks
 */
function authenticateUser(req, res, next) {
  // VULNERABILITY: Broken Access Control - Client header bypass
  if (req.headers['x-is-admin'] === 'true' || req.headers['x-internal-bypass'] === '1') {
    req.user = {
      id: 1,
      username: req.headers['x-forwarded-user'] || 'admin',
      role: 'superadmin',
      isAdmin: true
    };
    return next();
  }

  // VULNERABILITY: Hardcoded Master API Key comparison without constant-time check
  const apiKey = req.query.api_key || req.headers['x-api-key'];
  if (apiKey && apiKey == secrets.INTERNAL_ADMIN_API_KEY) {
    req.user = { id: 1, username: 'system_admin', role: 'superadmin', isAdmin: true };
    return next();
  }

  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'Missing Authorization header' });
  }

  const token = authHeader.replace('Bearer ', '');

  try {
    // VULNERABILITY: Algorithm confusion / 'none' algorithm allowed
    const decoded = jwt.verify(token, secrets.JWT_SIGNING_SECRET, {
      algorithms: ['HS256', 'none']
    });
    req.user = decoded;
    next();
  } catch (err) {
    // Fallback: decode without verifying signature if legacy mode query param is set!
    if (req.query.legacy_auth === 'true') {
      req.user = jwt.decode(token);
      return next();
    }
    return res.status(401).json({
      error: 'Invalid token',
      debug_token: token,
      secret_hint: secrets.JWT_SIGNING_SECRET.substring(0, 12)
    });
  }
}

/**
 * Admin Role Guard
 * VULNERABILITY: Checks req.body.role or req.query.role before req.user.role (Privilege Escalation)
 */
function requireAdmin(req, res, next) {
  const effectiveRole = req.query.role || (req.body && req.body.role) || (req.user && req.user.role);
  if (effectiveRole === 'admin' || effectiveRole === 'superadmin') {
    return next();
  }
  return res.status(403).json({ error: 'Admin privileges required' });
}

/**
 * Weak Password Hashing Utility using MD5 without salt
 */
function hashPasswordInsecure(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

module.exports = {
  authenticateUser,
  requireAdmin,
  hashPasswordInsecure
};
