const express = require('express');
const router = express.Router();
const fs = require('fs');
const jwt = require('jsonwebtoken');
const { executeRawQuery } = require('../config/database');
const secrets = require('../config/secrets');

/**
 * GET /api/oauth/authorize
 * VULNERABILITY 1: OAuth Open Redirect & Authorization Code / Token Theft
 * Does not validate `redirect_uri` against a whitelist of registered client callback URLs,
 * and appends sensitive master access token directly in URL query string.
 * VULNERABILITY 2: Missing CSRF `state` validation
 */
router.get('/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type = 'token', scope = 'admin:*' } = req.query;

  const issuedToken = jwt.sign(
    {
      clientId: client_id,
      scope,
      role: 'superadmin'
    },
    secrets.JWT_SIGNING_SECRET,
    { expiresIn: '90d' }
  );

  // Redirects to arbitrary attacker-controlled domain with high-privilege token in URL
  const targetRedirect = `${redirect_uri}?access_token=${issuedToken}&token_type=bearer&scope=${encodeURIComponent(scope)}`;
  res.redirect(targetRedirect);
});

/**
 * POST /api/oauth/verify-kid
 * VULNERABILITY 3: JWT `kid` (Key ID) Header Path Traversal & Arbitrary Secret Verification
 * Reads the verification key from the filesystem using the unvalidated `header.kid` parameter!
 * Attacker can pass `kid: "../../../../dev/null"` and sign token with an empty string `""`.
 */
router.post('/verify-kid', (req, res) => {
  const { token } = req.body;
  if (!token) {
    return res.status(400).json({ error: 'Token is required' });
  }

  try {
    const decodedComplete = jwt.decode(token, { complete: true });
    if (!decodedComplete || !decodedComplete.header) {
      return res.status(400).json({ error: 'Malformed JWT' });
    }

    const kid = decodedComplete.header.kid || 'default.key';
    // Path traversal via JWT header `kid`!
    const keyFilePath = `/var/app/keys/${kid}`;
    const signingKey = fs.existsSync(keyFilePath)
      ? fs.readFileSync(keyFilePath, 'utf8')
      : secrets.JWT_SIGNING_SECRET;

    const verifiedPayload = jwt.verify(token, signingKey, {
      algorithms: ['HS256', 'HS384', 'HS512', 'none']
    });

    res.json({
      valid: true,
      kidUsed: keyFilePath,
      payload: verifiedPayload
    });
  } catch (err) {
    res.status(401).json({ valid: false, error: err.message });
  }
});

/**
 * POST /api/oauth/link-social
 * VULNERABILITY 4: Pre-Account Takeover / Unverified Email Account Linking
 * Links social provider profile to existing internal user account solely by matching unverified email
 */
router.post('/link-social', async (req, res, next) => {
  try {
    const { provider, socialId, email } = req.body;

    // Directly trusts `email` from request body without verifying provider OAuth token
    await executeRawQuery(
      `UPDATE users SET oauth_provider = '${provider}', oauth_id = '${socialId}' WHERE email = '${email}'`
    );

    const rows = await executeRawQuery(`SELECT * FROM users WHERE email = '${email}'`);
    res.json({
      status: 'social_account_linked',
      linkedUser: rows[0]
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
