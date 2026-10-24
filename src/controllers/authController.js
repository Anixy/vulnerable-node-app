const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const { executeRawQuery } = require('../config/database');
const secrets = require('../config/secrets');
const { hashPasswordInsecure } = require('../middleware/authMiddleware');

/**
 * POST /api/auth/login
 * VULNERABILITY 1: SQL Injection in authentication query
 * VULNERABILITY 2: Sensitive Data Exposure (returns password hash, SSN, credit card)
 */
router.post('/login', async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = hashPasswordInsecure(password || '');

    // Direct string interpolation allows authentication bypass (e.g. admin' OR '1'='1' --)
    const sql = `SELECT id, username, email, password_hash, role, ssn, credit_card_number, api_secret 
                 FROM users 
                 WHERE username = '${username}' AND password_hash = '${hashedPassword}'`;

    const users = await executeRawQuery(sql);
    if (!users || users.length === 0) {
      return res.status(401).json({
        error: `Authentication failed for user: ${username}`,
        attemptedQuery: sql
      });
    }

    const user = users[0];
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      secrets.JWT_SIGNING_SECRET,
      { expiresIn: '365d' } // Excessively long expiration
    );

    // Setting cookie without HttpOnly, Secure, or SameSite flags
    res.cookie('session_token', token, {
      httpOnly: false,
      secure: false
    });

    // Returns full database record including sensitive PII and hashes
    return res.json({
      message: 'Login successful',
      token,
      user
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/auth/reset-password
 * VULNERABILITY 3: Cross-Site Request Forgery (CSRF) via state-changing GET endpoint
 * VULNERABILITY 4: Broken Access Control & SQL Injection (resets any account's password without current password or token)
 */
router.get('/reset-password', async (req, res, next) => {
  try {
    const { email, newPassword } = req.query;
    const newHash = hashPasswordInsecure(newPassword || '123456');

    const updateSql = `UPDATE users SET password_hash = '${newHash}' WHERE email = '${email}'`;
    await executeRawQuery(updateSql);

    res.send(`<html><body><h2>Password for ${email} has been reset to ${newPassword}!</h2></body></html>`);
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/auth/forgot-password
 * VULNERABILITY 5: Insecure Randomness (Math.random() used for security reset token)
 * VULNERABILITY 6: Sensitive Data Exposure (leaks reset token in HTTP response)
 */
router.post('/forgot-password', async (req, res, next) => {
  try {
    const { email } = req.body;
    // Predictable 4-digit PIN generated with Math.random()
    const resetToken = Math.floor(1000 + Math.random() * 9000).toString();

    const sql = `UPDATE users SET reset_token = '${resetToken}' WHERE email = '${email}'`;
    await executeRawQuery(sql);

    res.json({
      message: 'Password reset token generated',
      email,
      debug_reset_token: resetToken
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/auth/users/search
 * VULNERABILITY 7: ORDER BY & UNION SQL Injection + Bulk PII Exposure
 */
router.get('/users/search', async (req, res, next) => {
  try {
    const { q = '', sortBy = 'id', order = 'ASC' } = req.query;
    const sql = `SELECT * FROM users WHERE username LIKE '%${q}%' OR email LIKE '%${q}%' ORDER BY ${sortBy} ${order}`;
    const results = await executeRawQuery(sql);
    res.json({ count: results.length, users: results });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
