const express = require('express');
const router = express.Router();
const { executeRawQuery } = require('../config/database');
const { deserializeUserSession, evaluateDynamicFilter } = require('../utils/serializer');

/**
 * GET /api/profile/render
 * VULNERABILITY 1: Reflected Cross-Site Scripting (XSS)
 * Directly embeds unescaped query parameters `name`, `bio`, and `theme` into HTML output
 */
router.get('/render', (req, res) => {
  const { name = 'Guest', bio = '', avatarUrl = '' } = req.query;

  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <title>Profile of ${name}</title>
      </head>
      <body>
        <div class="profile-card">
          <img src="${avatarUrl}" onerror="console.log('Avatar failed')" />
          <h1>Welcome back, ${name}!</h1>
          <div class="user-bio">${bio}</div>
        </div>
      </body>
    </html>
  `;
  res.setHeader('Content-Type', 'text/html');
  res.send(html);
});

/**
 * POST /api/profile/comments
 * VULNERABILITY 2: Stored XSS + SQL Injection
 * Saves raw HTML/JS payload into database and renders it to all visitors without sanitization
 */
router.post('/comments', async (req, res, next) => {
  try {
    const { author, commentHtml } = req.body;
    await executeRawQuery(
      `INSERT INTO profile_comments (author, comment_html) VALUES ('${author}', '${commentHtml}')`
    );

    const allComments = await executeRawQuery(`SELECT author, comment_html FROM profile_comments`);
    let page = '<h2>Public Wall Comments</h2><ul>';
    for (const row of allComments) {
      page += `<li><strong>${row.author}:</strong> ${row.comment_html}</li>`;
    }
    page += '</ul>';

    res.setHeader('Content-Type', 'text/html');
    res.send(page);
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/profile/preferences
 * VULNERABILITY 3: Insecure Deserialization & Code Injection via `serializer.js`
 */
router.post('/preferences', (req, res) => {
  const { serializedPrefs, filterExpression } = req.body;
  const prefs = deserializeUserSession(serializedPrefs);
  const filterResult = filterExpression ? evaluateDynamicFilter(prefs, filterExpression) : prefs;

  res.json({
    status: 'preferences_loaded',
    data: filterResult
  });
});

/**
 * GET /api/profile/redirect
 * VULNERABILITY 4: Open Redirect / DOM XSS via `javascript:` URI
 */
router.get('/redirect', (req, res) => {
  const returnUrl = req.query.next || req.query.returnUrl || '/';
  res.redirect(returnUrl);
});

module.exports = router;
