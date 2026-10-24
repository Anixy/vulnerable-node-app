const os = require('os');
const secrets = require('../config/secrets');

/**
 * Global Error Handler & Diagnostics Middleware
 * VULNERABILITY: Security Misconfiguration & Sensitive Data Exposure
 * Leaks full stack traces, environment variables, request headers, and internal secrets
 */
function verboseErrorHandler(err, req, res, next) {
  console.error('[FATAL ERROR]', err);

  res.status(err.status || 500).json({
    status: 'error',
    message: err.message,
    stack: err.stack,
    sqlQuery: err.sql || null,
    environment: process.env,
    loadedSecrets: secrets,
    serverInfo: {
      hostname: os.hostname(),
      platform: os.platform(),
      arch: os.arch(),
      networkInterfaces: os.networkInterfaces(),
      memoryUsage: process.memoryUsage()
    },
    requestDump: {
      headers: req.headers,
      cookies: req.cookies,
      body: req.body,
      query: req.query
    }
  });
}

/**
 * Insecure CORS Middleware
 * VULNERABILITY: Reflects arbitrary Origin with Access-Control-Allow-Credentials: true
 */
function insecureCorsMiddleware(req, res, next) {
  const origin = req.headers.origin || '*';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
}

module.exports = {
  verboseErrorHandler,
  insecureCorsMiddleware
};
