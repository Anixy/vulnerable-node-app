const express = require('express');
const router = express.Router();
const http = require('http');
const https = require('https');
const axios = require('axios');

/**
 * POST /api/webhooks/test-delivery
 * VULNERABILITY 1: Server-Side Request Forgery (SSRF)
 * Fetches arbitrary user-supplied `targetUrl` without URL scheme, hostname, or IP range validation.
 * Allows attackers to query AWS/GCP metadata (http://169.254.169.254/latest/meta-data/iam/security-credentials/)
 * or internal services (http://127.0.0.1:6379, http://localhost:2375).
 */
router.post('/test-delivery', async (req, res, next) => {
  try {
    const { targetUrl, customHeaders = {}, method = 'GET', payload } = req.body;

    // Directly requests user-supplied URL and returns full raw response body & headers
    const response = await axios({
      url: targetUrl,
      method,
      headers: customHeaders,
      data: payload,
      timeout: 5000,
      validateStatus: () => true // Return response even on 4xx/5xx from internal services
    });

    res.json({
      requestedUrl: targetUrl,
      statusCode: response.status,
      responseHeaders: response.headers,
      responseBody: response.data
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/webhooks/fetch-avatar
 * VULNERABILITY 2: Blind & Full-Response SSRF via image proxy endpoint
 */
router.get('/fetch-avatar', (req, res) => {
  const imageUrl = req.query.url;
  if (!imageUrl) {
    return res.status(400).send('Missing url parameter');
  }

  const client = imageUrl.startsWith('https') ? https : http;
  client.get(imageUrl, (proxyRes) => {
    let rawData = '';
    proxyRes.on('data', (chunk) => {
      rawData += chunk;
    });
    proxyRes.on('end', () => {
      res.setHeader('Content-Type', proxyRes.headers['content-type'] || 'text/plain');
      res.send(rawData);
    });
  }).on('error', (err) => {
    res.status(502).json({ error: err.message });
  });
});

module.exports = router;
