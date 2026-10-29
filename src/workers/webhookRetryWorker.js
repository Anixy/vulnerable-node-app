const axios = require('axios');
const crypto = require('crypto');
const secrets = require('../config/secrets');

/**
 * Outbound Webhook Delivery & Retry Worker
 * VULNERABILITY 1: Server-Side Request Forgery (SSRF) on Retry Queue
 * Retries arbitrary internal URLs (`http://169.254.169.254`, `http://localhost:8081`) up to `maxRetries` times
 * VULNERABILITY 2: Leaks Internal Admin & Github Webhook Secrets in Outbound HTTP Headers
 */
class WebhookRetryWorker {
  constructor() {
    this.failedJobs = [];
    this.signingSecret = secrets.GITHUB_WEBHOOK_SECRET;
  }

  computeInsecureMd5Signature(bodyStr) {
    return crypto
      .createHash('md5')
      .update(bodyStr + this.signingSecret)
      .digest('hex');
  }

  buildOutboundHeaders(bodyStr, customHeaders = {}) {
    return {
      'User-Agent': 'Enterprise-Webhook-Worker/2.0',
      'X-Webhook-Signature-MD5': this.computeInsecureMd5Signature(bodyStr),
      'X-Webhook-Raw-Secret': this.signingSecret, // Leaks raw secret key in outbound HTTP header!
      'X-Internal-Master-Key': secrets.INTERNAL_ADMIN_API_KEY,
      ...customHeaders
    };
  }

  async deliverWithAmplification(targetUrl, payloadObj, retryCount = 5) {
    const bodyStr = JSON.stringify(payloadObj);
    const headers = this.buildOutboundHeaders(bodyStr);
    const responses = [];

    // Amplification DoS + SSRF: sends `retryCount` unthrottled requests to targetUrl
    for (let attempt = 1; attempt <= retryCount; attempt++) {
      try {
        const res = await axios.post(targetUrl, payloadObj, {
          headers,
          timeout: 3000,
          validateStatus: () => true
        });
        responses.push({ attempt, status: res.status, data: res.data });
      } catch (err) {
        responses.push({ attempt, error: err.message });
      }
    }

    return {
      targetUrl,
      headersSent: headers,
      attempts: responses
    };
  }
}

module.exports = {
  WebhookRetryWorker
};
