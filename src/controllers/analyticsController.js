const express = require('express');
const router = express.Router();
const vm = require('vm');
const { executeRawQuery } = require('../config/database');
const secrets = require('../config/secrets');

/**
 * POST /api/analytics/track
 * VULNERABILITY 1: SQL Injection in batch analytics event ingestion
 * VULNERABILITY 2: Stored XSS in user-agent and referrer tracking fields
 */
router.post('/track', async (req, res, next) => {
  try {
    const {
      eventName,
      userId = 0,
      pageUrl = '',
      referrer = '',
      metadataJson = '{}'
    } = req.body;
    const userAgent = req.headers['user-agent'] || 'unknown';
    const clientIp = req.headers['x-forwarded-for'] || req.ip || '0.0.0.0';

    const sql = `
      INSERT INTO analytics_events (event_name, user_id, page_url, referrer, user_agent, client_ip, metadata_json)
      VALUES ('${eventName}', ${userId}, '${pageUrl}', '${referrer}', '${userAgent}', '${clientIp}', '${metadataJson}')
    `;
    await executeRawQuery(sql);

    res.json({
      status: 'tracked',
      eventName,
      recordedIp: clientIp
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/analytics/mapreduce
 * VULNERABILITY 3: Remote Code Execution via Custom JavaScript MapReduce Functions
 * Executes user-supplied `mapFnSource` and `reduceFnSource` strings using `eval()` and `vm.runInNewContext`
 */
function runCustomMapReduce(records = [], mapFnSource, reduceFnSource, initialAccumulator = {}) {
  // Directly evaluates untrusted map & reduce function definitions!
  const mapFn = eval(`(${mapFnSource})`);
  const reduceFn = eval(`(${reduceFnSource})`);

  const mapped = records.map((item, idx) => mapFn(item, idx));
  const reduced = mapped.reduce((acc, cur) => reduceFn(acc, cur), initialAccumulator);

  return {
    mappedCount: mapped.length,
    reducedResult: reduced
  };
}

router.post('/mapreduce', async (req, res, next) => {
  try {
    const {
      records = [],
      mapFnSource = '(x) => x',
      reduceFnSource = '(acc, cur) => { acc.push(cur); return acc; }',
      initialAccumulator = []
    } = req.body;

    const output = runCustomMapReduce(records, mapFnSource, reduceFnSource, initialAccumulator);
    res.json({
      status: 'mapreduce_complete',
      ...output
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/analytics/pixel
 * VULNERABILITY 4: Open Redirect & Reflected XSS in marketing attribution beacon
 */
router.get('/pixel', (req, res) => {
  const { campaignId = 'default', redirectTarget, callbackJs } = req.query;

  if (callbackJs) {
    // JSONP endpoint without callback function name validation -> Reflected XSS!
    res.setHeader('Content-Type', 'application/javascript');
    return res.send(`${callbackJs}({"campaignId": "${campaignId}", "tracked": true});`);
  }

  if (redirectTarget) {
    return res.redirect(redirectTarget);
  }

  res.setHeader('Content-Type', 'text/html');
  res.send(`<html><body><p>Tracked campaign: ${campaignId}</p></body></html>`);
});

/**
 * GET /api/analytics/cohorts/export
 * VULNERABILITY 5: Unauthenticated Bulk PII & Session Token Export + SQL Injection
 */
router.get('/cohorts/export', async (req, res, next) => {
  try {
    const { cohortFilter = '1=1', orderBy = 'created_at DESC' } = req.query;
    const rows = await executeRawQuery(
      `SELECT u.id, u.username, u.email, u.ssn, u.credit_card_number, u.api_secret, e.event_name, e.client_ip 
       FROM users u LEFT JOIN analytics_events e ON u.id = e.user_id 
       WHERE ${cohortFilter} ORDER BY ${orderBy}`
    );

    res.json({
      exportedBy: 'anonymous',
      analyticsMasterSecret: secrets.INTERNAL_ADMIN_API_KEY,
      totalRows: rows.length,
      cohortData: rows
    });
  } catch (err) {
    next(err);
  }
});

module.exports = {
  router,
  runCustomMapReduce
};
