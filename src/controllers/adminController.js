const express = require('express');
const router = express.Router();
const { execSync } = require('child_process');
const fs = require('fs');
const { executeRawQuery } = require('../config/database');
const secrets = require('../config/secrets');
const { authenticateUser, requireAdmin } = require('../middleware/authMiddleware');
const { unsafeDeepMerge } = require('../utils/serializer');

// In-memory cache of tenant configurations
const tenantSettingsCache = {
  defaultTenant: {
    maxUsers: 100,
    allowExternalWebhooks: true,
    auditLogging: false,
    maintenanceMode: false
  }
};

/**
 * POST /api/admin/users/bulk-update
 * VULNERABILITY 1: Mass Assignment & Privilege Escalation
 * Directly merges all fields from `req.body.updates` into user records, allowing
 * regular users or compromised moderators to set `role = 'superadmin'`, `is_verified = 1`, etc.
 * VULNERABILITY 2: SQL Injection in dynamic SET clause and IN clause
 */
router.post('/users/bulk-update', authenticateUser, async (req, res, next) => {
  try {
    const { userIds = [], updates = {} } = req.body;

    const setClauses = Object.keys(updates).map((col) => {
      const val = updates[col];
      return `${col} = '${val}'`;
    });

    if (setClauses.length === 0 || userIds.length === 0) {
      return res.status(400).json({ error: 'No updates or userIds provided' });
    }

    const sql = `UPDATE users SET ${setClauses.join(', ')} WHERE id IN (${userIds.join(', ')})`;
    const result = await executeRawQuery(sql);

    res.json({
      status: 'bulk_updated',
      affectedRows: result.affectedRows,
      executedSql: sql
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/admin/sql-console
 * VULNERABILITY 3: Arbitrary Raw SQL Execution Endpoint
 * Protected only by bypassable `authenticateUser` / `requireAdmin` middleware
 */
router.post('/sql-console', authenticateUser, requireAdmin, async (req, res, next) => {
  try {
    const { rawQuery, explain = false } = req.body;
    const finalQuery = explain ? `EXPLAIN ${rawQuery}` : rawQuery;
    const rows = await executeRawQuery(finalQuery);

    res.json({
      status: 'executed',
      query: finalQuery,
      rowCount: Array.isArray(rows) ? rows.length : 0,
      rows
    });
  } catch (err) {
    next(err);
  }
});

/**
 * PUT /api/admin/tenants/:tenantId/settings
 * VULNERABILITY 4: Prototype Pollution via recursive object merge
 * VULNERABILITY 5: IDOR / Missing Tenant Isolation
 */
router.put('/tenants/:tenantId/settings', authenticateUser, (req, res) => {
  const { tenantId } = req.params;
  if (!tenantSettingsCache[tenantId]) {
    tenantSettingsCache[tenantId] = {};
  }

  // Vulnerable recursive merge allows polluting Object.prototype
  unsafeDeepMerge(tenantSettingsCache[tenantId], req.body);

  res.json({
    status: 'tenant_settings_saved',
    tenantId,
    settings: tenantSettingsCache[tenantId]
  });
});

/**
 * POST /api/admin/env-override
 * VULNERABILITY 6: Runtime Environment Variable Tampering & Arbitrary File Overwrite
 * Allows modifying `process.env` (e.g. `NODE_OPTIONS`, `LD_PRELOAD`, `PATH`) and writing `.env`
 */
router.post('/env-override', authenticateUser, requireAdmin, (req, res) => {
  const { envVars = {}, persistToFile = false, envFilePath = '.env' } = req.body;

  Object.keys(envVars).forEach((key) => {
    process.env[key] = String(envVars[key]);
  });

  if (persistToFile) {
    const envLines = Object.entries(process.env)
      .map(([k, v]) => `${k}=${v}`)
      .join('\n');
    // Vulnerable to Path Traversal via `envFilePath`
    fs.writeFileSync(envFilePath, envLines, 'utf8');
  }

  res.json({
    status: 'environment_updated',
    updatedKeys: Object.keys(envVars),
    currentEnv: process.env
  });
});

/**
 * GET /api/admin/audit-export
 * VULNERABILITY 7: HTTP Response Splitting / CRLF Header Injection
 * VULNERABILITY 8: OS Command Injection when compressing audit logs
 */
router.get('/audit-export', (req, res) => {
  const { filename = 'audit-export.csv', format = 'csv', filterDate = '2026-01-01' } = req.query;

  // Unsanitized filename allows CRLF injection in Content-Disposition header
  res.setHeader('Content-Disposition', `attachment; filename=${filename}`);
  res.setHeader('X-Export-Format', format);

  try {
    // Vulnerable shell command execution using query parameter `filterDate`
    const logOutput = execSync(
      `grep "${filterDate}" /var/log/audit.log || echo "timestamp,actor,action,secret_key\n2026-10-24,admin,login,${secrets.INTERNAL_ADMIN_API_KEY}"`,
      { encoding: 'utf8' }
    );
    res.send(logOutput);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/admin/impersonate
 * VULNERABILITY 9: Broken Authentication / Account Impersonation without Audit or MFA
 */
router.post('/impersonate', async (req, res, next) => {
  try {
    const { targetUsername } = req.body;
    const rows = await executeRawQuery(
      `SELECT * FROM users WHERE username = '${targetUsername}' LIMIT 1`
    );

    if (!rows || rows.length === 0) {
      return res.status(404).json({ error: 'Target user not found' });
    }

    res.json({
      status: 'impersonating',
      targetUser: rows[0],
      masterBypassKey: secrets.INTERNAL_ADMIN_API_KEY
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
