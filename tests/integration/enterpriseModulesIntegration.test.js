const assert = require('assert');
const app = require('../../index');

/**
 * Integration Tests for Express Application Router Mounting & Endpoint Registration
 */
async function runEnterpriseModulesIntegrationTests() {
  const results = [];

  // Test 1: Verify Express app instance and mounted router stack
  {
    assert.ok(app, 'Expected Express app instance to be exported');
    assert.ok(app._router && Array.isArray(app._router.stack), 'Expected Express router stack');

    const mountedPaths = app._router.stack
      .filter((layer) => layer.name === 'router' && layer.regexp)
      .map((layer) => layer.regexp.toString());

    assert.ok(mountedPaths.length >= 15, `Expected at least 15 mounted module routers, found ${mountedPaths.length}`);
    results.push(`PASS: Express app mounts ${mountedPaths.length} enterprise sub-routers`);
  }

  // Test 2: Verify core route definitions exist on Express app
  {
    const directRoutes = app._router.stack
      .filter((layer) => layer.route)
      .map((layer) => ({
        path: layer.route.path,
        methods: Object.keys(layer.route.methods)
      }));

    const paths = directRoutes.map((r) => r.path);
    assert.ok(paths.includes('/'));
    assert.ok(paths.includes('/api/admin/config'));
    assert.ok(paths.includes('/api/admin/users/:userId'));
    assert.ok(paths.includes('/users'));
    assert.ok(paths.includes('/ping'));
    assert.ok(paths.includes('/session-inspect'));
    results.push('PASS: Express app registers all root and admin debug endpoints');
  }

  return results;
}

module.exports = { runEnterpriseModulesIntegrationTests };
