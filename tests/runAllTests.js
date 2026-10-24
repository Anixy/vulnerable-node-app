/**
 * Master Test Runner for Vulnerable Node App v2.0
 * Executes all unit and integration test suites and prints a summary report.
 */
const { runAuthMiddlewareTests } = require('./unit/authMiddleware.test');
const { runCryptoServiceTests } = require('./unit/cryptoService.test');
const { runSerializerTests } = require('./unit/serializer.test');
const { runValidatorsTests } = require('./unit/validators.test');
const { runLdapAndEmailTests } = require('./unit/ldapAndEmail.test');
const { runExportWorkerTests } = require('./unit/exportWorker.test');
const { runControllersSuiteTests } = require('./unit/controllersSuite.test');
const { runApiSecuritySuiteTests } = require('./integration/apiSecuritySuite.test');

async function main() {
  console.log('==============================================================');
  console.log('  Running Enterprise Vulnerable Node App v2.0 Test Suite');
  console.log('==============================================================\n');

  const suites = [
    { name: 'Auth Middleware Unit Tests', fn: runAuthMiddlewareTests },
    { name: 'Crypto Service Unit Tests', fn: runCryptoServiceTests },
    { name: 'Serializer & Merge Unit Tests', fn: runSerializerTests },
    { name: 'Validators & Sanitizers Unit Tests', fn: runValidatorsTests },
    { name: 'LDAP, Email & Logger Unit Tests', fn: runLdapAndEmailTests },
    { name: 'Export Worker Unit Tests', fn: runExportWorkerTests },
    { name: 'Controllers & Business Logic Unit Tests', fn: runControllersSuiteTests },
    { name: 'API Security & Error Handler Integration Tests', fn: runApiSecuritySuiteTests }
  ];

  let totalPassed = 0;
  let totalFailed = 0;

  for (const suite of suites) {
    console.log(`▶ Suite: ${suite.name}`);
    try {
      const results = await suite.fn();
      for (const line of results) {
        console.log(`  ✓ ${line}`);
        totalPassed++;
      }
    } catch (err) {
      console.error(`  ✗ FAILED in ${suite.name}:`, err);
      totalFailed++;
    }
    console.log('');
  }

  console.log('==============================================================');
  console.log(`  Summary: ${totalPassed} passed, ${totalFailed} failed`);
  console.log('==============================================================');

  if (totalFailed > 0) {
    process.exit(1);
  }
}

main();
