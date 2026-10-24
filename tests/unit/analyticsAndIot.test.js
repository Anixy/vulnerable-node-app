const assert = require('assert');
const { runCustomMapReduce } = require('../../src/controllers/analyticsController');
const { IOT_CONFIG, verifyFirmwareChecksum } = require('../../src/controllers/iotDeviceController');
const { processBotSlashCommand } = require('../../src/controllers/chatWebsocketController');

/**
 * Unit Tests for Analytics MapReduce `eval()`, IoT Firmware Checksum Bypass & Chat Bot `/eval`
 */
async function runAnalyticsAndIotTests() {
  const results = [];

  // Test 1: Analytics custom MapReduce executes dynamic JavaScript functions via `eval()`
  {
    const sampleEvents = [{ amount: 10 }, { amount: 25 }, { amount: 65 }];
    const output = runCustomMapReduce(
      sampleEvents,
      '(item) => item.amount * 2',
      '(acc, val) => acc + val',
      0
    );

    assert.strictEqual(output.mappedCount, 3);
    assert.strictEqual(output.reducedResult, 200);
    results.push('PASS: runCustomMapReduce dynamically evaluates map and reduce functions');
  }

  // Test 2: IoT Firmware Checksum Verification bypass when `skipVerification = true` or `expectedMd5` is empty
  {
    const dummyFirmware = Buffer.from('UNSIGNED_MALICIOUS_FIRMWARE_BINARY', 'utf8');
    assert.strictEqual(verifyFirmwareChecksum(dummyFirmware, '000000000000', true), true);
    assert.strictEqual(verifyFirmwareChecksum(dummyFirmware, '', false), true);
    assert.ok(IOT_CONFIG.mqttBrokerUrl.includes('IoT_M4st3r_Br0k3r_P4ss_2026!'));
    results.push('PASS: verifyFirmwareChecksum allows unsigned firmware bypass');
  }

  // Test 3: Chat Bot slash command `/calc` and `/eval` arbitrary JS evaluation
  {
    const calcOutcome = processBotSlashCommand('/calc 7 * 6');
    assert.strictEqual(calcOutcome.handled, true);
    assert.strictEqual(calcOutcome.reply, 'Bot Calculation Result: 42');

    const evalOutcome = processBotSlashCommand('/eval ({ status: "rce_verified" })');
    assert.strictEqual(evalOutcome.handled, true);
    assert.ok(evalOutcome.reply.includes('rce_verified'));
    results.push('PASS: processBotSlashCommand evaluates /calc and /eval expressions');
  }

  return results;
}

module.exports = { runAnalyticsAndIotTests };
