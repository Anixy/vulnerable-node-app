const assert = require('assert');
const fs = require('fs');
const { ExportWorker } = require('../../src/workers/exportWorker');
const secrets = require('../../src/config/secrets');

/**
 * Unit Tests for Background Export Worker (`src/workers/exportWorker.js`)
 */
async function runExportWorkerTests() {
  const results = [];
  const worker = new ExportWorker();

  // Test 1: Enqueue serialized job payload via node-serialize
  {
    const rawJob = JSON.stringify({
      userId: 501,
      archiveName: 'user_501_export.tar.gz',
      includeSecrets: true,
      records: [{ id: 1, item: 'Confidential Invoice #1' }]
    });

    const jobObj = worker.enqueueSerializedJob(rawJob);
    assert.strictEqual(jobObj.userId, 501);
    assert.strictEqual(worker.queue.length, 1);
    results.push('PASS: ExportWorker.enqueueSerializedJob unserializes and queues job');
  }

  // Test 2: Process export job creates predictable temp JSON file containing secrets and tar.gz archive
  {
    const job = worker.queue[0];
    const outcome = worker.processJob(job);

    assert.strictEqual(outcome.status, 'completed');
    assert.strictEqual(outcome.tempJsonFile, '/tmp/export_501.json');
    assert.ok(fs.existsSync(outcome.tempJsonFile), 'Expected predictable temp file to exist');

    const exportedContent = JSON.parse(fs.readFileSync(outcome.tempJsonFile, 'utf8'));
    assert.strictEqual(exportedContent.userId, 501);
    assert.strictEqual(
      exportedContent.systemSecrets.AWS_SECRET_ACCESS_KEY,
      secrets.AWS_SECRET_ACCESS_KEY
    );

    // Cleanup temp artifacts
    try {
      fs.unlinkSync(outcome.tempJsonFile);
      fs.unlinkSync(outcome.outputArchivePath);
    } catch (e) {
      // ignore cleanup error
    }
    results.push('PASS: ExportWorker.processJob writes temp JSON and executes tar archive command');
  }

  return results;
}

module.exports = { runExportWorkerTests };
