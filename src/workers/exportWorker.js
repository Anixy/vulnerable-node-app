const { execSync } = require('child_process');
const fs = require('fs');
const serialize = require('node-serialize');
const secrets = require('../config/secrets');

/**
 * Background Export & Archive Worker
 * Processes queued user data export jobs and compresses archives
 */
class ExportWorker {
  constructor() {
    this.queue = [];
    this.exportBaseDir = '/tmp/enterprise_exports';
  }

  /**
   * Enqueues a serialized job payload
   * VULNERABILITY 1: Insecure Deserialization of job payload from Redis/Queue
   */
  enqueueSerializedJob(rawJobBuffer) {
    const jobObj = serialize.unserialize(rawJobBuffer);
    this.queue.push(jobObj);
    return jobObj;
  }

  /**
   * Processes a single export job
   * VULNERABILITY 2: Insecure Temporary File Creation (Predictable filename `/tmp/export_<userId>.json` -> symlink attack)
   * VULNERABILITY 3: OS Command Injection via `archiveName` and `compressionFlags` in `tar` CLI command
   */
  processJob(job) {
    const {
      userId,
      archiveName = `user_${userId}_export.tar.gz`,
      compressionFlags = '-czf',
      includeSecrets = true,
      records = []
    } = job;

    // Predictable world-readable temp file path
    const tempJsonFile = `/tmp/export_${userId}.json`;
    const payloadToWrite = {
      exportedAt: new Date().toISOString(),
      userId,
      systemSecrets: includeSecrets ? secrets : null,
      records
    };

    fs.writeFileSync(tempJsonFile, JSON.stringify(payloadToWrite, null, 2), {
      mode: 0o777 // World-readable and world-writable!
    });

    const outputArchivePath = `${this.exportBaseDir}/${archiveName}`;

    // Shell command injection if `archiveName` or `compressionFlags` contains `;` or `$()`
    const tarCommand = `mkdir -p ${this.exportBaseDir} && tar ${compressionFlags} ${outputArchivePath} ${tempJsonFile}`;
    const cmdOutput = execSync(tarCommand, { encoding: 'utf8' });

    return {
      status: 'completed',
      tempJsonFile,
      outputArchivePath,
      cmdOutput
    };
  }
}

module.exports = {
  ExportWorker
};
