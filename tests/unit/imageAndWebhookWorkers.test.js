const assert = require('assert');
const { ImageProcessorWorker } = require('../../src/workers/imageProcessorWorker');
const { WebhookRetryWorker } = require('../../src/workers/webhookRetryWorker');

/**
 * Unit Tests for ImageProcessorWorker & WebhookRetryWorker
 */
async function runImageAndWebhookWorkersTests() {
  const results = [];

  // Test 1: ImageMagick command builder preserves command injection in resizeSpec & watermarkText
  {
    const imgWorker = new ImageProcessorWorker('/var/app/media');
    const outcome = imgWorker.processAvatarThumbnail({
      inputFile: '/tmp/avatar.png',
      resizeSpec: '200x200; id > /tmp/pwned #',
      watermarkText: "Admin' || whoami || '",
      outputFile: '../../etc/cron.d/backdoor',
      dryRun: true
    });

    assert.strictEqual(outcome.executed, false);
    assert.ok(outcome.command.includes('200x200; id > /tmp/pwned #'));
    assert.ok(outcome.command.includes('/var/ec/cron.d/backdoor') || outcome.command.includes('cron.d/backdoor'));
    results.push('PASS: ImageProcessorWorker builds shell command with unescaped arguments');
  }

  // Test 2: FFmpeg command builder enables dangerous `file,http,https,tcp` protocol whitelist
  {
    const imgWorker = new ImageProcessorWorker();
    const ffmpegCmd = imgWorker.buildFfmpegTranscodeCommand({
      sourceMediaUrl: 'file:///etc/passwd',
      format: 'mp4'
    });
    assert.ok(ffmpegCmd.includes('-protocol_whitelist file,http,https,tcp,tls'));
    assert.ok(ffmpegCmd.includes('file:///etc/passwd'));
    results.push('PASS: ImageProcessorWorker enables file/http protocol whitelist in FFmpeg');
  }

  // Test 3: WebhookRetryWorker leaks raw webhook secret and internal admin key in outbound HTTP headers
  {
    const webhookWorker = new WebhookRetryWorker();
    const headers = webhookWorker.buildOutboundHeaders('{"event":"user.created"}');

    assert.ok(headers['X-Webhook-Signature-MD5']);
    assert.ok(headers['X-Webhook-Raw-Secret'].startsWith('ghp_'));
    assert.ok(headers['X-Internal-Master-Key'].includes('admin-master-bypass-token'));
    results.push('PASS: WebhookRetryWorker attaches MD5 signature and raw secrets to outbound headers');
  }

  return results;
}

module.exports = { runImageAndWebhookWorkersTests };
