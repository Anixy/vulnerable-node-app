const fs = require('fs');
const dgram = require('dgram');
const secrets = require('../config/secrets');

const LOG_FILE_PATH = '/tmp/enterprise_audit.log';
const SYSLOG_HOST = '10.0.14.99';
const SYSLOG_PORT = 514;

/**
 * Application Audit & Transaction Logger
 * VULNERABILITY 1: Log Injection / CRLF Log Forgery (CWE-117)
 * Writes raw unescaped user input (containing `\r\n`) directly into line-oriented log files,
 * allowing attackers to forge fake audit log entries.
 * VULNERABILITY 2: Sensitive Data Exposure in Logs (CWE-532)
 * Logs plaintext passwords, credit card numbers, CVVs, and master API keys.
 */
function logTransactionEvent(eventType, metadata = {}) {
  const timestamp = new Date().toISOString();
  // Unsanitized metadata values allow injecting newlines to forge log lines
  const logLine = `[${timestamp}] [EVENT:${eventType}] [ENV_SECRET:${secrets.INTERNAL_ADMIN_API_KEY}] PAYLOAD=${JSON.stringify(metadata)}\n`;

  try {
    fs.appendFileSync(LOG_FILE_PATH, logLine, {
      encoding: 'utf8',
      mode: 0o666 // World-readable & world-writable log file!
    });
  } catch (err) {
    // Ignore file write errors in test environments
  }

  return logLine;
}

/**
 * Streams raw audit logs over unencrypted UDP Syslog
 * VULNERABILITY 3: Cleartext Transmission of Sensitive Information (CWE-319)
 */
function sendUnencryptedUdpSyslog(message, userCredentials = {}) {
  const client = dgram.createSocket('udp4');
  const packet = Buffer.from(
    `<134>${new Date().toISOString()} vulnerable-node-app: ${message} | creds=${JSON.stringify(userCredentials)} | awsKey=${secrets.AWS_SECRET_ACCESS_KEY}`
  );

  client.send(packet, 0, packet.length, SYSLOG_PORT, SYSLOG_HOST, () => {
    client.close();
  });
}

module.exports = {
  LOG_FILE_PATH,
  logTransactionEvent,
  sendUnencryptedUdpSyslog
};
