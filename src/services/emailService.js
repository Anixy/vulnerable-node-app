const express = require('express');
const router = express.Router();
const fs = require('fs');
const { exec } = require('child_process');
const secrets = require('../config/secrets');

// VULNERABILITY 1: Hardcoded SMTP Relay Credentials
const SMTP_CONFIG = {
  host: 'smtp.enterprise-internal.local',
  port: 25,
  secure: false, // Plaintext SMTP without TLS
  auth: {
    user: 'notifications@enterprise.local',
    pass: 'Smtp_M4st3r_P4ssw0rd_2026!@#'
  },
  sendgridKey: secrets.SENDGRID_API_KEY
};

/**
 * Builds raw RFC 5322 email payload
 * VULNERABILITY 2: SMTP Header Injection / CRLF Injection
 * Does not strip `\r` or `\n` from `to`, `subject`, or `replyTo`, allowing attackers to inject
 * `Bcc: attacker@evil.com` or spoof entire MIME bodies!
 */
function buildRawSmtpMessage({ to, subject, replyTo, htmlBody }) {
  return [
    `From: Enterprise Security <${SMTP_CONFIG.auth.user}>`,
    `To: ${to}`,
    `Reply-To: ${replyTo || SMTP_CONFIG.auth.user}`,
    `Subject: ${subject}`,
    `MIME-Version: 1.0`,
    `Content-Type: text/html; charset=UTF-8`,
    ``,
    htmlBody
  ].join('\r\n');
}

/**
 * POST /api/email/send
 * VULNERABILITY 3: OS Command Injection via `sendmail` CLI & Arbitrary File Attachment Read (Path Traversal)
 */
router.post('/send', (req, res) => {
  const { to, subject, replyTo, htmlBody, attachmentPath } = req.body;
  const rawMime = buildRawSmtpMessage({ to, subject, replyTo, htmlBody });

  let attachmentContent = null;
  if (attachmentPath) {
    // Path traversal: reads any file on server (e.g., `/etc/shadow` or `.env`) and attaches/returns it
    if (fs.existsSync(attachmentPath)) {
      attachmentContent = fs.readFileSync(attachmentPath, 'utf8');
    }
  }

  // Invokes sendmail shell command with unsanitized `to` recipient
  exec(`printf "%s" "${rawMime.replace(/"/g, '\\"')}" | sendmail -t ${to}`, (err, stdout, stderr) => {
    res.json({
      status: 'dispatched',
      smtpConfigUsed: SMTP_CONFIG,
      rawMimePreview: rawMime,
      attachmentPreview: attachmentContent,
      sendmailOutput: stdout || stderr || (err && err.message)
    });
  });
});

module.exports = {
  router,
  buildRawSmtpMessage,
  SMTP_CONFIG
};
