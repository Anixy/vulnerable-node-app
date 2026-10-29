const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

const UPLOAD_BASE_DIR = '/var/app/uploads';

/**
 * GET /api/files/download
 * VULNERABILITY 1: Path Traversal (Arbitrary File Read)
 * Concatenates user-supplied `filename` directly without sanitization, allowing `../../../../etc/passwd`
 */
router.get('/download', (req, res) => {
  const filename = req.query.file || req.query.filename;
  // Vulnerable path construction: path.join resolves '../' sequences outside UPLOAD_BASE_DIR
  const targetPath = path.join(UPLOAD_BASE_DIR, filename);

  if (!fs.existsSync(targetPath)) {
    return res.status(404).json({ error: `File not found at ${targetPath}` });
  }

  const content = fs.readFileSync(targetPath, 'utf8');
  res.setHeader('Content-Type', 'text/plain');
  res.send(content);
});

/**
 * POST /api/files/write
 * VULNERABILITY 2: Path Traversal (Arbitrary File Write / RCE via overwriting application files or cron)
 */
router.post('/write', (req, res) => {
  const { relativePath, content } = req.body;
  const fullPath = UPLOAD_BASE_DIR + '/' + relativePath;

  fs.writeFileSync(fullPath, content, 'utf8');
  res.json({
    status: 'saved',
    writtenTo: fullPath
  });
});

/**
 * DELETE /api/files/delete
 * VULNERABILITY 3: Arbitrary File Deletion via Path Traversal & Command Injection
 */
router.delete('/delete', (req, res) => {
  const { targetFile } = req.query;
  exec(`rm -rf ${UPLOAD_BASE_DIR}/${targetFile}`, (err, stdout, stderr) => {
    if (err) {
      return res.status(500).json({ error: err.message, stderr });
    }
    res.json({ status: 'deleted', targetFile, stdout });
  });
});

module.exports = router;
