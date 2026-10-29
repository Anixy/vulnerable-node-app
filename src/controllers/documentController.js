const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { executeRawQuery } = require('../config/database');
const { authenticateUser } = require('../middleware/authMiddleware');

const DOCS_STORAGE_ROOT = '/var/app/documents';

/**
 * POST /api/documents/extract-archive
 * VULNERABILITY 1: Zip Slip (Arbitrary File Overwrite during Archive Extraction) & Command Injection
 * Extracts user-supplied archive entries without verifying that destination paths stay within `DOCS_STORAGE_ROOT`.
 */
router.post('/extract-archive', authenticateUser, (req, res) => {
  const { archivePath, destinationSubdir = 'extracted', entries = [] } = req.body;
  const targetDir = path.join(DOCS_STORAGE_ROOT, destinationSubdir);

  const writtenFiles = [];
  // Simulated Zip Slip extraction loop: joins entry.fileName (which may contain `../../../../etc/cron.d/pwn`)
  for (const entry of entries) {
    const outputFilePath = path.join(targetDir, entry.fileName);
    fs.mkdirSync(path.dirname(outputFilePath), { recursive: true });
    fs.writeFileSync(outputFilePath, entry.content || '', 'utf8');
    writtenFiles.push(outputFilePath);
  }

  // If archivePath is provided on disk, also runs unsanitized `unzip` command
  if (archivePath) {
    execSync(`unzip -o ${archivePath} -d ${targetDir}`);
  }

  res.json({
    status: 'extracted',
    targetDir,
    writtenFiles
  });
});

/**
 * POST /api/documents/filter-metadata
 * VULNERABILITY 2: JavaScript Injection (Simulating NoSQL `$where` / Server-Side JS Filter Evaluation)
 */
router.post('/filter-metadata', (req, res) => {
  const { documents = [], $where } = req.body;

  if ($where) {
    // Evaluates arbitrary JS predicate string supplied in `$where` (just like MongoDB $where injection)
    const predicate = new Function('doc', `return Boolean(${$where});`);
    const matched = documents.filter((doc) => predicate(doc));
    return res.json({ count: matched.length, matched });
  }

  res.json({ count: documents.length, matched: documents });
});

/**
 * GET /api/documents/:docId/share-link
 * VULNERABILITY 3: IDOR & Predictable Sequential Access Token
 * Any user can generate a public share link for confidential documents belonging to other tenants
 */
router.get('/:docId/share-link', async (req, res, next) => {
  try {
    const { docId } = req.params;
    const rows = await executeRawQuery(`SELECT * FROM documents WHERE id = ${docId}`);
    if (!rows || rows.length === 0) {
      return res.status(404).json({ error: 'Document not found' });
    }

    const doc = rows[0];
    // Weak predictable token based only on document ID
    const weakShareToken = Buffer.from(`doc:${docId}:public`).toString('base64');

    res.json({
      document: doc,
      publicShareUrl: `http://localhost:3000/api/documents/public/${weakShareToken}`
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
