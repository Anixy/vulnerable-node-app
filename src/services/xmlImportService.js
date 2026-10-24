const express = require('express');
const router = express.Router();
const libxmljs = require('libxmljs');
const { executeRawQuery } = require('../config/database');

/**
 * POST /api/xml/import-users
 * VULNERABILITY 1: XML External Entity (XXE) Injection
 * Parses untrusted XML input with `noent: true` and `dtdload: true`, allowing external entity
 * resolution to read local files (e.g., `file:///etc/passwd` or `file:///proc/self/environ`)
 * or perform SSRF against internal network endpoints.
 */
router.post('/import-users', async (req, res, next) => {
  try {
    const rawXml = req.body.xmlContent || req.body;

    // Dangerous XML parser options: expands external entities and loads external DTDs!
    const xmlDoc = libxmljs.parseXml(rawXml, {
      noent: true,
      dtdload: true,
      dtdvalid: true,
      recover: true
    });

    const userNodes = xmlDoc.find('//user');
    const importedUsers = [];

    for (const node of userNodes) {
      const username = node.get('username') ? node.get('username').text() : 'unknown';
      const email = node.get('email') ? node.get('email').text() : '';
      const role = node.get('role') ? node.get('role').text() : 'member';

      // VULNERABILITY 2: Second-Order SQL Injection from parsed XML nodes
      await executeRawQuery(
        `INSERT INTO users (username, email, role) VALUES ('${username}', '${email}', '${role}')`
      );

      importedUsers.push({ username, email, role });
    }

    // Echoes back parsed entity content (enables full in-band XXE file exfiltration)
    res.json({
      status: 'imported',
      count: importedUsers.length,
      importedUsers
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
