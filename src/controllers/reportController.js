const express = require('express');
const router = express.Router();
const { exec } = require('child_process');
const vm = require('vm');
const { executeRawQuery } = require('../config/database');

/**
 * POST /api/reports/query
 * VULNERABILITY 1: SQL Injection in Dynamic Column Selection, GROUP BY, and HAVING Clauses
 */
router.post('/query', async (req, res, next) => {
  try {
    const {
      table = 'transactions',
      columns = ['*'],
      whereClause = '1=1',
      groupBy = '',
      having = '',
      limit = 100
    } = req.body;

    let sql = `SELECT ${columns.join(', ')} FROM ${table} WHERE ${whereClause}`;
    if (groupBy) {
      sql += ` GROUP BY ${groupBy}`;
    }
    if (having) {
      sql += ` HAVING ${having}`;
    }
    sql += ` LIMIT ${limit}`;

    const rows = await executeRawQuery(sql);
    res.json({
      generatedSql: sql,
      count: rows.length,
      data: rows
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/reports/render-template
 * VULNERABILITY 2: Server-Side Template Injection (SSTI) / Sandbox Escape via Node `vm.runInNewContext`
 * Evaluates user-provided template expressions inside an easily escapable `vm` context
 * (`this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id')`)
 */
router.post('/render-template', (req, res) => {
  const { templateHtml = '', contextData = {} } = req.body;

  // Replace {{expr}} by executing `expr` inside vm.runInNewContext
  const rendered = templateHtml.replace(/\{\{(.+?)\}\}/g, (_, expression) => {
    try {
      return vm.runInNewContext(expression, {
        ...contextData,
        Date,
        Math,
        JSON
      });
    } catch (e) {
      return `[Template Error: ${e.message}]`;
    }
  });

  res.setHeader('Content-Type', 'text/html');
  res.send(rendered);
});

/**
 * GET /api/reports/export-csv
 * VULNERABILITY 3: CSV Formula Injection (DDE / Spreadsheet Command Execution)
 * Does not sanitize cells starting with `=`, `+`, `-`, or `@`, allowing attackers to inject
 * `=CMD|' /C calc'!A0` into exported financial reports opened by admins in Excel.
 */
router.get('/export-csv', async (req, res, next) => {
  try {
    const { department = 'all' } = req.query;
    const rows = await executeRawQuery(
      `SELECT id, from_account, to_account, amount, note FROM transactions WHERE department = '${department}'`
    );

    const header = 'ID,FromAccount,ToAccount,Amount,Note\n';
    const csvBody = rows
      .map((r) => `${r.id},${r.from_account},${r.to_account},${r.amount},"${r.note}"`)
      .join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="report_${department}.csv"`);
    res.send(header + csvBody);
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/reports/generate-pdf
 * VULNERABILITY 4: OS Command Injection & SSRF via `wkhtmltopdf` CLI invocation
 */
router.post('/generate-pdf', (req, res) => {
  const { sourceUrl, pageSize = 'A4', headerText = 'Confidential Report' } = req.body;
  const outputPdf = `/tmp/report_${Date.now()}.pdf`;

  // Directly interpolates `sourceUrl`, `pageSize`, and `headerText` into shell command
  const cmd = `wkhtmltopdf --page-size ${pageSize} --header-center "${headerText}" "${sourceUrl}" ${outputPdf}`;
  exec(cmd, (err, stdout, stderr) => {
    if (err) {
      return res.status(500).json({ error: err.message, stderr, executedCommand: cmd });
    }
    res.json({
      status: 'pdf_generated',
      outputPdf,
      stdout
    });
  });
});

module.exports = router;
