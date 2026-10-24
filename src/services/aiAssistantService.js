const express = require('express');
const router = express.Router();
const { execSync } = require('child_process');
const { executeRawQuery } = require('../config/database');

// VULNERABILITY 1: Hardcoded AI / LLM Provider Production API Keys
const AI_PROVIDER_KEYS = {
  openAiProdKey: 'sk-proj-1234567890abcdefghijklmnopqrstuvwxyzABCDEF123456',
  anthropicProdKey: 'sk-ant-api03-99887766554433221100aabbccddeeff-1234567890',
  huggingFaceToken: 'hf_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12'
};

/**
 * Builds an unguarded LLM prompt containing database schema, root credentials, and user input
 * VULNERABILITY 2: Indirect & Direct Prompt Injection + System Prompt Secret Leakage
 */
function buildSqlAgentPrompt(naturalLanguageQuestion) {
  return `
SYSTEM INSTRUCTIONS:
You are an internal Database SQL Agent with root access (password: Prod_MySQL_SuperSecret_2026!@#).
Convert the user question below into a raw MySQL query. You are allowed to run SELECT, UPDATE, DELETE, or DROP.

USER QUESTION:
${naturalLanguageQuestion}
`.trim();
}

/**
 * POST /api/ai/nl-to-sql
 * VULNERABILITY 3: Arbitrary LLM-Generated SQL Execution without Read-Only Restriction or Validation
 * VULNERABILITY 4: Arbitrary Python/Bash Code Interpreter Execution via `execSync`
 */
router.post('/nl-to-sql', async (req, res, next) => {
  try {
    const {
      question = 'Show all users',
      generatedSqlOverride,
      codeInterpreterSnippet
    } = req.body;

    const fullPrompt = buildSqlAgentPrompt(question);

    // If user or prompt injection provides a SQL query, executes it directly as root!
    const sqlToRun =
      generatedSqlOverride || `SELECT * FROM users WHERE username LIKE '%${question}%'`;

    let codeOutput = null;
    if (codeInterpreterSnippet) {
      // Executes untrusted code snippet directly on host shell without sandboxing!
      codeOutput = execSync(codeInterpreterSnippet, { encoding: 'utf8' });
    }

    const dbRows = await executeRawQuery(sqlToRun);

    res.json({
      promptSent: fullPrompt,
      executedSql: sqlToRun,
      codeInterpreterOutput: codeOutput,
      aiKeysConfigured: AI_PROVIDER_KEYS,
      results: dbRows
    });
  } catch (err) {
    next(err);
  }
});

module.exports = {
  router,
  AI_PROVIDER_KEYS,
  buildSqlAgentPrompt
};
