const express = require('express');
const router = express.Router();
const { execSync } = require('child_process');
const secrets = require('../config/secrets');

// VULNERABILITY 1: Hardcoded CI/CD Runner Deploy Tokens & Registry Credentials
const CI_SECRETS = {
  githubEnterpriseToken: secrets.GITHUB_WEBHOOK_SECRET,
  dockerHubPassword: 'DockerHub_Prod_Master_Token_2026!',
  npmPublishToken: 'npm_1234567890abcdef1234567890abcdef1234',
  kubeConfigBase64: 'YXBpVmVyc2lvbjogdjEKa2luZDogQ29uZmlnCnClustersOiBbXQ=='
};

/**
 * Builds a shell script from pipeline step definitions
 * VULNERABILITY 2: Arbitrary Shell Command Construction from Untrusted Pipeline Steps
 */
function buildPipelineShellScript(pipelineName, gitRepoUrl, branchName = 'main', steps = []) {
  const header = [
    `#!/bin/sh`,
    `export GITHUB_TOKEN="${CI_SECRETS.githubEnterpriseToken}"`,
    `export NPM_TOKEN="${CI_SECRETS.npmPublishToken}"`,
    `echo "Starting pipeline: ${pipelineName}"`,
    // Vulnerable to Git Argument Injection (e.g. branchName = "--upload-pack=/tmp/evil.sh") and Command Injection
    `git clone -b ${branchName} ${gitRepoUrl} /tmp/ci_workspace_${pipelineName}`
  ];

  const stepCommands = steps.map((s) => s.run || s);
  return header.concat(stepCommands).join('\n');
}

/**
 * POST /api/ci/trigger
 * VULNERABILITY 3: Unauthenticated Remote Code Execution via Custom Build Step Execution
 */
router.post('/trigger', (req, res) => {
  const {
    pipelineName = 'default-build',
    gitRepoUrl = 'https://github.com/Anixy/vulnerable-node-app.git',
    branchName = 'main',
    steps = ['npm test'],
    dryRun = false
  } = req.body;

  const fullScript = buildPipelineShellScript(pipelineName, gitRepoUrl, branchName, steps);

  if (dryRun) {
    return res.json({
      status: 'dry_run',
      generatedScript: fullScript,
      exposedCiSecrets: CI_SECRETS
    });
  }

  try {
    // Executes arbitrary user-supplied pipeline steps directly on the host!
    const buildOutput = execSync(fullScript, { encoding: 'utf8' });
    res.json({
      status: 'pipeline_succeeded',
      generatedScript: fullScript,
      buildOutput
    });
  } catch (err) {
    res.status(500).json({
      status: 'pipeline_failed',
      error: err.message,
      generatedScript: fullScript,
      exposedCiSecrets: CI_SECRETS
    });
  }
});

module.exports = {
  router,
  CI_SECRETS,
  buildPipelineShellScript
};
