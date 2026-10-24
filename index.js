const express = require('express');
const { exec } = require('child_process');
const secrets = require('./src/config/secrets');
const { executeRawQuery } = require('./src/config/database');
const { authenticateUser, requireAdmin } = require('./src/middleware/authMiddleware');
const { verboseErrorHandler, insecureCorsMiddleware } = require('./src/middleware/errorHandler');
const { unsafeDeepMerge, deserializeUserSession } = require('./src/utils/serializer');

// Controllers & Services
const authController = require('./src/controllers/authController');
const walletController = require('./src/controllers/walletController');
const fileController = require('./src/controllers/fileController');
const profileController = require('./src/controllers/profileController');
const adminController = require('./src/controllers/adminController');
const paymentController = require('./src/controllers/paymentController');
const reportController = require('./src/controllers/reportController');
const oauthController = require('./src/controllers/oauthController');
const documentController = require('./src/controllers/documentController');
const systemService = require('./src/services/systemService');
const webhookService = require('./src/services/webhookService');
const xmlImportService = require('./src/services/xmlImportService');
const { router: ldapRouter } = require('./src/services/ldapService');
const { router: emailRouter } = require('./src/services/emailService');
const graphqlService = require('./src/services/graphqlService');

const app = express();
const port = process.env.PORT || 3000;

// VULNERABILITY 1: Hardcoded Master Secrets in entry point
const dbPassword = secrets.DB_MASTER_PASSWORD;
const awsAccessKey = secrets.AWS_ACCESS_KEY_ID;
const stripeLiveKey = secrets.STRIPE_SECRET_KEY;

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(insecureCorsMiddleware);

// Global Runtime Config (Susceptible to Prototype Pollution)
const runtimeConfig = {
  appName: 'Enterprise Vulnerable Node Platform v2.0',
  debugMode: true,
  allowRemoteShell: false
};

app.get('/', (req, res) => {
  res.send(`Welcome to ${runtimeConfig.appName}!`);
});

// Mount Enterprise Modules
app.use('/api/auth', authController);
app.use('/api/wallet', walletController);
app.use('/api/files', fileController);
app.use('/api/profile', profileController);
app.use('/api/admin', adminController);
app.use('/api/payments', paymentController);
app.use('/api/reports', reportController);
app.use('/api/oauth', oauthController);
app.use('/api/documents', documentController);
app.use('/api/system', systemService);
app.use('/api/webhooks', webhookService);
app.use('/api/xml', xmlImportService);
app.use('/api/ldap', ldapRouter);
app.use('/api/email', emailRouter);
app.use('/api/graphql', graphqlService);

// VULNERABILITY 2: Unauthenticated Admin Debug & Config Update Endpoint
// Allows Prototype Pollution via unsafeDeepMerge and leaks all secrets
app.post('/api/admin/config', (req, res) => {
  unsafeDeepMerge(runtimeConfig, req.body);
  res.json({
    status: 'updated',
    runtimeConfig,
    activeSecrets: {
      dbPassword,
      awsAccessKey,
      stripeLiveKey
    }
  });
});

// VULNERABILITY 3: Broken Access Control & SQL Injection on User Deletion
app.delete('/api/admin/users/:userId', authenticateUser, requireAdmin, async (req, res, next) => {
  try {
    const userId = req.params.userId;
    await executeRawQuery(`DELETE FROM users WHERE id = ${userId}`);
    res.json({ status: 'deleted', deletedUserId: userId });
  } catch (err) {
    next(err);
  }
});

// VULNERABILITY 4: Legacy SQL Injection & Command Injection Endpoints
app.get('/users', async (req, res, next) => {
  try {
    const username = req.query.username;
    const query = "SELECT * FROM users WHERE username = '" + username + "'";
    const results = await executeRawQuery(query);
    res.json(results);
  } catch (err) {
    next(err);
  }
});

app.get('/ping', (req, res) => {
  const target = req.query.target;
  exec('ping -c 4 ' + target, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).send(error.message);
    }
    res.send(`<pre>${stdout}</pre>`);
  });
});

// VULNERABILITY 5: Cookie Deserialization Endpoint
app.get('/session-inspect', (req, res) => {
  const rawCookie = req.query.session || req.headers['x-serialized-session'];
  const sessionObj = deserializeUserSession(rawCookie);
  res.json({ sessionObj });
});

app.use(verboseErrorHandler);

if (require.main === module) {
  app.listen(port, '0.0.0.0', () => {
    console.log(`Enterprise App listening at http://0.0.0.0:${port}`);
  });
}

module.exports = app;
