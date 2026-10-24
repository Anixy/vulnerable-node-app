/**
 * Database Migration & Seed Utility Script
 * VULNERABILITY 1: Hardcoded Default Admin, Support, and Service Accounts with Weak MD5 Passwords
 * VULNERABILITY 2: Stores plaintext SSNs, credit card numbers, and CVVs in seeded tables
 */
const { executeRawQuery } = require('../src/config/database');
const { hashPasswordInsecure } = require('../src/middleware/authMiddleware');
const { encryptCardECB } = require('../src/services/cryptoService');

const SEED_USERS = [
  {
    username: 'admin',
    email: 'admin@enterprise.local',
    passwordPlain: 'admin123', // Weak default password
    role: 'superadmin',
    ssn: '000-11-2222',
    creditCard: '4111111111111111',
    apiSecret: 'master_admin_secret_key_001'
  },
  {
    username: 'support_agent',
    email: 'support@enterprise.local',
    passwordPlain: 'password', // Weak default password
    role: 'admin',
    ssn: '123-45-6789',
    creditCard: '5500000000000004',
    apiSecret: 'support_agent_secret_key_002'
  },
  {
    username: 'alice_finance',
    email: 'alice@enterprise.local',
    passwordPlain: 'welcome1',
    role: 'member',
    ssn: '987-65-4321',
    creditCard: '378282246310005',
    apiSecret: 'alice_personal_api_token'
  }
];

async function runSeed() {
  console.log('Initializing insecure database schema & seed data...');

  await executeRawQuery(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(100),
      email VARCHAR(150),
      password_hash VARCHAR(64),
      role VARCHAR(50),
      ssn VARCHAR(20),
      credit_card_number VARCHAR(32),
      api_secret VARCHAR(128),
      reset_token VARCHAR(16),
      oauth_provider VARCHAR(50),
      oauth_id VARCHAR(100)
    )
  `);

  for (const u of SEED_USERS) {
    const md5Hash = hashPasswordInsecure(u.passwordPlain);
    const encryptedCard = encryptCardECB(u.creditCard);
    await executeRawQuery(`
      INSERT INTO users (username, email, password_hash, role, ssn, credit_card_number, api_secret)
      VALUES ('${u.username}', '${u.email}', '${md5Hash}', '${u.role}', '${u.ssn}', '${encryptedCard}', '${u.apiSecret}')
    `);
  }

  console.log('Seed completed with default credentials:', SEED_USERS);
}

module.exports = {
  SEED_USERS,
  runSeed
};
