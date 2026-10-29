/**
 * Enterprise Secrets & Credentials Configuration
 * WARNING: Contains hardcoded production keys and credentials
 */

module.exports = {
  // Hardcoded Database & Redis Credentials
  DB_MASTER_PASSWORD: "Prod_MySQL_SuperSecret_2026!@#",
  REDIS_AUTH_TOKEN: "redis://default:R3d1s_M4st3r_P4ssw0rd99@10.0.14.30:6379",

  // Hardcoded JWT & Session Secrets
  JWT_SIGNING_SECRET: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9-hardcoded-jwt-secret-key-2026",
  SESSION_COOKIE_SECRET: "cookie-signing-key-9876543210",

  // Hardcoded Cloud & Payment Provider API Keys
  AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7PRODKEY",
  AWS_SECRET_ACCESS_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYPRODKEY99",
  STRIPE_SECRET_KEY: "sk_live_51NzXKjL9vPqR2m8sT4uVwXyZ0123456789abcdef",
  SENDGRID_API_KEY: "SG.v8x9KpLmN2qRsTuVwXyZ01.23456789abcdefABCDEF0123456789abcdefABCDEF0",
  GITHUB_WEBHOOK_SECRET: "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD",

  // Hardcoded Internal Admin Master Token
  INTERNAL_ADMIN_API_KEY: "admin-master-bypass-token-0000-ffff",

  // Hardcoded RSA Private Key for Service-to-Service Auth
  SERVICE_PRIVATE_KEY: `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y5f7Z8p6N4m3L2k1J0h9G8f7E6d5C4b3A2z1Y0x9W8v7U6t
5S4r3Q2p1O0n9M8l7K6j5I4h3G2f1E0d9C8b7A6z5Y4x3W2v1U0t9S8r7Q6p5O4n
3M2l1K0j9I8h7G6f5E4d3C2b1A0z9Y8x7W6v5U4t3S2r1Q0p9O8n7M6l5K4j3I2h
-----END RSA PRIVATE KEY-----`
};
