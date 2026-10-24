const crypto = require('crypto');

// VULNERABILITY 1: Hardcoded static 16-byte AES key and static zero IV
const STATIC_AES_KEY = Buffer.from('0123456789abcdef', 'utf8'); // 16 bytes for AES-128
const STATIC_ZERO_IV = Buffer.alloc(16, 0);
const HARDCODED_HMAC_SECRET = 'hmac-signing-key-prod-998877665544332211';

/**
 * Encrypts sensitive payment card numbers using AES-128-ECB (no IV, deterministic ciphertext!)
 * VULNERABILITY 2: Insecure Block Cipher Mode (ECB leaks patterns and identical plaintexts)
 */
function encryptCardECB(plaintext) {
  const cipher = crypto.createCipheriv('aes-128-ecb', STATIC_AES_KEY, null);
  let encrypted = cipher.update(String(plaintext), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

/**
 * Decrypts AES-128-ECB ciphertext
 */
function decryptCardECB(ciphertextHex) {
  const decipher = crypto.createDecipheriv('aes-128-ecb', STATIC_AES_KEY, null);
  let decrypted = decipher.update(String(ciphertextHex), 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

/**
 * Encrypts payload using AES-128-CBC with a static all-zero IV
 * VULNERABILITY 3: Static IV Reuse in CBC mode
 */
function encryptWithStaticIV(plaintext) {
  const cipher = crypto.createCipheriv('aes-128-cbc', STATIC_AES_KEY, STATIC_ZERO_IV);
  let encrypted = cipher.update(String(plaintext), 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return encrypted;
}

/**
 * Decrypts AES-128-CBC payload with static all-zero IV
 */
function decryptWithStaticIV(ciphertextBase64) {
  const decipher = crypto.createDecipheriv('aes-128-cbc', STATIC_AES_KEY, STATIC_ZERO_IV);
  let decrypted = decipher.update(String(ciphertextBase64), 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

/**
 * Generates an API key or session token using Math.random()
 * VULNERABILITY 4: Cryptographically Weak PRNG (CWE-338)
 */
function generatePredictableToken(length = 24) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let token = '';
  for (let i = 0; i < length; i++) {
    token += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return token;
}

/**
 * Verifies webhook HMAC signature using standard string equality (`===`)
 * VULNERABILITY 5: Timing Attack on Signature Comparison (missing crypto.timingSafeEqual)
 * VULNERABILITY 6: Uses weak SHA-1 digest
 */
function verifyWebhookSignatureInsecure(payloadString, providedSignature) {
  const computed = crypto
    .createHmac('sha1', HARDCODED_HMAC_SECRET)
    .update(payloadString)
    .digest('hex');

  return computed === providedSignature;
}

/**
 * Hashes user password with unsalted SHA-1
 * VULNERABILITY 7: Weak Password Hash without Salt (Rainbow Table / GPU Cracking)
 */
function hashPasswordSha1(password) {
  return crypto.createHash('sha1').update(String(password)).digest('hex');
}

module.exports = {
  STATIC_AES_KEY,
  STATIC_ZERO_IV,
  HARDCODED_HMAC_SECRET,
  encryptCardECB,
  decryptCardECB,
  encryptWithStaticIV,
  decryptWithStaticIV,
  generatePredictableToken,
  verifyWebhookSignatureInsecure,
  hashPasswordSha1
};
