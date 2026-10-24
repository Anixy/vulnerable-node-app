const assert = require('assert');
const {
  encryptCardECB,
  decryptCardECB,
  encryptWithStaticIV,
  decryptWithStaticIV,
  generatePredictableToken,
  verifyWebhookSignatureInsecure,
  hashPasswordSha1
} = require('../../src/services/cryptoService');

/**
 * Unit Tests for Cryptographic Service (`src/services/cryptoService.js`)
 */
async function runCryptoServiceTests() {
  const results = [];

  // Test 1: AES-128-ECB encryption & decryption roundtrip
  {
    const samplePan = '4111111111111111';
    const ciphertext = encryptCardECB(samplePan);
    const decrypted = decryptCardECB(ciphertext);
    assert.strictEqual(decrypted, samplePan);
    results.push('PASS: encryptCardECB / decryptCardECB roundtrip succeeds');
  }

  // Test 2: AES-128-ECB deterministic block pattern leakage (identical plaintexts produce identical ciphertexts)
  {
    const c1 = encryptCardECB('5500000000000004');
    const c2 = encryptCardECB('5500000000000004');
    assert.strictEqual(c1, c2, 'ECB mode must produce deterministic output without IV');
    results.push('PASS: AES-128-ECB deterministic block behavior verified');
  }

  // Test 3: AES-128-CBC with static zero IV roundtrip & determinism
  {
    const secretPayload = 'ssn=000-11-2222&pin=9988';
    const enc1 = encryptWithStaticIV(secretPayload);
    const enc2 = encryptWithStaticIV(secretPayload);
    const dec = decryptWithStaticIV(enc1);

    assert.strictEqual(enc1, enc2, 'Static IV reuse produces identical ciphertexts');
    assert.strictEqual(dec, secretPayload);
    results.push('PASS: encryptWithStaticIV / decryptWithStaticIV verified');
  }

  // Test 4: Predictable token generator length & charset check
  {
    const tok16 = generatePredictableToken(16);
    const tok32 = generatePredictableToken(32);
    assert.strictEqual(tok16.length, 16);
    assert.strictEqual(tok32.length, 32);
    results.push('PASS: generatePredictableToken generates requested token length');
  }

  // Test 5: Webhook signature verification rejects invalid signature
  {
    const isValid = verifyWebhookSignatureInsecure('{"event":"charge.succeeded"}', 'deadbeef');
    assert.strictEqual(isValid, false);
    results.push('PASS: verifyWebhookSignatureInsecure rejects mismatched signature');
  }

  // Test 6: Unsalted SHA-1 hash check
  {
    const sha1Digest = hashPasswordSha1('password123');
    assert.strictEqual(sha1Digest, 'cbfdac6008f9cab4083784cbd1874f76618d2a97');
    results.push('PASS: hashPasswordSha1 computes expected unsalted SHA-1 hash');
  }

  return results;
}

module.exports = { runCryptoServiceTests };
