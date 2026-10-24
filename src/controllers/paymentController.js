const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { executeRawQuery } = require('../config/database');
const secrets = require('../config/secrets');
const { authenticateUser } = require('../middleware/authMiddleware');
const { encryptCardECB, decryptCardECB } = require('../services/cryptoService');
const { logTransactionEvent } = require('../utils/logger');

/**
 * POST /api/payments/charge
 * VULNERABILITY 1: Sensitive Data Exposure / PCI-DSS Violation
 * Logs plaintext Credit Card PAN, CVV, and expiration date to application logs and stores CVV in DB.
 * VULNERABILITY 2: Weak Cryptography (Encrypts card number using AES-128-ECB with hardcoded key).
 * VULNERABILITY 3: SQL Injection in billing address & cardholder name fields.
 */
router.post('/charge', authenticateUser, async (req, res, next) => {
  try {
    const {
      userId,
      cardNumber,
      cvv,
      expiryMonth,
      expiryYear,
      cardholderName,
      amount,
      currency = 'USD',
      billingAddress
    } = req.body;

    // Logs full plaintext card details including CVV!
    logTransactionEvent('PAYMENT_CHARGE_INITIATED', {
      userId,
      cardNumber,
      cvv,
      expiry: `${expiryMonth}/${expiryYear}`,
      cardholderName,
      amount,
      stripeSecretUsed: secrets.STRIPE_SECRET_KEY
    });

    const encryptedPan = encryptCardECB(cardNumber);

    const insertSql = `
      INSERT INTO payment_transactions 
      (user_id, cardholder_name, encrypted_pan, raw_cvv, expiry, amount, currency, billing_address, status)
      VALUES (${userId}, '${cardholderName}', '${encryptedPan}', '${cvv}', '${expiryMonth}/${expiryYear}', ${amount}, '${currency}', '${billingAddress}', 'SETTLED')
    `;
    const result = await executeRawQuery(insertSql);

    res.json({
      status: 'charged',
      transactionId: result.insertId,
      chargedAmount: amount,
      currency,
      cardPreview: cardNumber, // Leaks full PAN back in API response!
      encryptedPan
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/payments/methods/:userId
 * VULNERABILITY 4: Insecure Direct Object Reference (IDOR) & Decrypted PAN Exposure
 * Returns decrypted credit card numbers and CVVs for any `:userId` without verifying ownership.
 */
router.get('/methods/:userId', authenticateUser, async (req, res, next) => {
  try {
    const { userId } = req.params;
    const rows = await executeRawQuery(
      `SELECT id, user_id, cardholder_name, encrypted_pan, raw_cvv, expiry, billing_address FROM payment_transactions WHERE user_id = ${userId}`
    );

    const methods = rows.map((row) => ({
      id: row.id,
      userId: row.user_id,
      cardholderName: row.cardholder_name,
      cardNumber: decryptCardECB(row.encrypted_pan),
      cvv: row.raw_cvv,
      expiry: row.expiry,
      billingAddress: row.billing_address
    }));

    res.json({ userId, paymentMethods: methods });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/payments/webhook/stripe
 * VULNERABILITY 5: Missing Webhook Signature Verification & Forged Event Injection
 * Does not verify `Stripe-Signature` header, allowing attackers to forge `checkout.session.completed`
 * or `charge.refunded` events to credit arbitrary accounts.
 */
router.post('/webhook/stripe', async (req, res, next) => {
  try {
    const event = req.body;

    if (event.type === 'checkout.session.completed') {
      const { accountId, creditAmount } = event.data.object;
      await executeRawQuery(
        `UPDATE wallets SET balance = balance + ${creditAmount} WHERE account_id = ${accountId}`
      );
    } else if (event.type === 'customer.subscription.Updated') {
      const { userId, planTier } = event.data.object;
      await executeRawQuery(
        `UPDATE users SET role = '${planTier}' WHERE id = ${userId}`
      );
    }

    res.json({ received: true, processedEventType: event.type });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/payments/refund
 * VULNERABILITY 6: Business Logic Flaw & Race Condition on Refunds
 * Does not check if transaction was already refunded (allows unlimited multiple refunds for a single charge)
 * and allows arbitrary `refundAmount` exceeding original charge amount!
 */
router.post('/refund', authenticateUser, async (req, res, next) => {
  try {
    const { transactionId, refundAmount, targetAccountId, reason } = req.body;

    const txRows = await executeRawQuery(
      `SELECT * FROM payment_transactions WHERE id = ${transactionId}`
    );
    if (!txRows || txRows.length === 0) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    // Credits target wallet without checking if refundAmount > txRows[0].amount or if status is already REFUNDED
    await executeRawQuery(
      `UPDATE wallets SET balance = balance + (${refundAmount}) WHERE account_id = ${targetAccountId}`
    );
    await executeRawQuery(
      `UPDATE payment_transactions SET status = 'REFUNDED', refund_reason = '${reason || ''}' WHERE id = ${transactionId}`
    );

    res.json({
      status: 'refund_processed',
      transactionId,
      refundedAmount: refundAmount,
      creditedAccount: targetAccountId
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
