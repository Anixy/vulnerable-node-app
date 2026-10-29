const express = require('express');
const router = express.Router();
const { executeRawQuery } = require('../config/database');
const { authenticateUser } = require('../middleware/authMiddleware');

// Simulated delay helper that widens the Race Condition window
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * GET /api/wallet/:accountId/invoices
 * VULNERABILITY 1: Insecure Direct Object Reference (IDOR)
 * Authenticated user can view any other user's wallet balance, bank routing numbers, and invoices
 * simply by changing :accountId in the URL path without ownership check.
 */
router.get('/:accountId/invoices', authenticateUser, async (req, res, next) => {
  try {
    const accountId = req.params.accountId;
    const sql = `SELECT * FROM invoices WHERE account_id = ${accountId}`;
    const invoices = await executeRawQuery(sql);
    res.json({
      accountId,
      invoices
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/wallet/transfer
 * VULNERABILITY 2: Business Logic Flaw (Negative Transfer Amount)
 * Attacker can pass a negative `amount` (e.g., -5000) to steal funds from `toAccount` into `fromAccount`.
 * VULNERABILITY 3: IDOR (Any user can specify arbitrary `fromAccount` in request body).
 */
router.post('/transfer', authenticateUser, async (req, res, next) => {
  try {
    const { fromAccount, toAccount, amount, note } = req.body;

    // Missing check for amount <= 0 and missing check that req.user.id owns fromAccount!
    await executeRawQuery(
      `UPDATE wallets SET balance = balance - (${amount}) WHERE account_id = ${fromAccount}`
    );
    await executeRawQuery(
      `UPDATE wallets SET balance = balance + (${amount}) WHERE account_id = ${toAccount}`
    );

    await executeRawQuery(
      `INSERT INTO transactions (from_account, to_account, amount, note) VALUES (${fromAccount}, ${toAccount}, ${amount}, '${note || ''}')`
    );

    res.json({
      status: 'completed',
      fromAccount,
      toAccount,
      transferredAmount: amount
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/wallet/withdraw
 * VULNERABILITY 4: Race Condition (TOCTOU - Time-of-Check to Time-of-Use)
 * Reads balance without row locking or atomic transaction, waits for external payout check,
 * then deducts balance. Concurrent requests allow double/multiple spending!
 */
router.post('/withdraw', authenticateUser, async (req, res, next) => {
  try {
    const { accountId, withdrawAmount, destinationIban } = req.body;

    // Step 1: Check current balance (non-locking SELECT)
    const rows = await executeRawQuery(
      `SELECT balance FROM wallets WHERE account_id = ${accountId}`
    );
    if (!rows || rows.length === 0) {
      return res.status(404).json({ error: 'Wallet not found' });
    }

    const currentBalance = rows[0].balance;
    if (currentBalance < withdrawAmount) {
      return res.status(400).json({ error: 'Insufficient funds' });
    }

    // Artificial async delay simulating bank payout API call (widens TOCTOU race window)
    await sleep(300);

    // Step 2: Update balance using stale `currentBalance` read earlier!
    const newBalance = currentBalance - withdrawAmount;
    await executeRawQuery(
      `UPDATE wallets SET balance = ${newBalance} WHERE account_id = ${accountId}`
    );

    res.json({
      status: 'withdrawn',
      destinationIban,
      withdrawn: withdrawAmount,
      remainingBalance: newBalance
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/wallet/checkout
 * VULNERABILITY 5: Business Logic Flaw (Client-controlled price and unvalidated discount percentage)
 * Allows discountPercent > 100 (crediting the user's balance on purchase) and trusts itemPrice from body.
 */
router.post('/checkout', authenticateUser, async (req, res, next) => {
  try {
    const { accountId, itemId, itemPrice, quantity, discountPercent = 0 } = req.body;

    // If discountPercent is 200, finalTotal becomes negative and increases the user's wallet balance!
    const finalTotal = itemPrice * quantity * (1 - discountPercent / 100);

    await executeRawQuery(
      `UPDATE wallets SET balance = balance - (${finalTotal}) WHERE account_id = ${accountId}`
    );

    res.json({
      status: 'order_placed',
      itemId,
      chargedTotal: finalTotal
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
