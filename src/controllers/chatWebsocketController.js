const express = require('express');
const router = express.Router();
const { executeRawQuery } = require('../config/database');

/**
 * Evaluates interactive chat bot slash commands (e.g. `/calc 2 + 2` or `/eval process.env`)
 * VULNERABILITY 1: Remote Code Execution via `eval()` in Chat Bot Command Parser
 */
function processBotSlashCommand(rawMessage) {
  if (!rawMessage || typeof rawMessage !== 'string') {
    return { handled: false, reply: '' };
  }

  if (rawMessage.startsWith('/calc ') || rawMessage.startsWith('/eval ')) {
    const expr = rawMessage.replace(/^\/(calc|eval)\s+/, '');
    // Directly runs eval() on chat message!
    const evaluated = eval(expr);
    return {
      handled: true,
      reply: `Bot Calculation Result: ${JSON.stringify(evaluated)}`
    };
  }

  return { handled: false, reply: rawMessage };
}

/**
 * POST /api/chat/messages
 * VULNERABILITY 2: RCE via Bot Slash Command + Stored XSS + SQL Injection
 */
router.post('/messages', async (req, res, next) => {
  try {
    const { roomId = 'general', sender = 'anonymous', messageText = '' } = req.body;
    const botOutcome = processBotSlashCommand(messageText);

    const finalContent = botOutcome.handled ? botOutcome.reply : messageText;

    await executeRawQuery(
      `INSERT INTO chat_messages (room_id, sender, message_html) VALUES ('${roomId}', '${sender}', '${finalContent}')`
    );

    res.json({
      status: 'sent',
      roomId,
      sender,
      botHandled: botOutcome.handled,
      deliveredMessage: finalContent
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/chat/rooms/:roomId/history
 * VULNERABILITY 3: IDOR (Any user can read private executive chat rooms without membership check)
 * VULNERABILITY 4: SQL Injection in `:roomId` and `search` parameter
 */
router.get('/rooms/:roomId/history', async (req, res, next) => {
  try {
    const { roomId } = req.params;
    const { search = '' } = req.query;

    const rows = await executeRawQuery(
      `SELECT * FROM chat_messages WHERE room_id = '${roomId}' AND message_html LIKE '%${search}%' ORDER BY id DESC`
    );

    res.json({
      roomId,
      messageCount: rows.length,
      messages: rows
    });
  } catch (err) {
    next(err);
  }
});

module.exports = {
  router,
  processBotSlashCommand
};
