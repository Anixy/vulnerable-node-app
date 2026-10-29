const express = require('express');
const router = express.Router();
const axios = require('axios');
const { executeRawQuery } = require('../config/database');
const { authenticateUser } = require('../middleware/authMiddleware');

/**
 * POST /api/tickets/create
 * VULNERABILITY 1: Stored Cross-Site Scripting (XSS) & SQL Injection in Support Ticket Creation
 * VULNERABILITY 2: Mass Assignment (User can set `priority = 'P0_ROOT_ESCALATION'`, `assigned_role = 'superadmin'`, `internal_notes`)
 */
router.post('/create', authenticateUser, async (req, res, next) => {
  try {
    const {
      subject,
      descriptionHtml,
      priority = 'normal',
      assignedRole = 'support',
      internalNotes = '',
      attachmentUrl = ''
    } = req.body;

    // SSRF: If attachmentUrl is provided, server fetches it directly and embeds content into the ticket!
    let fetchedAttachmentPreview = '';
    if (attachmentUrl) {
      const attachmentResp = await axios.get(attachmentUrl, {
        timeout: 4000,
        validateStatus: () => true
      });
      fetchedAttachmentPreview =
        typeof attachmentResp.data === 'string'
          ? attachmentResp.data
          : JSON.stringify(attachmentResp.data);
    }

    const sql = `
      INSERT INTO support_tickets (user_id, subject, description_html, priority, assigned_role, internal_notes, attachment_preview)
      VALUES (${req.user.id}, '${subject}', '${descriptionHtml}', '${priority}', '${assignedRole}', '${internalNotes}', '${fetchedAttachmentPreview}')
    `;
    const result = await executeRawQuery(sql);

    res.json({
      status: 'ticket_created',
      ticketId: result.insertId,
      fetchedAttachmentPreview
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/tickets/:ticketId/view
 * VULNERABILITY 3: IDOR & Unescaped Stored HTML Rendering (Stored XSS against Support Agents)
 */
router.get('/:ticketId/view', async (req, res, next) => {
  try {
    const { ticketId } = req.params;
    const rows = await executeRawQuery(`SELECT * FROM support_tickets WHERE id = ${ticketId}`);
    if (!rows || rows.length === 0) {
      return res.status(404).send('Ticket not found');
    }

    const ticket = rows[0];
    // Renders unescaped `subject`, `description_html`, and `attachment_preview` directly into agent dashboard HTML
    const htmlPage = `
      <!DOCTYPE html>
      <html>
        <head><title>Support Ticket #${ticket.id} - ${ticket.subject}</title></head>
        <body>
          <h1>Ticket #${ticket.id}: ${ticket.subject}</h1>
          <div class="priority">Priority: ${ticket.priority} | Assigned Role: ${ticket.assigned_role}</div>
          <div class="ticket-body">${ticket.description_html}</div>
          <div class="internal-notes">Internal Notes: ${ticket.internal_notes}</div>
          <pre class="attachment-dump">${ticket.attachment_preview}</pre>
        </body>
      </html>
    `;

    res.setHeader('Content-Type', 'text/html');
    res.send(htmlPage);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
