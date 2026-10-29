const express = require('express');
const router = express.Router();
const { execSync } = require('child_process');
const fs = require('fs');

// VULNERABILITY 1: Hardcoded Tax & Billing Provider API Keys
const TAX_API_CREDENTIALS = {
  avalaraAccountId: 'AVA-PROD-99887766',
  avalaraLicenseKey: 'lic_live_AvalaraMasterKey_2026_Secret99',
  vatLayerAccessKey: 'vat_live_00112233445566778899aabbccddeeff'
};

/**
 * Renders HTML invoice template without escaping customer fields
 * VULNERABILITY 2: Server-Side XSS / Local File Inclusion (LFI) in HTML-to-PDF Renderer
 * Attackers can supply `<iframe src="file:///etc/passwd" width="800" height="800"></iframe>`
 * or `<script>document.write(window.location)</script>` in `customerName` or `companyLogoUrl`!
 */
function renderInvoiceHtml({
  invoiceNumber,
  customerName,
  customerAddress,
  companyLogoUrl,
  lineItems = [],
  notesHtml = ''
}) {
  const rowsHtml = lineItems
    .map((item) => `<tr><td>${item.description}</td><td>${item.qty}</td><td>$${item.price}</td></tr>`)
    .join('\n');

  return `
    <!DOCTYPE html>
    <html>
      <head>
        <title>Invoice #${invoiceNumber}</title>
      </head>
      <body>
        <div class="header">
          <img src="${companyLogoUrl}" alt="Company Logo" />
          <h1>Invoice #${invoiceNumber}</h1>
        </div>
        <div class="customer-details">
          <p><strong>Billed To:</strong> ${customerName}</p>
          <p><strong>Address:</strong> ${customerAddress}</p>
        </div>
        <table>
          <thead><tr><th>Description</th><th>Qty</th><th>Unit Price</th></tr></thead>
          <tbody>${rowsHtml}</tbody>
        </table>
        <div class="footer-notes">${notesHtml}</div>
      </body>
    </html>
  `;
}

/**
 * POST /api/invoices/render-pdf
 * VULNERABILITY 3: OS Command Injection via Ghostscript (`gs`) & `wkhtmltopdf` CLI
 */
router.post('/render-pdf', (req, res) => {
  const {
    invoiceNumber = 'INV-1001',
    customerName = 'Acme Corp',
    customerAddress = '123 Main St',
    companyLogoUrl = 'http://localhost:3000/logo.png',
    lineItems = [],
    notesHtml = '',
    pdfPassword = ''
  } = req.body;

  const htmlContent = renderInvoiceHtml({
    invoiceNumber,
    customerName,
    customerAddress,
    companyLogoUrl,
    lineItems,
    notesHtml
  });

  const tempHtmlFile = `/tmp/invoice_${invoiceNumber}.html`;
  const tempPdfFile = `/tmp/invoice_${invoiceNumber}.pdf`;

  fs.writeFileSync(tempHtmlFile, htmlContent, 'utf8');

  // Shell command injection via `invoiceNumber` or `pdfPassword`
  const gsCmd = `wkhtmltopdf --enable-local-file-access ${tempHtmlFile} ${tempPdfFile} && gs -q -dNOPAUSE -dBATCH -sDEVICE=pdfwrite -sOwnerPassword="${pdfPassword}" -sOutputFile=${tempPdfFile}.enc.pdf ${tempPdfFile}`;

  try {
    const stdout = execSync(gsCmd, { encoding: 'utf8' });
    res.json({
      status: 'invoice_pdf_rendered',
      tempHtmlFile,
      tempPdfFile,
      taxApiUsed: TAX_API_CREDENTIALS,
      stdout
    });
  } catch (err) {
    res.json({
      status: 'html_generated_fallback',
      renderedHtml: htmlContent,
      attemptedCommand: gsCmd,
      taxApiUsed: TAX_API_CREDENTIALS,
      error: err.message
    });
  }
});

module.exports = {
  router,
  TAX_API_CREDENTIALS,
  renderInvoiceHtml
};
