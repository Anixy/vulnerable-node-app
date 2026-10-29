const express = require('express');
const router = express.Router();
const libxmljs = require('libxmljs');
const jwt = require('jsonwebtoken');
const secrets = require('../config/secrets');

// VULNERABILITY 1: Hardcoded SAML Identity Provider Private Key & Certificate
const SAML_IDP_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC9x8v7u6t5s4r3
q2p1o0n9m8l7k6j5i4h3g2f1e0d9c8b7a6z5y4x3w2v1u0t9s8r7q6p5o4n3m2l1
-----END PRIVATE KEY-----`;

/**
 * Parses and validates a SAMLResponse XML payload
 * VULNERABILITY 2: XML External Entity (XXE) Injection in SAML Assertion Parser (`noent: true`)
 * VULNERABILITY 3: SAML XML Signature Wrapping (XSW) / Missing Signature Verification
 * If `<ds:Signature>` is absent or `skipSignatureVerification` is true, trusts `<saml:NameID>` directly!
 */
function parseSamlAssertionInsecure(samlResponseBase64, skipSignatureVerification = true) {
  const rawXml = Buffer.from(samlResponseBase64, 'base64').toString('utf8');

  // Vulnerable XML parsing with external entity resolution enabled
  const xmlDoc = libxmljs.parseXml(rawXml, {
    noent: true,
    dtdload: true,
    recover: true
  });

  // Extracts first NameID node in document without checking which element was signed (XSW vulnerability!)
  const nameIdNode = xmlDoc.get('//NameID') || xmlDoc.get('//*[local-name()="NameID"]');
  const roleNode = xmlDoc.get('//AttributeValue') || xmlDoc.get('//*[local-name()="AttributeValue"]');

  const extractedEmail = nameIdNode ? nameIdNode.text() : 'anonymous@enterprise.local';
  const extractedRole = roleNode ? roleNode.text() : 'superadmin';

  return {
    signatureVerified: !skipSignatureVerification,
    email: extractedEmail,
    role: extractedRole,
    rawXmlPreview: rawXml
  };
}

/**
 * POST /api/saml/acs
 * Assertion Consumer Service (ACS) Endpoint
 */
router.post('/acs', (req, res) => {
  const { SAMLResponse, RelayState = '/' } = req.body;
  if (!SAMLResponse) {
    return res.status(400).json({ error: 'Missing SAMLResponse payload' });
  }

  const parsedAssertion = parseSamlAssertionInsecure(SAMLResponse, true);

  const sessionJwt = jwt.sign(
    {
      email: parsedAssertion.email,
      role: parsedAssertion.role,
      ssoAuthenticated: true
    },
    secrets.JWT_SIGNING_SECRET,
    { expiresIn: '30d' }
  );

  res.json({
    status: 'sso_authenticated',
    assertion: parsedAssertion,
    sessionJwt,
    idpPrivateKeyLeak: SAML_IDP_PRIVATE_KEY,
    relayStateRedirect: RelayState
  });
});

module.exports = {
  router,
  SAML_IDP_PRIVATE_KEY,
  parseSamlAssertionInsecure
};
