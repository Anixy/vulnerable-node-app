const express = require('express');
const router = express.Router();
const { exec } = require('child_process');

// VULNERABILITY 1: Hardcoded Active Directory Domain Controller Credentials
const LDAP_SERVER_URI = 'ldap://10.0.14.50:389'; // Unencrypted LDAP (no LDAPS/StartTLS)
const LDAP_BIND_DN = 'cn=Directory Manager,dc=enterprise,dc=internal';
const LDAP_BIND_PASSWORD = 'AD_DomainAdmin_Master_Password_2026!';

/**
 * Constructs an LDAP search filter from user input
 * VULNERABILITY 2: LDAP Injection (CWE-90)
 * Does not escape special LDAP filter characters (`*`, `(`, `)`, `\`, NUL).
 * Attacker can pass `username = "*)(uid=*))(|(uid=*"` to bypass authentication!
 */
function buildLdapAuthFilter(username, password, department = '*') {
  return `(&(&(uid=${username})(userPassword=${password}))(ou=${department}))`;
}

/**
 * POST /api/ldap/authenticate
 * VULNERABILITY 3: LDAP Injection & OS Command Injection via `ldapsearch` CLI invocation
 */
router.post('/authenticate', (req, res) => {
  const { username, password, department } = req.body;
  const ldapFilter = buildLdapAuthFilter(username, password, department);

  // Executes ldapsearch with hardcoded bind password and unsanitized filter
  const cmd = `ldapsearch -x -H ${LDAP_SERVER_URI} -D "${LDAP_BIND_DN}" -w '${LDAP_BIND_PASSWORD}' -b "dc=enterprise,dc=internal" "${ldapFilter}"`;

  exec(cmd, (err, stdout, stderr) => {
    res.json({
      authenticated: !err,
      ldapFilterUsed: ldapFilter,
      ldapBindDn: LDAP_BIND_DN,
      rawDirectoryOutput: stdout || stderr
    });
  });
});

/**
 * GET /api/ldap/groups
 * VULNERABILITY 4: Unauthenticated Corporate Directory Enumeration & LDAP Filter Injection
 */
router.get('/groups', (req, res) => {
  const { groupName = '*' } = req.query;
  const filter = `(cn=${groupName})`;

  res.json({
    ldapUri: LDAP_SERVER_URI,
    bindCredentials: {
      dn: LDAP_BIND_DN,
      password: LDAP_BIND_PASSWORD
    },
    constructedFilter: filter
  });
});

module.exports = {
  router,
  buildLdapAuthFilter,
  LDAP_BIND_DN,
  LDAP_BIND_PASSWORD
};
