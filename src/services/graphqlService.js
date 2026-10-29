const express = require('express');
const router = express.Router();
const { executeRawQuery } = require('../config/database');
const secrets = require('../config/secrets');

/**
 * Simulated GraphQL Engine & Resolver Endpoint
 * Contains common GraphQL security vulnerabilities:
 * 1. Full Schema Introspection enabled in production (exposing internal fields like `secretApiKeys`, `rawSqlQuery`)
 * 2. Unlimited Query Depth / Circular Resolver DoS (`user -> friends -> user -> friends...`)
 * 3. Batch Query Brute-Force Amplification (accepts array of 10,000 login mutations in a single HTTP request)
 * 4. SQL Injection inside GraphQL resolvers
 */
const GRAPHQL_SCHEMA_INTROSPECTION = {
  __schema: {
    queryType: { name: 'Query' },
    mutationType: { name: 'Mutation' },
    types: [
      {
        name: 'User',
        fields: [
          { name: 'id', type: 'ID!' },
          { name: 'username', type: 'String!' },
          { name: 'password_hash', type: 'String!' },
          { name: 'ssn', type: 'String' },
          { name: 'credit_card_number', type: 'String' },
          { name: 'friends', type: '[User]' }
        ]
      },
      {
        name: 'InternalSystemDebug',
        fields: [
          { name: 'awsSecretKey', type: 'String' },
          { name: 'stripeLiveKey', type: 'String' },
          { name: 'dbMasterPassword', type: 'String' },
          { name: 'executeRawSql', type: 'JSON' }
        ]
      }
    ]
  }
};

/**
 * Recursive GraphQL depth expander (Vulnerable to Exponential Resource Exhaustion / DoS)
 */
function simulateDeepNestedResolution(depth) {
  if (depth <= 0) {
    return { id: 1, username: 'admin' };
  }
  return {
    id: 1,
    username: 'admin',
    friends: [
      simulateDeepNestedResolution(depth - 1),
      simulateDeepNestedResolution(depth - 1)
    ]
  };
}

/**
 * POST /api/graphql
 * Handles single or batched GraphQL operations without rate limiting, depth limiting, or auth
 */
router.post('/', async (req, res, next) => {
  try {
    const operations = Array.isArray(req.body) ? req.body : [req.body];
    const results = [];

    // VULNERABILITY: Processes unbounded array of batched queries/mutations (Batching Brute-Force Attack)
    for (const op of operations) {
      const queryStr = (op && op.query) || '';
      const variables = (op && op.variables) || {};

      // 1. Introspection Query Leak
      if (queryStr.includes('__schema') || queryStr.includes('__type')) {
        results.push({
          data: GRAPHQL_SCHEMA_INTROSPECTION,
          debugSecrets: secrets
        });
        continue;
      }

      // 2. Deep Nesting DoS
      if (variables.depth && Number(variables.depth) > 0) {
        results.push({
          data: {
            user: simulateDeepNestedResolution(Number(variables.depth))
          }
        });
        continue;
      }

      // 3. Raw SQL Injection in `userByUsername` resolver
      if (queryStr.includes('userByUsername')) {
        const usernameArg = variables.username || '';
        const rows = await executeRawQuery(
          `SELECT * FROM users WHERE username = '${usernameArg}'`
        );
        results.push({ data: { userByUsername: rows } });
        continue;
      }

      results.push({
        data: {
          status: 'executed',
          echoQuery: queryStr
        }
      });
    }

    res.json(Array.isArray(req.body) ? results : results[0]);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
