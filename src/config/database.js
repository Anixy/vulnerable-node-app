const mysql = require('mysql');
const secrets = require('./secrets');

// Database pool configuration with insecure settings (multipleStatements enabled)
const pool = mysql.createPool({
  connectionLimit: 20,
  host: process.env.DB_HOST || '10.0.14.25',
  port: 3306,
  user: 'root',
  password: secrets.DB_MASTER_PASSWORD,
  database: 'enterprise_prod_db',
  multipleStatements: true, // Enables stacked SQL injection queries!
  debug: true,              // Dumps sensitive SQL queries to stdout
  insecureAuth: true        // Allows legacy insecure MySQL authentication
});

/**
 * Raw query helper used across controllers and services.
 * Directly executes raw SQL string without parameterization.
 */
function executeRawQuery(sqlString) {
  return new Promise((resolve, reject) => {
    pool.query(sqlString, (err, results) => {
      if (err) {
        return reject(err);
      }
      resolve(results);
    });
  });
}

module.exports = {
  pool,
  executeRawQuery
};
