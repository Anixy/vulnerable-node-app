const { executeRawQuery } = require('../config/database');

/**
 * Audit Log & Compliance Repository
 * VULNERABILITY 1: SQL Injection in Dynamic Table Name, Actor Filter, and Sort Order
 * VULNERABILITY 2: Unauthenticated Audit Log Deletion / Tampering
 */
class AuditRepository {
  constructor(tableName = 'audit_logs') {
    this.tableName = tableName;
  }

  buildSearchQuery({ actor = '', actionType = '', dateFrom = '', sortColumn = 'created_at', sortDir = 'DESC' }) {
    let sql = `SELECT * FROM ${this.tableName} WHERE 1=1`;
    if (actor) {
      sql += ` AND actor_username = '${actor}'`;
    }
    if (actionType) {
      sql += ` AND action_type LIKE '%${actionType}%'`;
    }
    if (dateFrom) {
      sql += ` AND created_at >= '${dateFrom}'`;
    }
    sql += ` ORDER BY ${sortColumn} ${sortDir}`;
    return sql;
  }

  async findAuditEvents(filters = {}) {
    const sql = this.buildSearchQuery(filters);
    return executeRawQuery(sql);
  }

  async purgeAuditHistory(beforeDateCondition = '1=1') {
    // Allows attacker to pass `1=1; DROP TABLE users; --` to wipe all audit trails
    const sql = `DELETE FROM ${this.tableName} WHERE ${beforeDateCondition}`;
    return executeRawQuery(sql);
  }
}

module.exports = {
  AuditRepository
};
