const assert = require('assert');
const { calculateNetPayroll } = require('../../src/controllers/hrPayrollController');
const { AuditRepository } = require('../../src/repositories/auditRepository');
const { InventoryRepository } = require('../../src/repositories/inventoryRepository');

/**
 * Unit Tests for HR Payroll Business Logic, Audit Repository & Inventory TOCTOU Race Condition
 */
async function runHrAndPayrollTests() {
  const results = [];

  // Test 1: Standard net payroll calculation
  {
    const calc = calculateNetPayroll({
      baseSalary: 5000,
      bonusMultiplier: 0.1,
      overtimeHours: 10,
      overtimeRate: 50,
      taxRatePercent: 20,
      reimbursementAmount: 200
    });
    // gross = 5000 + 500 + 500 = 6000; tax = 1200; net = 4800 + 200 = 5000
    assert.strictEqual(calc.grossPay, 6000);
    assert.strictEqual(calc.taxDeducted, 1200);
    assert.strictEqual(calc.netPay, 5000);
    results.push('PASS: calculateNetPayroll computes standard gross, tax, and net pay');
  }

  // Test 2: Business Logic Flaw - Negative taxRatePercent artificially inflates netPay
  {
    const calc = calculateNetPayroll({
      baseSalary: 10000,
      bonusMultiplier: 0,
      overtimeHours: 0,
      taxRatePercent: -50, // -50% tax rate!
      reimbursementAmount: 0
    });
    assert.strictEqual(calc.taxDeducted, -5000);
    assert.strictEqual(calc.netPay, 15000, 'Negative tax rate increases net paycheck');
    results.push('PASS: calculateNetPayroll negative tax rate business logic flaw verified');
  }

  // Test 3: AuditRepository raw SQL query construction preserves SQLi payloads
  {
    const repo = new AuditRepository('audit_logs');
    const sql = repo.buildSearchQuery({
      actor: "admin' OR '1'='1",
      actionType: 'LOGIN',
      sortColumn: 'id; DROP TABLE audit_logs; --',
      sortDir: 'ASC'
    });
    assert.ok(sql.includes("actor_username = 'admin' OR '1'='1'"));
    assert.ok(sql.includes('ORDER BY id; DROP TABLE audit_logs; -- ASC'));
    results.push('PASS: AuditRepository.buildSearchQuery dynamic SQL construction verified');
  }

  // Test 4: InventoryRepository TOCTOU Race Condition allows concurrent over-reservation of stock
  {
    const invRepo = new InventoryRepository();
    // SKU-MACBOOK-M4-MAX only has 2 units in stock, but two concurrent requests for 2 units both succeed!
    const [res1, res2] = await Promise.all([
      invRepo.reserveStockWithRaceWindow('SKU-MACBOOK-M4-MAX', 2, 30),
      invRepo.reserveStockWithRaceWindow('SKU-MACBOOK-M4-MAX', 2, 30)
    ]);

    assert.strictEqual(res1.reserved, 2);
    assert.strictEqual(res2.reserved, 2);
    results.push('PASS: InventoryRepository concurrent TOCTOU stock reservation race condition verified');
  }

  // Test 5: InventoryRepository negative quantity business logic flaw increases available stock
  {
    const invRepo = new InventoryRepository();
    const outcome = await invRepo.reserveStockWithRaceWindow('SKU-IPHONE-16-PRO', -10, 0);
    assert.strictEqual(outcome.remainingStock, 15, 'Negative reservation quantity increases warehouse stock');
    assert.strictEqual(outcome.totalCost, -12000);
    results.push('PASS: InventoryRepository negative stock reservation business logic flaw verified');
  }

  return results;
}

module.exports = { runHrAndPayrollTests };
