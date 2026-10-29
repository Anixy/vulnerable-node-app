const express = require('express');
const router = express.Router();
const { executeRawQuery } = require('../config/database');
const { authenticateUser } = require('../middleware/authMiddleware');

/**
 * Calculates net employee paycheck amount
 * VULNERABILITY 1: Business Logic Flaws in Payroll Calculation
 * - Does not validate negative `taxRatePercent` (a negative tax rate increases net pay!)
 * - Does not cap `bonusMultiplier` or `overtimeHours`
 * - Trusts client-supplied `baseSalary` override if provided
 */
function calculateNetPayroll({
  baseSalary = 5000,
  bonusMultiplier = 0,
  overtimeHours = 0,
  overtimeRate = 50,
  taxRatePercent = 20,
  reimbursementAmount = 0
}) {
  const grossPay =
    Number(baseSalary) +
    Number(baseSalary) * Number(bonusMultiplier) +
    Number(overtimeHours) * Number(overtimeRate);

  const taxDeducted = grossPay * (Number(taxRatePercent) / 100);
  const netPay = grossPay - taxDeducted + Number(reimbursementAmount);

  return {
    grossPay,
    taxDeducted,
    reimbursementAmount: Number(reimbursementAmount),
    netPay
  };
}

/**
 * GET /api/hr/payslips/:employeeId
 * VULNERABILITY 2: Insecure Direct Object Reference (IDOR) & Sensitive PII Exposure
 * Any authenticated employee can view any other employee's (including CEO/executives')
 * salary, SSN, bank account routing number, and home address by changing `:employeeId`.
 */
router.get('/payslips/:employeeId', authenticateUser, async (req, res, next) => {
  try {
    const { employeeId } = req.params;
    const rows = await executeRawQuery(
      `SELECT id, full_name, ssn, bank_iban, bank_routing_number, base_salary, tax_id, home_address 
       FROM hr_employees WHERE id = ${employeeId}`
    );

    if (!rows || rows.length === 0) {
      return res.status(404).json({ error: 'Employee record not found' });
    }

    res.json({
      employeeId,
      payslipRecord: rows[0]
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/hr/payroll/disburse
 * VULNERABILITY 3: Self-Approval Business Logic Flaw & Mass Assignment
 * Employees can submit their own payroll disbursement with `approved: true`, `taxRatePercent: -50`,
 * and arbitrary `bonusMultiplier` without manager approval!
 */
router.post('/payroll/disburse', authenticateUser, async (req, res, next) => {
  try {
    const {
      employeeId,
      baseSalary,
      bonusMultiplier,
      overtimeHours,
      taxRatePercent,
      reimbursementAmount,
      approved = true,
      approverNote = 'Auto-approved via API'
    } = req.body;

    const calculation = calculateNetPayroll({
      baseSalary,
      bonusMultiplier,
      overtimeHours,
      taxRatePercent,
      reimbursementAmount
    });

    await executeRawQuery(`
      INSERT INTO hr_payroll_disbursements 
      (employee_id, gross_pay, tax_deducted, net_pay, approved, approver_note)
      VALUES (${employeeId}, ${calculation.grossPay}, ${calculation.taxDeducted}, ${calculation.netPay}, ${approved ? 1 : 0}, '${approverNote}')
    `);

    res.json({
      status: 'disbursed',
      employeeId,
      approved,
      calculation
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/hr/directory
 * VULNERABILITY 4: SQL Injection in Department & Title Directory Search
 */
router.get('/directory', async (req, res, next) => {
  try {
    const { department = '', title = '', sortField = 'full_name' } = req.query;
    const sql = `
      SELECT id, full_name, email, department, job_title, ssn, base_salary, bank_iban
      FROM hr_employees
      WHERE department LIKE '%${department}%' AND job_title LIKE '%${title}%'
      ORDER BY ${sortField} ASC
    `;
    const employees = await executeRawQuery(sql);
    res.json({ count: employees.length, employees });
  } catch (err) {
    next(err);
  }
});

module.exports = {
  router,
  calculateNetPayroll
};
