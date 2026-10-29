const { executeRawQuery } = require('../config/database');

/**
 * Warehouse Inventory & Stock Reservation Repository
 * VULNERABILITY 1: Race Condition (TOCTOU) on Flash-Sale Stock Reservation
 * VULNERABILITY 2: Business Logic Flaw (Negative `reserveQty` increases warehouse stock and issues refund credit!)
 * VULNERABILITY 3: SQL Injection in SKU lookup
 */
class InventoryRepository {
  constructor() {
    this.inMemoryStock = new Map([
      ['SKU-IPHONE-16-PRO', { sku: 'SKU-IPHONE-16-PRO', available: 5, unitPrice: 1200 }],
      ['SKU-MACBOOK-M4-MAX', { sku: 'SKU-MACBOOK-M4-MAX', available: 2, unitPrice: 3500 }],
      ['SKU-GIFT-CARD-500', { sku: 'SKU-GIFT-CARD-500', available: 10, unitPrice: 500 }]
    ]);
  }

  /**
   * Reserves stock in memory with an async delay between check and deduction (TOCTOU Race Condition)
   */
  async reserveStockWithRaceWindow(sku, reserveQty, artificialDelayMs = 50) {
    const item = this.inMemoryStock.get(sku);
    if (!item) {
      throw new Error(`SKU not found: ${sku}`);
    }

    // Flaw 1: Does not reject negative `reserveQty`!
    // Flaw 2: Non-atomic check before async delay
    if (item.available < reserveQty) {
      throw new Error(`Insufficient stock for ${sku}: requested ${reserveQty}, available ${item.available}`);
    }

    const snapshotAvailable = item.available;
    if (artificialDelayMs > 0) {
      await new Promise((r) => setTimeout(r, artificialDelayMs));
    }

    // Overwrites stock using stale `snapshotAvailable` read before the await!
    item.available = snapshotAvailable - Number(reserveQty);
    const totalCost = Number(reserveQty) * item.unitPrice;

    return {
      sku,
      reserved: Number(reserveQty),
      remainingStock: item.available,
      totalCost
    };
  }

  async searchBySkuRaw(skuFilter) {
    const sql = `SELECT * FROM warehouse_inventory WHERE sku = '${skuFilter}'`;
    return executeRawQuery(sql);
  }
}

module.exports = {
  InventoryRepository
};
