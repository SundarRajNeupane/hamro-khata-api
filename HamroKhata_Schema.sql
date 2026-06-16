-- ================================================================
-- HAMRO KHATA — Database Schema
-- Supports: SQLite (offline/local) + PostgreSQL (cloud)
-- Strategy: UUID primary keys for conflict-free offline sync
-- ================================================================

-- ── Businesses ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS businesses (
  id           TEXT PRIMARY KEY,          -- UUID
  name         TEXT NOT NULL,
  owner_name   TEXT,
  phone        TEXT UNIQUE,
  address      TEXT,
  logo_url     TEXT,
  currency     TEXT DEFAULT 'NPR',
  timezone     TEXT DEFAULT 'Asia/Kathmandu',
  created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ── Users ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id           TEXT PRIMARY KEY,
  business_id  TEXT NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  phone        TEXT NOT NULL UNIQUE,
  pin_hash     TEXT NOT NULL,             -- bcrypt hash of 4-digit PIN
  role         TEXT NOT NULL DEFAULT 'owner'
                   CHECK(role IN ('owner', 'employee', 'accountant')),
  is_active    INTEGER DEFAULT 1,
  last_login   DATETIME,
  created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ── Customers ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS customers (
  id           TEXT PRIMARY KEY,          -- UUID (generated offline)
  business_id  TEXT NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  phone        TEXT,
  address      TEXT,
  notes        TEXT,
  local_id     TEXT,                      -- client-side temp id before sync
  created_by   TEXT REFERENCES users(id),
  created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
  deleted_at   DATETIME                  -- soft-delete for sync tombstones
);

CREATE INDEX IF NOT EXISTS idx_customers_business
  ON customers(business_id, deleted_at);
CREATE INDEX IF NOT EXISTS idx_customers_phone
  ON customers(phone);

-- ── Customer Transactions (Khata) ─────────────────────────────────
CREATE TABLE IF NOT EXISTS transactions (
  id           TEXT PRIMARY KEY,
  business_id  TEXT NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
  customer_id  TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  type         TEXT NOT NULL CHECK(type IN ('credit', 'payment')),
  amount       REAL NOT NULL CHECK(amount > 0),
  description  TEXT,
  date         DATE NOT NULL,
  local_id     TEXT,
  created_by   TEXT REFERENCES users(id),
  created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
  deleted_at   DATETIME
);

CREATE INDEX IF NOT EXISTS idx_transactions_customer
  ON transactions(customer_id, deleted_at);
CREATE INDEX IF NOT EXISTS idx_transactions_business_date
  ON transactions(business_id, date, deleted_at);

-- ── Cashbook Entries ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cashbook_entries (
  id           TEXT PRIMARY KEY,
  business_id  TEXT NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
  type         TEXT NOT NULL CHECK(type IN ('income', 'expense')),
  amount       REAL NOT NULL CHECK(amount > 0),
  description  TEXT NOT NULL,
  category     TEXT NOT NULL
                   DEFAULT 'Other'
                   CHECK(category IN (
                     'Sales','Payment received','Interest','Other income',
                     'Stock','Rent','Utilities','Salary','Transport',
                     'Marketing','Other'
                   )),
  date         DATE NOT NULL,
  local_id     TEXT,
  created_by   TEXT REFERENCES users(id),
  created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
  deleted_at   DATETIME
);

CREATE INDEX IF NOT EXISTS idx_cashbook_business_date
  ON cashbook_entries(business_id, date, deleted_at);
CREATE INDEX IF NOT EXISTS idx_cashbook_category
  ON cashbook_entries(business_id, category);

-- ── Invoices ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS invoices (
  id             TEXT PRIMARY KEY,
  business_id    TEXT NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
  customer_id    TEXT REFERENCES customers(id),
  customer_name  TEXT NOT NULL,           -- denormalised for flexibility
  items          TEXT NOT NULL,           -- JSON array [{desc, qty, rate, amt}]
  subtotal       REAL NOT NULL,
  tax_amount     REAL DEFAULT 0,
  total          REAL NOT NULL,
  notes          TEXT,
  status         TEXT DEFAULT 'sent'
                     CHECK(status IN ('draft','sent','paid','cancelled')),
  date           DATE NOT NULL,
  due_date       DATE,
  local_id       TEXT,
  created_by     TEXT REFERENCES users(id),
  created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_invoices_business
  ON invoices(business_id, date);

-- ── Inventory / Stock ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS products (
  id           TEXT PRIMARY KEY,
  business_id  TEXT NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  sku          TEXT,
  unit         TEXT DEFAULT 'pcs',       -- pcs, kg, ltr, etc.
  buy_price    REAL,
  sell_price   REAL,
  stock_qty    REAL DEFAULT 0,
  low_stock_at REAL DEFAULT 5,
  local_id     TEXT,
  created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
  deleted_at   DATETIME
);

-- ── Offline Sync Queue ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sync_queue (
  id             TEXT PRIMARY KEY,
  business_id    TEXT NOT NULL,
  device_id      TEXT NOT NULL,
  action         TEXT NOT NULL CHECK(action IN ('create','update','delete')),
  entity_type    TEXT NOT NULL CHECK(entity_type IN (
                   'customer','transaction','cashbook_entry',
                   'invoice','product'
                 )),
  entity_id      TEXT NOT NULL,
  payload        TEXT NOT NULL,           -- JSON
  client_ts      DATETIME NOT NULL,       -- when change happened on device
  server_ts      DATETIME,               -- when synced to server
  conflict       INTEGER DEFAULT 0,
  resolved       INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_sync_unsynced
  ON sync_queue(business_id, device_id, server_ts);

-- ── Reminder Log ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS reminder_log (
  id           TEXT PRIMARY KEY,
  business_id  TEXT NOT NULL,
  customer_id  TEXT NOT NULL REFERENCES customers(id),
  channel      TEXT NOT NULL CHECK(channel IN ('whatsapp','sms','in_app')),
  message      TEXT,
  sent_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
  status       TEXT DEFAULT 'sent' CHECK(status IN ('sent','delivered','failed'))
);

-- ── Views ─────────────────────────────────────────────────────────

-- Customer balance view
CREATE VIEW IF NOT EXISTS customer_balances AS
SELECT
  c.id,
  c.business_id,
  c.name,
  c.phone,
  c.updated_at,
  COALESCE(SUM(CASE WHEN t.type = 'credit'  THEN t.amount ELSE 0 END), 0) AS total_credit,
  COALESCE(SUM(CASE WHEN t.type = 'payment' THEN t.amount ELSE 0 END), 0) AS total_paid,
  COALESCE(SUM(CASE WHEN t.type = 'credit'  THEN t.amount ELSE -t.amount END), 0) AS balance,
  COUNT(t.id) AS tx_count,
  MAX(t.date) AS last_tx_date
FROM customers c
LEFT JOIN transactions t
  ON t.customer_id = c.id AND t.deleted_at IS NULL
WHERE c.deleted_at IS NULL
GROUP BY c.id;

-- Daily cashbook summary view
CREATE VIEW IF NOT EXISTS daily_summary AS
SELECT
  business_id,
  date,
  COALESCE(SUM(CASE WHEN type = 'income'  THEN amount ELSE 0 END), 0) AS income,
  COALESCE(SUM(CASE WHEN type = 'expense' THEN amount ELSE 0 END), 0) AS expense,
  COALESCE(SUM(CASE WHEN type = 'income'  THEN amount ELSE -amount END), 0) AS net
FROM cashbook_entries
WHERE deleted_at IS NULL
GROUP BY business_id, date;

-- ── Triggers: auto-update updated_at ──────────────────────────────
CREATE TRIGGER IF NOT EXISTS trg_customers_updated
AFTER UPDATE ON customers
BEGIN
  UPDATE customers SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_transactions_updated
AFTER UPDATE ON transactions
BEGIN
  UPDATE transactions SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_cashbook_updated
AFTER UPDATE ON cashbook_entries
BEGIN
  UPDATE cashbook_entries SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
