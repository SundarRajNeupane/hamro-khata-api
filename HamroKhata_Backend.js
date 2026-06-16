/**
 * HAMRO KHATA — Backend API
 * Stack : Node.js + Express + better-sqlite3
 * Auth  : JWT with 4-digit PIN (no password complexity for field users)
 * Sync  : POST /sync — push local, pull remote, resolve conflicts
 *
 * Install:
 *   npm install express better-sqlite3 bcryptjs jsonwebtoken uuid cors dotenv
 *
 * Run:
 *   node HamroKhata_Backend.js
 */

"use strict";
require("dotenv").config();
const express   = require("express");
const Database  = require("better-sqlite3");
const bcrypt    = require("bcryptjs");
const jwt       = require("jsonwebtoken");
const { v4: uuid } = require("uuid");
const cors      = require("cors");
const path      = require("path");
const fs        = require("fs");

// ── Config ────────────────────────────────────────────────────────
const PORT       = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || "hamro-khata-secret-change-in-prod";
const DB_PATH    = process.env.DB_PATH    || path.join(__dirname, "hamro_khata.db");

// ── Database ──────────────────────────────────────────────────────
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");   // better concurrent reads
db.pragma("foreign_keys = ON");

const schemaPath = path.join(__dirname, "HamroKhata_Schema.sql");
if (fs.existsSync(schemaPath)) {
  db.exec(fs.readFileSync(schemaPath, "utf8"));
} else {
  // Inline minimal schema if SQL file not present
  db.exec(`
    CREATE TABLE IF NOT EXISTS businesses   (id TEXT PRIMARY KEY, name TEXT NOT NULL, phone TEXT UNIQUE, owner_name TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS users        (id TEXT PRIMARY KEY, business_id TEXT NOT NULL, name TEXT NOT NULL, phone TEXT NOT NULL UNIQUE, pin_hash TEXT NOT NULL, role TEXT DEFAULT 'owner', created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS customers    (id TEXT PRIMARY KEY, business_id TEXT NOT NULL, name TEXT NOT NULL, phone TEXT, notes TEXT, local_id TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, deleted_at DATETIME);
    CREATE TABLE IF NOT EXISTS transactions (id TEXT PRIMARY KEY, business_id TEXT NOT NULL, customer_id TEXT NOT NULL, type TEXT NOT NULL, amount REAL NOT NULL, description TEXT, date DATE NOT NULL, local_id TEXT, created_by TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, deleted_at DATETIME);
    CREATE TABLE IF NOT EXISTS cashbook_entries (id TEXT PRIMARY KEY, business_id TEXT NOT NULL, type TEXT NOT NULL, amount REAL NOT NULL, description TEXT NOT NULL, category TEXT DEFAULT 'Other', date DATE NOT NULL, local_id TEXT, created_by TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, deleted_at DATETIME);
    CREATE TABLE IF NOT EXISTS invoices     (id TEXT PRIMARY KEY, business_id TEXT NOT NULL, customer_name TEXT NOT NULL, items TEXT NOT NULL, total REAL NOT NULL, date DATE NOT NULL, local_id TEXT, status TEXT DEFAULT 'sent', created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS sync_queue   (id TEXT PRIMARY KEY, business_id TEXT NOT NULL, device_id TEXT NOT NULL, action TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, payload TEXT NOT NULL, client_ts DATETIME NOT NULL, server_ts DATETIME, conflict INTEGER DEFAULT 0, resolved INTEGER DEFAULT 0);
  `);
}

// ── App & Middleware ──────────────────────────────────────────────
const app = express();
app.use(cors({ origin: "*" }));
app.use(express.json({ limit: "2mb" }));
app.use((req, _res, next) => { console.log(`${new Date().toISOString()} ${req.method} ${req.path}`); next(); });

// ── Helpers ───────────────────────────────────────────────────────
const today = () => new Date().toISOString().split("T")[0];
const nowISO = () => new Date().toISOString();
const ok  = (res, data, status = 200) => res.status(status).json({ success: true, data });
const err = (res, msg, status = 400) => res.status(status).json({ success: false, error: msg });

// ── Auth Middleware ───────────────────────────────────────────────
const auth = (req, res, next) => {
  const header = req.headers.authorization || "";
  const token  = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return err(res, "Token required", 401);
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    err(res, "Invalid or expired token", 401);
  }
};

// ── Role guard ────────────────────────────────────────────────────
const ownerOnly = (req, res, next) =>
  req.user.role === "owner" ? next() : err(res, "Owner access only", 403);

// ═══════════════════════════════════════════════════════════════════
// AUTH
// ═══════════════════════════════════════════════════════════════════

/** POST /auth/register — Create a new business + owner account */
app.post("/auth/register", (req, res) => {
  const { businessName, ownerName, phone, pin } = req.body;
  if (!businessName || !phone || !pin) return err(res, "businessName, phone, and pin are required");
  if (pin.length !== 4 || !/^\d{4}$/.test(pin)) return err(res, "PIN must be exactly 4 digits");

  const bid = uuid(), uid = uuid();
  const pinHash = bcrypt.hashSync(pin, 10);

  try {
    db.prepare("INSERT INTO businesses (id, name, owner_name, phone) VALUES (?,?,?,?)").run(bid, businessName, ownerName || "", phone);
    db.prepare("INSERT INTO users (id, business_id, name, phone, pin_hash, role) VALUES (?,?,?,?,?,?)").run(uid, bid, ownerName || businessName, phone, pinHash, "owner");
    const token = jwt.sign({ userId: uid, businessId: bid, role: "owner" }, JWT_SECRET, { expiresIn: "30d" });
    ok(res, { token, userId: uid, businessId: bid, businessName }, 201);
  } catch (e) {
    if (e.message.includes("UNIQUE")) return err(res, "Phone number already registered");
    err(res, e.message, 500);
  }
});

/** POST /auth/login — Login with phone + PIN */
app.post("/auth/login", (req, res) => {
  const { phone, pin } = req.body;
  if (!phone || !pin) return err(res, "phone and pin required");
  const user = db.prepare("SELECT u.*, b.name as businessName FROM users u JOIN businesses b ON b.id = u.business_id WHERE u.phone = ? AND u.is_active = 1").get(phone);
  if (!user || !bcrypt.compareSync(pin, user.pin_hash)) return err(res, "Invalid phone or PIN", 401);
  db.prepare("UPDATE users SET last_login = ? WHERE id = ?").run(nowISO(), user.id);
  const token = jwt.sign({ userId: user.id, businessId: user.business_id, role: user.role }, JWT_SECRET, { expiresIn: "30d" });
  ok(res, { token, userId: user.id, businessId: user.business_id, businessName: user.businessName, role: user.role });
});

/** GET /auth/me — Current user info */
app.get("/auth/me", auth, (req, res) => {
  const user = db.prepare("SELECT u.id, u.name, u.phone, u.role, b.name as businessName, b.id as businessId FROM users u JOIN businesses b ON b.id = u.business_id WHERE u.id = ?").get(req.user.userId);
  if (!user) return err(res, "User not found", 404);
  ok(res, user);
});

// ═══════════════════════════════════════════════════════════════════
// CUSTOMERS
// ═══════════════════════════════════════════════════════════════════

/** GET /customers — List all customers with computed balance */
app.get("/customers", auth, (req, res) => {
  const rows = db.prepare(`
    SELECT c.*,
      COALESCE(SUM(CASE WHEN t.type='credit'  THEN t.amount ELSE 0 END),0) AS total_credit,
      COALESCE(SUM(CASE WHEN t.type='payment' THEN t.amount ELSE 0 END),0) AS total_paid,
      COALESCE(SUM(CASE WHEN t.type='credit'  THEN t.amount ELSE -t.amount END),0) AS balance,
      COUNT(t.id) AS tx_count,
      MAX(t.date)  AS last_tx_date
    FROM customers c
    LEFT JOIN transactions t ON t.customer_id = c.id AND t.deleted_at IS NULL
    WHERE c.business_id = ? AND c.deleted_at IS NULL
    GROUP BY c.id
    ORDER BY c.name ASC
  `).all(req.user.businessId);
  ok(res, rows);
});

/** POST /customers — Create customer */
app.post("/customers", auth, (req, res) => {
  const { name, phone, notes, localId } = req.body;
  if (!name?.trim()) return err(res, "name is required");
  const id = uuid();
  db.prepare("INSERT INTO customers (id, business_id, name, phone, notes, local_id, created_by) VALUES (?,?,?,?,?,?,?)").run(id, req.user.businessId, name.trim(), phone || null, notes || null, localId || null, req.user.userId);
  ok(res, db.prepare("SELECT * FROM customers WHERE id = ?").get(id), 201);
});

/** PUT /customers/:id — Update customer */
app.put("/customers/:id", auth, (req, res) => {
  const { name, phone, notes } = req.body;
  const result = db.prepare("UPDATE customers SET name=?, phone=?, notes=? WHERE id=? AND business_id=? AND deleted_at IS NULL").run(name, phone || null, notes || null, req.params.id, req.user.businessId);
  if (!result.changes) return err(res, "Customer not found", 404);
  ok(res, db.prepare("SELECT * FROM customers WHERE id = ?").get(req.params.id));
});

/** DELETE /customers/:id — Soft-delete */
app.delete("/customers/:id", auth, ownerOnly, (req, res) => {
  db.prepare("UPDATE customers SET deleted_at=? WHERE id=? AND business_id=?").run(nowISO(), req.params.id, req.user.businessId);
  ok(res, { deleted: true });
});

/** GET /customers/:id/transactions — Full ledger for one customer */
app.get("/customers/:id/transactions", auth, (req, res) => {
  const txs = db.prepare("SELECT * FROM transactions WHERE customer_id=? AND business_id=? AND deleted_at IS NULL ORDER BY date DESC, created_at DESC").all(req.params.id, req.user.businessId);
  const credit = txs.filter(t => t.type === "credit").reduce((s, t) => s + t.amount, 0);
  const paid   = txs.filter(t => t.type === "payment").reduce((s, t) => s + t.amount, 0);
  ok(res, { transactions: txs, summary: { credit, paid, balance: credit - paid } });
});

// ═══════════════════════════════════════════════════════════════════
// TRANSACTIONS (customer ledger entries)
// ═══════════════════════════════════════════════════════════════════

/** POST /transactions — Record credit or payment */
app.post("/transactions", auth, (req, res) => {
  const { customerId, type, amount, description, date, localId } = req.body;
  if (!customerId || !type || !amount) return err(res, "customerId, type, and amount required");
  if (!["credit", "payment"].includes(type)) return err(res, "type must be credit or payment");
  if (+amount <= 0) return err(res, "amount must be positive");
  const customer = db.prepare("SELECT id FROM customers WHERE id=? AND business_id=? AND deleted_at IS NULL").get(customerId, req.user.businessId);
  if (!customer) return err(res, "Customer not found", 404);
  const id = uuid();
  db.prepare("INSERT INTO transactions (id, business_id, customer_id, type, amount, description, date, local_id, created_by) VALUES (?,?,?,?,?,?,?,?,?)").run(id, req.user.businessId, customerId, type, +amount, description || null, date || today(), localId || null, req.user.userId);
  ok(res, db.prepare("SELECT * FROM transactions WHERE id = ?").get(id), 201);
});

/** DELETE /transactions/:id */
app.delete("/transactions/:id", auth, (req, res) => {
  const result = db.prepare("UPDATE transactions SET deleted_at=? WHERE id=? AND business_id=?").run(nowISO(), req.params.id, req.user.businessId);
  if (!result.changes) return err(res, "Transaction not found", 404);
  ok(res, { deleted: true });
});

// ═══════════════════════════════════════════════════════════════════
// CASHBOOK
// ═══════════════════════════════════════════════════════════════════

/** GET /cashbook — Entries for a date range */
app.get("/cashbook", auth, (req, res) => {
  const { date, startDate, endDate } = req.query;
  let q = "SELECT * FROM cashbook_entries WHERE business_id=? AND deleted_at IS NULL";
  const p = [req.user.businessId];
  if (date)      { q += " AND date=?";    p.push(date); }
  if (startDate) { q += " AND date>=?";   p.push(startDate); }
  if (endDate)   { q += " AND date<=?";   p.push(endDate); }
  q += " ORDER BY date DESC, created_at DESC";
  ok(res, db.prepare(q).all(...p));
});

/** POST /cashbook — Add income or expense */
app.post("/cashbook", auth, (req, res) => {
  const { type, amount, description, category, date, localId } = req.body;
  if (!type || !amount || !description) return err(res, "type, amount, and description required");
  if (!["income", "expense"].includes(type)) return err(res, "type must be income or expense");
  if (+amount <= 0) return err(res, "amount must be positive");
  const id = uuid();
  db.prepare("INSERT INTO cashbook_entries (id, business_id, type, amount, description, category, date, local_id, created_by) VALUES (?,?,?,?,?,?,?,?,?)").run(id, req.user.businessId, type, +amount, description.trim(), category || "Other", date || today(), localId || null, req.user.userId);
  ok(res, db.prepare("SELECT * FROM cashbook_entries WHERE id = ?").get(id), 201);
});

/** DELETE /cashbook/:id */
app.delete("/cashbook/:id", auth, (req, res) => {
  const result = db.prepare("UPDATE cashbook_entries SET deleted_at=? WHERE id=? AND business_id=?").run(nowISO(), req.params.id, req.user.businessId);
  if (!result.changes) return err(res, "Entry not found", 404);
  ok(res, { deleted: true });
});

/** GET /cashbook/summary?days=7 — Aggregated income/expense per day */
app.get("/cashbook/summary", auth, (req, res) => {
  const days = Math.min(parseInt(req.query.days || "7"), 365);
  const since = new Date(); since.setDate(since.getDate() - days);
  const sinceStr = since.toISOString().split("T")[0];
  const rows = db.prepare(`
    SELECT date, type, SUM(amount) AS total
    FROM cashbook_entries
    WHERE business_id=? AND date>=? AND deleted_at IS NULL
    GROUP BY date, type
    ORDER BY date ASC
  `).all(req.user.businessId, sinceStr);
  const byDate = {};
  rows.forEach(r => {
    if (!byDate[r.date]) byDate[r.date] = { date: r.date, income: 0, expense: 0, net: 0 };
    byDate[r.date][r.type] += r.total;
    byDate[r.date].net = byDate[r.date].income - byDate[r.date].expense;
  });
  ok(res, Object.values(byDate));
});

// ═══════════════════════════════════════════════════════════════════
// INVOICES
// ═══════════════════════════════════════════════════════════════════

/** GET /invoices */
app.get("/invoices", auth, (req, res) => {
  ok(res, db.prepare("SELECT * FROM invoices WHERE business_id=? ORDER BY date DESC").all(req.user.businessId));
});

/** POST /invoices */
app.post("/invoices", auth, (req, res) => {
  const { customerName, customerId, items, total, date, notes, localId } = req.body;
  if (!customerName || !items || !total) return err(res, "customerName, items, and total required");
  const id = uuid();
  db.prepare("INSERT INTO invoices (id, business_id, customer_id, customer_name, items, total, date, notes, local_id, created_by) VALUES (?,?,?,?,?,?,?,?,?,?)").run(id, req.user.businessId, customerId || null, customerName, JSON.stringify(items), +total, date || today(), notes || null, localId || null, req.user.userId);
  ok(res, db.prepare("SELECT * FROM invoices WHERE id = ?").get(id), 201);
});

/** PUT /invoices/:id/status — Mark paid/cancelled */
app.put("/invoices/:id/status", auth, (req, res) => {
  const { status } = req.body;
  if (!["draft","sent","paid","cancelled"].includes(status)) return err(res, "Invalid status");
  const result = db.prepare("UPDATE invoices SET status=? WHERE id=? AND business_id=?").run(status, req.params.id, req.user.businessId);
  if (!result.changes) return err(res, "Invoice not found", 404);
  ok(res, db.prepare("SELECT * FROM invoices WHERE id = ?").get(req.params.id));
});

// ═══════════════════════════════════════════════════════════════════
// ANALYTICS
// ═══════════════════════════════════════════════════════════════════

/** GET /analytics/dashboard — All KPIs in one call */
app.get("/analytics/dashboard", auth, (req, res) => {
  const bid = req.user.businessId;
  const todayStr = today();

  const todayCash = db.prepare("SELECT type, SUM(amount) AS total FROM cashbook_entries WHERE business_id=? AND date=? AND deleted_at IS NULL GROUP BY type").all(bid, todayStr);
  const todayInc  = todayCash.find(r => r.type === "income")?.total || 0;
  const todayExp  = todayCash.find(r => r.type === "expense")?.total || 0;

  const outstanding = db.prepare(`
    SELECT COALESCE(SUM(CASE WHEN type='credit' THEN amount ELSE -amount END),0) AS total
    FROM transactions WHERE business_id=? AND deleted_at IS NULL
  `).get(bid)?.total || 0;

  const topDebtors = db.prepare(`
    SELECT c.id, c.name, c.phone,
      SUM(CASE WHEN t.type='credit' THEN t.amount ELSE -t.amount END) AS balance
    FROM customers c
    LEFT JOIN transactions t ON t.customer_id=c.id AND t.deleted_at IS NULL
    WHERE c.business_id=? AND c.deleted_at IS NULL
    GROUP BY c.id HAVING balance > 0
    ORDER BY balance DESC LIMIT 5
  `).all(bid);

  const weeklyTrend = db.prepare(`
    SELECT date,
      SUM(CASE WHEN type='income'  THEN amount ELSE 0 END) AS income,
      SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) AS expense
    FROM cashbook_entries
    WHERE business_id=? AND date >= date('now','-6 days') AND deleted_at IS NULL
    GROUP BY date ORDER BY date ASC
  `).all(bid);

  const customerCount = db.prepare("SELECT COUNT(*) AS n FROM customers WHERE business_id=? AND deleted_at IS NULL").get(bid)?.n || 0;

  ok(res, {
    today:         { income: todayInc, expense: todayExp, net: todayInc - todayExp },
    totalOutstanding: outstanding,
    customerCount,
    topDebtors,
    weeklyTrend,
  });
});

// ═══════════════════════════════════════════════════════════════════
// SYNC — Offline → Online reconciliation
// ═══════════════════════════════════════════════════════════════════

/**
 * POST /sync
 * Body: { deviceId, lastSyncAt, changes: [{ action, entityType, entityId, payload, clientTs }] }
 * Response: { pushed: [], conflicts: [], pulled: {}, syncedAt }
 */
app.post("/sync", auth, (req, res) => {
  const { deviceId, lastSyncAt, changes = [] } = req.body;
  const bid = req.user.businessId;
  const result = { pushed: [], conflicts: [], pulled: {} };

  // ── Apply incoming changes (device → server) ──
  const applyChange = db.transaction((change) => {
    const { action, entityType, entityId, payload, clientTs } = change;

    // Record in sync_queue for auditability
    db.prepare("INSERT OR IGNORE INTO sync_queue (id,business_id,device_id,action,entity_type,entity_id,payload,client_ts,server_ts) VALUES (?,?,?,?,?,?,?,?,?)").run(uuid(), bid, deviceId || "unknown", action, entityType, entityId, JSON.stringify(payload), clientTs, nowISO());

    if (entityType === "customer") {
      if (action === "create") {
        db.prepare("INSERT OR IGNORE INTO customers (id,business_id,name,phone,notes,local_id,created_at) VALUES (?,?,?,?,?,?,?)").run(payload.id || uuid(), bid, payload.name, payload.phone || null, payload.notes || null, payload.localId || null, payload.createdAt || nowISO());
      } else if (action === "update") {
        db.prepare("UPDATE customers SET name=?,phone=?,notes=? WHERE id=? AND business_id=?").run(payload.name, payload.phone || null, payload.notes || null, payload.id, bid);
      } else if (action === "delete") {
        db.prepare("UPDATE customers SET deleted_at=? WHERE id=? AND business_id=?").run(nowISO(), payload.id, bid);
      }
    } else if (entityType === "transaction") {
      if (action === "create") {
        db.prepare("INSERT OR IGNORE INTO transactions (id,business_id,customer_id,type,amount,description,date,local_id,created_at) VALUES (?,?,?,?,?,?,?,?,?)").run(payload.id || uuid(), bid, payload.customerId, payload.type, payload.amount, payload.description || null, payload.date, payload.localId || null, payload.createdAt || nowISO());
      } else if (action === "delete") {
        db.prepare("UPDATE transactions SET deleted_at=? WHERE id=? AND business_id=?").run(nowISO(), payload.id, bid);
      }
    } else if (entityType === "cashbook_entry") {
      if (action === "create") {
        db.prepare("INSERT OR IGNORE INTO cashbook_entries (id,business_id,type,amount,description,category,date,local_id,created_at) VALUES (?,?,?,?,?,?,?,?,?)").run(payload.id || uuid(), bid, payload.type, payload.amount, payload.description, payload.category || "Other", payload.date, payload.localId || null, payload.createdAt || nowISO());
      } else if (action === "delete") {
        db.prepare("UPDATE cashbook_entries SET deleted_at=? WHERE id=? AND business_id=?").run(nowISO(), payload.id, bid);
      }
    } else if (entityType === "invoice") {
      if (action === "create") {
        db.prepare("INSERT OR IGNORE INTO invoices (id,business_id,customer_name,items,total,date,local_id,created_at) VALUES (?,?,?,?,?,?,?,?)").run(payload.id || uuid(), bid, payload.customerName, JSON.stringify(payload.items), payload.total, payload.date, payload.localId || null, payload.createdAt || nowISO());
      }
    }
  });

  for (const change of changes) {
    try {
      applyChange(change);
      result.pushed.push({ entityId: change.entityId, status: "ok" });
    } catch (e) {
      result.conflicts.push({ entityId: change.entityId, error: e.message });
    }
  }

  // ── Pull server changes since lastSyncAt ──
  const since = lastSyncAt || "1970-01-01T00:00:00.000Z";
  result.pulled = {
    customers:      db.prepare("SELECT * FROM customers      WHERE business_id=? AND updated_at > ?").all(bid, since),
    transactions:   db.prepare("SELECT * FROM transactions   WHERE business_id=? AND updated_at > ?").all(bid, since),
    cashbookEntries:db.prepare("SELECT * FROM cashbook_entries WHERE business_id=? AND updated_at > ?").all(bid, since),
    invoices:       db.prepare("SELECT * FROM invoices       WHERE business_id=? AND created_at > ?").all(bid, since),
  };
  result.syncedAt = nowISO();

  ok(res, result);
});

// ═══════════════════════════════════════════════════════════════════
// HEALTH + 404 + Error handler
// ═══════════════════════════════════════════════════════════════════

app.get("/health", (_req, res) =>
  res.json({ status: "ok", version: "1.0.0", db: DB_PATH, ts: nowISO() })
);

app.use((_req, res) => err(res, "Route not found", 404));

app.use((e, _req, res, _next) => {
  console.error(e);
  err(res, e.message || "Internal server error", 500);
});

// ── Start ─────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`
  ┌─────────────────────────────────────────┐
  │  Hamro Khata API — listening on :${PORT}   │
  │  DB  : ${DB_PATH}          │
  │  Docs: http://localhost:${PORT}/health      │
  └─────────────────────────────────────────┘`);
});

module.exports = app;
