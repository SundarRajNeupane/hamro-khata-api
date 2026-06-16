"use strict";
require("dotenv").config();
const express      = require("express");
const { Pool }     = require("pg");
const bcrypt       = require("bcryptjs");
const jwt          = require("jsonwebtoken");
const { v4: uuid } = require("uuid");
const cors         = require("cors");

// ── Config ────────────────────────────────────────────────────────
const PORT       = process.env.PORT       || 3001;
const JWT_SECRET = process.env.JWT_SECRET || "hamro-khata-secret-change-in-prod";

// ── Database ──────────────────────────────────────────────────────
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ── App & Middleware ──────────────────────────────────────────────
const app = express();
app.use(cors({ origin: "*" }));
app.use(express.json({ limit: "2mb" }));
app.use((req, _res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
  next();
});

// ── Helpers ───────────────────────────────────────────────────────
const today  = () => new Date().toISOString().split("T")[0];
const nowISO = () => new Date().toISOString();
const ok  = (res, data, status = 200) => res.status(status).json({ success: true, data });
const err = (res, msg, status = 400) => res.status(status).json({ success: false, error: msg });

// run a query and return all rows
const all = (text, params) => db.query(text, params).then(r => r.rows);
// run a query and return first row
const get = (text, params) => db.query(text, params).then(r => r.rows[0] || null);
// run a query and return rowCount
const run = (text, params) => db.query(text, params).then(r => r.rowCount);

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

const ownerOnly = (req, res, next) =>
  req.user.role === "owner" ? next() : err(res, "Owner access only", 403);

// ═══════════════════════════════════════════════════════════════════
// AUTH
// ═══════════════════════════════════════════════════════════════════

app.post("/auth/register", async (req, res) => {
  const { businessName, ownerName, phone, pin } = req.body;
  if (!businessName || !phone || !pin) return err(res, "businessName, phone, and pin are required");
  if (pin.length !== 4 || !/^\d{4}$/.test(pin)) return err(res, "PIN must be exactly 4 digits");

  const bid = uuid(), uid = uuid();
  const pinHash = bcrypt.hashSync(pin, 10);

  try {
    await run(
      "INSERT INTO businesses (id, name, owner_name, phone) VALUES ($1,$2,$3,$4)",
      [bid, businessName, ownerName || "", phone]
    );
    await run(
      "INSERT INTO users (id, business_id, name, phone, pin_hash, role) VALUES ($1,$2,$3,$4,$5,$6)",
      [uid, bid, ownerName || businessName, phone, pinHash, "owner"]
    );
    const token = jwt.sign({ userId: uid, businessId: bid, role: "owner" }, JWT_SECRET, { expiresIn: "30d" });
    ok(res, { token, userId: uid, businessId: bid, businessName }, 201);
  } catch (e) {
    if (e.message.includes("unique") || e.message.includes("duplicate")) return err(res, "Phone number already registered");
    err(res, e.message, 500);
  }
});

app.post("/auth/login", async (req, res) => {
  const { phone, pin } = req.body;
  if (!phone || !pin) return err(res, "phone and pin required");
  const user = await get(
    "SELECT u.*, b.name as businessname FROM users u JOIN businesses b ON b.id = u.business_id WHERE u.phone = $1 AND u.is_active = 1",
    [phone]
  );
  if (!user || !bcrypt.compareSync(pin, user.pin_hash)) return err(res, "Invalid phone or PIN", 401);
  await run("UPDATE users SET last_login = $1 WHERE id = $2", [nowISO(), user.id]);
  const token = jwt.sign({ userId: user.id, businessId: user.business_id, role: user.role }, JWT_SECRET, { expiresIn: "30d" });
  ok(res, { token, userId: user.id, businessId: user.business_id, businessName: user.businessname, role: user.role });
});

app.get("/auth/me", auth, async (req, res) => {
  const user = await get(
    "SELECT u.id, u.name, u.phone, u.role, b.name as businessName, b.id as businessId FROM users u JOIN businesses b ON b.id = u.business_id WHERE u.id = $1",
    [req.user.userId]
  );
  if (!user) return err(res, "User not found", 404);
  ok(res, user);
});

// ═══════════════════════════════════════════════════════════════════
// CUSTOMERS
// ═══════════════════════════════════════════════════════════════════

app.get("/customers", auth, async (req, res) => {
  const rows = await all(`
    SELECT c.*,
      COALESCE(SUM(CASE WHEN t.type='credit'  THEN t.amount ELSE 0 END),0) AS total_credit,
      COALESCE(SUM(CASE WHEN t.type='payment' THEN t.amount ELSE 0 END),0) AS total_paid,
      COALESCE(SUM(CASE WHEN t.type='credit'  THEN t.amount ELSE -t.amount END),0) AS balance,
      COUNT(t.id) AS tx_count,
      MAX(t.date) AS last_tx_date
    FROM customers c
    LEFT JOIN transactions t ON t.customer_id = c.id AND t.deleted_at IS NULL
    WHERE c.business_id = $1 AND c.deleted_at IS NULL
    GROUP BY c.id
    ORDER BY c.name ASC
  `, [req.user.businessId]);
  ok(res, rows);
});

app.post("/customers", auth, async (req, res) => {
  const { name, phone, notes, localId } = req.body;
  if (!name?.trim()) return err(res, "name is required");
  const id = uuid();
  await run(
    "INSERT INTO customers (id, business_id, name, phone, notes, local_id, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7)",
    [id, req.user.businessId, name.trim(), phone || null, notes || null, localId || null, req.user.userId]
  );
  ok(res, await get("SELECT * FROM customers WHERE id = $1", [id]), 201);
});

app.put("/customers/:id", auth, async (req, res) => {
  const { name, phone, notes } = req.body;
  const count = await run(
    "UPDATE customers SET name=$1, phone=$2, notes=$3 WHERE id=$4 AND business_id=$5 AND deleted_at IS NULL",
    [name, phone || null, notes || null, req.params.id, req.user.businessId]
  );
  if (!count) return err(res, "Customer not found", 404);
  ok(res, await get("SELECT * FROM customers WHERE id = $1", [req.params.id]));
});

app.delete("/customers/:id", auth, ownerOnly, async (req, res) => {
  await run(
    "UPDATE customers SET deleted_at=$1 WHERE id=$2 AND business_id=$3",
    [nowISO(), req.params.id, req.user.businessId]
  );
  ok(res, { deleted: true });
});

app.get("/customers/:id/transactions", auth, async (req, res) => {
  const txs = await all(
    "SELECT * FROM transactions WHERE customer_id=$1 AND business_id=$2 AND deleted_at IS NULL ORDER BY date DESC, created_at DESC",
    [req.params.id, req.user.businessId]
  );
  const credit = txs.filter(t => t.type === "credit").reduce((s, t) => s + +t.amount, 0);
  const paid   = txs.filter(t => t.type === "payment").reduce((s, t) => s + +t.amount, 0);
  ok(res, { transactions: txs, summary: { credit, paid, balance: credit - paid } });
});

// ═══════════════════════════════════════════════════════════════════
// TRANSACTIONS
// ═══════════════════════════════════════════════════════════════════

app.post("/transactions", auth, async (req, res) => {
  const { customerId, type, amount, description, date, localId } = req.body;
  if (!customerId || !type || !amount) return err(res, "customerId, type, and amount required");
  if (!["credit", "payment"].includes(type)) return err(res, "type must be credit or payment");
  if (+amount <= 0) return err(res, "amount must be positive");
  const customer = await get(
    "SELECT id FROM customers WHERE id=$1 AND business_id=$2 AND deleted_at IS NULL",
    [customerId, req.user.businessId]
  );
  if (!customer) return err(res, "Customer not found", 404);
  const id = uuid();
  await run(
    "INSERT INTO transactions (id, business_id, customer_id, type, amount, description, date, local_id, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    [id, req.user.businessId, customerId, type, +amount, description || null, date || today(), localId || null, req.user.userId]
  );
  ok(res, await get("SELECT * FROM transactions WHERE id = $1", [id]), 201);
});

app.delete("/transactions/:id", auth, async (req, res) => {
  const count = await run(
    "UPDATE transactions SET deleted_at=$1 WHERE id=$2 AND business_id=$3",
    [nowISO(), req.params.id, req.user.businessId]
  );
  if (!count) return err(res, "Transaction not found", 404);
  ok(res, { deleted: true });
});

// ═══════════════════════════════════════════════════════════════════
// CASHBOOK
// ═══════════════════════════════════════════════════════════════════

app.get("/cashbook", auth, async (req, res) => {
  const { date, startDate, endDate } = req.query;
  let q = "SELECT * FROM cashbook_entries WHERE business_id=$1 AND deleted_at IS NULL";
  const p = [req.user.businessId];
  let i = 2;
  if (date)      { q += ` AND date=$${i++}`;   p.push(date); }
  if (startDate) { q += ` AND date>=$${i++}`;  p.push(startDate); }
  if (endDate)   { q += ` AND date<=$${i++}`;  p.push(endDate); }
  q += " ORDER BY date DESC, created_at DESC";
  ok(res, await all(q, p));
});

app.post("/cashbook", auth, async (req, res) => {
  const { type, amount, description, category, date, localId } = req.body;
  if (!type || !amount || !description) return err(res, "type, amount, and description required");
  if (!["income", "expense"].includes(type)) return err(res, "type must be income or expense");
  if (+amount <= 0) return err(res, "amount must be positive");
  const id = uuid();
  await run(
    "INSERT INTO cashbook_entries (id, business_id, type, amount, description, category, date, local_id, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    [id, req.user.businessId, type, +amount, description.trim(), category || "Other", date || today(), localId || null, req.user.userId]
  );
  ok(res, await get("SELECT * FROM cashbook_entries WHERE id = $1", [id]), 201);
});

app.delete("/cashbook/:id", auth, async (req, res) => {
  const count = await run(
    "UPDATE cashbook_entries SET deleted_at=$1 WHERE id=$2 AND business_id=$3",
    [nowISO(), req.params.id, req.user.businessId]
  );
  if (!count) return err(res, "Entry not found", 404);
  ok(res, { deleted: true });
});

app.get("/cashbook/summary", auth, async (req, res) => {
  const days = Math.min(parseInt(req.query.days || "7"), 365);
  const since = new Date(); since.setDate(since.getDate() - days);
  const sinceStr = since.toISOString().split("T")[0];
  const rows = await all(`
    SELECT date, type, SUM(amount) AS total
    FROM cashbook_entries
    WHERE business_id=$1 AND date>=$2 AND deleted_at IS NULL
    GROUP BY date, type ORDER BY date ASC
  `, [req.user.businessId, sinceStr]);
  const byDate = {};
  rows.forEach(r => {
    if (!byDate[r.date]) byDate[r.date] = { date: r.date, income: 0, expense: 0, net: 0 };
    byDate[r.date][r.type] += +r.total;
    byDate[r.date].net = byDate[r.date].income - byDate[r.date].expense;
  });
  ok(res, Object.values(byDate));
});

// ═══════════════════════════════════════════════════════════════════
// INVOICES
// ═══════════════════════════════════════════════════════════════════

app.get("/invoices", auth, async (req, res) => {
  ok(res, await all("SELECT * FROM invoices WHERE business_id=$1 ORDER BY date DESC", [req.user.businessId]));
});

app.post("/invoices", auth, async (req, res) => {
  const { customerName, customerId, items, total, date, notes, localId } = req.body;
  if (!customerName || !items || !total) return err(res, "customerName, items, and total required");
  const id = uuid();
  await run(
    "INSERT INTO invoices (id, business_id, customer_id, customer_name, items, total, date, notes, local_id, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    [id, req.user.businessId, customerId || null, customerName, JSON.stringify(items), +total, date || today(), notes || null, localId || null, req.user.userId]
  );
  ok(res, await get("SELECT * FROM invoices WHERE id = $1", [id]), 201);
});

app.put("/invoices/:id/status", auth, async (req, res) => {
  const { status } = req.body;
  if (!["draft","sent","paid","cancelled"].includes(status)) return err(res, "Invalid status");
  const count = await run(
    "UPDATE invoices SET status=$1 WHERE id=$2 AND business_id=$3",
    [status, req.params.id, req.user.businessId]
  );
  if (!count) return err(res, "Invoice not found", 404);
  ok(res, await get("SELECT * FROM invoices WHERE id = $1", [req.params.id]));
});

// ═══════════════════════════════════════════════════════════════════
// ANALYTICS
// ═══════════════════════════════════════════════════════════════════

app.get("/analytics/dashboard", auth, async (req, res) => {
  const bid = req.user.businessId;
  const todayStr = today();

  const todayCash = await all(
    "SELECT type, SUM(amount) AS total FROM cashbook_entries WHERE business_id=$1 AND date=$2 AND deleted_at IS NULL GROUP BY type",
    [bid, todayStr]
  );
  const todayInc = +todayCash.find(r => r.type === "income")?.total || 0;
  const todayExp = +todayCash.find(r => r.type === "expense")?.total || 0;

  const outstandingRow = await get(`
    SELECT COALESCE(SUM(CASE WHEN type='credit' THEN amount ELSE -amount END),0) AS total
    FROM transactions WHERE business_id=$1 AND deleted_at IS NULL
  `, [bid]);
  const outstanding = +outstandingRow?.total || 0;

  const topDebtors = await all(`
    SELECT c.id, c.name, c.phone,
      SUM(CASE WHEN t.type='credit' THEN t.amount ELSE -t.amount END) AS balance
    FROM customers c
    LEFT JOIN transactions t ON t.customer_id=c.id AND t.deleted_at IS NULL
    WHERE c.business_id=$1 AND c.deleted_at IS NULL
    GROUP BY c.id, c.name, c.phone
    HAVING SUM(CASE WHEN t.type='credit' THEN t.amount ELSE -t.amount END) > 0
    ORDER BY balance DESC LIMIT 5
  `, [bid]);

  const weeklyTrend = await all(`
    SELECT date,
      SUM(CASE WHEN type='income'  THEN amount ELSE 0 END) AS income,
      SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) AS expense
    FROM cashbook_entries
    WHERE business_id=$1 AND date >= CURRENT_DATE - INTERVAL '6 days' AND deleted_at IS NULL
    GROUP BY date ORDER BY date ASC
  `, [bid]);

  const countRow = await get(
    "SELECT COUNT(*) AS n FROM customers WHERE business_id=$1 AND deleted_at IS NULL",
    [bid]
  );
  const customerCount = +countRow?.n || 0;

  ok(res, {
    today: { income: todayInc, expense: todayExp, net: todayInc - todayExp },
    totalOutstanding: outstanding,
    customerCount,
    topDebtors,
    weeklyTrend,
  });
});

// ═══════════════════════════════════════════════════════════════════
// SYNC
// ═══════════════════════════════════════════════════════════════════

app.post("/sync", auth, async (req, res) => {
  const { deviceId, lastSyncAt, changes = [] } = req.body;
  const bid = req.user.businessId;
  const result = { pushed: [], conflicts: [], pulled: {} };

  for (const change of changes) {
    try {
      const { action, entityType, entityId, payload, clientTs } = change;

      await run(
        `INSERT INTO sync_queue (id,business_id,device_id,action,entity_type,entity_id,payload,client_ts,server_ts)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (id) DO NOTHING`,
        [uuid(), bid, deviceId || "unknown", action, entityType, entityId, JSON.stringify(payload), clientTs, nowISO()]
      );

      if (entityType === "customer") {
        if (action === "create") {
          await run(
            `INSERT INTO customers (id,business_id,name,phone,notes,local_id,created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO NOTHING`,
            [payload.id || uuid(), bid, payload.name, payload.phone || null, payload.notes || null, payload.localId || null, payload.createdAt || nowISO()]
          );
        } else if (action === "update") {
          await run(
            "UPDATE customers SET name=$1, phone=$2, notes=$3 WHERE id=$4 AND business_id=$5",
            [payload.name, payload.phone || null, payload.notes || null, payload.id, bid]
          );
        } else if (action === "delete") {
          await run("UPDATE customers SET deleted_at=$1 WHERE id=$2 AND business_id=$3", [nowISO(), payload.id, bid]);
        }
      } else if (entityType === "transaction") {
        if (action === "create") {
          await run(
            `INSERT INTO transactions (id,business_id,customer_id,type,amount,description,date,local_id,created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (id) DO NOTHING`,
            [payload.id || uuid(), bid, payload.customerId, payload.type, payload.amount, payload.description || null, payload.date, payload.localId || null, payload.createdAt || nowISO()]
          );
        } else if (action === "delete") {
          await run("UPDATE transactions SET deleted_at=$1 WHERE id=$2 AND business_id=$3", [nowISO(), payload.id, bid]);
        }
      } else if (entityType === "cashbook_entry") {
        if (action === "create") {
          await run(
            `INSERT INTO cashbook_entries (id,business_id,type,amount,description,category,date,local_id,created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (id) DO NOTHING`,
            [payload.id || uuid(), bid, payload.type, payload.amount, payload.description, payload.category || "Other", payload.date, payload.localId || null, payload.createdAt || nowISO()]
          );
        } else if (action === "delete") {
          await run("UPDATE cashbook_entries SET deleted_at=$1 WHERE id=$2 AND business_id=$3", [nowISO(), payload.id, bid]);
        }
      } else if (entityType === "invoice") {
        if (action === "create") {
          await run(
            `INSERT INTO invoices (id,business_id,customer_name,items,total,date,local_id,created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (id) DO NOTHING`,
            [payload.id || uuid(), bid, payload.customerName, JSON.stringify(payload.items), payload.total, payload.date, payload.localId || null, payload.createdAt || nowISO()]
          );
        }
      }

      result.pushed.push({ entityId: change.entityId, status: "ok" });
    } catch (e) {
      result.conflicts.push({ entityId: change.entityId, error: e.message });
    }
  }

  const since = lastSyncAt || "1970-01-01T00:00:00.000Z";
  result.pulled = {
    customers:       await all("SELECT * FROM customers       WHERE business_id=$1 AND updated_at > $2", [bid, since]),
    transactions:    await all("SELECT * FROM transactions    WHERE business_id=$1 AND updated_at > $2", [bid, since]),
    cashbookEntries: await all("SELECT * FROM cashbook_entries WHERE business_id=$1 AND updated_at > $2", [bid, since]),
    invoices:        await all("SELECT * FROM invoices        WHERE business_id=$1 AND created_at > $2", [bid, since]),
  };
  result.syncedAt = nowISO();

  ok(res, result);
});

// ═══════════════════════════════════════════════════════════════════
// HEALTH + 404 + Error handler
// ═══════════════════════════════════════════════════════════════════

app.get("/health", (_req, res) =>
  res.json({ status: "ok", version: "1.0.0", db: "postgresql", ts: nowISO() })
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
  │  DB  : PostgreSQL (Railway)             │
  │  Docs: http://localhost:${PORT}/health      │
  └─────────────────────────────────────────┘`);
});

module.exports = app;