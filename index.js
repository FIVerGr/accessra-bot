"use strict";

/**
 * AccessraBot — Premium Subscription System (English UI + Secure + Button-driven)
 *
 * Features:
 * - Button UI: Buy -> Product -> Duration -> Invoice -> "I paid" -> paste TX
 * - Products: paid_access, security, alerts, bundle (bundle covers all)
 * - Setup fee once + monthly renewals (30 days per month)
 * - Prepay extends from current expiry (e.g., renew 3 days early => 33 days left)
 * - Solana verification: treasury + amount + memo/reference (anti fake-claims)
 * - Invoice expiry (default 30 min) to reduce fraud/confusion
 * - Rate limiting + anti-spam
 * - Auto reminders 3 days before expiry
 * - Auto-kick from linked group after expiry + grace hours
 * - Group linking without numeric ID: owner runs /setgroup in the group
 */

require("dotenv").config();
const { Telegraf, Markup } = require("telegraf");
const cron = require("node-cron");
const Database = require("better-sqlite3");
const { Connection, PublicKey, LAMPORTS_PER_SOL } = require("@solana/web3.js");

// ===================== YOUR FIXED DATA =====================
const OWNER_ID = "6905624065";
const TREASURY_SOL_ADDRESS = "EyTtALk3AJubxGgkEvkkU4cJQcQuke8ovGV3AucuGs3J";

// ===================== SYSTEM CONFIG =====================
const BOT_TOKEN = process.env.BOT_TOKEN;
if (!BOT_TOKEN) throw new Error("Missing BOT_TOKEN in .env");

const SOLANA_RPC = process.env.SOLANA_RPC || "https://api.mainnet-beta.solana.com";
const solana = new Connection(SOLANA_RPC, "confirmed");
const TREASURY_PUBKEY = new PublicKey(TREASURY_SOL_ADDRESS);

// Subscription rules
const DAYS_PER_MONTH = 30;
const REMINDER_DAYS_BEFORE = 3;
const KICK_GRACE_HOURS_AFTER_EXPIRY = 12;

// Security settings
const INVOICE_EXPIRE_MINUTES = 30;     // invoice must be confirmed within 30 minutes
const MAX_MONTHS_PER_PURCHASE = 60;    // safety limit
const RATE_LIMIT_WINDOW_MS = 10_000;   // 10 seconds window
const RATE_LIMIT_MAX_ACTIONS = 8;      // max actions per window per user

// Solana memo program
const MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

// Pricing (as you requested)
const PRODUCTS = {
  paid_access: { key: "paid_access", name: "Paid Access", icon: "💎", setup: 0.7, monthly: 0.2 },
  security:    { key: "security",    name: "Security",    icon: "🔒", setup: 0.4, monthly: 0.15 },
  alerts:      { key: "alerts",      name: "Alerts",      icon: "🚨", setup: 0.3, monthly: 0.2 },
  bundle:      { key: "bundle",      name: "All-in-One Bundle", icon: "🌟", setup: 1.6, monthly: 0.55 },
};

// Optional: special offer (turn on/off)
const PAID_ACCESS_SPECIAL = {
  enabled: true,
  pay_sol: 1.0,
  months: 5,
  renewal_only: true,
};

// ===================== BOT + DB =====================
const bot = new Telegraf(BOT_TOKEN);

// Simple in-memory rate limiter (fast + effective)
const rateMap = new Map(); // tgId -> {count, resetAt}
function rateLimitOk(tgId) {
  const t = Date.now();
  const s = rateMap.get(tgId);
  if (!s || t > s.resetAt) {
    rateMap.set(tgId, { count: 1, resetAt: t + RATE_LIMIT_WINDOW_MS });
    return true;
  }
  s.count += 1;
  if (s.count > RATE_LIMIT_MAX_ACTIONS) return false;
  return true;
}

// DB
const db = new Database("accessra.db");
db.pragma("journal_mode = WAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS settings (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS users (
    tg_id TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS subscriptions (
    tg_id TEXT NOT NULL,
    product TEXT NOT NULL,
    setup_paid INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL,
    last_reminder_at INTEGER,
    last_expired_notice_at INTEGER,
    PRIMARY KEY (tg_id, product)
  );

  CREATE TABLE IF NOT EXISTS invoices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tg_id TEXT NOT NULL,
    product TEXT NOT NULL,
    months INTEGER NOT NULL,
    amount_sol REAL NOT NULL,
    memo TEXT NOT NULL,
    status TEXT NOT NULL,        -- pending | paid | cancelled | expired
    created_at INTEGER NOT NULL,
    paid_at INTEGER,
    tx_sig TEXT
  );

  CREATE TABLE IF NOT EXISTS payments (
    tx_sig TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS user_state (
    tg_id TEXT PRIMARY KEY,
    state TEXT NOT NULL,         -- none | awaiting_tx
    invoice_id INTEGER,
    updated_at INTEGER NOT NULL
  );
`);

const S = {
  setSetting: db.prepare(`INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`),
  getSetting: db.prepare(`SELECT v FROM settings WHERE k=?`),

  upsertUser: db.prepare(`
    INSERT INTO users(tg_id, created_at, last_seen_at)
    VALUES (?, ?, ?)
    ON CONFLICT(tg_id) DO UPDATE SET last_seen_at=excluded.last_seen_at
  `),

  getSub: db.prepare(`SELECT * FROM subscriptions WHERE tg_id=? AND product=?`),
  getSubs: db.prepare(`SELECT * FROM subscriptions WHERE tg_id=? ORDER BY product`),
  upsertSub: db.prepare(`
    INSERT INTO subscriptions(tg_id, product, setup_paid, expires_at, last_reminder_at, last_expired_notice_at)
    VALUES (?, ?, ?, ?, NULL, NULL)
    ON CONFLICT(tg_id, product) DO UPDATE SET
      setup_paid=excluded.setup_paid,
      expires_at=excluded.expires_at
  `),
  listUsersWithSubs: db.prepare(`SELECT DISTINCT tg_id FROM subscriptions`),
  updateReminder: db.prepare(`UPDATE subscriptions SET last_reminder_at=? WHERE tg_id=? AND product=?`),
  updateExpiredNotice: db.prepare(`UPDATE subscriptions SET last_expired_notice_at=? WHERE tg_id=?`),

  createInvoice: db.prepare(`
    INSERT INTO invoices(tg_id, product, months, amount_sol, memo, status, created_at)
    VALUES (?, ?, ?, ?, ?, 'pending', ?)
  `),
  getInvoice: db.prepare(`SELECT * FROM invoices WHERE id=?`),
  markInvoicePaid: db.prepare(`UPDATE invoices SET status='paid', paid_at=?, tx_sig=? WHERE id=?`),
  expireInvoice: db.prepare(`UPDATE invoices SET status='expired' WHERE id=? AND status='pending'`),
  cancelInvoice: db.prepare(`UPDATE invoices SET status='cancelled' WHERE id=? AND status='pending'`),

  hasPayment: db.prepare(`SELECT tx_sig FROM payments WHERE tx_sig=?`),
  addPayment: db.prepare(`INSERT INTO payments(tx_sig, created_at) VALUES(?, ?)`),

  setState: db.prepare(`
    INSERT INTO user_state(tg_id, state, invoice_id, updated_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(tg_id) DO UPDATE SET state=excluded.state, invoice_id=excluded.invoice_id, updated_at=excluded.updated_at
  `),
  getState: db.prepare(`SELECT * FROM user_state WHERE tg_id=?`),
};

// ===================== HELPERS =====================
function nowTs() { return Math.floor(Date.now() / 1000); }
function secDays(d) { return d * 86400; }
function secMonths(m) { return secDays(DAYS_PER_MONTH * m); }

function isOwner(ctx) { return String(ctx.from?.id || "") === OWNER_ID; }

function ensureUser(tgId) {
  const t = nowTs();
  S.upsertUser.run(String(tgId), t, t);
}

function groupId() {
  const r = S.getSetting.get("group_id");
  return r ? r.v : null;
}

function productValid(p) {
  return Object.prototype.hasOwnProperty.call(PRODUCTS, p);
}

function bundleActive(tgId) {
  const s = S.getSub.get(String(tgId), "bundle");
  return !!s && s.expires_at > nowTs();
}

function hasAccess(tgId, product) {
  if (bundleActive(tgId)) return true;
  const s = S.getSub.get(String(tgId), product);
  return !!s && s.expires_at > nowTs();
}

function hasAnyActiveSub(tgId) {
  const subs = S.getSubs.all(String(tgId));
  const t = nowTs();
  return subs.some(s => s.expires_at > t);
}

function daysLeft(expiresAt) {
  return Math.max(0, Math.ceil((expiresAt - nowTs()) / 86400));
}

function memoFor(tgId, product) {
  const rnd = Math.floor(1000 + Math.random() * 9000);
  return `ACC-${tgId}-${product}-${nowTs()}-${rnd}`;
}

function calcAmount(product, months, setupAlreadyPaid) {
  const p = PRODUCTS[product];
  let amount = (setupAlreadyPaid ? 0 : p.setup) + (p.monthly * months);

  if (
    PAID_ACCESS_SPECIAL.enabled &&
    product === "paid_access" &&
    months === PAID_ACCESS_SPECIAL.months &&
    (setupAlreadyPaid || !PAID_ACCESS_SPECIAL.renewal_only)
  ) {
    amount = setupAlreadyPaid ? PAID_ACCESS_SPECIAL.pay_sol : (p.setup + PAID_ACCESS_SPECIAL.pay_sol);
  }

  return Number(amount.toFixed(6));
}

function invoiceExpired(inv) {
  const ageSec = nowTs() - inv.created_at;
  return ageSec > (INVOICE_EXPIRE_MINUTES * 60);
}

// PREPAY: extend from current expiry if still active, else from now
function applySubscription(tgId, product, months) {
  const t = nowTs();
  const ex = S.getSub.get(String(tgId), product);
  const base = ex ? Math.max(ex.expires_at, t) : t;
  const newExpiry = base + secMonths(months);
  // once paid => setup_paid becomes 1
  S.upsertSub.run(String(tgId), product, 1, newExpiry);
  return newExpiry;
}

// Invite (1 use / 1 hour)
async function sendInvite(tgId) {
  const g = groupId();
  if (!g) return false;

  try {
    const invite = await bot.telegram.createChatInviteLink(g, {
      member_limit: 1,
      expire_date: nowTs() + 3600,
    });
    await bot.telegram.sendMessage(
      tgId,
      `✅ Access granted.\nHere is your one-time group invite (valid for 1 hour):\n${invite.invite_link}`
    );
    return true;
  } catch (e) {
    return false;
  }
}

async function kickIfNoActive(tgId) {
  const g = groupId();
  if (!g) return false;
  if (hasAnyActiveSub(tgId)) return false;

  try {
    await bot.telegram.banChatMember(g, tgId);
    await bot.telegram.unbanChatMember(g, tgId);
    return true;
  } catch (e) {
    return false;
  }
}

// ===================== SOLANA VERIFY (memo + treasury + amount) =====================
async function verifySolanaTx(txSig, expectedAmountSol, expectedMemo) {
  const tx = await solana.getParsedTransaction(txSig, { maxSupportedTransactionVersion: 0 });
  if (!tx) return { ok: false, reason: "Transaction not found or not confirmed yet." };

  const ixs = tx.transaction.message.instructions || [];

  // Memo check (parsed OR logs fallback)
  let memoOk = false;
  for (const ix of ixs) {
    const pid = ix.programId?.toBase58?.() || null;
    if (pid === MEMO_PROGRAM_ID) {
      if (ix.parsed?.type === "memo" && typeof ix.parsed?.info === "string") {
        if (ix.parsed.info === expectedMemo) memoOk = true;
      }
    }
  }
  if (!memoOk && Array.isArray(tx.meta?.logMessages)) {
    const logs = tx.meta.logMessages.join("\n");
    if (logs.includes(expectedMemo)) memoOk = true;
  }
  if (!memoOk) return { ok: false, reason: "Memo/Reference does not match the invoice." };

  // Amount to treasury check
  const expectedLamports = Math.floor(expectedAmountSol * LAMPORTS_PER_SOL);
  let receivedLamports = 0;

  for (const ix of ixs) {
    if (ix.program !== "system") continue;
    if (!ix.parsed || ix.parsed.type !== "transfer") continue;
    const info = ix.parsed.info;
    if (!info) continue;

    if (String(info.destination) === TREASURY_PUBKEY.toBase58()) {
      receivedLamports += Number(info.lamports || 0);
    }
  }

  if (receivedLamports < expectedLamports) {
    return { ok: false, reason: `Insufficient payment received (${(receivedLamports / LAMPORTS_PER_SOL).toFixed(4)} SOL).` };
  }

  return { ok: true };
}

// ===================== UI (Inline Keyboards) =====================
function kbHome() {
  return Markup.inlineKeyboard([
    [Markup.button.callback("🛒 Buy / Renew", "HOME_BUY")],
    [Markup.button.callback("📦 My Status", "HOME_STATUS")],
    [Markup.button.callback("💰 Pricing", "HOME_PRICING")],
    [Markup.button.callback("🆘 Support", "HOME_SUPPORT")],
  ]);
}

function kbBuyProducts() {
  return Markup.inlineKeyboard([
    [Markup.button.callback(`${PRODUCTS.paid_access.icon} ${PRODUCTS.paid_access.name}`, "BUY_paid_access")],
    [Markup.button.callback(`${PRODUCTS.security.icon} ${PRODUCTS.security.name}`, "BUY_security")],
    [Markup.button.callback(`${PRODUCTS.alerts.icon} ${PRODUCTS.alerts.name}`, "BUY_alerts")],
    [Markup.button.callback(`${PRODUCTS.bundle.icon} ${PRODUCTS.bundle.name}`, "BUY_bundle")],
    [Markup.button.callback("⬅️ Back", "HOME")],
  ]);
}

function kbDuration(productKey) {
  const p = PRODUCTS[productKey];
  // Keep it simple + high-conversion options
  return Markup.inlineKeyboard([
    [Markup.button.callback("1 month", `DUR_${productKey}_1`), Markup.button.callback("3 months", `DUR_${productKey}_3`)],
    [Markup.button.callback("5 months", `DUR_${productKey}_5`), Markup.button.callback("12 months", `DUR_${productKey}_12`)],
    [Markup.button.callback("⬅️ Back", "HOME_BUY")],
  ]);
}

function kbInvoice(invoiceId) {
  return Markup.inlineKeyboard([
    [Markup.button.callback("✅ I paid (enter TX)", `PAID_${invoiceId}`)],
    [Markup.button.callback("❌ Cancel invoice", `CANCEL_${invoiceId}`)],
    [Markup.button.callback("⬅️ Back to menu", "HOME")],
  ]);
}

// ===================== TEXT BUILDERS =====================
function textWelcome(meUsername) {
  return (
    `✅ Welcome to Accessra.\n\n` +
    `This bot manages your subscription automatically.\n` +
    `• 30 days = 1 month\n` +
    `• Prepay extends your remaining time (renew early = more days)\n` +
    `• Reminder: ${REMINDER_DAYS_BEFORE} days before expiry\n\n` +
    `Use the buttons below to continue.`
  );
}

function textPricing() {
  let t = `💰 Pricing\n\n`;
  for (const k of Object.keys(PRODUCTS)) {
    const p = PRODUCTS[k];
    t += `${p.icon} ${p.name} (${k})\n`;
    t += `• Setup (one-time): ${p.setup} SOL\n`;
    t += `• Monthly (30 days): ${p.monthly} SOL\n\n`;
  }
  if (PAID_ACCESS_SPECIAL.enabled) {
    t += `🎁 Special\n`;
    t += `• Paid Access: ${PAID_ACCESS_SPECIAL.pay_sol} SOL = ${PAID_ACCESS_SPECIAL.months} months (renewal)\n\n`;
  }
  t += `🔔 Reminder: ${REMINDER_DAYS_BEFORE} days before expiry\n`;
  t += `👢 Auto-kick: after expiry + ${KICK_GRACE_HOURS_AFTER_EXPIRY} hours grace\n`;
  return t;
}

function textSupport() {
  return (
    `🆘 Support\n\n` +
    `If something goes wrong:\n` +
    `1) Check "My Status"\n` +
    `2) Create a new invoice (Buy / Renew)\n` +
    `3) Pay with the exact Memo/Reference\n` +
    `4) Press "I paid" and paste your TX signature\n\n` +
    `Tip: Make sure your payment includes the memo — otherwise it cannot be confirmed automatically.`
  );
}

function formatStatus(tgId) {
  const subs = S.getSubs.all(String(tgId));
  const active = hasAnyActiveSub(tgId);
  const bActive = bundleActive(tgId);

  if (!subs.length) {
    return `📦 My Status\n\nYou have no active subscriptions.\n\nTap "Buy / Renew" to get started.`;
  }

  let t = `📦 My Status\n\n`;
  for (const s of subs) {
    const p = PRODUCTS[s.product];
    const icon = p?.icon || "•";
    const name = p?.name || s.product;
    t += `${icon} ${name}: ${daysLeft(s.expires_at)} days left\n`;
  }
  t += `\nBundle active: ${bActive ? "✅" : "❌"}\n`;
  t += `Access active: ${active ? "✅" : "❌"}\n\n`;
  t += `Renew early to extend your remaining time (prepay).`;
  return t;
}

// ===================== COMMANDS =====================
bot.start(async (ctx) => {
  ensureUser(ctx.from.id);
  if (!rateLimitOk(String(ctx.from.id))) return;

  const me = await bot.telegram.getMe();
  await ctx.reply(textWelcome(me.username), kbHome());
});

// Owner: link group
bot.command("setgroup", async (ctx) => {
  ensureUser(ctx.from.id);
  if (!isOwner(ctx)) return;
  if (!rateLimitOk(String(ctx.from.id))) return;

  if (ctx.chat.type !== "group" && ctx.chat.type !== "supergroup") {
    return ctx.reply("Run /setgroup inside your group (not in private chat).");
  }

  S.setSetting.run("group_id", String(ctx.chat.id));
  return ctx.reply(`✅ Group linked successfully.\nChat ID saved: ${ctx.chat.id}`);
});

// Quick ping
bot.hears(/^ping$/i, (ctx) => ctx.reply("pong ✅"));

// Fallback help
bot.command("help", async (ctx) => {
  ensureUser(ctx.from.id);
  if (!rateLimitOk(String(ctx.from.id))) return;

  await ctx.reply(
    `Commands:\n` +
    `/start - open menu\n` +
    `/setgroup - (owner only) run inside group\n\n` +
    `Tip: Use the buttons for a smooth purchase flow.`
  );
});

// ===================== CALLBACK HANDLERS =====================
bot.action("HOME", async (ctx) => {
  ensureUser(ctx.from.id);
  if (!rateLimitOk(String(ctx.from.id))) return ctx.answerCbQuery("Slow down.");
  await ctx.answerCbQuery();
  await ctx.editMessageText("🏠 Main Menu", kbHome());
});

bot.action("HOME_BUY", async (ctx) => {
  ensureUser(ctx.from.id);
  if (!rateLimitOk(String(ctx.from.id))) return ctx.answerCbQuery("Slow down.");
  await ctx.answerCbQuery();
  await ctx.editMessageText("🛒 Choose a product:", kbBuyProducts());
});

bot.action("HOME_STATUS", async (ctx) => {
  ensureUser(ctx.from.id);
  if (!rateLimitOk(String(ctx.from.id))) return ctx.answerCbQuery("Slow down.");
  await ctx.answerCbQuery();

  const text = formatStatus(ctx.from.id);
  await ctx.editMessageText(text, kbHome());

  // If active, try sending invite automatically (in DM)
  if (hasAnyActiveSub(ctx.from.id)) {
    await sendInvite(ctx.from.id);
  }
});

bot.action("HOME_PRICING", async (ctx) => {
  ensureUser(ctx.from.id);
  if (!rateLimitOk(String(ctx.from.id))) return ctx.answerCbQuery("Slow down.");
  await ctx.answerCbQuery();
  await ctx.editMessageText(textPricing(), kbHome());
});

bot.action("HOME_SUPPORT", async (ctx) => {
  ensureUser(ctx.from.id);
  if (!rateLimitOk(String(ctx.from.id))) return ctx.answerCbQuery("Slow down.");
  await ctx.answerCbQuery();
  await ctx.editMessageText(textSupport(), kbHome());
});

// Select product
bot.on("callback_query", async (ctx, next) => {
  const data = ctx.callbackQuery?.data || "";
  if (!data.startsWith("BUY_")) return next();

  ensureUser(ctx.from.id);
  if (!rateLimitOk(String(ctx.from.id))) return ctx.answerCbQuery("Slow down.");

  await ctx.answerCbQuery();

  const productKey = data.replace("BUY_", "");
  if (!productValid(productKey)) return;

  const p = PRODUCTS[productKey];
  const perks =
    productKey === "bundle"
      ? "Includes Paid Access + Security + Alerts."
      : "Tap a duration to generate your invoice.";

  const txt =
    `${p.icon} ${p.name}\n\n` +
    `${perks}\n\n` +
    `Choose duration:`;

  await ctx.editMessageText(txt, kbDuration(productKey));
});

// Select duration -> create invoice
bot.on("callback_query", async (ctx, next) => {
  const data = ctx.callbackQuery?.data || "";
  if (!data.startsWith("DUR_")) return next();

  ensureUser(ctx.from.id);
  if (!rateLimitOk(String(ctx.from.id))) return ctx.answerCbQuery("Slow down.");

  await ctx.answerCbQuery();

  const [, productKey, monthsStr] = data.split("_"); // DUR product months
  const months = Number(monthsStr);

  if (!productValid(productKey)) return;
  if (!Number.isFinite(months) || months <= 0 || months > MAX_MONTHS_PER_PURCHASE) {
    return ctx.editMessageText("Invalid duration. Please try again.", kbHome());
  }

  const ex = S.getSub.get(String(ctx.from.id), productKey);
  const setupAlreadyPaid = ex ? ex.setup_paid === 1 : false;

  const memo = memoFor(ctx.from.id, productKey);
  const amount = calcAmount(productKey, months, setupAlreadyPaid);
  const createdAt = nowTs();

  const info = S.createInvoice.run(String(ctx.from.id), productKey, months, amount, memo, createdAt);
  const invoiceId = info.lastInsertRowid;

  const p = PRODUCTS[productKey];

  const msg =
    `🧾 Invoice #${invoiceId}\n\n` +
    `Product: ${p.icon} ${p.name}\n` +
    `Duration: ${months} month(s) (${months * DAYS_PER_MONTH} days)\n` +
    `Amount: ${amount} SOL\n\n` +
    `Send SOL to:\n${TREASURY_SOL_ADDRESS}\n\n` +
    `⚠️ Memo/Reference (must be exact):\n${memo}\n\n` +
    `After paying, tap ✅ "I paid" and paste your TX signature.\n\n` +
    `This invoice expires in ${INVOICE_EXPIRE_MINUTES} minutes.`;

  await ctx.editMessageText(msg, kbInvoice(invoiceId));
});

// Cancel invoice
bot.on("callback_query", async (ctx, next) => {
  const data = ctx.callbackQuery?.data || "";
  if (!data.startsWith("CANCEL_")) return next();

  ensureUser(ctx.from.id);
  if (!rateLimitOk(String(ctx.from.id))) return ctx.answerCbQuery("Slow down.");

  await ctx.answerCbQuery();

  const invoiceId = Number(data.replace("CANCEL_", ""));
  if (!Number.isFinite(invoiceId)) return;

  const inv = S.getInvoice.get(invoiceId);
  if (!inv || String(inv.tg_id) !== String(ctx.from.id)) {
    return ctx.editMessageText("Invoice not found.", kbHome());
  }

  S.cancelInvoice.run(invoiceId);
  S.setState.run(String(ctx.from.id), "none", null, nowTs());

  await ctx.editMessageText("✅ Invoice cancelled.", kbHome());
});

// "I paid" -> set state awaiting tx
bot.on("callback_query", async (ctx, next) => {
  const data = ctx.callbackQuery?.data || "";
  if (!data.startsWith("PAID_")) return next();

  ensureUser(ctx.from.id);
  if (!rateLimitOk(String(ctx.from.id))) return ctx.answerCbQuery("Slow down.");

  await ctx.answerCbQuery();

  const invoiceId = Number(data.replace("PAID_", ""));
  if (!Number.isFinite(invoiceId)) return;

  const inv = S.getInvoice.get(invoiceId);
  if (!inv || String(inv.tg_id) !== String(ctx.from.id)) {
    return ctx.editMessageText("Invoice not found.", kbHome());
  }

  if (inv.status !== "pending") {
    return ctx.editMessageText(`Invoice is already ${inv.status}.`, kbHome());
  }

  if (invoiceExpired(inv)) {
    S.expireInvoice.run(invoiceId);
    return ctx.editMessageText("⏳ This invoice has expired. Please create a new one.", kbHome());
  }

  S.setState.run(String(ctx.from.id), "awaiting_tx", invoiceId, nowTs());

  await ctx.reply(
    `✅ Great. Now paste your Solana TX signature here.\n\n` +
    `Tip: It looks like a long string (base58).\n` +
    `If you prefer, you can also paste it with the command:\n` +
    `/confirm ${invoiceId} <tx>`
  );
});

// Optional /confirm (still supported)
bot.command("confirm", async (ctx) => {
  ensureUser(ctx.from.id);
  if (!rateLimitOk(String(ctx.from.id))) return;

  const parts = ctx.message.text.trim().split(/\s+/);
  if (parts.length < 3) {
    return ctx.reply("Usage:\n/confirm <invoiceId> <txSignature>");
  }

  const invoiceId = Number(parts[1]);
  const txSig = parts[2];
  await handleConfirm(ctx, invoiceId, txSig);
});

// If awaiting TX, any text that looks like a signature will be treated as TX
bot.on("text", async (ctx) => {
  ensureUser(ctx.from.id);
  if (!rateLimitOk(String(ctx.from.id))) return;

  const st = S.getState.get(String(ctx.from.id));
  if (!st || st.state !== "awaiting_tx" || !st.invoice_id) return;

  const txSig = (ctx.message.text || "").trim();
  // Very light validation: length & base58-like chars
  if (txSig.length < 40 || txSig.length > 120 || !/^[1-9A-HJ-NP-Za-km-z]+$/.test(txSig)) {
    return ctx.reply("That does not look like a valid Solana TX signature. Please paste the TX signature again.");
  }

  await handleConfirm(ctx, Number(st.invoice_id), txSig);
});

async function handleConfirm(ctx, invoiceId, txSig) {
  if (!Number.isFinite(invoiceId)) return ctx.reply("Invalid invoice id.");

  const inv = S.getInvoice.get(invoiceId);
  if (!inv) return ctx.reply("Invoice not found.");
  if (String(inv.tg_id) !== String(ctx.from.id)) return ctx.reply("That invoice is not yours.");
  if (inv.status !== "pending") return ctx.reply(`Invoice is already ${inv.status}.`);

  if (invoiceExpired(inv)) {
    S.expireInvoice.run(invoiceId);
    S.setState.run(String(ctx.from.id), "none", null, nowTs());
    return ctx.reply("⏳ This invoice has expired. Please create a new one from the menu.");
  }

  if (S.hasPayment.get(txSig)) return ctx.reply("This transaction signature has already been used.");

  await ctx.reply("🔎 Verifying payment on-chain (treasury + amount + memo)...");

  try {
    const v = await verifySolanaTx(txSig, inv.amount_sol, inv.memo);
    if (!v.ok) return ctx.reply(`❌ Verification failed: ${v.reason}`);

    // mark payment
    S.addPayment.run(txSig, nowTs());
    S.markInvoicePaid.run(nowTs(), txSig, invoiceId);
    S.setState.run(String(ctx.from.id), "none", null, nowTs());

    // activate subscription
    const newExpiry = applySubscription(ctx.from.id, inv.product, inv.months);
    const p = PRODUCTS[inv.product];

    await ctx.reply(
      `✅ Payment confirmed!\n\n` +
      `Activated: ${p.icon} ${p.name}\n` +
      `Time left: ${daysLeft(newExpiry)} days\n\n` +
      `You will be reminded ${REMINDER_DAYS_BEFORE} days before expiry.\n` +
      `Renew early to extend your remaining time (prepay).`
    );

    // Send invite if group linked
    if (hasAnyActiveSub(ctx.from.id)) {
      await sendInvite(ctx.from.id);
    }
  } catch (e) {
    console.error("confirm error:", e);
    return ctx.reply("❌ Verification error. Try again in a moment.");
  }
}

// ===================== AUTOMATIONS (Reminder + Kick + Invoice expiry cleanup) =====================

// Every 30 minutes: reminders + kick
cron.schedule("*/30 * * * *", async () => {
  const t = nowTs();
  const graceSec = KICK_GRACE_HOURS_AFTER_EXPIRY * 3600;

  const users = S.listUsersWithSubs.all().map(r => r.tg_id);

  for (const tgId of users) {
    const subs = S.getSubs.all(String(tgId));
    if (!subs.length) continue;

    // Reminders per subscription exactly 3 days before expiry
    for (const s of subs) {
      if (s.expires_at <= t) continue;

      const leftDays = Math.ceil((s.expires_at - t) / 86400);
      if (leftDays !== REMINDER_DAYS_BEFORE) continue;

      const last = s.last_reminder_at || 0;
      if (t - last < 20 * 3600) continue; // anti-spam

      try {
        const p = PRODUCTS[s.product];
        await bot.telegram.sendMessage(
          tgId,
          `⏳ Reminder: ${p?.icon || "•"} ${p?.name || s.product} expires in ${REMINDER_DAYS_BEFORE} days.\n` +
          `Renew early to extend your remaining time.\n\n` +
          `Open the bot and tap: Buy / Renew`
        );
        S.updateReminder.run(t, String(tgId), s.product);
      } catch (_) {}
    }

    // If no active subscriptions -> notice + kick after grace
    const anyActive = subs.some(s => s.expires_at > t);
    if (!anyActive) {
      const latestExpiry = Math.max(...subs.map(s => s.expires_at));
      const expiredSince = t - latestExpiry;

      const lastNotice = subs[0].last_expired_notice_at || 0;
      if (t - lastNotice > 24 * 3600) {
        try {
          await bot.telegram.sendMessage(
            tgId,
            `⚠️ Your access has expired.\n` +
            `To stay in the group, please renew your subscription.\n\n` +
            `Open the bot and tap: Buy / Renew`
          );
          S.updateExpiredNotice.run(t, String(tgId));
        } catch (_) {}
      }

      if (expiredSince >= graceSec) {
        await kickIfNoActive(tgId);
      }
    }
  }
});

// Every 10 minutes: auto-expire old invoices (security + clarity)
cron.schedule("*/10 * * * *", async () => {
  try {
    const cutoff = nowTs() - (INVOICE_EXPIRE_MINUTES * 60);
    // Expire pending invoices older than cutoff
    db.prepare(`UPDATE invoices SET status='expired' WHERE status='pending' AND created_at < ?`).run(cutoff);
  } catch (_) {}
});

// ===================== SAFE START =====================
bot.catch((err) => {
  console.error("❌ Bot error:", err);
});

bot.telegram.getMe()
  .then((me) => console.log("✅ Bot Username:", me.username))
  .catch((err) => console.error("❌ getMe error:", err));

(async () => {
  try {
    // Drop pending updates -> avoids startup issues and reduces risk from backlog spam
    await bot.launch({ dropPendingUpdates: true });
    console.log("✅ Bot started (polling active)");
  } catch (err) {
    console.error("❌ bot.launch error:", err);
  }
})();

process.once("SIGINT", () => bot.stop("SIGINT"));
process.once("SIGTERM", () => bot.stop("SIGTERM"));

