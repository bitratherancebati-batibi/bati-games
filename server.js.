
require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "20kb" }));

// Autoriser uniquement le site BATI GAMES
const allowedOrigins = (
  process.env.FRONTEND_ORIGINS ||
  "https://bati-games.onrender.com,https://bitratherancebati-batibi.github.io"
).split(",").map(x => x.trim()).filter(Boolean);

app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Vary", "Origin");
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type"
    );
    res.setHeader(
      "Access-Control-Allow-Methods",
      "GET, POST, OPTIONS"
    );
  }

  if (req.method === "OPTIONS") {
    return res.sendStatus(
      !origin || allowedOrigins.includes(origin) ? 204 : 403
    );
  }

  next();
});

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSLMODE === "require"
    ? { rejectUnauthorized: false }
    : undefined
});

const PRICE = 1000;
const CURRENCY = "XOF";
const COOKIE = "bati_session";
const SESSION_DURATION = 7 * 24 * 60 * 60 * 1000;

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function checkPassword(password, stored) {
  if (!stored || !stored.includes(":")) return false;

  const [salt, oldHash] = stored.split(":");
  const newHash = crypto.scryptSync(password, salt, 64);
  const oldBuffer = Buffer.from(oldHash, "hex");

  return oldBuffer.length === newHash.length &&
    crypto.timingSafeEqual(newHash, oldBuffer);
}

function makeToken(user) {
  const payload = Buffer.from(JSON.stringify({
    id: user.id,
    exp: Date.now() + SESSION_DURATION
  })).toString("base64url");

  const signature = crypto
    .createHmac("sha256", process.env.SESSION_SECRET)
    .update(payload)
    .digest("base64url");

  return `${payload}.${signature}`;
}

function getSession(req) {
  try {
    const cookies = (req.headers.cookie || "").split(";").map(x => x.trim());
    const item = cookies.find(x => x.startsWith(COOKIE + "="));

    if (!item) return null;

    const token = decodeURIComponent(item.substring(COOKIE.length + 1));
    const [payload, signature] = token.split(".");

    if (!payload || !signature) return null;

    const expected = crypto
      .createHmac("sha256", process.env.SESSION_SECRET)
      .update(payload)
      .digest("base64url");

    const a = Buffer.from(signature);
    const b = Buffer.from(expected);

    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return null;
    }

    const data = JSON.parse(
      Buffer.from(payload, "base64url").toString()
    );

    if (!Number.isInteger(data.id) || data.exp < Date.now()) {
      return null;
    }

    return data;
  } catch {
    return null;
  }
}

function setSessionCookie(res, user) {
  res.cookie(COOKIE, makeToken(user), {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    maxAge: SESSION_DURATION,
    path: "/"
  });
}

async function requireUser(req, res, next) {
  try {
    const session = getSession(req);

    if (!session) {
      return res.status(401).json({
        error: "Connexion nécessaire."
      });
    }

    const result = await pool.query(
      `SELECT id, email, name, role, premium_until
       FROM users WHERE id=$1`,
      [session.id]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        error: "Compte introuvable."
      });
    }

    req.user = result.rows[0];
    next();
  } catch (error) {
    next(error);
  }
}

// Création des tables et du compte administrateur
async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'member',
      premium_until TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS payments (
      id SERIAL PRIMARY KEY,
      tx_ref TEXT UNIQUE NOT NULL,
      user_id INTEGER REFERENCES users(id),
      amount INTEGER NOT NULL,
      currency TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      transaction_id TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE UNIQUE INDEX IF NOT EXISTS
      payments_transaction_id_unique
      ON payments(transaction_id)
      WHERE transaction_id IS NOT NULL;
  `);

  const email = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
  const password = process.env.ADMIN_PASSWORD || "";

  if (!email || !email.includes("@") || password.length < 12) {
    throw new Error("Configuration administrateur incorrecte.");
  }

  await pool.query(`
    INSERT INTO users (email, name, password_hash, role)
    VALUES ($1, 'Administrateur BATI GAMES', $2, 'admin')
    ON CONFLICT (email)
    DO UPDATE SET password_hash=$2, role='admin'
  `, [email, hashPassword(password)]);
}

// Inscription
app.post("/api/register", async (req, res, next) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const name = String(req.body.name || "").trim();
    const password = String(req.body.password || "");

    if (
      !email.includes("@") ||
      email.length > 254 ||
      !name ||
      name.length > 100 ||
      password.length < 12 ||
      password.length > 200
    ) {
      return res.status(400).json({
        error: "Vérifie ton e-mail, ton nom et ton mot de passe (12 caractères minimum)."
      });
    }

    const result = await pool.query(
      `INSERT INTO users (email, name, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, email, name, role`,
      [email, name, hashPassword(password)]
    );

    setSessionCookie(res, result.rows[0]);

    res.json({
      message: "Inscription réussie.",
      user: {
        email: result.rows[0].email,
        name: result.rows[0].name
      }
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        error: "Cette adresse e-mail est déjà utilisée."
      });
    }
    next(error);
  }
});

// Connexion
app.post("/api/login", async (req, res, next) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    const result = await pool.query(
      "SELECT * FROM users WHERE email=$1",
      [email]
    );

    const user = result.rows[0];

    if (!user || !checkPassword(password, user.password_hash)) {
      return res.status(401).json({
        error: "E-mail ou mot de passe incorrect."
      });
    }

    setSessionCookie(res, user);

    res.json({
      message: "Connexion réussie."
    });
  } catch (error) {
    next(error);
  }
});

// Déconnexion
app.post("/api/logout", (req, res) => {
  res.clearCookie(COOKIE, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    path: "/"
  });

  res.json({ message: "Déconnexion réussie." });
});

// Informations du compte
app.get("/api/me", requireUser, (req, res) => {
  const admin = req.user.role === "admin";

  const active = admin || (
    req.user.premium_until &&
    new Date(req.user.premium_until) > new Date()
  );

  res.json({
    email: req.user.email,
    name: req.user.name,
    admin,
    premium: Boolean(active),
    premiumUntil: admin ? null : req.user.premium_until
  });
});

// Préparer un paiement Flutterwave
app.post("/api/checkout", requireUser, async (req, res) => {
  let txRef;

  try {
    if (req.user.role === "admin") {
      return res.status(400).json({
        error: "Ton accès administrateur est gratuit."
      });
    }

    if (!process.env.FLW_SECRET_KEY || !process.env.FRONTEND_URL) {
      return res.status(503).json({
        error: "Le paiement n'est pas encore configuré."
      });
    }

    txRef = "BATI-" + crypto.randomUUID();

    await pool.query(
      `INSERT INTO payments (tx_ref, user_id, amount, currency)
       VALUES ($1, $2, $3, $4)`,
      [txRef, req.user.id, PRICE, CURRENCY]
    );

    const frontend = process.env.FRONTEND_URL.replace(/\/$/, "");

    const response = await fetch(
      "https://api.flutterwave.com/v3/payments",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${process.env.FLW_SECRET_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          tx_ref: txRef,
          amount: PRICE,
          currency: CURRENCY,
          redirect_url: `${frontend}/?payment=return&tx_ref=${encodeURIComponent(txRef)}`,
          customer: {
            email: req.user.email,
            name: req.user.name
          },
          customizations: {
            title: "BATI GAMES Premium",
            description: "Abonnement Premium de 30 jours"
          }
        })
      }
    );

    const data = await response.json();

    if (!response.ok || !data.data?.link) {
      await pool.query(
        "UPDATE payments SET status='failed' WHERE tx_ref=$1",
        [txRef]
      );

      return res.status(502).json({
        error: "Flutterwave n'a pas pu préparer le paiement."
      });
    }

    res.json({ link: data.data.link });
  } catch (error) {
    console.error("Checkout error:", error.message);

    if (txRef) {
      await pool.query(
        "UPDATE payments SET status='failed' WHERE tx_ref=$1",
        [txRef]
      ).catch(() => {});
    }

    res.status(500).json({
      error: "Impossible de préparer le paiement."
    });
  }
});

// Vérifier une transaction auprès de Flutterwave
async function verifyAndActivate(transactionId) {
  const response = await fetch(
    `https://api.flutterwave.com/v3/transactions/${encodeURIComponent(transactionId)}/verify`,
    {
      headers: {
        Authorization: `Bearer ${process.env.FLW_SECRET_KEY}`
      }
    }
  );

  if (response.status >= 500) {
    throw new Error("Flutterwave est temporairement indisponible.");
  }

  const result = await response.json();
  const payment = result.data;

  if (!response.ok || result.status !== "success" || !payment) {
    return false;
  }

  if (
    payment.status !== "successful" ||
    payment.currency !== CURRENCY
  ) {
    return false;
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const found = await client.query(
      "SELECT * FROM payments WHERE tx_ref=$1 FOR UPDATE",
      [payment.tx_ref]
    );

    if (!found.rows.length) {
      await client.query("ROLLBACK");
      return false;
    }

    const order = found.rows[0];

    if (order.status === "paid") {
      await client.query("COMMIT");
      return true;
    }

    if (
      order.amount !== PRICE ||
      order.currency !== CURRENCY ||
      Number(payment.amount) < order.amount
    ) {
      await client.query("ROLLBACK");
      return false;
    }

    await client.query(
      `UPDATE payments
       SET status='paid', transaction_id=$1
       WHERE id=$2`,
      [String(transactionId), order.id]
    );

    await client.query(
      `UPDATE users
       SET premium_until =
         GREATEST(COALESCE(premium_until, NOW()), NOW())
         + INTERVAL '30 days'
       WHERE id=$1 AND role <> 'admin'`,
      [order.user_id]
    );

    await client.query("COMMIT");
    return true;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

// Notification Flutterwave (API v3)
app.post("/api/flutterwave-webhook", async (req, res) => {
  const supplied = req.get("verif-hash") || "";
  const expected = process.env.FLW_SECRET_HASH || "";

  if (!expected || !supplied) {
    return res.sendStatus(401);
  }

  const a = Buffer.from(supplied);
  const b = Buffer.from(expected);

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.sendStatus(401);
  }

  try {
    const id = req.body?.data?.id;

    if (id) {
      await verifyAndActivate(id);
    }

    res.sendStatus(200);
  } catch (error) {
    console.error("Webhook error:", error.message);
    res.sendStatus(500);
  }
});

// Consulter l'état d'un paiement
app.get("/api/payment-status", requireUser, async (req, res, next) => {
  try {
    const txRef = String(req.query.tx_ref || "");

    const result = await pool.query(
      `SELECT status FROM payments
       WHERE tx_ref=$1 AND user_id=$2`,
      [txRef, req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: "Paiement introuvable."
      });
    }

    res.json({ status: result.rows[0].status });
  } catch (error) {
    next(error);
  }
});

// Vérification du serveur
app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok", database: "connected" });
  } catch {
    res.status(503).json({
      status: "error",
      database: "unavailable"
    });
  }
});

// Gestion des erreurs
app.use((error, req, res, next) => {
  console.error("Server error:", error.message);

  if (res.headersSent) return next(error);

  res.status(500).json({
    error: "Une erreur interne est survenue."
  });
});

const PORT = process.env.PORT || 10000;

async function startServer() {
  if (
    !process.env.DATABASE_URL ||
    !process.env.SESSION_SECRET ||
    process.env.SESSION_SECRET.length < 32 ||
    !process.env.FLW_SECRET_KEY
  ) {
    throw new Error("Une variable d'environnement obligatoire est manquante.");
  }

  await initDatabase();

  app.listen(PORT, () => {
    console.log("BATI GAMES API démarrée.");
  });
}

startServer().catch(error => {
  console.error("Démarrage impossible:", error.message);
  process.exit(1);
});
