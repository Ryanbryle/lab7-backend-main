const fs = require('fs');
const path = require('path');

// ─── JSON File Store (Local Dev) ─────────────────────────────────────────────
const DB_DIR = path.join(__dirname, '..', 'data');
const DB_PATH = path.join(DB_DIR, 'db.json');
const DEFAULT_DB = { accounts: [], refreshTokens: [] };
let _db = null;

function initJsonDb() {
    if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
    if (!fs.existsSync(DB_PATH)) fs.writeFileSync(DB_PATH, JSON.stringify(DEFAULT_DB, null, 2));
    _db = JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
    console.log(`✅ JSON database ready at: ${DB_PATH}`);
}

function saveJson() {
    fs.writeFileSync(DB_PATH, JSON.stringify(_db, null, 2));
}

function getJsonDb() {
    if (!_db) throw new Error('Database not initialized');
    return { accounts: _db.accounts, refreshTokens: _db.refreshTokens, save: saveJson };
}

// ─── PostgreSQL (Production on Render) ───────────────────────────────────────
let pgPool = null;

async function initPgDb() {
    const { Pool } = require('pg');
    pgPool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

    await pgPool.query(`
        CREATE TABLE IF NOT EXISTS accounts (
            id SERIAL PRIMARY KEY,
            title VARCHAR(10),
            "firstName" VARCHAR(100) NOT NULL,
            "lastName" VARCHAR(100) NOT NULL,
            email VARCHAR(255) NOT NULL UNIQUE,
            "passwordHash" VARCHAR(255) NOT NULL,
            role VARCHAR(10) NOT NULL DEFAULT 'User',
            "verificationToken" VARCHAR(255),
            verified TIMESTAMPTZ,
            "resetToken" VARCHAR(255),
            "resetTokenExpires" TIMESTAMPTZ,
            "passwordReset" TIMESTAMPTZ,
            created TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated TIMESTAMPTZ
        )
    `);
    await pgPool.query(`
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id SERIAL PRIMARY KEY,
            "accountId" INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
            token VARCHAR(255) NOT NULL UNIQUE,
            expires TIMESTAMPTZ NOT NULL,
            created TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "createdByIp" VARCHAR(45),
            revoked TIMESTAMPTZ,
            "revokedByIp" VARCHAR(45),
            "replacedByToken" VARCHAR(255)
        )
    `);
    console.log('✅ PostgreSQL database ready');
}

// ─── Unified DB Interface ─────────────────────────────────────────────────────
const USE_PG = !!process.env.DATABASE_URL;

async function initializeDatabase() {
    if (USE_PG) {
        await initPgDb();
    } else {
        initJsonDb();
    }
}

// Returns a unified adapter regardless of backend
function getDb() {
    if (USE_PG) {
        return {
            isPg: true,
            pool: pgPool,
            // pg methods are async — controllers check isPg and use pool directly
        };
    }
    return getJsonDb();
}

module.exports = { initializeDatabase, getDb, USE_PG };
