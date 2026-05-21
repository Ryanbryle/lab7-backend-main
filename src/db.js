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
let mysqlPool = null;

async function initMysqlDb() {
    const mysql = require('mysql2/promise');
    mysqlPool = mysql.createPool(process.env.DATABASE_URL);

    await mysqlPool.query(`
        CREATE TABLE IF NOT EXISTS accounts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(10),
            firstName VARCHAR(100) NOT NULL,
            lastName VARCHAR(100) NOT NULL,
            email VARCHAR(255) NOT NULL UNIQUE,
            passwordHash VARCHAR(255) NOT NULL,
            role VARCHAR(10) NOT NULL DEFAULT 'User',
            verificationToken VARCHAR(255),
            verified DATETIME,
            resetToken VARCHAR(255),
            resetTokenExpires DATETIME,
            passwordReset DATETIME,
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated DATETIME
        )
    `);
    await mysqlPool.query(`
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id INT AUTO_INCREMENT PRIMARY KEY,
            accountId INT NOT NULL,
            token VARCHAR(255) NOT NULL UNIQUE,
            expires DATETIME NOT NULL,
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            createdByIp VARCHAR(45),
            revoked DATETIME,
            revokedByIp VARCHAR(45),
            replacedByToken VARCHAR(255),
            FOREIGN KEY (accountId) REFERENCES accounts(id) ON DELETE CASCADE
        )
    `);
    console.log('✅ MySQL database ready');
}

// ─── Unified DB Interface ─────────────────────────────────────────────────────
const USE_MYSQL = !!process.env.DATABASE_URL;

async function initializeDatabase() {
    if (USE_MYSQL) {
        await initMysqlDb();
        try {
            await mysqlPool.query("UPDATE accounts SET role='Admin' WHERE email='admin@lab7.com'");
            console.log("🚀 Automatically promoted admin@lab7.com to Admin in MySQL!");
        } catch (err) {
            console.error("Failed to automatically promote admin:", err.message);
        }
    } else {
        initJsonDb();
        try {
            const db = getJsonDb();
            const adminAcc = db.accounts.find(x => x.email === 'admin@lab7.com');
            if (adminAcc && adminAcc.role !== 'Admin') {
                adminAcc.role = 'Admin';
                db.save();
                console.log("🚀 Automatically promoted admin@lab7.com to Admin in local JSON!");
            }
        } catch (err) {
            console.error("Failed to automatically promote local admin:", err.message);
        }
    }
}

// Returns a unified adapter regardless of backend
function getDb() {
    if (USE_MYSQL) {
        return {
            isMysql: true,
            pool: mysqlPool,
            // pg methods are async — controllers check isMysql and use pool directly
        };
    }
    return getJsonDb();
}

module.exports = { initializeDatabase, getDb, USE_MYSQL };
