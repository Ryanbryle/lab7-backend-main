const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { getDb } = require('../db');

const JWT_SECRET = process.env.JWT_SECRET || 'lab7-secret';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '15m';
const REFRESH_DAYS = parseInt(process.env.REFRESH_TOKEN_EXPIRES_DAYS || '7');

function generateJwtToken(account) {
    return jwt.sign({ id: account.id, role: account.role }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

// ─── JSON methods ─────────────────────────────────────────────────────────────
function generateRefreshTokenJson(accountId, ipAddress) {
    const db = getDb();
    const token = uuidv4();
    const expires = new Date(Date.now() + REFRESH_DAYS * 24 * 60 * 60 * 1000).toISOString();
    db.refreshTokens.push({ id: Date.now(), accountId, token, expires, created: new Date().toISOString(), createdByIp: ipAddress, revoked: null, revokedByIp: null, replacedByToken: null });
    db.save();
    return token;
}

function getRefreshTokenJson(token) {
    const db = getDb();
    const rt = db.refreshTokens.find(x => x.token === token);
    if (!rt || new Date() > new Date(rt.expires) || rt.revoked) throw new Error('Invalid token');
    return rt;
}

function revokeTokenJson(token, ipAddress, replacedByToken = null) {
    const db = getDb();
    const rt = db.refreshTokens.find(x => x.token === token);
    if (rt) { rt.revoked = new Date().toISOString(); rt.revokedByIp = ipAddress; rt.replacedByToken = replacedByToken; db.save(); }
}

// ─── PostgreSQL methods ───────────────────────────────────────────────────────
async function generateRefreshTokenMysql(accountId, ipAddress) {
    const { pool } = getDb();
    const token = uuidv4();
    const expires = new Date(Date.now() + REFRESH_DAYS * 24 * 60 * 60 * 1000);
    await pool.query(
        `INSERT INTO refresh_tokens (accountId,token,expires,createdByIp) VALUES(?,?,?,?)`,
        [accountId, token, expires, ipAddress]
    );
    return token;
}

async function getRefreshTokenMysql(token) {
    const { pool } = getDb();
    const [r] = await pool.query('SELECT * FROM refresh_tokens WHERE token=?', [token]);
    const rt = r[0];
    if (!rt || new Date() > new Date(rt.expires) || rt.revoked) throw new Error('Invalid token');
    return rt;
}

async function revokeTokenMysql(token, ipAddress, replacedByToken = null) {
    const { pool } = getDb();
    await pool.query(
        `UPDATE refresh_tokens SET revoked=NOW(),revokedByIp=?,replacedByToken=? WHERE token=?`,
        [ipAddress, replacedByToken, token]
    );
}

// ─── Cookie helper ────────────────────────────────────────────────────────────
function setRefreshTokenCookie(res, token) {
    res.cookie('refreshToken', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        maxAge: REFRESH_DAYS * 24 * 60 * 60 * 1000,
        path: '/'
    });
}

function verifyJwt(token) {
    return jwt.verify(token, JWT_SECRET);
}

module.exports = {
    generateJwtToken, verifyJwt, setRefreshTokenCookie,
    generateRefreshTokenJson, getRefreshTokenJson, revokeTokenJson,
    generateRefreshTokenMysql, getRefreshTokenMysql, revokeTokenMysql
};
