const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { getDb, USE_MYSQL } = require('../db');
const {
    generateJwtToken,
    generateRefreshTokenJson,
    generateRefreshTokenMysql,
    getRefreshTokenJson,
    getRefreshTokenMysql,
    revokeTokenJson,
    revokeTokenMysql,
    setRefreshTokenCookie
} = require('../utils/jwt');
const {
    sendVerificationEmail,
    sendAlreadyRegisteredEmail,
    sendPasswordResetEmail
} = require('../utils/email');

function getOrigin(req) {
    return req.get('origin') || `${req.protocol}://${req.get('host')}`;
}

function basicDetails(a) {
    return {
        id: a.id,
        title: a.title,
        firstName: a.firstName,
        lastName: a.lastName,
        email: a.email,
        role: a.role,
        dateCreated: a.created,
        isVerified: !!a.verified
    };
}

// ─── Helper: get/save via correct backend ────────────────────────────────────
async function findAccountByEmail(email) {
    if (USE_MYSQL) {
        const { pool } = getDb();
        const [r] = await pool.query('SELECT * FROM accounts WHERE email=?', [email]);
        return r[0];
    }
    return getDb().accounts.find(x => x.email === email);
}

async function findAccountById(id) {
    if (USE_MYSQL) {
        const { pool } = getDb();
        const [r] = await pool.query('SELECT * FROM accounts WHERE id=?', [id]);
        return r[0];
    }
    return getDb().accounts.find(x => x.id === id);
}

async function countAccounts() {
    if (USE_MYSQL) {
        const { pool } = getDb();
        const [r] = await pool.query('SELECT COUNT(*) as count FROM accounts');
        return parseInt(r[0].count);
    }
    return getDb().accounts.length;
}

// ─── POST /accounts/authenticate ─────────────────────────────────────────────
async function authenticate(req, res) {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password are required' });

    const account = await findAccountByEmail(email);
    if (!account || !bcrypt.compareSync(password, account.passwordHash)) {
        return res.status(400).json({ message: 'Email or password is incorrect' });
    }
    if (!account.verified) {
        return res.status(400).json({ message: 'Please verify your email before logging in' });
    }

    const jwtToken = generateJwtToken(account);
    const refreshToken = USE_MYSQL
        ? await generateRefreshTokenMysql(account.id, req.ip)
        : generateRefreshTokenJson(account.id, req.ip);
    setRefreshTokenCookie(res, refreshToken);
    res.json({ ...basicDetails(account), jwtToken });
}

// ─── POST /accounts/refresh-token ────────────────────────────────────────────
async function refreshToken(req, res) {
    const token = req.cookies.refreshToken;
    if (!token) return res.status(401).json({ message: 'Unauthorized' });
    try {
        const rt = USE_MYSQL ? await getRefreshTokenMysql(token) : getRefreshTokenJson(token);
        const account = await findAccountById(rt.accountId);
        const newToken = USE_MYSQL
            ? await generateRefreshTokenMysql(account.id, req.ip)
            : generateRefreshTokenJson(account.id, req.ip);
        USE_MYSQL ? await revokeTokenMysql(token, req.ip, newToken) : revokeTokenJson(token, req.ip, newToken);
        setRefreshTokenCookie(res, newToken);
        res.json({ ...basicDetails(account), jwtToken: generateJwtToken(account) });
    } catch { return res.status(401).json({ message: 'Unauthorized' }); }
}

// ─── POST /accounts/revoke-token ─────────────────────────────────────────────
async function revokeTokenHandler(req, res) {
    const token = req.body.token || req.cookies.refreshToken;
    if (!token) return res.status(400).json({ message: 'Token is required' });
    USE_MYSQL ? await revokeTokenMysql(token, req.ip) : revokeTokenJson(token, req.ip);
    res.json({ message: 'Token revoked' });
}

// ─── POST /accounts/register ─────────────────────────────────────────────────
async function register(req, res) {
    const { title, firstName, lastName, email, password, confirmPassword } = req.body;
    if (!firstName || !lastName || !email || !password) return res.status(400).json({ message: 'All fields are required' });
    if (password !== confirmPassword) return res.status(400).json({ message: 'Passwords do not match' });

    const existing = await findAccountByEmail(email);
    if (existing) {
        sendAlreadyRegisteredEmail(email, getOrigin(req)).catch(console.error);
        return res.json({ message: 'Registration successful — please check your email' });
    }

    const count = await countAccounts();
    const role = count === 0 ? 'Admin' : 'User';
    const passwordHash = bcrypt.hashSync(password, 10);
    const verificationToken = uuidv4();

    if (USE_MYSQL) {
        const { pool } = getDb();
        await pool.query(
            `INSERT INTO accounts (title,firstName,lastName,email,passwordHash,role,verificationToken,verified) VALUES(?,?,?,?,?,?,?,NOW())`,
            [title||null, firstName, lastName, email, passwordHash, role, verificationToken]
        );
    } else {
        const db = getDb();
        const id = db.accounts.length > 0 ? Math.max(...db.accounts.map(x=>x.id))+1 : 1;
        db.accounts.push({ id, title:title||null, firstName, lastName, email, passwordHash, role, verificationToken, verified:new Date().toISOString(), resetToken:null, resetTokenExpires:null, created:new Date().toISOString(), updated:null });
        db.save();
    }

    sendVerificationEmail(email, getOrigin(req), verificationToken).catch(console.error);

    // Include verification link in response (works even if email is blocked on hosting)
    const verifyUrl = `${getOrigin(req)}/account/verify-email?token=${verificationToken}`;
    res.json({
        message: 'Registration successful — please check your email to verify your account',
        verificationLink: verifyUrl  // Shown in response for demo/testing purposes
    });
}

// ─── POST /accounts/verify-email ─────────────────────────────────────────────
async function verifyEmail(req, res) {
    const { token } = req.body;
    if (!token) return res.status(400).json({ message: 'Token is required' });

    if (USE_MYSQL) {
        const { pool } = getDb();
        const [r] = await pool.query('SELECT * FROM accounts WHERE verificationToken=?', [token]);
        if (!r[0]) return res.status(400).json({ message: 'Verification failed' });
        await pool.query('UPDATE accounts SET verified=NOW(),verificationToken=NULL WHERE id=?', [r[0].id]);
    } else {
        const db = getDb();
        const account = db.accounts.find(x => x.verificationToken === token);
        if (!account) return res.status(400).json({ message: 'Verification failed' });
        account.verified = new Date().toISOString();
        account.verificationToken = null;
        db.save();
    }
    res.json({ message: 'Verification successful, you can now log in' });
}

// ─── POST /accounts/forgot-password ──────────────────────────────────────────
async function forgotPassword(req, res) {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email is required' });

    const account = await findAccountByEmail(email);
    if (!account) return res.json({ message: 'If that email exists, a reset link has been sent' });

    const resetToken = uuidv4();
    const resetExpires = new Date(Date.now() + 24*60*60*1000);

    if (USE_MYSQL) {
        const { pool } = getDb();
        await pool.query('UPDATE accounts SET resetToken=?,resetTokenExpires=? WHERE id=?', [resetToken, resetExpires, account.id]);
    } else {
        const db = getDb();
        const acc = db.accounts.find(x => x.email === email);
        acc.resetToken = resetToken;
        acc.resetTokenExpires = resetExpires.toISOString();
        db.save();
    }

    sendPasswordResetEmail(email, getOrigin(req), resetToken).catch(console.error);
    res.json({ message: 'If that email exists, a reset link has been sent' });
}

// ─── POST /accounts/validate-reset-token ─────────────────────────────────────
async function validateResetToken(req, res) {
    const { token } = req.body;
    if (!token) return res.status(400).json({ message: 'Token is required' });

    let found;
    if (USE_MYSQL) {
        const { pool } = getDb();
        const [r] = await pool.query('SELECT id FROM accounts WHERE resetToken=? AND resetTokenExpires>NOW()', [token]);
        found = r[0];
    } else {
        found = getDb().accounts.find(x => x.resetToken===token && x.resetTokenExpires && new Date()<new Date(x.resetTokenExpires));
    }
    if (!found) return res.status(400).json({ message: 'Invalid token' });
    res.json({ message: 'Token is valid' });
}

// ─── POST /accounts/reset-password ───────────────────────────────────────────
async function resetPassword(req, res) {
    const { token, password, confirmPassword } = req.body;
    if (!token || !password) return res.status(400).json({ message: 'Token and password are required' });
    if (password !== confirmPassword) return res.status(400).json({ message: 'Passwords do not match' });

    const hash = bcrypt.hashSync(password, 10);
    if (USE_MYSQL) {
        const { pool } = getDb();
        const [r] = await pool.query('SELECT id FROM accounts WHERE resetToken=? AND resetTokenExpires>NOW()', [token]);
        if (!r[0]) return res.status(400).json({ message: 'Invalid token' });
        await pool.query(`UPDATE accounts SET passwordHash=?,verified=COALESCE(verified,NOW()),resetToken=NULL,resetTokenExpires=NULL,passwordReset=NOW() WHERE id=?`, [hash, r[0].id]);
    } else {
        const db = getDb();
        const acc = db.accounts.find(x => x.resetToken===token && x.resetTokenExpires && new Date()<new Date(x.resetTokenExpires));
        if (!acc) return res.status(400).json({ message: 'Invalid token' });
        acc.passwordHash = hash;
        acc.verified = acc.verified || new Date().toISOString();
        acc.resetToken = null; acc.resetTokenExpires = null;
        db.save();
    }
    res.json({ message: 'Password reset successful, you can now log in' });
}

// ─── GET /accounts ────────────────────────────────────────────────────────────
async function getAll(req, res) {
    if (USE_MYSQL) {
        const { pool } = getDb();
        const [r] = await pool.query('SELECT * FROM accounts');
        return res.json(r.map(basicDetails));
    }
    res.json(getDb().accounts.map(basicDetails));
}

// ─── GET /accounts/:id ────────────────────────────────────────────────────────
async function getById(req, res) {
    const id = parseInt(req.params.id);
    const account = await findAccountById(id);
    if (!account) return res.status(404).json({ message: 'Account not found' });
    if (req.user.role !== 'Admin' && req.user.id !== id) return res.status(401).json({ message: 'Unauthorized' });
    res.json(basicDetails(account));
}

// ─── POST /accounts ───────────────────────────────────────────────────────────
async function create(req, res) {
    const { title, firstName, lastName, email, password, confirmPassword, role } = req.body;
    if (!firstName || !lastName || !email || !password || !role) return res.status(400).json({ message: 'All fields are required' });
    if (password !== confirmPassword) return res.status(400).json({ message: 'Passwords do not match' });

    const existing = await findAccountByEmail(email);
    if (existing) return res.status(400).json({ message: `Email ${email} is already registered` });

    const hash = bcrypt.hashSync(password, 10);
    if (USE_MYSQL) {
        const { pool } = getDb();
        await pool.query(`INSERT INTO accounts (title,firstName,lastName,email,passwordHash,role,verified) VALUES(?,?,?,?,?,?,NOW())`, [title||null,firstName,lastName,email,hash,role]);
    } else {
        const db = getDb();
        const id = db.accounts.length > 0 ? Math.max(...db.accounts.map(x=>x.id))+1 : 1;
        db.accounts.push({ id, title:title||null, firstName, lastName, email, passwordHash:hash, role, verified:new Date().toISOString(), verificationToken:null, resetToken:null, resetTokenExpires:null, created:new Date().toISOString(), updated:null });
        db.save();
    }
    res.json({ message: 'Account created successfully' });
}

// ─── PUT /accounts/:id ────────────────────────────────────────────────────────
async function update(req, res) {
    const id = parseInt(req.params.id);
    const account = await findAccountById(id);
    if (!account) return res.status(404).json({ message: 'Account not found' });
    if (req.user.role !== 'Admin' && req.user.id !== id) return res.status(401).json({ message: 'Unauthorized' });

    const { title, firstName, lastName, email, password, confirmPassword, role } = req.body;
    if (password && password !== confirmPassword) return res.status(400).json({ message: 'Passwords do not match' });

    if (USE_MYSQL) {
        const { pool } = getDb();
        const sets = ['updated=NOW()'];
        const vals = [];
        let i = 1;
        if (title!==undefined){sets.push(`title=$${i++}`);vals.push(title);}
        if (firstName){sets.push(`firstName=$${i++}`);vals.push(firstName);}
        if (lastName){sets.push(`lastName=$${i++}`);vals.push(lastName);}
        if (email){sets.push(`email=$${i++}`);vals.push(email);}
        if (password){sets.push(`passwordHash=$${i++}`);vals.push(bcrypt.hashSync(password,10));}
        if (role && req.user.role==='Admin'){sets.push(`role=$${i++}`);vals.push(role);}
        vals.push(id);
        await pool.query(`UPDATE accounts SET ${sets.join(',')} WHERE id=$${i}`, vals);
        const [r] = await pool.query('SELECT * FROM accounts WHERE id=?',[id]);
        return res.json(basicDetails(r[0]));
    } else {
        const db = getDb();
        const acc = db.accounts.find(x=>x.id===id);
        if (title!==undefined) acc.title=title;
        if (firstName) acc.firstName=firstName;
        if (lastName) acc.lastName=lastName;
        if (email) acc.email=email;
        if (password) acc.passwordHash=bcrypt.hashSync(password,10);
        if (role && req.user.role==='Admin') acc.role=role;
        acc.updated=new Date().toISOString();
        db.save();
        return res.json(basicDetails(acc));
    }
}

// ─── DELETE /accounts/:id ─────────────────────────────────────────────────────
async function deleteAccount(req, res) {
    const id = parseInt(req.params.id);
    const account = await findAccountById(id);
    if (!account) return res.status(404).json({ message: 'Account not found' });
    if (req.user.role !== 'Admin' && req.user.id !== id) return res.status(401).json({ message: 'Unauthorized' });

    if (USE_MYSQL) {
        const { pool } = getDb();
        await pool.query('DELETE FROM accounts WHERE id=?', [id]);
    } else {
        const db = getDb();
        const idx = db.accounts.findIndex(x=>x.id===id);
        db.accounts.splice(idx,1);
        db.save();
    }
    res.json({ message: 'Account deleted successfully' });
}

module.exports = { authenticate, refreshToken, revokeTokenHandler, register, verifyEmail, forgotPassword, validateResetToken, resetPassword, getAll, getById, create, update, deleteAccount };
