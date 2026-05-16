const { verifyJwt } = require('../utils/jwt');
const { getDb, USE_PG } = require('../db');

async function authenticate(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Unauthorized' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = verifyJwt(token);
        let account;
        if (USE_PG) {
            const { pool } = getDb();
            const r = await pool.query('SELECT * FROM accounts WHERE id=$1', [decoded.id]);
            account = r.rows[0];
        } else {
            account = getDb().accounts.find(x => x.id === decoded.id);
        }
        if (!account) return res.status(401).json({ message: 'Unauthorized' });
        req.user = account;
        next();
    } catch {
        return res.status(401).json({ message: 'Unauthorized' });
    }
}

function authorize(role) {
    return [
        authenticate,
        (req, res, next) => {
            if (role && req.user.role !== role) return res.status(401).json({ message: 'Unauthorized' });
            next();
        }
    ];
}

module.exports = { authenticate, authorize };
