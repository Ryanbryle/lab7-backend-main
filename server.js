require('dotenv').config();
require('express-async-errors');

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

const { initializeDatabase } = require('./src/db');
const accountRoutes = require('./src/routes/accounts');
const errorHandler = require('./src/middleware/errorHandler');

const app = express();
const PORT = process.env.PORT || 4000;

// ─── CORS ────────────────────────────────────────────────────────────────────
app.use(cors({
    origin: function (origin, callback) {
        callback(null, true);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ─── Swagger ──────────────────────────────────────────────────────────────────
const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'Lab7 Auth API',
            version: '1.0.0',
            description: 'Full-Stack Authentication System API — JWT + Refresh Tokens + RBAC',
        },
        servers: [
            { url: 'https://lab7-backend-6o88.onrender.com', description: 'Production (Render)' },
            { url: 'http://localhost:4000', description: 'Local Development' }
        ],
        components: {
            securitySchemes: {
                bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' }
            }
        }
    },
    apis: ['./src/routes/*.js'],
};
const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// ─── Routes ──────────────────────────────────────────────────────────────────
app.use('/accounts', accountRoutes);

// Health check
app.get('/', (req, res) => {
    res.json({ status: 'ok', message: 'Lab7 Auth API is running', docs: `/api-docs` });
});

// ─── Error Handler ───────────────────────────────────────────────────────────
app.use(errorHandler);

// ─── Start ───────────────────────────────────────────────────────────────────
function start() {
    try {
        initializeDatabase();
        app.listen(PORT, () => {
            console.log(`\n✅ Lab7 API running at http://localhost:${PORT}`);
            console.log(`📚 Swagger docs at  http://localhost:${PORT}/api-docs\n`);
        });
    } catch (err) {
        console.error('❌ Failed to start server:', err.message);
        process.exit(1);
    }
}

start();
