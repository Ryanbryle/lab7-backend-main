# Lab7 Auth Backend — README

## Live Demo
- **API:** https://lab7-backend-6o88.onrender.com
- **API Docs (Swagger):** https://lab7-backend-6o88.onrender.com/api-docs
- **Frontend:** https://lab7-frontend.onrender.com

## Setup Instructions

### Local Development
```bash
# Install dependencies
npm install

# Create .env file (see Environment Variables below)
# Start server
npm start
```

### Environment Variables
Create a `.env` file in the root (never commit this):

| Variable | Description | Example |
|----------|-------------|---------|
| `PORT` | Server port | `4000` |
| `JWT_SECRET` | Secret key for JWT signing | `your-secret-key` |
| `CORS_ORIGIN` | Frontend URL for CORS | `https://lab7-frontend.onrender.com` |
| `DATABASE_URL` | PostgreSQL URL (set by Render auto) | `postgres://...` |
| `NODE_ENV` | Environment | `production` |

> **Security Note:** No secrets are hardcoded. All sensitive data is handled via `.env` (locally) or Render environment variables (production). The `.env` file is listed in `.gitignore`.

> **Database Note:** Uses PostgreSQL in production (via `DATABASE_URL` on Render) and a local JSON file for development (no installation needed).

### API Endpoints
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/accounts/register` | None | Register new account |
| POST | `/accounts/authenticate` | None | Login |
| POST | `/accounts/verify-email` | None | Verify email |
| POST | `/accounts/refresh-token` | Cookie | Refresh JWT |
| POST | `/accounts/revoke-token` | JWT | Logout |
| POST | `/accounts/forgot-password` | None | Request reset |
| POST | `/accounts/reset-password` | None | Reset password |
| GET | `/accounts` | Admin | List all accounts |
| GET/PUT/DELETE | `/accounts/:id` | JWT | Manage account |

## Security Practices
- JWT tokens expire in 15 minutes (short-lived)
- Refresh tokens rotate on every use and are stored in DB
- Passwords hashed with bcrypt (cost factor 10)
- CORS restricted to frontend origin only
- No secrets committed to repository
