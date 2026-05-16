# Lab7 Backend - Authentication API

This is the backend component of the Lab7 full-stack authentication boilerplate, built with Node.js, Express, and MySQL.

## Live Links
* **Frontend Application:** https://lab7-frontend.onrender.com
* **Backend API (Swagger):** https://lab7-backend-6o88-ymfb.onrender.com/api-docs
* **Frontend Repository:** https://github.com/lilad25/Lab7

## Setup Instructions
1. Clone the repository
2. Run `npm install` to install dependencies
3. Set up your `.env` file with `DATABASE_URL`, `JWT_SECRET`, and email settings.
4. Run `npm start` or `npm run dev` to start the backend server at `http://localhost:4000`.

## Production Configuration
- **Database**: Connects to remote Aiven MySQL instance using `DATABASE_URL` environment variable.
- **Emails**: Uses `ethereal.email` for testing verification and reset emails. Check server console logs for the Ethereal message links.
- **Security**: JWT and passwords are not hardcoded. Handled via environment variables securely.
