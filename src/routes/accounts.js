const express = require('express');
const router = express.Router();
const { authenticate, authorize } = require('../middleware/auth');
const ctrl = require('../controllers/accounts.controller');

/**
 * @swagger
 * tags:
 *   name: Accounts
 *   description: User account management and authentication
 */

/**
 * @swagger
 * /accounts/authenticate:
 *   post:
 *     summary: Login with email and password
 *     tags: [Accounts]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email: { type: string, example: admin@lab7.com }
 *               password: { type: string, example: password123 }
 *     responses:
 *       200:
 *         description: Login successful — returns account info + jwtToken
 *       400:
 *         description: Invalid credentials
 */
router.post('/authenticate', ctrl.authenticate);

/**
 * @swagger
 * /accounts/refresh-token:
 *   post:
 *     summary: Refresh JWT using refresh token cookie
 *     tags: [Accounts]
 *     responses:
 *       200:
 *         description: New JWT token issued
 *       401:
 *         description: Unauthorized
 */
router.post('/refresh-token', ctrl.refreshToken);

/**
 * @swagger
 * /accounts/revoke-token:
 *   post:
 *     summary: Revoke a refresh token (logout)
 *     tags: [Accounts]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Token revoked
 */
router.post('/revoke-token', authenticate, ctrl.revokeTokenHandler);

/**
 * @swagger
 * /accounts/register:
 *   post:
 *     summary: Register a new account
 *     tags: [Accounts]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               title: { type: string, example: Mr }
 *               firstName: { type: string, example: John }
 *               lastName: { type: string, example: Doe }
 *               email: { type: string, example: john@example.com }
 *               password: { type: string, example: password123 }
 *               confirmPassword: { type: string, example: password123 }
 *               acceptTerms: { type: boolean, example: true }
 *     responses:
 *       200:
 *         description: Registration successful — check email
 */
router.post('/register', ctrl.register);

/**
 * @swagger
 * /accounts/verify-email:
 *   post:
 *     summary: Verify email address with token
 *     tags: [Accounts]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               token: { type: string }
 *     responses:
 *       200:
 *         description: Email verified
 *       400:
 *         description: Invalid token
 */
router.post('/verify-email', ctrl.verifyEmail);

/**
 * @swagger
 * /accounts/forgot-password:
 *   post:
 *     summary: Send password reset email
 *     tags: [Accounts]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email: { type: string }
 *     responses:
 *       200:
 *         description: Reset email sent (if account exists)
 */
router.post('/forgot-password', ctrl.forgotPassword);

/**
 * @swagger
 * /accounts/validate-reset-token:
 *   post:
 *     summary: Validate password reset token
 *     tags: [Accounts]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               token: { type: string }
 *     responses:
 *       200:
 *         description: Token is valid
 *       400:
 *         description: Invalid token
 */
router.post('/validate-reset-token', ctrl.validateResetToken);

/**
 * @swagger
 * /accounts/reset-password:
 *   post:
 *     summary: Reset password using token
 *     tags: [Accounts]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               token: { type: string }
 *               password: { type: string }
 *               confirmPassword: { type: string }
 *     responses:
 *       200:
 *         description: Password reset successful
 */
router.post('/reset-password', ctrl.resetPassword);

/**
 * @swagger
 * /accounts:
 *   get:
 *     summary: Get all accounts (Admin only)
 *     tags: [Accounts]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of accounts
 *   post:
 *     summary: Create a new account (Admin only)
 *     tags: [Accounts]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Account created
 */
router.get('/', authorize('Admin'), ctrl.getAll);
router.post('/', authorize('Admin'), ctrl.create);

/**
 * @swagger
 * /accounts/{id}:
 *   get:
 *     summary: Get account by ID
 *     tags: [Accounts]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         schema: { type: integer }
 *         required: true
 *     responses:
 *       200:
 *         description: Account details
 *   put:
 *     summary: Update account by ID
 *     tags: [Accounts]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         schema: { type: integer }
 *         required: true
 *     responses:
 *       200:
 *         description: Updated account
 *   delete:
 *     summary: Delete account by ID
 *     tags: [Accounts]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         schema: { type: integer }
 *         required: true
 *     responses:
 *       200:
 *         description: Account deleted
 */
router.get('/:id', authenticate, ctrl.getById);
router.put('/:id', authenticate, ctrl.update);
router.delete('/:id', authenticate, ctrl.deleteAccount);

module.exports = router;
