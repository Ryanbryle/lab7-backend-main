const nodemailer = require('nodemailer');

let transporter;
let etherealUser, etherealPass;

async function getTransporter() {
    if (transporter) return transporter;

    // Use real SMTP if configured (e.g. Gmail, Mailgun, SendGrid)
    if (process.env.SMTP_HOST && process.env.SMTP_USER) {
        transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST,
            port: parseInt(process.env.SMTP_PORT || '587'),
            auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
        });
        console.log(`📧 Using SMTP: ${process.env.SMTP_HOST}`);
        return transporter;
    }

    // Use hardcoded Ethereal account (avoids network call on startup)
    // This is a pre-created test account safe for demo/submission
    etherealUser = process.env.ETHEREAL_USER || 'lab7test@ethereal.email';
    etherealPass = process.env.ETHEREAL_PASS || 'lab7testpass';

    try {
        // Try to create a fresh test account (works locally, may timeout on Render)
        const testAccount = await Promise.race([
            nodemailer.createTestAccount(),
            new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 5000))
        ]);
        etherealUser = testAccount.user;
        etherealPass = testAccount.pass;
        console.log(`\n📧 Ethereal Test Email Account Created:`);
        console.log(`   User: ${etherealUser}`);
        console.log(`   Pass: ${etherealPass}`);
        console.log(`   View emails at: https://ethereal.email/messages\n`);
    } catch {
        console.log(`📧 Using fallback email mode (Ethereal connection timed out)`);
    }

    transporter = nodemailer.createTransport({
        host: 'smtp.ethereal.email',
        port: 587,
        auth: { user: etherealUser, pass: etherealPass },
    });

    return transporter;
}

async function sendEmail({ to, subject, html }) {
    try {
        const t = await getTransporter();
        const info = await Promise.race([
            t.sendMail({
                from: process.env.EMAIL_FROM || '"Lab7 Auth" <noreply@lab7.com>',
                to, subject, html,
            }),
            new Promise((_, reject) => setTimeout(() => reject(new Error('SMTP timeout')), 8000))
        ]);

        const previewUrl = nodemailer.getTestMessageUrl(info);
        if (previewUrl) {
            console.log(`📬 Email Preview URL: ${previewUrl}`);
        }
        return info;
    } catch (err) {
        // Email failure is non-fatal — log it and continue
        console.warn(`⚠️  Email send failed (non-fatal): ${err.message}`);
        return null;
    }
}

async function sendVerificationEmail(email, origin, token) {
    const verifyUrl = `${origin}/account/verify-email?token=${token}`;
    console.log(`🔗 Verification link for ${email}: ${verifyUrl}`);
    await sendEmail({
        to: email,
        subject: 'Lab7 — Verify your email address',
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #1e293b;">Verify Your Email Address</h2>
                <p>Thanks for registering! Please click the link below to verify your email address:</p>
                <p style="margin: 24px 0;">
                    <a href="${verifyUrl}" style="background:#1e293b;color:#fff;padding:12px 24px;text-decoration:none;border-radius:4px;">
                        Verify Email
                    </a>
                </p>
                <p>Or copy this link: <a href="${verifyUrl}">${verifyUrl}</a></p>
                <p style="color:#64748b;font-size:12px;">If you did not register, please ignore this email.</p>
            </div>
        `
    });
}

async function sendAlreadyRegisteredEmail(email, origin) {
    await sendEmail({
        to: email,
        subject: 'Lab7 — Email Already Registered',
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #1e293b;">Email Already Registered</h2>
                <p>Your email <strong>${email}</strong> is already registered.</p>
                <p>If you forgot your password, you can reset it here:</p>
                <p style="margin: 24px 0;">
                    <a href="${origin}/account/forgot-password" style="background:#1e293b;color:#fff;padding:12px 24px;text-decoration:none;border-radius:4px;">
                        Forgot Password
                    </a>
                </p>
            </div>
        `
    });
}

async function sendPasswordResetEmail(email, origin, token) {
    const resetUrl = `${origin}/account/reset-password?token=${token}`;
    console.log(`🔗 Password reset link for ${email}: ${resetUrl}`);
    await sendEmail({
        to: email,
        subject: 'Lab7 — Reset your password',
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #1e293b;">Reset Your Password</h2>
                <p>Please click the link below to reset your password. The link is valid for 24 hours.</p>
                <p style="margin: 24px 0;">
                    <a href="${resetUrl}" style="background:#1e293b;color:#fff;padding:12px 24px;text-decoration:none;border-radius:4px;">
                        Reset Password
                    </a>
                </p>
                <p>Or copy this link: <a href="${resetUrl}">${resetUrl}</a></p>
                <p style="color:#64748b;font-size:12px;">If you did not request a password reset, please ignore this email.</p>
            </div>
        `
    });
}

module.exports = {
    sendVerificationEmail,
    sendAlreadyRegisteredEmail,
    sendPasswordResetEmail,
};
