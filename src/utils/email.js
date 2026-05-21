const nodemailer = require('nodemailer');

let transporter;
let etherealUser, etherealPass;

// Helper to parse Name and Email from standard "Name" <email@example.com> format
function parseEmailFrom(emailFromStr) {
    if (!emailFromStr) return { name: 'Lab7 Support', email: 'noreply@lab7.com' };
    const emailMatch = emailFromStr.match(/<(.+)>/);
    const email = emailMatch ? emailMatch[1].trim() : emailFromStr.trim();
    
    let name = 'Lab7 Support';
    const nameMatch = emailFromStr.match(/^[^<]+/);
    if (nameMatch && emailMatch) {
        name = nameMatch[0].replace(/['"]/g, '').trim();
    }
    return { name, email };
}

// HTTP API: Brevo (Sendinblue)
async function sendEmailViaBrevo(apiKey, { to, subject, html }) {
    if (typeof fetch === 'undefined') {
        throw new Error('fetch is not defined in this Node environment. Please upgrade Node.js to v18+');
    }
    const { name, email } = parseEmailFrom(process.env.EMAIL_FROM);
    const response = await fetch('https://api.brevo.com/v3/smtp/email', {
        method: 'POST',
        headers: {
            'accept': 'application/json',
            'api-key': apiKey,
            'content-type': 'application/json'
        },
        body: JSON.stringify({
            sender: { name, email },
            to: [{ email: to }],
            subject: subject,
            htmlContent: html
        })
    });

    if (!response.ok) {
        const errText = await response.text();
        throw new Error(`Brevo API error: ${response.status} - ${errText}`);
    }
    return await response.json();
}

// HTTP API: Resend
async function sendEmailViaResend(apiKey, { to, subject, html }) {
    if (typeof fetch === 'undefined') {
        throw new Error('fetch is not defined in this Node environment. Please upgrade Node.js to v18+');
    }
    const fromStr = process.env.EMAIL_FROM || 'Lab7 Support <onboarding@resend.dev>';
    const response = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            from: fromStr,
            to: [to],
            subject: subject,
            html: html
        })
    });

    if (!response.ok) {
        const errText = await response.text();
        throw new Error(`Resend API error: ${response.status} - ${errText}`);
    }
    return await response.json();
}

async function getTransporter() {
    if (transporter) return transporter;

    // Use real SMTP if configured (e.g. Gmail, Mailgun, SendGrid)
    if (process.env.SMTP_HOST && process.env.SMTP_USER) {
        const port = parseInt(process.env.SMTP_PORT || '587');
        const secure = port === 465 || process.env.SMTP_SECURE === 'true';
        transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST,
            port: port,
            secure: secure,
            auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
        });
        console.log(`📧 Using SMTP: ${process.env.SMTP_HOST} (port: ${port}, secure: ${secure})`);
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
        // Try Brevo HTTP API first
        if (process.env.BREVO_API_KEY) {
            console.log(`📧 Sending email via Brevo HTTP API to ${to}...`);
            const info = await sendEmailViaBrevo(process.env.BREVO_API_KEY, { to, subject, html });
            console.log(`📬 Brevo email sent successfully! ID:`, info);
            return info;
        }

        // Try Resend HTTP API second
        if (process.env.RESEND_API_KEY) {
            console.log(`📧 Sending email via Resend HTTP API to ${to}...`);
            const info = await sendEmailViaResend(process.env.RESEND_API_KEY, { to, subject, html });
            console.log(`📬 Resend email sent successfully! ID:`, info);
            return info;
        }

        // Fallback to standard SMTP (Gmail/etc.) or Ethereal test mail
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
