const nodemailer = require("nodemailer");

let transporter;

function getTransporter() {
    const host = process.env.EMAIL_HOST;
    const from = process.env.EMAIL_FROM;

    if (!host || !from) {
        throw new Error("Email 2FA is not configured. Set EMAIL_HOST and EMAIL_FROM.");
    }

    const port = Number(process.env.EMAIL_PORT || 587);
    const user = process.env.EMAIL_USER;
    const pass = process.env.EMAIL_PASS;

    if ((user && !pass) || (!user && pass)) {
        throw new Error("Set both EMAIL_USER and EMAIL_PASS, or leave both unset for an unauthenticated SMTP relay.");
    }

    if (!transporter) {
        transporter = nodemailer.createTransport({
            host,
            port,
            secure: process.env.EMAIL_SECURE === "true" || port === 465,
            ...(user ? { auth: { user, pass } } : {})
        });
    }

    return { transporter, from };
}

async function sendTwoFactorCode({ to, code }) {
    const { transporter, from } = getTransporter();

    await transporter.sendMail({
        from,
        to,
        subject: "Your SecureDesk sign-in code",
        text: `Your SecureDesk verification code is ${code}. It expires in 10 minutes. If you did not try to sign in, you can ignore this email.`,
        html: `<!doctype html><html lang="en"><body style="margin:0;padding:32px;background:#f2f1ed;font-family:Arial,sans-serif;color:#202723"><table role="presentation" style="max-width:520px;margin:auto;background:#fff;border-radius:12px;padding:36px;width:100%"><tr><td><p style="font-weight:bold;letter-spacing:1px;color:#243a31">SECUREDESK</p><h1 style="font-size:24px">Your sign-in code</h1><p>Use this code to finish signing in. It expires in 10 minutes.</p><p style="font-size:32px;font-weight:bold;letter-spacing:8px;padding:16px 0">${code}</p><p style="font-size:13px;color:#737373">If you did not try to sign in, you can ignore this email.</p></td></tr></table></body></html>`
    });
}

async function sendPasswordResetEmail({ to, resetUrl }) {
    const { transporter, from } = getTransporter();

    await transporter.sendMail({
        from,
        to,
        subject: "Reset your SecureDesk password",
        text: `We received a request to reset your SecureDesk password. Use this link within 30 minutes:\n\n${resetUrl}\n\nIf you did not request this, you can ignore this email. Your password and authenticator settings have not changed.`,
        html: `<!doctype html><html lang="en"><body style="margin:0;padding:32px;background:#f2f1ed;font-family:Arial,sans-serif;color:#202723"><table role="presentation" style="max-width:520px;margin:auto;background:#fff;border-radius:12px;padding:36px;width:100%"><tr><td><p style="font-weight:bold;letter-spacing:1px;color:#243a31">SECUREDESK</p><h1 style="font-size:24px">Reset your password</h1><p>Use the button below within 30 minutes to choose a new password.</p><p style="margin:28px 0"><a href="${resetUrl}" style="display:inline-block;padding:14px 22px;background:#202020;color:#fff;text-decoration:none;border-radius:7px">Choose a new password</a></p><p style="font-size:13px;color:#737373">If you did not request this, you can ignore this email. Your password and authenticator settings have not changed.</p></td></tr></table></body></html>`
    });
}

module.exports = { sendTwoFactorCode, sendPasswordResetEmail };