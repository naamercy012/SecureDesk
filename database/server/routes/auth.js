const express = require("express");
const {
    createHash,
    createHmac,
    randomBytes,
    randomUUID,
    timingSafeEqual
} = require("crypto");
const {
    generateSecret,
    generate,
    verify,
    generateURI
} = require("otplib");
const QRCode = require("qrcode");

const pool = require("../../db");
const {
    decryptTotpSecret,
    encryptTotpSecret,
    isEncryptedTotpSecret
} = require("../totp-secret");
const {
    hashPassword,
    verifyPassword
} = require("../password");
const { sendPasswordResetEmail } = require("../email");
const { requireAuth } = require("../server/middleware/auth");

const router = express.Router();
const TWO_FACTOR_MAX_ATTEMPTS = 5;
const MAX_EMAIL_LENGTH = 254;
const MAX_PASSWORD_LENGTH = 128;
const MAX_USERNAME_LENGTH = 32;
const MIN_USERNAME_LENGTH = 3;
const RECOVERY_CODE_COUNT = 10;
const PASSWORD_RESET_TOKEN_TTL_MINUTES = 30;
let passwordResetSchemaInitialization;

function ensurePasswordResetSchema() {
    if (!passwordResetSchemaInitialization) {
        passwordResetSchemaInitialization = pool.query(`
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                token_hash TEXT PRIMARY KEY,
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at TIMESTAMPTZ NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user
            ON password_reset_tokens(user_id);
            CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expiry
            ON password_reset_tokens(expires_at)
        `).catch((error) => {
            passwordResetSchemaInitialization = undefined;
            throw error;
        });
    }

    return passwordResetSchemaInitialization;
}

function hashPasswordResetToken(token) {
    return createHash("sha256").update(token).digest("hex");
}

function getSessionDeviceId(sessionId) {
    const secret = process.env.SESSION_SECRET;
    if (!secret) {
        throw new Error("SESSION_SECRET is required to identify sessions.");
    }

    return createHmac("sha256", secret)
        .update(`SecureDesk session device v1:${sessionId}`)
        .digest("hex");
}

function isSameDeviceId(left, right) {
    if (typeof left !== "string" || typeof right !== "string" || left.length !== 64 || right.length !== 64) {
        return false;
    }

    const leftBuffer = Buffer.from(left, "hex");
    const rightBuffer = Buffer.from(right, "hex");
    return leftBuffer.length === 32 &&
        rightBuffer.length === 32 &&
        timingSafeEqual(leftBuffer, rightBuffer);
}

function getDeviceName(userAgent) {
    const browser = /Edg(?:e|A|iOS)?\//.test(userAgent)
        ? "Edge"
        : /OPR\//.test(userAgent)
            ? "Opera"
            : /Firefox|FxiOS\//.test(userAgent)
                ? "Firefox"
                : /Chrome|CriOS\//.test(userAgent)
                    ? "Chrome"
                    : /Safari\//.test(userAgent)
                        ? "Safari"
                        : null;
    const platform = /iPhone|iPad|iPod/.test(userAgent)
        ? "iPhone or iPad"
        : /Android/.test(userAgent)
            ? "Android"
            : /Windows/.test(userAgent)
                ? "Windows"
                : /Macintosh|Mac OS/.test(userAgent)
                    ? "Mac"
                    : /Linux/.test(userAgent)
                        ? "Linux"
                        : null;

    if (browser && platform) {
        return `${browser} on ${platform}`;
    }
    return browser || platform || "Previously signed-in device";
}

function sanitizeUsername(value) {
    return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function isValidUsername(value) {
    return value.length >= MIN_USERNAME_LENGTH &&
        value.length <= MAX_USERNAME_LENGTH &&
        /^[a-z0-9][a-z0-9._-]*$/.test(value);
}

function sanitizeEmail(value) {
    return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function isValidEmailAddress(value) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function validatePassword(password) {
    return typeof password === "string" &&
        password.length >= 8 &&
        password.length <= MAX_PASSWORD_LENGTH &&
        !/\s/.test(password);
}

function normalizeTotpCode(code) {
    return typeof code === "string" ? code.trim().replace(/\s+/g, "") : "";
}

function normalizeRecoveryCode(code) {
    return typeof code === "string"
        ? code.trim().toUpperCase().replace(/[\s-]/g, "")
        : "";
}

function generateRecoveryCodes() {
    return Array.from({ length: RECOVERY_CODE_COUNT }, () => {
        const value = randomBytes(16).toString("hex").toUpperCase();
        return value.match(/.{4}/g).join("-");
    });
}

function hashRecoveryCode(code) {
    const pepper = process.env.PASSWORD_PEPPER;
    if (!pepper) {
        throw new Error("PASSWORD_PEPPER is required to protect recovery codes.");
    }

    return createHmac("sha256", pepper)
        .update(`SecureDesk recovery code v1:${normalizeRecoveryCode(code)}`)
        .digest("hex");
}

async function writeAuditEvent(req, action, userId = null) {
    try {
        await pool.query(
            `
            INSERT INTO audit_logs (user_id, action, ip_address, user_agent)
            VALUES ($1, $2, $3, $4)
            `,
            [
                userId,
                action,
                req.ip || null,
                (req.get("user-agent") || "").slice(0, 500)
            ]
        );
    } catch (error) {
        console.error(`Unable to write authentication audit event "${action}":`, error);
    }
}

async function verifyTotpCode(code, secret) {
    const normalizedCode = normalizeTotpCode(code);

    if (!secret || !/^\d{6}$/.test(normalizedCode)) {
        return false;
    }

    const result = await verify({
        secret,
        token: normalizedCode,
        epochTolerance: 30
    });
    return result.valid;
}

function generateTotpSecret() {
    return generateSecret();
}

function regenerateSession(req) {
    return new Promise((resolve, reject) => {
        req.session.regenerate((error) => {
            if (error) {
                reject(error);
                return;
            }

            resolve();
        });
    });
}

/*
REQUEST PASSWORD RESET
*/
router.post("/password-reset/request", async (req, res) => {
    const email = sanitizeEmail(req.body?.email);
    if (!email || email.length > MAX_EMAIL_LENGTH || !isValidEmailAddress(email)) {
        return res.status(400).json({
            message: "Enter the email address associated with your account."
        });
    }

    try {
        await ensurePasswordResetSchema();
        const result = await pool.query(
            "SELECT id, email FROM users WHERE email = $1 AND is_active = TRUE",
            [email]
        );

        res.json({
            message: "If an account matches that email, we'll send a password reset link shortly. Check your inbox and spam folder."
        });

        if (result.rows.length === 0) {
            return;
        }

        const user = result.rows[0];
        const token = randomBytes(32).toString("base64url");
        const tokenHash = hashPasswordResetToken(token);
        const configuredBaseUrl = req.app.get("appBaseUrl");
        const resetUrl = new URL("/reset-password.html", configuredBaseUrl);
        resetUrl.searchParams.set("token", token);

        setImmediate(async () => {
            try {
                await pool.query(
                    "DELETE FROM password_reset_tokens WHERE expires_at <= NOW()"
                );
                await pool.query(
                    `
                    INSERT INTO password_reset_tokens (token_hash, user_id, expires_at)
                    VALUES ($1, $2, NOW() + ($3 * INTERVAL '1 minute'))
                    `,
                    [tokenHash, user.id, PASSWORD_RESET_TOKEN_TTL_MINUTES]
                );
                await sendPasswordResetEmail({
                    to: user.email,
                    resetUrl: resetUrl.toString()
                });
                await writeAuditEvent(req, "password_reset.email_sent", user.id);
            } catch (error) {
                try {
                    await pool.query(
                        "DELETE FROM password_reset_tokens WHERE token_hash = $1",
                        [tokenHash]
                    );
                } catch (cleanupError) {
                    console.error("Unable to remove an unsent password reset token:", cleanupError);
                }
                console.error("Unable to send password reset email:", error);
            }
        });
    } catch (error) {
        console.error("Unable to process password reset request:", error);
        res.status(500).json({
            message: "We couldn't process your request right now. Please try again in a moment."
        });
    }
});

/*
COMPLETE PASSWORD RESET
*/
router.post("/password-reset/complete", async (req, res) => {
    const { token, password } = req.body || {};
    if (
        typeof token !== "string" ||
        !/^[A-Za-z0-9_-]{40,50}$/.test(token) ||
        !validatePassword(password)
    ) {
        return res.status(400).json({
            message: "Choose a password between 8 and 128 characters with no spaces, then try the link again."
        });
    }

    let passwordHash;
    try {
        passwordHash = await hashPassword(password);
    } catch (error) {
        console.error("Unable to prepare a password reset:", error);
        return res.status(500).json({
            message: "We couldn't update your password right now. Please try again."
        });
    }

    let client;
    let userId;
    try {
        client = await pool.connect();
        await client.query("BEGIN");
        const tokenResult = await client.query(
            `
            DELETE FROM password_reset_tokens
            WHERE token_hash = $1
            AND expires_at > NOW()
            RETURNING user_id
            `,
            [hashPasswordResetToken(token)]
        );

        if (tokenResult.rowCount !== 1) {
            await client.query("ROLLBACK");
            return res.status(400).json({
                message: "This password reset link has expired or was already used. Request a new link to continue."
            });
        }

        userId = tokenResult.rows[0].user_id;
        const updateResult = await client.query(
            "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2 AND is_active = TRUE",
            [passwordHash, userId]
        );
        if (updateResult.rowCount !== 1) {
            await client.query("ROLLBACK");
            return res.status(400).json({
                message: "This password reset link can't be used. Request a new link to continue."
            });
        }

        await client.query(
            "DELETE FROM password_reset_tokens WHERE user_id = $1",
            [userId]
        );
        await client.query(
            "DELETE FROM user_sessions WHERE sess::jsonb #>> '{user,id}' = $1",
            [userId]
        );
        await client.query("COMMIT");
    } catch (error) {
        if (client) {
            await client.query("ROLLBACK");
        }
        console.error("Unable to complete password reset:", error);
        return res.status(500).json({
            message: "We couldn't update your password right now. Please try again."
        });
    } finally {
        client?.release();
    }

    await writeAuditEvent(req, "password_reset.completed", userId);
    res.json({
        success: true,
        message: "Your password has been updated. Sign in with your new password and authenticator code."
    });
});

/*
REGISTER
*/
router.post("/register", async (req, res) => {

    try {

        const {
            username,
            email,
            password
        } = req.body;

        if (typeof username !== "string" || typeof email !== "string" || typeof password !== "string") {
            return res.status(400).json({
                message: "Please enter a username, email address, and password."
            });
        }

        const normalizedUsername = sanitizeUsername(username);
        if (!isValidUsername(normalizedUsername)) {
            return res.status(400).json({
                message: "Choose a username between 3 and 32 characters. Use letters, numbers, dots, underscores, or hyphens, and start with a letter or number."
            });
        }

        const normalizedEmail = sanitizeEmail(email);

        if (!normalizedEmail || normalizedEmail.length > MAX_EMAIL_LENGTH || !isValidEmailAddress(normalizedEmail)) {
            return res.status(400).json({
                message: "Enter a valid email address."
            });
        }

        if (!validatePassword(password)) {
            return res.status(400).json({
                message: "Choose a password between 8 and 128 characters with no spaces."
            });
        }

        const existingUser = await pool.query(
            "SELECT id FROM users WHERE email = $1 OR username = $2",
            [normalizedEmail, normalizedUsername]
        );

        if (existingUser.rows.length > 0) {
            return res.status(409).json({
                message: "We couldn't create your account with those details. Check them or try signing in if you already have an account."
            });
        }

        const passwordHash =
            await hashPassword(password);

        const roleResult = await pool.query(
            "SELECT id FROM roles WHERE name = $1",
            ["user"]
        );

        if (roleResult.rows.length === 0) {
            throw new Error("The user role is missing. Apply database/schema.sql first.");
        }

        const user = await pool.query(
            `
            INSERT INTO users
            (username, email, password_hash, role_id, two_factor_enabled)

            VALUES
            ($1, $2, $3, $4, FALSE)

            RETURNING id, username, email
            `,
            [
                normalizedUsername,
                normalizedEmail,
                passwordHash,
                roleResult.rows[0].id
            ]
        );

        const totpSecret = generateTotpSecret();
        const otpauthUri = generateURI({
            secret: totpSecret,
            label: normalizedUsername,
            issuer: "SecureDesk"
        });
        const qrCodeDataUrl = await QRCode.toDataURL(otpauthUri);

        await regenerateSession(req);
        req.session.pending2FA = {
            userId: user.rows[0].id,
            purpose: "signup",
            secret: encryptTotpSecret(totpSecret),
            attempts: 0
        };
        await writeAuditEvent(req, "signup.started", user.rows[0].id);

        res.status(201).json({
            requires2FA: true,
            message: "Scan the QR code with your authenticator app and verify the six-digit code.",
            qrCodeDataUrl
        });

    } catch (error) {

        console.error(error);
        if (error.code === "23505") {
            return res.status(409).json({
                message: "We couldn't create your account with those details. Check them or try signing in if you already have an account."
            });
        }

        res.status(500).json({
            message: "We couldn't create your account right now. Please try again in a moment."
        });
    }
});


/*
LOGIN
*/
router.post("/login", async (req, res) => {

    try {

        const {
            username,
            password
        } = req.body;

        if (typeof username !== "string" || typeof password !== "string") {
            return res.status(400).json({
                message: "Please enter your username and password."
            });
        }

        const normalizedUsername = sanitizeUsername(username);
        if (!isValidUsername(normalizedUsername)) {
            return res.status(400).json({
                message: "Enter a valid username and try again."
            });
        }

        if (!validatePassword(password)) {
            return res.status(400).json({
                message: "Your password must be between 8 and 128 characters with no spaces."
            });
        }

        const result = await pool.query(
            `
            SELECT
                users.id,
                users.username,
                users.email,
                users.password_hash,
                users.two_factor_enabled,
                users.two_factor_secret,
                roles.name AS role

            FROM users

            JOIN roles
            ON users.role_id = roles.id

            WHERE users.username = $1
            AND users.is_active = TRUE
            `,
            [normalizedUsername]
        );

        if (result.rows.length === 0) {
            await writeAuditEvent(req, "login.failed");
            return res.status(401).json({
                message: "We couldn't sign you in with those details. Check your username and password and try again."
            });
        }

        const user = result.rows[0];

        const passwordValid =
            await verifyPassword(
                password,
                user.password_hash
            );

        if (!passwordValid) {
            await writeAuditEvent(req, "login.failed", user.id);
            return res.status(401).json({
                message: "We couldn't sign you in with those details. Check your username and password and try again."
            });
        }

        if (!user.two_factor_enabled || !user.two_factor_secret) {
            console.error(`User ${user.id} has not completed TOTP enrollment.`);
            return res.status(403).json({
                message: "Authenticator setup isn't complete for this account. Please contact support."
            });
        }

        await regenerateSession(req);
        req.session.pending2FA = {
            userId: user.id,
            purpose: "login",
            attempts: 0
        };
        await writeAuditEvent(req, "login.password_verified", user.id);

        res.json({
            requires2FA: true,
            message: "Enter the six-digit code from your authenticator app."
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            message: "We couldn't sign you in right now. Please try again in a moment."
        });
    }
});


/*
CURRENT SESSION
*/
router.get("/me", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({
            message: "Please sign in to continue."
        });
    }

    pool.query(
        `
        SELECT users.id, users.username, users.email, users.last_seen_at, roles.name AS role
        FROM users
        JOIN roles ON users.role_id = roles.id
        WHERE users.id = $1
        AND users.is_active = TRUE
        `,
        [req.session.user.id]
    ).then((result) => {
        const user = result.rows[0];
        if (!user) {
            return res.status(401).json({ message: "Please sign in to continue." });
        }

        req.session.user = {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role
        };

        res.json({
            user: req.session.user,
            lastSeenAt: user.last_seen_at
        });
    }).catch((error) => {
        console.error("Unable to load account activity:", error);
        res.status(500).json({ message: "We couldn't load your account right now. Please try again." });
    });
});

router.get("/activity", async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({
            message: "Please sign in to continue."
        });
    }

    try {
        const result = await pool.query(
            `
            SELECT action, status_code, metadata, created_at
            FROM audit_logs
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT 20
            `,
            [req.session.user.id]
        );

        res.json({
            activity: result.rows.map((event) => ({
                action: event.action,
                statusCode: event.status_code,
                method: event.metadata?.method || null,
                path: event.metadata?.path || null,
                occurredAt: event.created_at
            }))
        });
    } catch (error) {
        console.error("Unable to load recent account activity:", error);
        res.status(500).json({ message: "We couldn't load your recent activity. Please try again." });
    }
});

router.get("/sessions", requireAuth, async (req, res) => {
    try {
        if (!req.session.device) {
            req.session.device = {
                signedInAt: null,
                userAgent: (req.get("user-agent") || "").slice(0, 500),
                ipAddress: req.ip || null
            };
        }

        const result = await pool.query(
            `
            SELECT
                sid,
                expire AS expires_at,
                sess::jsonb #>> '{device,signedInAt}' AS signed_in_at,
                sess::jsonb #>> '{device,userAgent}' AS user_agent,
                sess::jsonb #>> '{device,ipAddress}' AS ip_address
            FROM user_sessions
            WHERE sess::jsonb #>> '{user,id}' = $1
            AND expire > NOW()
            ORDER BY (sid = $2) DESC, expire DESC
            `,
            [req.session.user.id, req.sessionID]
        );

        const sessions = result.rows.map((session) => {
            const isCurrent = session.sid === req.sessionID;
            const device = isCurrent ? req.session.device : null;
            return {
                id: getSessionDeviceId(session.sid),
                isCurrent,
                signedInAt: device?.signedInAt || session.signed_in_at,
                expiresAt: session.expires_at,
                deviceName: getDeviceName(device?.userAgent || session.user_agent || ""),
                ipAddress: device?.ipAddress || session.ip_address || null
            };
        });

        if (!sessions.some((session) => session.isCurrent)) {
            sessions.unshift({
                id: getSessionDeviceId(req.sessionID),
                isCurrent: true,
                signedInAt: req.session.device.signedInAt,
                expiresAt: null,
                deviceName: getDeviceName(req.session.device.userAgent || "") || "This device",
                ipAddress: req.session.device.ipAddress
            });
        }

        res.json({ sessions });
    } catch (error) {
        console.error("Unable to load account sessions:", error);
        res.status(500).json({
            message: "We couldn't load your signed-in devices. Please try again."
        });
    }
});

router.delete("/sessions", requireAuth, async (req, res) => {
    try {
        const result = await pool.query(
            `
            DELETE FROM user_sessions
            WHERE sess::jsonb #>> '{user,id}' = $1
            AND sid <> $2
            `,
            [req.session.user.id, req.sessionID]
        );
        await writeAuditEvent(req, "sessions.other_devices_revoked", req.session.user.id);
        res.json({
            success: true,
            revokedCount: result.rowCount,
            message: result.rowCount === 1
                ? "Signed out the other device."
                : `Signed out ${result.rowCount} other devices.`
        });
    } catch (error) {
        console.error("Unable to sign out other account sessions:", error);
        res.status(500).json({
            message: "We couldn't sign out your other devices. Please try again."
        });
    }
});

router.delete("/sessions/:deviceId", requireAuth, async (req, res) => {
    const { deviceId } = req.params;
    if (!/^[a-f0-9]{64}$/.test(deviceId)) {
        return res.status(400).json({
            message: "That device session couldn't be identified. Refresh the page and try again."
        });
    }

    try {
        const result = await pool.query(
            `
            SELECT sid
            FROM user_sessions
            WHERE sess::jsonb #>> '{user,id}' = $1
            AND expire > NOW()
            `,
            [req.session.user.id]
        );
        const session = result.rows.find((row) =>
            isSameDeviceId(getSessionDeviceId(row.sid), deviceId)
        );

        if (!session) {
            return res.status(404).json({
                message: "That device is no longer signed in. Refresh the page to see your current devices."
            });
        }

        if (session.sid === req.sessionID) {
            return res.status(400).json({
                message: "This is the device you're using now. Use Sign out to end this session."
            });
        }

        const deleted = await pool.query(
            `
            DELETE FROM user_sessions
            WHERE sid = $1
            AND sess::jsonb #>> '{user,id}' = $2
            `,
            [session.sid, req.session.user.id]
        );
        if (deleted.rowCount !== 1) {
            return res.status(404).json({
                message: "That device is no longer signed in. Refresh the page to see your current devices."
            });
        }

        await writeAuditEvent(req, "sessions.device_revoked", req.session.user.id);
        res.json({ success: true, message: "That device has been signed out." });
    } catch (error) {
        console.error("Unable to revoke account session:", error);
        res.status(500).json({
            message: "We couldn't sign out that device. Please try again."
        });
    }
});


/*
VERIFY 2FA
*/
router.post("/verify-2fa", async (req, res) => {

    try {

        const { code } = req.body;

        if (!req.session.pending2FA) {
            return res.status(401).json({
                message: "Your verification session has expired. Please sign in again."
            });
        }

        const pending = req.session.pending2FA;
        const normalizedCode = normalizeTotpCode(code);
        const normalizedRecoveryCode = normalizeRecoveryCode(code);
        const isTotpCode = /^\d{6}$/.test(normalizedCode);
        const isRecoveryCode = /^[A-F0-9]{32}$/.test(normalizedRecoveryCode);

        if (typeof code !== "string" || (!isTotpCode && !isRecoveryCode)) {
            return res.status(400).json({ message: "Enter an authenticator code or a recovery code." });
        }

        if (pending.purpose === "signup" && !isTotpCode) {
            return res.status(400).json({ message: "Use the six-digit authenticator code to complete setup." });
        }

        if (pending.attempts >= TWO_FACTOR_MAX_ATTEMPTS) {
            delete req.session.pending2FA;
            return res.status(429).json({ message: "Too many incorrect codes. Please sign in again." });
        }

        let authenticatedUser;
        let secret = pending.purpose === "signup"
            ? decryptTotpSecret(pending.secret)
            : undefined;
        let storedTotpSecret;

        if (pending.purpose === "login") {
            const result = await pool.query(
                `
                SELECT
                    users.id,
                    users.username,
                    users.email,
                    users.last_seen_at,
                    users.two_factor_enabled,
                    users.two_factor_secret,
                    roles.name AS role
                FROM users
                JOIN roles ON users.role_id = roles.id
                WHERE users.id = $1
                AND users.is_active = TRUE
                `,
                [pending.userId]
            );

            const user = result.rows[0];
            if (!user || !user.two_factor_enabled || !user.two_factor_secret) {
                delete req.session.pending2FA;
                return res.status(401).json({
                    message: "Sign-in session expired. Please sign in again."
                });
            }

            storedTotpSecret = user.two_factor_secret;
            secret = decryptTotpSecret(storedTotpSecret);
            authenticatedUser = {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role
            };
        } else if (pending.purpose === "signup") {
            const result = await pool.query(
                `
                SELECT users.id, users.username, users.email, roles.name AS role
                FROM users
                JOIN roles ON users.role_id = roles.id
                WHERE users.id = $1
                AND users.is_active = TRUE
                `,
                [pending.userId]
            );

            const user = result.rows[0];
            if (!user || !secret) {
                delete req.session.pending2FA;
                return res.status(401).json({
                    message: "Sign-up session expired. Please create your account again."
                });
            }

            authenticatedUser = {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role
            };
        } else {
            delete req.session.pending2FA;
            return res.status(401).json({
                message: "Verification session expired. Please sign in again."
            });
        }

        let valid = false;
        let usedRecoveryCode = false;

        if (isTotpCode) {
            valid = await verifyTotpCode(normalizedCode, secret);
        } else if (pending.purpose === "login") {
            const consumedCode = await pool.query(
                `
                UPDATE recovery_codes
                SET used_at = NOW()
                WHERE user_id = $1
                AND code_hash = $2
                AND used_at IS NULL
                RETURNING id
                `,
                [pending.userId, hashRecoveryCode(normalizedRecoveryCode)]
            );
            valid = consumedCode.rowCount === 1;
            usedRecoveryCode = valid;
        }

        if (!valid) {
            pending.attempts += 1;
            await writeAuditEvent(req, "second_factor.failed", pending.userId);
            if (pending.attempts >= TWO_FACTOR_MAX_ATTEMPTS) {
                delete req.session.pending2FA;
                return res.status(429).json({ message: "Too many incorrect codes. Please sign in again." });
            }
            return res.status(401).json({
                message: "That code is not valid. Check your authenticator app and try again."
            });
        }

        let recoveryCodes;
        if (pending.purpose === "signup") {
            recoveryCodes = generateRecoveryCodes();
            const client = await pool.connect();
            try {
                await client.query("BEGIN");
                const result = await client.query(
                    "UPDATE users SET two_factor_enabled = TRUE, two_factor_secret = $1, updated_at = NOW() WHERE id = $2 AND is_active = TRUE",
                    [encryptTotpSecret(secret), pending.userId]
                );
                if (result.rowCount !== 1) {
                    await client.query("ROLLBACK");
                    delete req.session.pending2FA;
                    return res.status(401).json({
                        message: "Sign-up session expired. Please create your account again."
                    });
                }

                for (const recoveryCode of recoveryCodes) {
                    await client.query(
                        "INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)",
                        [pending.userId, hashRecoveryCode(recoveryCode)]
                    );
                }
                await client.query("COMMIT");
            } catch (error) {
                await client.query("ROLLBACK");
                throw error;
            } finally {
                client.release();
            }
        } else if (!isEncryptedTotpSecret(storedTotpSecret)) {
            const result = await pool.query(
                `
                UPDATE users
                SET two_factor_secret = $1, updated_at = NOW()
                WHERE id = $2
                AND two_factor_secret = $3
                AND two_factor_enabled = TRUE
                AND is_active = TRUE
                `,
                [encryptTotpSecret(secret), pending.userId, storedTotpSecret]
            );
            if (result.rowCount !== 1) {
                delete req.session.pending2FA;
                return res.status(401).json({
                    message: "Sign-in session expired. Please sign in again."
                });
            }
        }

        await regenerateSession(req);
        req.session.user = authenticatedUser;
        req.session.device = {
            signedInAt: new Date().toISOString(),
            userAgent: (req.get("user-agent") || "").slice(0, 500),
            ipAddress: req.ip || null
        };
        await pool.query(
            "UPDATE users SET last_seen_at = NOW() WHERE id = $1 AND is_active = TRUE",
            [authenticatedUser.id]
        );
        await writeAuditEvent(
            req,
            pending.purpose === "signup"
                ? "signup.completed"
                : usedRecoveryCode
                    ? "login.recovery_code_used"
                    : "login.success",
            authenticatedUser.id
        );

        res.json({
            success: true,
            user: req.session.user,
            ...(recoveryCodes ? { recoveryCodes } : {})
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            message: "We couldn't verify your code right now. Please try again."
        });
    }
});


/*
RESEND EMAIL 2FA CODE
*/
router.post("/resend-2fa", async (req, res) => {
    const pending = req.session.pending2FA;

    if (!pending) {
        return res.status(401).json({ message: "Your sign-in session has expired. Please sign in again." });
    }

    return res.status(400).json({
        message: "Authenticator codes are created in your authenticator app. Open the app to get your current code."
    });
});


/*
LOGOUT
*/
router.post("/logout", async (req, res) => {
    await writeAuditEvent(req, "logout", req.session.user?.id);

    req.session.destroy((error) => {
        if (error) {
            console.error("Unable to destroy session:", error);
            return res.status(500).json({
                message: "We couldn't sign you out. Please try again."
            });
        }

        res.clearCookie(req.app.get("sessionCookieName"), {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            path: "/"
        });

        res.json({
            success: true
        });
    });
});


module.exports = router;