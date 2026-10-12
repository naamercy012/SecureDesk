const rateLimit = require("express-rate-limit");
const { createHash } = require("crypto");
const pool = require("../../../db");

let tableInitialization;

function ensureRateLimitTable() {
    if (!tableInitialization) {
        tableInitialization = pool.query(`
            CREATE TABLE IF NOT EXISTS rate_limit_counters (
                key TEXT PRIMARY KEY,
                hits INTEGER NOT NULL,
                reset_at TIMESTAMPTZ NOT NULL
            )
        `).catch((error) => {
            tableInitialization = undefined;
            throw error;
        });
    }

    return tableInitialization;
}

class PostgresRateLimitStore {
    constructor(namespace) {
        this.namespace = namespace;
        this.windowMs = 0;
        this.localKeys = true;
    }

    async init(options) {
        this.windowMs = options.windowMs;
        await ensureRateLimitTable();
    }

    async increment(key) {
        const hashedKey = createHash("sha256")
            .update(`${this.namespace}:${key}`)
            .digest("hex");
        const result = await pool.query(
            `
            INSERT INTO rate_limit_counters (key, hits, reset_at)
            VALUES ($1, 1, NOW() + ($2 * INTERVAL '1 millisecond'))
            ON CONFLICT (key) DO UPDATE
            SET
                hits = CASE
                    WHEN rate_limit_counters.reset_at <= NOW() THEN 1
                    ELSE rate_limit_counters.hits + 1
                END,
                reset_at = CASE
                    WHEN rate_limit_counters.reset_at <= NOW()
                        THEN NOW() + ($2 * INTERVAL '1 millisecond')
                    ELSE rate_limit_counters.reset_at
                END
            RETURNING hits, reset_at
            `,
            [hashedKey, this.windowMs]
        );

        return {
            totalHits: result.rows[0].hits,
            resetTime: result.rows[0].reset_at
        };
    }

    async decrement(key) {
        const hashedKey = createHash("sha256")
            .update(`${this.namespace}:${key}`)
            .digest("hex");
        await pool.query(
            "UPDATE rate_limit_counters SET hits = GREATEST(hits - 1, 0) WHERE key = $1",
            [hashedKey]
        );
    }

    async resetKey(key) {
        const hashedKey = createHash("sha256")
            .update(`${this.namespace}:${key}`)
            .digest("hex");
        await pool.query("DELETE FROM rate_limit_counters WHERE key = $1", [hashedKey]);
    }
}

let cleanupTimer;

function createLimiter(namespace, options) {
    return rateLimit({
        ...options,
        store: new PostgresRateLimitStore(namespace)
    });
}

const apiLimiter = createLimiter("api", {
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: {
        message: "Too many requests. Please slow down and try again later."
    },
    standardHeaders: true,
    legacyHeaders: false
});

const loginLimiter = createLimiter("login", {
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: {
        message: "Too many login attempts. Please try again later."
    },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true
});

const registrationLimiter = createLimiter("register", {
    windowMs: 60 * 60 * 1000,
    max: 5,
    message: {
        message: "Too many account creation attempts. Please try again later."
    },
    standardHeaders: true,
    legacyHeaders: false
});

const verificationLimiter = createLimiter("verify-2fa", {
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: {
        message: "Too many verification attempts. Please try again later."
    },
    standardHeaders: true,
    legacyHeaders: false
});

const resendLimiter = createLimiter("resend-2fa", {
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: {
        message: "Too many code requests. Please try again later."
    },
    standardHeaders: true,
    legacyHeaders: false
});

const passwordResetRequestLimiter = createLimiter("password-reset-request", {
    windowMs: 60 * 60 * 1000,
    max: 5,
    message: {
        message: "You've requested several reset links. Please wait a while before trying again."
    },
    standardHeaders: true,
    legacyHeaders: false
});

const passwordResetCompleteLimiter = createLimiter("password-reset-complete", {
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: {
        message: "There have been too many password reset attempts. Please wait a little while and try again."
    },
    standardHeaders: true,
    legacyHeaders: false
});

if (!cleanupTimer) {
    cleanupTimer = setInterval(() => {
        pool.query("DELETE FROM rate_limit_counters WHERE reset_at <= NOW()")
            .catch((error) => {
                console.error("Unable to clean expired rate limit counters:", error);
            });
    }, 60 * 60 * 1000);
    cleanupTimer.unref();
}

module.exports = {
    apiLimiter,
    loginLimiter,
    registrationLimiter,
    verificationLimiter,
    resendLimiter,
    passwordResetRequestLimiter,
    passwordResetCompleteLimiter
};