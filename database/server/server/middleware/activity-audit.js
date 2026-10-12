const { randomUUID } = require("crypto");
const pool = require("../../../db");

let schemaInitialization;

function ensureAuditSchema() {
    if (!schemaInitialization) {
        schemaInitialization = pool.query(`
            ALTER TABLE audit_logs
            ADD COLUMN IF NOT EXISTS request_id UUID,
            ADD COLUMN IF NOT EXISTS status_code INTEGER,
            ADD COLUMN IF NOT EXISTS metadata JSONB
        `).then(() => pool.query(`
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ
        `)).catch((error) => {
            schemaInitialization = undefined;
            throw error;
        });
    }

    return schemaInitialization;
}

async function activityAudit(req, res, next) {
    if (!req.originalUrl.startsWith("/api/")) {
        next();
        return;
    }

    const requestId = randomUUID();
    const path = req.originalUrl.split("?")[0].slice(0, 300);
    const authenticatedUserId = req.session?.user?.id || null;
    const userId = authenticatedUserId || req.session?.pending2FA?.userId || null;
    let auditId;

    try {
        await ensureAuditSchema();
        const result = await pool.query(
            `
            INSERT INTO audit_logs (
                request_id,
                user_id,
                action,
                ip_address,
                user_agent,
                metadata
            )
            VALUES ($1, $2, 'api.request', $3, $4, $5)
            RETURNING id
            `,
            [
                requestId,
                userId,
                req.ip || null,
                (req.get("user-agent") || "").slice(0, 500),
                JSON.stringify({ method: req.method, path })
            ]
        );
        auditId = result.rows[0].id;
    } catch (error) {
        console.error("Unable to persist API activity audit event:", error);
        res.status(503).json({
            message: "Activity logging is temporarily unavailable. Please try again."
        });
        return;
    }

    res.once("finish", () => {
        const updates = [
            pool.query(
                "UPDATE audit_logs SET status_code = $1 WHERE id = $2",
                [res.statusCode, auditId]
            )
        ];

        if (authenticatedUserId && res.statusCode < 400) {
            updates.push(pool.query(
                "UPDATE users SET last_seen_at = NOW() WHERE id = $1 AND is_active = TRUE",
                [authenticatedUserId]
            ));
        }

        Promise.all(updates).catch((error) => {
            console.error(`Unable to complete API activity updates for request ${requestId}:`, error);
        });
    });

    next();
}

module.exports = activityAudit;
