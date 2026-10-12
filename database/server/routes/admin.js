const express = require("express");
const pool = require("../../db");
const { requireAdmin } = require("../server/middleware/auth");

const router = express.Router();
const DEFAULT_PAGE_SIZE = 25;
const MAX_PAGE_SIZE = 100;
const MAX_PAGE_NUMBER = 1_000_000;

function parsePagination(query) {
    const pageValue = query.page === undefined ? "1" : query.page;
    const limitValue = query.limit === undefined
        ? String(DEFAULT_PAGE_SIZE)
        : query.limit;

    if (
        typeof pageValue !== "string" ||
        !/^[1-9]\d*$/.test(pageValue) ||
        typeof limitValue !== "string" ||
        !/^[1-9]\d*$/.test(limitValue)
    ) {
        return null;
    }

    const page = Number(pageValue);
    const limit = Number(limitValue);
    if (
        !Number.isSafeInteger(page) ||
        page > MAX_PAGE_NUMBER ||
        !Number.isSafeInteger(limit) ||
        limit > MAX_PAGE_SIZE
    ) {
        return null;
    }

    return { page, limit, offset: (page - 1) * limit };
}

router.use(requireAdmin);

router.get("/users", async (req, res) => {
    const pagination = parsePagination(req.query);
    if (!pagination) {
        return res.status(400).json({
            message: "Choose a valid page number and a page size between 1 and 100."
        });
    }

    try {
        const [usersResult, countResult] = await Promise.all([
            pool.query(
                `
                SELECT
                    users.id,
                    users.username,
                    users.email,
                    roles.name AS role,
                    users.is_active,
                    users.two_factor_enabled,
                    users.last_seen_at,
                    users.created_at
                FROM users
                JOIN roles ON users.role_id = roles.id
                ORDER BY users.created_at DESC, users.id
                LIMIT $1 OFFSET $2
                `,
                [pagination.limit, pagination.offset]
            ),
            pool.query("SELECT COUNT(*)::int AS total FROM users")
        ]);

        res.json({
            users: usersResult.rows,
            total: countResult.rows[0].total,
            page: pagination.page,
            limit: pagination.limit
        });
    } catch (error) {
        console.error("Unable to load administrator user list:", error);
        res.status(500).json({ message: "We couldn't load account data. Please try again." });
    }
});

router.get("/audit-logs", async (req, res) => {
    const pagination = parsePagination(req.query);
    if (!pagination) {
        return res.status(400).json({
            message: "Choose a valid page number and a page size between 1 and 100."
        });
    }

    try {
        const [logsResult, countResult] = await Promise.all([
            pool.query(
                `
                SELECT
                    audit_logs.id,
                    audit_logs.request_id,
                    audit_logs.user_id,
                    users.username,
                    audit_logs.action,
                    audit_logs.ip_address,
                    audit_logs.user_agent,
                    audit_logs.status_code,
                    audit_logs.metadata->>'method' AS method,
                    audit_logs.metadata->>'path' AS path,
                    audit_logs.created_at
                FROM audit_logs
                LEFT JOIN users ON audit_logs.user_id = users.id
                ORDER BY audit_logs.created_at DESC, audit_logs.id
                LIMIT $1 OFFSET $2
                `,
                [pagination.limit, pagination.offset]
            ),
            pool.query("SELECT COUNT(*)::int AS total FROM audit_logs")
        ]);

        res.json({
            logs: logsResult.rows,
            total: countResult.rows[0].total,
            page: pagination.page,
            limit: pagination.limit
        });
    } catch (error) {
        console.error("Unable to load administrator audit logs:", error);
        res.status(500).json({ message: "We couldn't load audit logs. Please try again." });
    }
});

module.exports = router;
