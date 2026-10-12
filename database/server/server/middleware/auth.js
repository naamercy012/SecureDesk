const pool = require("../../../db");

function requireAuth(req, res, next) {

    if (!req.session.user) {
        return res.status(401).json({
            message: "Please sign in to continue."
        });
    }

    next();
}

async function requireAdmin(req, res, next) {
    if (!req.session.user) {
        return res.status(401).json({
            message: "Please sign in to continue."
        });
    }

    try {
        const result = await pool.query(
            `
            SELECT users.is_active, roles.name AS role
            FROM users
            JOIN roles ON users.role_id = roles.id
            WHERE users.id = $1
            `,
            [req.session.user.id]
        );
        const user = result.rows[0];

        if (!user || !user.is_active) {
            return res.status(401).json({
                message: "Authentication required"
            });
        }

        if (user.role !== "admin") {
            return res.status(403).json({
                message: "You don't have permission to view this page."
            });
        }

        next();
    } catch (error) {
        console.error("Unable to verify administrator access:", error);
        res.status(500).json({
            message: "We couldn't verify your access right now. Please try again."
        });
    }
}


function requireRole(role) {

    return (req, res, next) => {

        if (!req.session.user) {
            return res.status(401).json({
                message: "Please sign in to continue."
            });
        }

        if (req.session.user.role !== role) {
            return res.status(403).json({
                message: "You don't have permission to view this page."
            });
        }

        next();
    };
}


module.exports = {
    requireAuth,
    requireRole,
    requireAdmin
};