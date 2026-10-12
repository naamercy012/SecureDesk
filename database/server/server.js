require("dotenv").config();

const express = require("express");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const path = require("path");
const helmet = require("helmet");
const cors = require("cors");

const pool = require("../db");
const authRoutes = require("./routes/auth");
const adminRoutes = require("./routes/admin");
const activityAudit = require("./server/middleware/activity-audit");
const {
    apiLimiter,
    loginLimiter,
    registrationLimiter,
    verificationLimiter,
    resendLimiter,
    passwordResetRequestLimiter,
    passwordResetCompleteLimiter
} = require("./server/middleware/ratelimit");

const app = express();
const sessionSecret = process.env.SESSION_SECRET;
const trustProxyHops = Number(process.env.TRUST_PROXY_HOPS || 0);

app.disable("x-powered-by");
if (!Number.isInteger(trustProxyHops) || trustProxyHops < 0) {
    throw new Error("TRUST_PROXY_HOPS must be a non-negative integer.");
}
app.set("trust proxy", trustProxyHops);

const requiredEnvironment = [
    ["DATABASE_URL", process.env.DATABASE_URL],
    ["SESSION_SECRET", sessionSecret],
    ["PASSWORD_PEPPER", process.env.PASSWORD_PEPPER]
];
const missingEnvironment = requiredEnvironment
    .filter(([, value]) => !value)
    .map(([name]) => name);

if (missingEnvironment.length > 0) {
    throw new Error(`Missing required environment variables: ${missingEnvironment.join(", ")}. Copy .env.example to .env and set them.`);
}

if (
    process.env.NODE_ENV === "production" &&
    (
        sessionSecret.length < 32 ||
        process.env.PASSWORD_PEPPER.length < 32 ||
        sessionSecret === process.env.PASSWORD_PEPPER
    )
) {
    throw new Error("Production SESSION_SECRET and PASSWORD_PEPPER must be different values of at least 32 characters.");
}

const isProduction = process.env.NODE_ENV === "production";
const appBaseUrl = process.env.APP_BASE_URL || (isProduction ? "" : "http://localhost:3000");
let parsedAppBaseUrl;
try {
    parsedAppBaseUrl = new URL(appBaseUrl);
} catch (error) {
    throw new Error("APP_BASE_URL must be an absolute URL for password recovery.");
}
if (
    (parsedAppBaseUrl.protocol !== "https:" && isProduction) ||
    !["http:", "https:"].includes(parsedAppBaseUrl.protocol) ||
    parsedAppBaseUrl.username ||
    parsedAppBaseUrl.password
) {
    throw new Error("APP_BASE_URL must be a valid HTTPS URL in production.");
}
app.set("appBaseUrl", parsedAppBaseUrl.origin);
const sessionCookieName = isProduction
    ? "__Host-securedesk.sid"
    : "securedesk.sid";
app.set("sessionCookieName", sessionCookieName);

app.use(helmet({
    contentSecurityPolicy: {
        useDefaults: false,
        directives: {
            defaultSrc: ["'self'"],
            fontSrc: ["'self'"],
            scriptSrc: ["'self'"],
            scriptSrcAttr: ["'none'"],
            styleSrc: ["'self'"],
            styleSrcAttr: ["'none'"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            frameAncestors: ["'none'"],
            formAction: ["'self'"],
            upgradeInsecureRequests: isProduction ? [] : null
        }
    },
    crossOriginResourcePolicy: { policy: "same-origin" },
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    strictTransportSecurity: isProduction
        ? { maxAge: 31536000, includeSubDomains: true }
        : false
}));

app.use(cors({
    origin: false
}));

app.use(express.json({
    limit: "10kb"
}));

app.use(express.urlencoded({
    extended: false,
    limit: "10kb"
}));


/*
SESSION
*/

app.use(
    session({
        name: sessionCookieName,
        store: new pgSession({
            pool: pool,
            tableName: "user_sessions",
            createTableIfMissing: true
        }),

        secret: sessionSecret,

        resave: false,

        saveUninitialized: false,

        cookie: {
            httpOnly: true,
            secure: isProduction,
            sameSite: "strict",
            path: "/",
            maxAge: 1000 * 60 * 60 * 4
        }
    })
);

app.use(activityAudit);


/*
STATIC FRONTEND
*/

app.use(
    express.static(
        path.join(__dirname, "../../public")
    )
);

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "../../public/login.html"));
});


/*
AUTH
*/

app.use(
    "/api",
    apiLimiter
);

app.use("/api", (req, res, next) => {
    res.set("Cache-Control", "no-store");
    next();
});

app.use("/api/auth", (req, res, next) => {
    if (req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS") {
        next();
        return;
    }

    const fetchSite = req.get("Sec-Fetch-Site");
    if (fetchSite && fetchSite !== "same-origin" && fetchSite !== "none") {
        res.status(403).json({ message: "This request couldn't be completed. Refresh the page and try again." });
        return;
    }

    const origin = req.get("Origin");
    if (origin) {
        let originUrl;
        try {
            originUrl = new URL(origin);
        } catch (error) {
            res.status(403).json({ message: "This request couldn't be verified. Refresh the page and try again." });
            return;
        }

        const expectedOrigin = `${req.protocol}://${req.get("host")}`;
        if (originUrl.origin !== expectedOrigin) {
            res.status(403).json({ message: "This request couldn't be completed. Refresh the page and try again." });
            return;
        }
    }

    next();
});

app.use(
    "/api/auth/login",
    loginLimiter
);

app.use(
    "/api/auth/register",
    registrationLimiter
);

app.use(
    "/api/auth/verify-2fa",
    verificationLimiter
);

app.use(
    "/api/auth/resend-2fa",
    resendLimiter
);

app.use(
    "/api/auth/password-reset/request",
    passwordResetRequestLimiter
);

app.use(
    "/api/auth/password-reset/complete",
    passwordResetCompleteLimiter
);


app.use(
    "/api/auth",
    authRoutes
);

app.use("/api/admin", adminRoutes);


/*
HEALTH CHECK
*/

app.get("/api/health", (req, res) => {

    res.json({
        status: "ok"
    });
});

app.use((error, req, res, next) => {
    if (res.headersSent) {
        next(error);
        return;
    }

    if (error.type === "entity.parse.failed") {
        res.status(400).json({ message: "Some of the information sent couldn't be read. Please check your entries and try again." });
        return;
    }

    if (error.type === "entity.too.large") {
        res.status(413).json({ message: "That request is too large. Please shorten your entries and try again." });
        return;
    }

    console.error("Unhandled request error:", error);
    res.status(500).json({ message: "Something went wrong on our end. Please try again in a moment." });
});


/*
SERVER
*/

const PORT =
    process.env.PORT || 3000;

app.listen(PORT, () => {

    console.log(
        `Server running at http://localhost:${PORT}`
    );
});