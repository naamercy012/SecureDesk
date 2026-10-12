# SecureDesk authentication

## Setup

1. Create a project in Supabase and open its **SQL Editor**.
2. Run the contents of `database/schema.sql` to create the application tables and roles.
3. In the Supabase dashboard, open **Connect** and copy a PostgreSQL connection string. Use the session pooler connection string for a long-running Node.js server, or the direct connection if your host supports its network requirements.
4. Copy `.env.example` to `.env`. Replace `DATABASE_URL` with the complete connection string from Supabase and set `DATABASE_SSL=true`. Set `SESSION_SECRET` and `PASSWORD_PEPPER` to different, random values of at least 32 characters. In production, serve the app over HTTPS. If it is behind a reverse proxy, set `TRUST_PROXY_HOPS` to the exact number of trusted proxies between the internet and the app; leave it at `0` when the app is directly exposed.
5. Install dependencies with `npm install`.
6. Start the app with `npm start` (or use `npm run dev` during development).
7. Open `http://localhost:3000/`.

The server connects directly to Supabase PostgreSQL with the `pg` driver; it does not use the Supabase browser client. Keep the database connection string private and never put it in frontend code or commit `.env`.

## Deploying to Vercel

Import the repository into Vercel with the repository root as the project root. The root `index.js` exports the Express app for Vercel, and `vercel.json` routes `/` to the static login page in `public/`. Vercel serves files in `public/` directly; Express serves those files locally during development.

In the Vercel project settings, add the production environment variables `DATABASE_URL`, `DATABASE_SSL`, `SESSION_SECRET`, `PASSWORD_PEPPER`, and `APP_BASE_URL`. Use `DATABASE_SSL=true`, a public HTTPS origin for `APP_BASE_URL`, and different random values of at least 32 characters for `SESSION_SECRET` and `PASSWORD_PEPPER`. Add the `EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_SECURE`, `EMAIL_USER`, `EMAIL_PASS`, and `EMAIL_FROM` variables to enable password-reset email. Redeploy after changing environment variables. Keep `.env` out of Git and configure secrets in Vercel's project settings.

## Required TOTP verification

Registration requires a unique username, email address, and password. Sign-in uses the username and password. After registration, the app generates a TOTP secret and returns a QR code that must be scanned with a TOTP authenticator app such as Google Authenticator or Authy. Every sign-in requires a valid six-digit TOTP code or a one-time recovery code before the user is authenticated.

The app no longer relies on email-based challenge codes. Use a TOTP app for sign-in and setup, and keep the server secret values in `.env` as usual.

## Password recovery and signed-in devices

The sign-in page links to password recovery. A reset request always shows the same response whether or not an email address belongs to an active account. For a matching account, SecureDesk emails a random, single-use link that expires after 30 minutes. Only a SHA-256 hash of the reset token is stored. Resetting the password preserves TOTP and recovery-code settings, consumes outstanding reset links, and signs that account out of all devices. The user must sign in again with the new password and their authenticator code.

Password recovery requires the `EMAIL_HOST` and `EMAIL_FROM` settings already used for application email. Set `APP_BASE_URL` to the public site origin; use the exact HTTPS origin in production so reset links point to the deployed app. In local development the default is `http://localhost:3000`. Configure the SMTP relay for delivery; failed sends are reported in the server log without revealing account existence in the response.

Authenticated account pages show signed-in devices and allow a user to sign out one other device or all other devices while keeping the current session. Device selectors are HMAC-derived rather than raw session IDs, and revocation is restricted to the authenticated user's own sessions. Password changes and recovery invalidate every session.

## Security protections

- Argon2id password hashing with a server-side pepper.
- TOTP secrets are AES-256-GCM encrypted in the database and pending sessions using a domain-separated key derived from `PASSWORD_PEPPER`. Existing plaintext TOTP secrets are migrated after a successful TOTP sign-in; keep `PASSWORD_PEPPER` stable and backed up.
- API-wide and endpoint-specific PostgreSQL-backed rate limits, shared between instances using this database. Successful logins do not consume the failed-login allowance.
- Ten one-time recovery codes (128 bits of random entropy each) are generated after TOTP enrollment. They are shown once; store them securely. Their HMAC hashes are stored in the database and each code is consumed atomically on use.
- Every API request is recorded in Supabase before it is processed, with its route, method, user/session identity when available, request ID, IP address, and user agent; the HTTP result is recorded when the request completes. Authentication-specific events also record signup, login failures/successes, second-factor failures, recovery-code use, and logout.
- `last_seen_at` is set at successful authentication and updated after each successful authenticated API request. The account pages show the last-seen timestamp and the latest 20 account activity events.
- Password reset links are random, single-use, expire after 30 minutes, and are stored only as hashes. Reset requests use a generic response to reduce account enumeration; successful password changes preserve TOTP and revoke all sessions.
- Signed-in device management lists only the current user's sessions and lets them revoke individual other devices or sign out all other devices. The current session remains active when revoking other devices.
- Deleting an account in `public.users` keeps its audit events but sets their `user_id` to `NULL`; a database trigger also removes that user's active and pending sessions. Recovery codes and password-reset tokens are deleted by their existing cascading foreign keys.
- Administrators can use `/admin.html` to view paginated account metadata and audit events. The server checks the account's current active status and role in PostgreSQL on every admin API request. Password hashes, TOTP secrets, and recovery-code hashes are never included in these views.
- Session IDs are rotated when a verification challenge starts and after successful verification. Cookies are HttpOnly and SameSite Strict; production uses Secure and the `__Host-` cookie prefix.
- Requests to authentication endpoints reject cross-origin browser requests. Authentication responses are marked `no-store`.
- Login fails closed if TOTP enrollment is incomplete or an enabled account has no TOTP secret; pending login challenges re-check that the account remains active and 2FA-enabled.
- Helmet security headers include a restrictive Content Security Policy without inline scripts or styles. HSTS and HTTPS-upgrade policy are enabled in production.
- Production startup rejects short or reused session/password secrets. Reverse-proxy trust is disabled by default and must be configured explicitly.

The session store, PostgreSQL rate-limit table, password-reset table, audit fields, and last-seen field are initialized automatically when the app first uses PostgreSQL; `database/schema.sql` also defines them for fresh installations. Re-run `database/schema.sql` on an existing database to add/backfill the username column and add activity-audit, password-reset, and last-seen fields. Legacy accounts receive `user_` followed by the first 12 hexadecimal characters of their ID; an administrator can look these up in the database. New registrations receive the `user` role; assign `admin` only to trusted accounts directly in the database. Admin API pages use a maximum page size of 100 and return account metadata and audit event details, but never credential hashes or authentication secrets. API requests fail closed with HTTP 503 if the activity event cannot be written; updating the final HTTP status happens after the response and any update failure is reported in server logs. This is an audit trail in the same Supabase database, not an independent backup or point-in-time recovery copy. Configure Supabase backups/PITR separately for disaster recovery.
