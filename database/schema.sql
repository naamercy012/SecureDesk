CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL
);

INSERT INTO roles (name)
VALUES
    ('user'),
    ('admin')
ON CONFLICT (name) DO NOTHING;


CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    username VARCHAR(32) NOT NULL,

    email VARCHAR(255) UNIQUE NOT NULL,

    password_hash TEXT NOT NULL,

    role_id INTEGER NOT NULL
        REFERENCES roles(id),

    two_factor_enabled BOOLEAN DEFAULT FALSE,

    two_factor_secret TEXT,

    is_active BOOLEAN DEFAULT TRUE,

    last_seen_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ DEFAULT NOW(),

    updated_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE users
ADD COLUMN IF NOT EXISTS username VARCHAR(32);

ALTER TABLE users
ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ;

UPDATE users
SET username = 'user_' || substr(replace(id::text, '-', ''), 1, 12)
WHERE username IS NULL OR username = '';

ALTER TABLE users
ALTER COLUMN username SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username
ON users(username);


CREATE TABLE recovery_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

    code_hash TEXT NOT NULL,

    used_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id UUID NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user
ON password_reset_tokens(user_id);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expiry
ON password_reset_tokens(expires_at);


CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    request_id UUID,

    user_id UUID,

    action VARCHAR(100) NOT NULL,

    ip_address INET,

    user_agent TEXT,

    status_code INTEGER,

    metadata JSONB,

    created_at TIMESTAMPTZ DEFAULT NOW()
);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'public.audit_logs'::regclass
          AND conname = 'audit_logs_user_id_fkey'
          AND confdeltype <> 'n'
    ) THEN
        ALTER TABLE public.audit_logs
        DROP CONSTRAINT audit_logs_user_id_fkey;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'public.audit_logs'::regclass
          AND conname = 'audit_logs_user_id_fkey'
    ) THEN
        ALTER TABLE public.audit_logs
        ADD CONSTRAINT audit_logs_user_id_fkey
        FOREIGN KEY (user_id)
        REFERENCES public.users(id)
        ON DELETE SET NULL;
    END IF;
END
$$;

ALTER TABLE audit_logs
ADD COLUMN IF NOT EXISTS request_id UUID,
ADD COLUMN IF NOT EXISTS status_code INTEGER,
ADD COLUMN IF NOT EXISTS metadata JSONB;

CREATE OR REPLACE FUNCTION public.cleanup_user_sessions_before_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    DELETE FROM public.user_sessions
    WHERE sess::jsonb #>> '{user,id}' = OLD.id::text
       OR sess::jsonb #>> '{pending2FA,userId}' = OLD.id::text;

    RETURN OLD;
EXCEPTION
    WHEN undefined_table THEN
        RETURN OLD;
END
$$;

DROP TRIGGER IF EXISTS cleanup_user_sessions_before_delete ON public.users;

CREATE TRIGGER cleanup_user_sessions_before_delete
BEFORE DELETE ON public.users
FOR EACH ROW
EXECUTE FUNCTION public.cleanup_user_sessions_before_delete();


CREATE INDEX idx_users_email
ON users(email);

CREATE INDEX idx_audit_user
ON audit_logs(user_id);

CREATE INDEX IF NOT EXISTS idx_audit_created
ON audit_logs(created_at);

CREATE TABLE IF NOT EXISTS rate_limit_counters (
    key TEXT PRIMARY KEY,
    hits INTEGER NOT NULL,
    reset_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rate_limit_reset
ON rate_limit_counters(reset_at);