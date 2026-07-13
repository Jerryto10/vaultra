
-- Client portal users (separate from admin_users)
CREATE TABLE IF NOT EXISTS client_users (
    id            TEXT PRIMARY KEY,
    client_id     TEXT NOT NULL REFERENCES clients(id),
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    REAL NOT NULL,
    last_login    REAL,
    status        TEXT NOT NULL DEFAULT 'active'
);

-- Client portal sessions
CREATE TABLE IF NOT EXISTS client_sessions (
    id            TEXT PRIMARY KEY,
    client_user_id TEXT NOT NULL REFERENCES client_users(id),
    created_at    REAL NOT NULL,
    expires_at    REAL NOT NULL,
    ip_address    TEXT
);

-- Client invitations (onboarding flow)
CREATE TABLE IF NOT EXISTS client_invitations (
    id            TEXT PRIMARY KEY,
    client_id     TEXT NOT NULL REFERENCES clients(id),
    email         TEXT NOT NULL,
    token         TEXT NOT NULL UNIQUE,
    created_at    REAL NOT NULL,
    expires_at    REAL NOT NULL,
    used          INTEGER NOT NULL DEFAULT 0
);
