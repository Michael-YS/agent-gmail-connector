CREATE TABLE users (
    id TEXT PRIMARY KEY NOT NULL,
    google_sub TEXT NOT NULL UNIQUE,
    login_email TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('owner', 'member')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoking')),
    last_activity_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX users_single_owner_idx ON users(role) WHERE role = 'owner';

CREATE TABLE invitations (
    id TEXT PRIMARY KEY NOT NULL,
    target_email TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    invited_by TEXT NOT NULL REFERENCES users(id),
    expires_at TEXT NOT NULL,
    accepted_at TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX invitations_target_email_idx ON invitations(target_email);

CREATE TABLE web_sessions (
    id TEXT PRIMARY KEY NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token_hash TEXT NOT NULL,
    idle_expires_at TEXT NOT NULL,
    absolute_expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);
CREATE INDEX web_sessions_user_idx ON web_sessions(user_id);

CREATE TABLE oauth_transactions (
    id TEXT PRIMARY KEY NOT NULL,
    flow_type TEXT NOT NULL CHECK (flow_type IN ('login', 'gmail')),
    state_hash TEXT NOT NULL UNIQUE,
    pkce_verifier TEXT NOT NULL,
    nonce_hash TEXT NOT NULL,
    initiated_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    target_connection_id TEXT REFERENCES gmail_connections(id) ON DELETE SET NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX oauth_transactions_expires_idx ON oauth_transactions(expires_at);
CREATE INDEX oauth_transactions_target_connection_idx ON oauth_transactions(target_connection_id);

CREATE TABLE gmail_connections (
    id TEXT PRIMARY KEY NOT NULL,
    owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    google_sub TEXT NOT NULL UNIQUE,
    primary_email TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'reauth_required', 'revoking')),
    granted_scopes TEXT NOT NULL,
    refresh_token_envelope TEXT,
    last_used_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX gmail_connections_owner_idx ON gmail_connections(owner_id);

CREATE TABLE access_keys (
    id TEXT PRIMARY KEY NOT NULL,
    owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    public_prefix TEXT NOT NULL UNIQUE,
    secret_hash TEXT NOT NULL,
    generation INTEGER NOT NULL DEFAULT 1 CHECK (generation > 0),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    last_used_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX access_keys_owner_idx ON access_keys(owner_id);

CREATE TABLE access_key_grants (
    access_key_id TEXT NOT NULL REFERENCES access_keys(id) ON DELETE CASCADE,
    connection_id TEXT NOT NULL REFERENCES gmail_connections(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    PRIMARY KEY (access_key_id, connection_id)
);

CREATE TABLE managed_drafts (
    id TEXT PRIMARY KEY NOT NULL,
    connection_id TEXT NOT NULL REFERENCES gmail_connections(id) ON DELETE CASCADE,
    gmail_draft_id TEXT NOT NULL,
    stable_message_id TEXT NOT NULL UNIQUE,
    current_version TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'sending', 'sent', 'deleted', 'send_state_unknown')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (connection_id, gmail_draft_id)
);
CREATE INDEX managed_drafts_connection_idx ON managed_drafts(connection_id);

CREATE TABLE send_confirmations (
    id TEXT PRIMARY KEY NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    access_key_id TEXT NOT NULL REFERENCES access_keys(id) ON DELETE CASCADE,
    key_generation INTEGER NOT NULL,
    connection_id TEXT NOT NULL REFERENCES gmail_connections(id) ON DELETE CASCADE,
    draft_id TEXT NOT NULL REFERENCES managed_drafts(id) ON DELETE CASCADE,
    draft_version TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    result_json TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX send_confirmations_expiry_idx ON send_confirmations(expires_at);

CREATE TABLE idempotency_records (
    id TEXT PRIMARY KEY NOT NULL,
    caller_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    idempotency_key_hash TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('in_progress', 'completed', 'failed')),
    status_code INTEGER,
    result_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (caller_id, operation, idempotency_key_hash)
);

CREATE TABLE audit_events (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    access_key_id TEXT REFERENCES access_keys(id) ON DELETE SET NULL,
    connection_id TEXT REFERENCES gmail_connections(id) ON DELETE SET NULL,
    operation TEXT NOT NULL,
    result_category TEXT NOT NULL,
    latency_ms INTEGER NOT NULL CHECK (latency_ms >= 0),
    request_id TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX audit_events_created_idx ON audit_events(created_at);

CREATE TABLE rate_limit_buckets (
    bucket_key TEXT PRIMARY KEY NOT NULL,
    window_started_at TEXT NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0 CHECK (request_count >= 0),
    updated_at TEXT NOT NULL
);

CREATE TABLE instance_counters (
    counter_name TEXT PRIMARY KEY NOT NULL,
    counter_value INTEGER NOT NULL DEFAULT 0 CHECK (counter_value >= 0),
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO instance_counters (counter_name, counter_value) VALUES ('historical_gmail_authorizations', 0);

CREATE TABLE authorized_gmail_subjects (
    google_sub TEXT PRIMARY KEY NOT NULL,
    first_authorized_at TEXT NOT NULL,
    counter_name TEXT NOT NULL DEFAULT 'historical_gmail_authorizations'
        REFERENCES instance_counters(counter_name) ON DELETE RESTRICT,
    CHECK (length(trim(google_sub)) > 0)
);
CREATE INDEX authorized_gmail_subjects_counter_idx
    ON authorized_gmail_subjects(counter_name);
