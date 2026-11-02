

CREATE TABLE IF NOT EXISTS arguss_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS arguss_rooms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL
        REFERENCES arguss_users(id) ON DELETE CASCADE,
    room_key VARCHAR(50) NOT NULL,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, room_key)
);

CREATE TABLE IF NOT EXISTS arguss_room_states (
    id BIGSERIAL PRIMARY KEY,
    room_id UUID NOT NULL UNIQUE
        REFERENCES arguss_rooms(id) ON DELETE CASCADE,
    state JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS arguss_change_history (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL
        REFERENCES arguss_users(id) ON DELETE CASCADE,
    room_id UUID
        REFERENCES arguss_rooms(id) ON DELETE SET NULL,
    action VARCHAR(80) NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_arguss_rooms_user_id
ON arguss_rooms(user_id);

CREATE INDEX IF NOT EXISTS idx_arguss_history_user_created
ON arguss_change_history(user_id, created_at DESC);
