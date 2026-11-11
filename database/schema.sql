-- ========================================
-- BASE DE DATOS ARGUSS
-- ========================================

-- ========================================
-- USUARIOS
-- ========================================

CREATE TABLE IF NOT EXISTS arguss_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE arguss_users
ADD COLUMN IF NOT EXISTS role VARCHAR(20) NOT NULL DEFAULT 'user';

ALTER TABLE arguss_users
ADD COLUMN IF NOT EXISTS department INTEGER NOT NULL DEFAULT 1;

-- Fotografía del residente
ALTER TABLE arguss_users
ADD COLUMN IF NOT EXISTS photo_data BYTEA;

ALTER TABLE arguss_users
ADD COLUMN IF NOT EXISTS photo_mime_type VARCHAR(50);

-- PIN de seis dígitos almacenado como hash bcrypt
ALTER TABLE arguss_users
ADD COLUMN IF NOT EXISTS pin_hash TEXT;

UPDATE arguss_users
SET role = 'user'
WHERE role IS NULL OR role NOT IN ('admin', 'user');

UPDATE arguss_users
SET department = 1
WHERE department IS NULL OR department NOT IN (1, 2, 3);


-- ========================================
-- HABITACIONES
-- ========================================

CREATE TABLE IF NOT EXISTS arguss_rooms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES arguss_users(id) ON DELETE CASCADE,
    room_key VARCHAR(50) NOT NULL,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, room_key)
);


-- ========================================
-- ESTADOS DE LAS HABITACIONES
-- ========================================

CREATE TABLE IF NOT EXISTS arguss_room_states (
    id BIGSERIAL PRIMARY KEY,
    room_id UUID NOT NULL UNIQUE REFERENCES arguss_rooms(id) ON DELETE CASCADE,
    state JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ========================================
-- HISTORIAL DE CAMBIOS
-- ========================================

CREATE TABLE IF NOT EXISTS arguss_change_history (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES arguss_users(id) ON DELETE CASCADE,
    room_id UUID REFERENCES arguss_rooms(id) ON DELETE SET NULL,
    action VARCHAR(80) NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ========================================
-- TÓTEM: SOLICITUDES DE VISITAS
-- ========================================

CREATE TABLE IF NOT EXISTS arguss_visit_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    department INTEGER NOT NULL
        CHECK (department IN (1, 2, 3)),

    visitor_name VARCHAR(120) NOT NULL,
    visitor_reason VARCHAR(500),

    photo_storage_key TEXT,
    photo_mime_type VARCHAR(50),
    photo_captured_at TIMESTAMPTZ,

    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'accepted', 'rejected', 'expired')),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    expires_at TIMESTAMPTZ NOT NULL
        DEFAULT (NOW() + INTERVAL '5 minutes'),

    responded_by UUID REFERENCES arguss_users(id) ON DELETE SET NULL,
    responded_at TIMESTAMPTZ,
    response_note TEXT
);


-- ========================================
-- TÓTEM: NOTIFICACIONES
-- ========================================

CREATE TABLE IF NOT EXISTS arguss_notifications (
    id BIGSERIAL PRIMARY KEY,

    user_id UUID NOT NULL
        REFERENCES arguss_users(id) ON DELETE CASCADE,

    visit_request_id UUID
        REFERENCES arguss_visit_requests(id) ON DELETE CASCADE,

    notification_type VARCHAR(50) NOT NULL,
    title VARCHAR(150) NOT NULL,
    message TEXT NOT NULL,

    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    read_at TIMESTAMPTZ
);


-- ========================================
-- TÓTEM: EVENTOS DE SEGURIDAD
-- ========================================

CREATE TABLE IF NOT EXISTS arguss_security_events (
    id BIGSERIAL PRIMARY KEY,

    visit_request_id UUID
        REFERENCES arguss_visit_requests(id) ON DELETE SET NULL,

    user_id UUID
        REFERENCES arguss_users(id) ON DELETE SET NULL,

    event_type VARCHAR(80) NOT NULL,

    details JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ========================================
-- ÍNDICES
-- ========================================

CREATE INDEX IF NOT EXISTS idx_arguss_rooms_user_id
ON arguss_rooms(user_id);

CREATE INDEX IF NOT EXISTS idx_arguss_history_user_created
ON arguss_change_history(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_arguss_users_email
ON arguss_users(email);

CREATE INDEX IF NOT EXISTS idx_arguss_users_department
ON arguss_users(department);

CREATE INDEX IF NOT EXISTS idx_arguss_visits_department
ON arguss_visit_requests(department, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_arguss_visits_status
ON arguss_visit_requests(status);

CREATE INDEX IF NOT EXISTS idx_arguss_notifications_user
ON arguss_notifications(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_arguss_security_events_visit
ON arguss_security_events(visit_request_id);

CREATE INDEX IF NOT EXISTS idx_arguss_security_events_created
ON arguss_security_events(created_at DESC);


-- ========================================
-- FIN DEL ESQUEMA ARGUSS
-- ========================================
