
const express = require("express");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");

const app = express();
app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const TOTEM_API_KEY = process.env.TOTEM_API_KEY;

if (!DATABASE_URL) throw new Error("Falta DATABASE_URL.");
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET debe tener al menos 32 caracteres.");
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false,
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

app.use(express.json({ limit: "5mb" }));
app.use(express.static(path.join(__dirname, "public")));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 60,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

const totemLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

const DEFAULT_ROOMS = [
  ["dormitorio_1", "Dormitorio 1"],
  ["dormitorio_2", "Dormitorio 2"],
  ["bano", "Baño"],
  ["antebano", "Antebaño"],
  ["cocina_comedor", "Cocina-comedor"],
  ["sala_estar", "Sala de estar"],
  ["balcon", "Balcón"]
];

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validDepartment(value) {
  return [1, 2, 3].includes(Number(value));
}

function validUUID(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value || ""));
}

function validState(state) {
  return state &&
    typeof state === "object" &&
    !Array.isArray(state) &&
    JSON.stringify(state).length <= 10000;
}

async function createDefaultRooms(userId, client = pool) {
  for (const [roomKey, name] of DEFAULT_ROOMS) {
    await client.query(
      `INSERT INTO arguss_rooms (user_id, room_key, name)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id, room_key) DO NOTHING`,
      [userId, roomKey, name]
    );
  }
}

// ========================================
// ADMINISTRADOR
// ========================================

async function ensureAdmin() {
  const email = normalizeEmail(
    process.env.ADMIN_EMAIL || "matiblanco641@gmail.com"
  );
  const password = process.env.ADMIN_PASSWORD;

  if (!validEmail(email)) {
    throw new Error("ADMIN_EMAIL inválido.");
  }

  if (!password || password.length < 10) {
    throw new Error("ADMIN_PASSWORD debe tener al menos 10 caracteres.");
  }

  const result = await pool.query(
    "SELECT id FROM arguss_users WHERE email = $1",
    [email]
  );

  let userId;

  if (!result.rows.length) {
    const hash = await bcrypt.hash(password, 12);
    const created = await pool.query(
      `INSERT INTO arguss_users
       (email, password_hash, role, department)
       VALUES ($1, $2, 'admin', 1)
       RETURNING id`,
      [email, hash]
    );
    userId = created.rows[0].id;
  } else {
    userId = result.rows[0].id;
    await pool.query(
      "UPDATE arguss_users SET role = 'admin' WHERE id = $1",
      [userId]
    );

    if (process.env.ADMIN_FORCE_RESET === "true") {
      const hash = await bcrypt.hash(password, 12);
      await pool.query(
        "UPDATE arguss_users SET password_hash = $1 WHERE id = $2",
        [hash, userId]
      );
    }
  }

  await createDefaultRooms(userId);
}

async function ensureDemoAdmin() {
  if (process.env.ENABLE_DEMO_ADMIN !== "true") return;

  const email = normalizeEmail(process.env.DEMO_ADMIN_EMAIL);
  const password = process.env.DEMO_ADMIN_PASSWORD;

  if (!validEmail(email) || !password || password.length < 12) {
    throw new Error("Configuración de administrador demo inválida.");
  }

  const result = await pool.query(
    "SELECT id FROM arguss_users WHERE email = $1",
    [email]
  );

  if (!result.rows.length) {
    const hash = await bcrypt.hash(password, 12);
    const created = await pool.query(
      `INSERT INTO arguss_users
       (email, password_hash, role, department)
       VALUES ($1, $2, 'admin', 1)
       RETURNING id`,
      [email, hash]
    );
    await createDefaultRooms(created.rows[0].id);
  } else if (process.env.DEMO_ADMIN_FORCE_RESET === "true") {
    const hash = await bcrypt.hash(password, 12);
    await pool.query(
      `UPDATE arguss_users
       SET password_hash = $1, role = 'admin'
       WHERE id = $2`,
      [hash, result.rows[0].id]
    );
  }
}

// ========================================
// AUTENTICACIÓN
// ========================================

function generateToken(user) {
  return jwt.sign({ sub: String(user.id) }, JWT_SECRET, {
    expiresIn: "7d"
  });
}

function authenticate(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: "Debés iniciar sesión." });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Sesión inválida o vencida." });
  }
}

async function loadCurrentUser(req, res, next) {
  try {
    const result = await pool.query(
      `SELECT id, email, role, department
       FROM arguss_users WHERE id = $1`,
      [req.user.sub]
    );

    if (!result.rows.length) {
      return res.status(401).json({ error: "La cuenta no existe." });
    }

    req.currentUser = result.rows[0];
    next();
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "No se pudo verificar la cuenta." });
  }
}

function requireAdmin(req, res, next) {
  if (req.currentUser?.role !== "admin") {
    return res.status(403).json({ error: "Acceso administrativo denegado." });
  }
  next();
}

function authenticateTotem(req, res, next) {
  const key = req.headers["x-totem-key"];

  if (!TOTEM_API_KEY || TOTEM_API_KEY.length < 32) {
    return res.status(503).json({ error: "Tótem no configurado." });
  }

  if (typeof key !== "string" || key !== TOTEM_API_KEY) {
    return res.status(401).json({ error: "Tótem no autorizado." });
  }

  next();
}

// ========================================
// SALUD
// ========================================

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, proyecto: "ARGUSS", database: "connected" });
  } catch (error) {
    console.error(error);
    res.status(503).json({ ok: false, database: "disconnected" });
  }
});

// ========================================
// REGISTRO Y LOGIN
// ========================================

app.post("/api/auth/register", authLimiter, async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || "");

  if (!validEmail(email)) {
    return res.status(400).json({ error: "Correo inválido." });
  }
  if (password.length < 10) {
    return res.status(400).json({ error: "La contraseña debe tener al menos 10 caracteres." });
  }

  let client;

  try {
    client = await pool.connect();
    await client.query("BEGIN");

    const hash = await bcrypt.hash(password, 12);
    const result = await client.query(
      `INSERT INTO arguss_users
       (email, password_hash, role, department)
       VALUES ($1, $2, 'user', 1)
       RETURNING id, email, role, department`,
      [email, hash]
    );

    const user = result.rows[0];
    await createDefaultRooms(user.id, client);
    await client.query("COMMIT");

    res.status(201).json({ token: generateToken(user), user });
  } catch (error) {
    if (client) await client.query("ROLLBACK").catch(() => {});
    if (error.code === "23505") {
      return res.status(409).json({ error: "Ese correo ya está registrado." });
    }
    console.error(error);
    res.status(500).json({ error: "No se pudo crear la cuenta." });
  } finally {
    if (client) client.release();
  }
});

app.post("/api/auth/login", authLimiter, async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    const result = await pool.query(
      `SELECT id, email, password_hash, role, department
       FROM arguss_users WHERE email = $1`,
      [email]
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Correo o contraseña incorrectos." });
    }

    res.json({
      token: generateToken(user),
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        department: user.department
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "No se pudo iniciar sesión." });
  }
});

app.get("/api/me", authenticate, loadCurrentUser, (req, res) => {
  res.json({ user: req.currentUser });
});

// ========================================
// HABITACIONES
// ========================================

app.get("/api/rooms", authenticate, loadCurrentUser, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT r.id, r.room_key, r.name, s.state, s.updated_at
       FROM arguss_rooms r
       LEFT JOIN arguss_room_states s ON s.room_id = r.id
       WHERE r.user_id = $1
       ORDER BY r.created_at`,
      [req.currentUser.id]
    );

    res.json({ rooms: result.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "No se pudieron cargar las habitaciones." });
  }
});

app.put(
  "/api/rooms/:roomKey/state",
  authenticate,
  loadCurrentUser,
  async (req, res) => {
    const roomKey = String(req.params.roomKey || "");
    const state = req.body.state;

    if (!validState(state)) {
      return res.status(400).json({ error: "Estado inválido." });
    }

    try {
      const room = await pool.query(
        `SELECT id FROM arguss_rooms
         WHERE user_id = $1 AND room_key = $2`,
        [req.currentUser.id, roomKey]
      );

      if (!room.rows.length) {
        return res.status(404).json({ error: "Habitación no encontrada." });
      }

      await pool.query(
        `INSERT INTO arguss_room_states (room_id, state, updated_at)
         VALUES ($1, $2::jsonb, NOW())
         ON CONFLICT (room_id)
         DO UPDATE SET state = EXCLUDED.state, updated_at = NOW()`,
        [room.rows[0].id, JSON.stringify(state)]
      );

      await pool.query(
        `INSERT INTO arguss_change_history
         (user_id, room_id, action, details)
         VALUES ($1, $2, 'room_state_changed', $3::jsonb)`,
        [req.currentUser.id, room.rows[0].id, JSON.stringify(state)]
      );

      res.json({ ok: true, state });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "No se pudo actualizar la habitación." });
    }
  }
);

// ========================================
// HISTORIAL
// ========================================

app.get("/api/history", authenticate, loadCurrentUser, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT h.id, h.action, h.details, h.created_at,
              r.room_key, r.name AS room_name
       FROM arguss_change_history h
       LEFT JOIN arguss_rooms r ON r.id = h.room_id
       WHERE h.user_id = $1
       ORDER BY h.created_at DESC
       LIMIT 200`,
      [req.currentUser.id]
    );

    res.json({ history: result.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "No se pudo cargar el historial." });
  }
});

// ========================================
// ADMINISTRACIÓN DE USUARIOS
// ========================================

app.get(
  "/api/admin/users",
  authenticate,
  loadCurrentUser,
  requireAdmin,
  adminLimiter,
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT id, email, role, department, created_at
         FROM arguss_users ORDER BY created_at DESC`
      );
      res.json({ users: result.rows });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "No se pudieron cargar los usuarios." });
    }
  }
);

app.post(
  "/api/admin/users",
  authenticate,
  loadCurrentUser,
  requireAdmin,
  adminLimiter,
  async (req, res) => {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");
    const department = Number(req.body.department || 1);

    if (!validEmail(email) || password.length < 10 || !validDepartment(department)) {
      return res.status(400).json({ error: "Datos de usuario inválidos." });
    }

    let client;
    try {
      client = await pool.connect();
      await client.query("BEGIN");

      const hash = await bcrypt.hash(password, 12);
      const result = await client.query(
        `INSERT INTO arguss_users
         (email, password_hash, role, department)
         VALUES ($1, $2, 'user', $3)
         RETURNING id, email, role, department, created_at`,
        [email, hash, department]
      );

      await createDefaultRooms(result.rows[0].id, client);
      await client.query("COMMIT");
      res.status(201).json({ user: result.rows[0] });
    } catch (error) {
      if (client) await client.query("ROLLBACK").catch(() => {});
      if (error.code === "23505") {
        return res.status(409).json({ error: "Ese correo ya existe." });
      }
      console.error(error);
      res.status(500).json({ error: "No se pudo crear el usuario." });
    } finally {
      if (client) client.release();
    }
  }
);

app.post(
  "/api/admin/users/:id/password",
  authenticate,
  loadCurrentUser,
  requireAdmin,
  adminLimiter,
  async (req, res) => {
    const id = req.params.id;
    const password = String(req.body.password || "");

    if (!validUUID(id) || password.length < 10) {
      return res.status(400).json({ error: "Datos inválidos." });
    }

    try {
      const hash = await bcrypt.hash(password, 12);
      const result = await pool.query(
        `UPDATE arguss_users SET password_hash = $1
         WHERE id = $2 RETURNING id`,
        [hash, id]
      );

      if (!result.rows.length) {
        return res.status(404).json({ error: "Usuario no encontrado." });
      }

      res.json({ ok: true });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "No se pudo cambiar la contraseña." });
    }
  }
);

app.delete(
  "/api/admin/users/:id",
  authenticate,
  loadCurrentUser,
  requireAdmin,
  adminLimiter,
  async (req, res) => {
    const id = req.params.id;

    if (!validUUID(id)) {
      return res.status(400).json({ error: "ID inválido." });
    }
    if (id === String(req.currentUser.id)) {
      return res.status(400).json({ error: "No podés eliminar tu propia cuenta." });
    }

    try {
      const result = await pool.query(
        `DELETE FROM arguss_users WHERE id = $1 RETURNING id`,
        [id]
      );

      if (!result.rows.length) {
        return res.status(404).json({ error: "Usuario no encontrado." });
      }

      res.json({ ok: true });
    } catch (error) {
      console.error(error);
      res.status(500).json({
        error: "No se pudo eliminar el usuario. Puede tener datos relacionados."
      });
    }
  }
);

// ========================================
// TÓTEM: REGISTRAR VISITA
// ========================================

app.post(
  "/api/totem/visits",
  totemLimiter,
  authenticateTotem,
  async (req, res) => {
    const department = Number(req.body.department);
    const visitorName = String(req.body.visitor_name || "").trim();
    const visitorReason = String(req.body.visitor_reason || "").trim();
    const photoStorageKey = req.body.photo_storage_key
      ? String(req.body.photo_storage_key).trim()
      : null;
    const photoMimeType = req.body.photo_mime_type
      ? String(req.body.photo_mime_type).trim()
      : null;

    if (!validDepartment(department)) {
      return res.status(400).json({ error: "Departamento inválido." });
    }
    if (visitorName.length < 2 || visitorName.length > 120) {
      return res.status(400).json({ error: "Nombre de visitante inválido." });
    }
    if (visitorReason.length > 500) {
      return res.status(400).json({ error: "Motivo demasiado largo." });
    }
    if (photoStorageKey && photoStorageKey.length > 1000) {
      return res.status(400).json({ error: "Referencia de foto inválida." });
    }
    if (photoMimeType && !["image/jpeg", "image/png", "image/webp"].includes(photoMimeType)) {
      return res.status(400).json({ error: "Formato de foto inválido." });
    }

    let client;
    try {
      client = await pool.connect();
      await client.query("BEGIN");

      const result = await client.query(
        `INSERT INTO arguss_visit_requests
         (department, visitor_name, visitor_reason,
          photo_storage_key, photo_mime_type, photo_captured_at)
         VALUES ($1, $2, $3, $4, $5,
           CASE WHEN $4::text IS NOT NULL THEN NOW() ELSE NULL END)
         RETURNING id, department, visitor_name, visitor_reason,
                   status, created_at, expires_at`,
        [department, visitorName, visitorReason || null, photoStorageKey, photoMimeType]
      );

      const visit = result.rows[0];

      const users = await client.query(
        "SELECT id FROM arguss_users WHERE department = $1",
        [department]
      );

      for (const user of users.rows) {
        await client.query(
          `INSERT INTO arguss_notifications
           (user_id, visit_request_id, notification_type, title, message)
           VALUES ($1, $2, 'visit_request', $3, $4)`,
          [
            user.id,
            visit.id,
            "Nueva visita",
            `Hay un visitante esperando en el departamento ${department}.`
          ]
        );
      }

      await client.query(
        `INSERT INTO arguss_security_events
         (visit_request_id, event_type, details)
         VALUES ($1, 'visit_created', $2::jsonb)`,
        [visit.id, JSON.stringify({ department, visitor_name: visitorName })]
      );

      await client.query("COMMIT");
      res.status(201).json({ ok: true, message: "Visita registrada.", visit });
    } catch (error) {
      if (client) await client.query("ROLLBACK").catch(() => {});
      console.error("Error registrando visita:", error);
      res.status(500).json({ error: "No se pudo registrar la visita." });
    } finally {
      if (client) client.release();
    }
  }
);

// ========================================
// TÓTEM: CONSULTAR VISITAS
// ========================================

app.get("/api/visits", authenticate, loadCurrentUser, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, department, visitor_name, visitor_reason, status,
              photo_storage_key, photo_mime_type, created_at, expires_at,
              responded_by, responded_at, response_note
       FROM arguss_visit_requests
       WHERE department = $1
       ORDER BY created_at DESC LIMIT 100`,
      [req.currentUser.department]
    );
    res.json({ visits: result.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "No se pudieron cargar las visitas." });
  }
});

// ========================================
// TÓTEM: RESPONDER VISITA
// ========================================

app.patch(
  "/api/visits/:id/respond",
  authenticate,
  loadCurrentUser,
  async (req, res) => {
    const visitId = req.params.id;
    const decision = String(req.body.decision || "");

    if (!validUUID(visitId) || !["accepted", "rejected"].includes(decision)) {
      return res.status(400).json({ error: "Solicitud inválida." });
    }

    let client;
    try {
      client = await pool.connect();
      await client.query("BEGIN");

      const found = await client.query(
        `SELECT * FROM arguss_visit_requests
         WHERE id = $1 AND department = $2 FOR UPDATE`,
        [visitId, req.currentUser.department]
      );

      const visit = found.rows[0];

      if (!visit) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "Visita no encontrada." });
      }

      if (visit.status !== "pending") {
        await client.query("ROLLBACK");
        return res.status(409).json({ error: "La visita ya fue respondida." });
      }

      if (visit.expires_at && new Date(visit.expires_at) <= new Date()) {
        await client.query(
          "UPDATE arguss_visit_requests SET status = 'expired' WHERE id = $1",
          [visitId]
        );
        await client.query("COMMIT");
        return res.status(410).json({ error: "La visita venció." });
      }

      await client.query(
        `UPDATE arguss_visit_requests
         SET status = $1, responded_by = $2, responded_at = NOW()
         WHERE id = $3`,
        [decision, req.currentUser.id, visitId]
      );

      await client.query(
        `INSERT INTO arguss_security_events
         (visit_request_id, user_id, event_type, details)
         VALUES ($1, $2, $3, $4::jsonb)`,
        [
          visitId,
          req.currentUser.id,
          decision === "accepted" ? "visit_accepted" : "visit_rejected",
          JSON.stringify({ department: req.currentUser.department })
        ]
      );

      await client.query("COMMIT");
      res.json({ ok: true, status: decision });
    } catch (error) {
      if (client) await client.query("ROLLBACK").catch(() => {});
      console.error(error);
      res.status(500).json({ error: "No se pudo responder la visita." });
    } finally {
      if (client) client.release();
    }
  }
);

// ========================================
// NOTIFICACIONES
// ========================================

app.get("/api/notifications", authenticate, loadCurrentUser, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, visit_request_id, notification_type, title,
              message, is_read, created_at
       FROM arguss_notifications
       WHERE user_id = $1
       ORDER BY created_at DESC LIMIT 100`,
      [req.currentUser.id]
    );

    res.json({
      notifications: result.rows,
      unread_count: result.rows.filter(n => !n.is_read).length
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "No se pudieron cargar las notificaciones." });
  }
});

app.patch(
  "/api/notifications/:id/read",
  authenticate,
  loadCurrentUser,
  async (req, res) => {
    const id = Number(req.params.id);

    if (!Number.isSafeInteger(id) || id < 1) {
      return res.status(400).json({ error: "ID inválido." });
    }

    try {
      const result = await pool.query(
        `UPDATE arguss_notifications
         SET is_read = TRUE, read_at = NOW()
         WHERE id = $1 AND user_id = $2
         RETURNING id`,
        [id, req.currentUser.id]
      );

      if (!result.rows.length) {
        return res.status(404).json({ error: "Notificación no encontrada." });
      }

      res.json({ ok: true });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "No se pudo marcar como leída." });
    }
  }
);

// ========================================
// APLICACIÓN WEB
// ========================================

app.use((req, res, next) => {
  if (req.method === "GET" && !req.path.startsWith("/api/")) {
    return res.sendFile(path.join(__dirname, "public", "index.html"));
  }
  next();
});

// ========================================
// ERRORES API
// ========================================

app.use("/api", (req, res) => {
  res.status(404).json({ error: "Ruta API no encontrada." });
});

// ========================================
// INICIO
// ========================================

async function startServer() {
  const schemaPath = path.join(__dirname, "database", "schema.sql");
  const schema = fs.readFileSync(schemaPath, "utf8");

  await pool.query(schema);
  console.log("Base de datos ARGUSS verificada.");

  await ensureAdmin();
  await ensureDemoAdmin();

  app.listen(PORT, () => {
    console.log(`ARGUSS funcionando en puerto ${PORT}`);
  });
}

startServer().catch(error => {
  console.error("Error al iniciar ARGUSS:", error);
  process.exit(1);
});

process.on("SIGTERM", async () => {
  await pool.end();
  process.exit(0);
});
