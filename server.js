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

if (!DATABASE_URL) {
  throw new Error("Falta configurar DATABASE_URL.");
}

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

app.use(express.json({ limit: "100kb" }));
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
// CONFIGURAR ADMINISTRADOR
// ========================================

async function ensureAdmin() {
  const email = normalizeEmail(
    process.env.ADMIN_EMAIL || "matiblanco641@gmail.com"
  );

  const password = process.env.ADMIN_PASSWORD;

  if (!validEmail(email)) {
    throw new Error("ADMIN_EMAIL no es válido.");
  }

  if (!password || password.length < 10) {
    throw new Error(
      "ADMIN_PASSWORD debe tener al menos 10 caracteres."
    );
  }

  const existing = await pool.query(
    `SELECT id
     FROM arguss_users
     WHERE email = $1`,
    [email]
  );

  let userId;

  if (existing.rows.length === 0) {
    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO arguss_users
         (email, password_hash, role, department)
       VALUES ($1, $2, 'admin', 1)
       RETURNING id`,
      [email, passwordHash]
    );

    userId = result.rows[0].id;

    console.log("Administrador ARGUSS creado correctamente.");

  } else {
    userId = existing.rows[0].id;

    await pool.query(
      `UPDATE arguss_users
       SET role = 'admin'
       WHERE id = $1`,
      [userId]
    );

    if (process.env.ADMIN_FORCE_RESET === "true") {
      const passwordHash = await bcrypt.hash(password, 12);

      await pool.query(
        `UPDATE arguss_users
         SET password_hash = $1
         WHERE id = $2`,
        [passwordHash, userId]
      );

      console.log("Contraseña del administrador actualizada.");
    }

    console.log("Permisos de administrador verificados.");
  }

  await createDefaultRooms(userId);
}

// ========================================
// TOKENS Y AUTENTICACIÓN
// ========================================

function generateToken(user) {
  return jwt.sign(
    {
      sub: String(user.id)
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function authenticate(req, res, next) {
  const header = req.headers.authorization || "";

  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({
      error: "Debés iniciar sesión."
    });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      error: "Sesión inválida o vencida."
    });
  }
}

// Consultar el usuario y su rol actual en la base de datos
async function loadCurrentUser(req, res, next) {
  try {
    const result = await pool.query(
      `SELECT id, email, role, department
       FROM arguss_users
       WHERE id = $1`,
      [req.user.sub]
    );

    if (!result.rows[0]) {
      return res.status(401).json({
        error: "La cuenta ya no existe."
      });
    }

    req.currentUser = result.rows[0];
    next();

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "No se pudo verificar la cuenta."
    });
  }
}

function requireAdmin(req, res, next) {
  if (req.currentUser?.role !== "admin") {
    return res.status(403).json({
      error: "Esta cuenta no tiene permisos de administrador."
    });
  }

  next();
}

function validState(state) {
  if (
    !state ||
    typeof state !== "object" ||
    Array.isArray(state)
  ) {
    return false;
  }

  return JSON.stringify(state).length <= 10000;
}

// ========================================
// ESTADO DEL SERVIDOR
// ========================================

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      proyecto: "ARGUSS",
      database: "connected"
    });

  } catch (error) {
    console.error(error);

    res.status(503).json({
      ok: false,
      database: "disconnected"
    });
  }
});

// ========================================
// REGISTRO DE USUARIOS
// ========================================

app.post(
  "/api/auth/register",
  authLimiter,
  async (req, res) => {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    if (!validEmail(email)) {
      return res.status(400).json({
        error: "Ingresá un correo válido."
      });
    }

    if (password.length < 10) {
      return res.status(400).json({
        error: "La contraseña debe tener al menos 10 caracteres."
      });
    }

    let client;

    try {
      client = await pool.connect();
      await client.query("BEGIN");

      const passwordHash = await bcrypt.hash(password, 12);

      const result = await client.query(
        `INSERT INTO arguss_users
           (email, password_hash, role, department)
         VALUES ($1, $2, 'user', 1)
         RETURNING id, email, role, department`,
        [email, passwordHash]
      );

      const user = result.rows[0];

      await createDefaultRooms(user.id, client);

      await client.query("COMMIT");

      res.status(201).json({
        token: generateToken(user),
        user
      });

    } catch (error) {
      if (client) {
        await client.query("ROLLBACK").catch(() => {});
      }

      if (error.code === "23505") {
        return res.status(409).json({
          error: "Ese correo ya está registrado."
        });
      }

      console.error(error);

      res.status(500).json({
        error: "No se pudo crear la cuenta."
      });

    } finally {
      if (client) client.release();
    }
  }
);

// ========================================
// INICIAR SESIÓN
// ========================================

app.post(
  "/api/auth/login",
  authLimiter,
  async (req, res) => {
    try {
      const email = normalizeEmail(req.body.email);
      const password = String(req.body.password || "");

      const result = await pool.query(
        `SELECT id, email, password_hash, role, department
         FROM arguss_users
         WHERE email = $1`,
        [email]
      );

      const user = result.rows[0];

      if (
        !user ||
        !(await bcrypt.compare(password, user.password_hash))
      ) {
        return res.status(401).json({
          error: "Correo o contraseña incorrectos."
        });
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

      res.status(500).json({
        error: "No se pudo iniciar sesión."
      });
    }
  }
);

// ========================================
// USUARIO CONECTADO
// ========================================

app.get(
  "/api/me",
  authenticate,
  loadCurrentUser,
  (req, res) => {
    res.json({
      user: req.currentUser
    });
  }
);

// ========================================
// COMPROBAR PERMISOS DE ADMINISTRADOR
// ========================================

app.get(
  "/api/admin/check",
  authenticate,
  loadCurrentUser,
  requireAdmin,
  (req, res) => {
    res.json({
      ok: true,
      message: "Permisos de administrador confirmados."
    });
  }
);

// ========================================
// LISTAR USUARIOS
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
        `SELECT id, email, department, role, created_at
         FROM arguss_users
         WHERE role = 'user'
         ORDER BY created_at DESC`
      );

      res.json({
        users: result.rows
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "No se pudieron cargar los usuarios."
      });
    }
  }
);

// ========================================
// CREAR USUARIO DESDE ADMINISTRACIÓN
// ========================================

app.post(
  "/api/admin/users",
  authenticate,
  loadCurrentUser,
  requireAdmin,
  adminLimiter,
  async (req, res) => {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");
    const department = Number(req.body.department);

    if (!validEmail(email)) {
      return res.status(400).json({
        error: "Ingresá un correo válido."
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "La contraseña debe tener al menos 8 caracteres."
      });
    }

    if (!validDepartment(department)) {
      return res.status(400).json({
        error: "Seleccioná un departamento válido."
      });
    }

    let client;

    try {
      client = await pool.connect();
      await client.query("BEGIN");

      const passwordHash = await bcrypt.hash(password, 12);

      const result = await client.query(
        `INSERT INTO arguss_users
           (email, password_hash, role, department)
         VALUES ($1, $2, 'user', $3)
         RETURNING id, email, department, role, created_at`,
        [email, passwordHash, department]
      );

      const user = result.rows[0];

      await createDefaultRooms(user.id, client);

      await client.query("COMMIT");

      res.status(201).json({
        ok: true,
        user
      });

    } catch (error) {
      if (client) {
        await client.query("ROLLBACK").catch(() => {});
      }

      if (error.code === "23505") {
        return res.status(409).json({
          error: "Ese correo ya está registrado."
        });
      }

      console.error(error);

      res.status(500).json({
        error: "No se pudo crear el usuario."
      });

    } finally {
      if (client) client.release();
    }
  }
);

// ========================================
// CAMBIAR CONTRASEÑA DE USUARIO
// ========================================

app.post(
  "/api/admin/users/:id/password",
  authenticate,
  loadCurrentUser,
  requireAdmin,
  adminLimiter,
  async (req, res) => {
    const userId = req.params.id;
    const password = String(req.body.password || "");

    if (password.length < 8) {
      return res.status(400).json({
        error: "La contraseña debe tener al menos 8 caracteres."
      });
    }

    try {
      const passwordHash = await bcrypt.hash(password, 12);

      const result = await pool.query(
        `UPDATE arguss_users
         SET password_hash = $1
         WHERE id = $2 AND role = 'user'
         RETURNING id`,
        [passwordHash, userId]
      );

      if (!result.rows[0]) {
        return res.status(404).json({
          error: "Usuario no encontrado."
        });
      }

      res.json({
        ok: true,
        message: "Contraseña actualizada."
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "No se pudo cambiar la contraseña."
      });
    }
  }
);

// ========================================
// ELIMINAR USUARIO
// ========================================

app.delete(
  "/api/admin/users/:id",
  authenticate,
  loadCurrentUser,
  requireAdmin,
  adminLimiter,
  async (req, res) => {
    try {
      const result = await pool.query(
        `DELETE FROM arguss_users
         WHERE id = $1 AND role = 'user'
         RETURNING id`,
        [req.params.id]
      );

      if (!result.rows[0]) {
        return res.status(404).json({
          error: "Usuario no encontrado."
        });
      }

      res.json({
        ok: true,
        message: "Usuario eliminado."
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "No se pudo eliminar el usuario."
      });
    }
  }
);

// ========================================
// HABITACIONES
// ========================================

app.get(
  "/api/rooms",
  authenticate,
  loadCurrentUser,
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT
           r.id,
           r.room_key,
           r.name,
           COALESCE(s.state, '{}'::jsonb) AS state,
           s.updated_at
         FROM arguss_rooms r
         LEFT JOIN arguss_room_states s
           ON s.room_id = r.id
         WHERE r.user_id = $1
         ORDER BY r.created_at`,
        [req.currentUser.id]
      );

      res.json({
        rooms: result.rows
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "No se pudieron cargar las habitaciones."
      });
    }
  }
);

// ========================================
// GUARDAR ESTADO DE HABITACIÓN
// ========================================

app.put(
  "/api/rooms/:roomKey/state",
  authenticate,
  loadCurrentUser,
  async (req, res) => {
    const roomKey = req.params.roomKey;
    const state = req.body.state;

    if (!/^[a-z0-9_-]{1,50}$/.test(roomKey)) {
      return res.status(400).json({
        error: "Identificador de habitación inválido."
      });
    }

    if (!validState(state)) {
      return res.status(400).json({
        error: "El estado enviado no es válido."
      });
    }

    let client;

    try {
      client = await pool.connect();
      await client.query("BEGIN");

      const room = await client.query(
        `SELECT id
         FROM arguss_rooms
         WHERE user_id = $1 AND room_key = $2`,
        [req.currentUser.id, roomKey]
      );

      if (!room.rows[0]) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error: "Habitación no encontrada."
        });
      }

      const roomId = room.rows[0].id;

      const saved = await client.query(
        `INSERT INTO arguss_room_states
           (room_id, state, updated_at)
         VALUES ($1, $2::jsonb, NOW())
         ON CONFLICT (room_id)
         DO UPDATE SET
           state = EXCLUDED.state,
           updated_at = NOW()
         RETURNING state, updated_at`,
        [roomId, JSON.stringify(state)]
      );

      await client.query(
        `INSERT INTO arguss_change_history
           (user_id, room_id, action, details)
         VALUES ($1, $2, $3, $4::jsonb)`,
        [
          req.currentUser.id,
          roomId,
          "state_updated",
          JSON.stringify(state)
        ]
      );

      await client.query("COMMIT");

      res.json({
        ok: true,
        state: saved.rows[0].state,
        updated_at: saved.rows[0].updated_at
      });

    } catch (error) {
      if (client) {
        await client.query("ROLLBACK").catch(() => {});
      }

      console.error(error);

      res.status(500).json({
        error: "No se pudo guardar el estado."
      });

    } finally {
      if (client) client.release();
    }
  }
);

// ========================================
// HISTORIAL
// ========================================

app.get(
  "/api/history",
  authenticate,
  loadCurrentUser,
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT
           h.id,
           r.room_key,
           r.name AS room_name,
           h.action,
           h.details,
           h.created_at
         FROM arguss_change_history h
         LEFT JOIN arguss_rooms r
           ON r.id = h.room_id
         WHERE h.user_id = $1
         ORDER BY h.created_at DESC
         LIMIT 100`,
        [req.currentUser.id]
      );

      res.json({
        history: result.rows
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "No se pudo cargar el historial."
      });
    }
  }
);

// ========================================
// MOSTRAR APLICACIÓN
// ========================================

app.use((req, res, next) => {
  if (
    req.method === "GET" &&
    !req.path.startsWith("/api/")
  ) {
    return res.sendFile(
      path.join(__dirname, "public", "index.html")
    );
  }

  next();
});

// ========================================
// INICIAR SERVIDOR
// ========================================

async function startServer() {
  const schema = fs.readFileSync(
    path.join(__dirname, "database", "schema.sql"),
    "utf8"
  );

  await pool.query(schema);
  console.log("Base de datos ARGUSS verificada.");

  await ensureAdmin();

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
