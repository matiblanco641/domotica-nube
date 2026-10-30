
const express = require("express");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");

const app = express();
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
    : false
});

app.use(express.json({ limit: "100kb" }));
app.use(express.static(path.join(__dirname, "public")));

const authLimiter = rateLimit({
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

function generateToken(user) {
  return jwt.sign(
    {
      sub: String(user.id),
      email: user.email
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

// Comprobar servidor y base de datos
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

// Registrar usuario
app.post(
  "/api/auth/register",
  authLimiter,
  async (req, res) => {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();

    const password = String(req.body.password || "");

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({
        error: "Ingresá un correo válido."
      });
    }

    if (password.length < 10) {
      return res.status(400).json({
        error: "La contraseña debe tener al menos 10 caracteres."
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const passwordHash = await bcrypt.hash(password, 12);

      const result = await client.query(
        `INSERT INTO users (email, password_hash)
         VALUES ($1, $2)
         RETURNING id, email`,
        [email, passwordHash]
      );

      const user = result.rows[0];

      for (const [roomKey, name] of DEFAULT_ROOMS) {
        await client.query(
          `INSERT INTO rooms (user_id, room_key, name)
           VALUES ($1, $2, $3)`,
          [user.id, roomKey, name]
        );
      }

      await client.query("COMMIT");

      res.status(201).json({
        token: generateToken(user),
        user: {
          id: user.id,
          email: user.email
        }
      });

    } catch (error) {
      await client.query("ROLLBACK");

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
      client.release();
    }
  }
);

// Iniciar sesión
app.post(
  "/api/auth/login",
  authLimiter,
  async (req, res) => {
    try {
      const email = String(req.body.email || "")
        .trim()
        .toLowerCase();

      const password = String(req.body.password || "");

      const result = await pool.query(
        `SELECT id, email, password_hash
         FROM users
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
          email: user.email
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

// Consultar usuario conectado
app.get("/api/me", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, email, created_at
       FROM users
       WHERE id = $1`,
      [req.user.sub]
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        error: "Usuario no encontrado."
      });
    }

    res.json({
      user: result.rows[0]
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error interno." });
  }
});

// Obtener habitaciones y estados guardados
app.get("/api/rooms", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
         r.id,
         r.room_key,
         r.name,
         COALESCE(s.state, '{}'::jsonb) AS state,
         s.updated_at
       FROM rooms r
       LEFT JOIN room_states s ON s.room_id = r.id
       WHERE r.user_id = $1
       ORDER BY r.id`,
      [req.user.sub]
    );

    res.json({
      rooms: result.rows
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "No se pudieron cargar las habitaciones." });
  }
});

// Guardar estado de una habitación
app.put(
  "/api/rooms/:roomKey/state",
  authenticate,
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

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const room = await client.query(
        `SELECT id
         FROM rooms
         WHERE user_id = $1 AND room_key = $2`,
        [req.user.sub, roomKey]
      );

      if (!room.rows[0]) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error: "Habitación no encontrada."
        });
      }

      const roomId = room.rows[0].id;

      const saved = await client.query(
        `INSERT INTO room_states (room_id, state, updated_at)
         VALUES ($1, $2::jsonb, NOW())
         ON CONFLICT (room_id)
         DO UPDATE SET
           state = EXCLUDED.state,
           updated_at = NOW()
         RETURNING state, updated_at`,
        [roomId, JSON.stringify(state)]
      );

      await client.query(
        `INSERT INTO change_history
         (user_id, room_id, action, details)
         VALUES ($1, $2, $3, $4::jsonb)`,
        [
          req.user.sub,
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
      await client.query("ROLLBACK");

      console.error(error);

      res.status(500).json({
        error: "No se pudo guardar el estado."
      });

    } finally {
      client.release();
    }
  }
);

// Consultar historial de cambios
app.get("/api/history", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
         h.id,
         r.room_key,
         r.name AS room_name,
         h.action,
         h.details,
         h.created_at
       FROM change_history h
       LEFT JOIN rooms r ON r.id = h.room_id
       WHERE h.user_id = $1
       ORDER BY h.created_at DESC
       LIMIT 100`,
      [req.user.sub]
    );

    res.json({
      history: result.rows
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "No se pudo cargar el historial." });
  }
});

// Mostrar la página principal
app.use((req, res, next) => {
  if (req.method === "GET" && !req.path.startsWith("/api/")) {
    return res.sendFile(
      path.join(__dirname, "public", "index.html")
    );
  }

  next();
});

// Crear las tablas e iniciar servidor
async function startServer() {
  const schema = fs.readFileSync(
    path.join(__dirname, "database", "schema.sql"),
    "utf8"
  );

  await pool.query(schema);

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
