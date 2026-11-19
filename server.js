

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
const UNIGUARD_API_URL = (process.env.UNIGUARD_API_URL || "").replace(/\/$/, "");
const UNIGUARD_PUBLIC_WS_URL = (process.env.UNIGUARD_PUBLIC_WS_URL || "").replace(/\/$/, "");
const UNIGUARD_RESIDENT_TOKEN = process.env.UNIGUARD_RESIDENT_TOKEN || "";



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

function parseResidentPhoto(dataUrl) {
  if (typeof dataUrl !== "string") return null;

  const match = dataUrl.match(/^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/]+=*)$/);
  if (!match) return null;

  const mimeType = match[1];
  const buffer = Buffer.from(match[2], "base64");
  if (!buffer.length || buffer.length > 3 * 1024 * 1024) return null;

  const signatures = {
    "image/jpeg": buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff,
    "image/png": buffer.length >= 8 && buffer.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])),
    "image/webp": buffer.length >= 12 && buffer.toString("ascii", 0, 4) === "RIFF" && buffer.toString("ascii", 8, 12) === "WEBP"
  };

  if (!signatures[mimeType]) return null;
  return { buffer, mimeType };
}

function validResidentPin(pin) {
  return /^\d{6}$/.test(String(pin || ""));
}




function validUUID(value) {

  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(

    String(value || "")

  );

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

// Cuenta administrativa de prueba: solo se crea si se habilita expresamente
// mediante variables de entorno. No usar credenciales de prueba en producción.
async function ensureDemoAdmin() {
  if (process.env.ENABLE_DEMO_ADMIN !== "true") return;

  const email = normalizeEmail(process.env.DEMO_ADMIN_EMAIL);
  const password = process.env.DEMO_ADMIN_PASSWORD;

  if (!validEmail(email) || !password || password.length < 12) {
    throw new Error("La cuenta demo requiere DEMO_ADMIN_EMAIL válido y DEMO_ADMIN_PASSWORD de al menos 12 caracteres.");
  }

  const existing = await pool.query(
    "SELECT id FROM arguss_users WHERE email = $1",
    [email]
  );

  if (!existing.rows[0]) {
    const passwordHash = await bcrypt.hash(password, 12);
    const created = await pool.query(
      `INSERT INTO arguss_users (email, password_hash, role, department)
       VALUES ($1, $2, 'admin', 1) RETURNING id`,
      [email, passwordHash]
    );
    await createDefaultRooms(created.rows[0].id);
    console.log("Cuenta administrativa de prueba creada.");
  } else if (process.env.DEMO_ADMIN_FORCE_RESET === "true") {
    const passwordHash = await bcrypt.hash(password, 12);
    await pool.query(
      "UPDATE arguss_users SET password_hash = $1, role = 'admin' WHERE id = $2",
      [passwordHash, existing.rows[0].id]
    );
    await createDefaultRooms(existing.rows[0].id);
    console.log("Cuenta administrativa de prueba actualizada.");
  }
}

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



// ========================================

// AUTENTICACIÓN DEL TÓTEM

// ========================================



function authenticateTotem(req, res, next) {

  const configuredKey = process.env.TOTEM_API_KEY;

  const receivedKey = req.headers["x-totem-key"];



  if (!configuredKey || configuredKey.length < 32) {

    return res.status(503).json({

      error: "El acceso del tótem no está configurado."

    });

  }



  if (

    typeof receivedKey !== "string" ||

    receivedKey !== configuredKey

  ) {

    return res.status(401).json({

      error: "Tótem no autorizado."

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

        await client.query("ROLLBACK").catch(() => { });

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

// Foto del residente autenticado. El PIN y su hash nunca se devuelven.
app.get(
  "/api/me/photo",
  authenticate,
  loadCurrentUser,
  async (req, res) => {
    try {
      const result = await pool.query(
        "SELECT photo_data, photo_mime_type FROM arguss_users WHERE id = $1",
        [req.currentUser.id]
      );
      const row = result.rows[0];
      if (!row || !row.photo_data) return res.status(404).json({ error: "Este usuario todavía no tiene fotografía." });
      res.set("Cache-Control", "private, no-store");
      res.type(row.photo_mime_type || "image/jpeg").send(row.photo_data);
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "No se pudo cargar la fotografía." });
    }
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
        `SELECT id, email, department, role, created_at,
                (photo_data IS NOT NULL) AS has_photo,
                (pin_hash IS NOT NULL) AS has_pin
         FROM arguss_users
         WHERE role = 'user'
         ORDER BY created_at DESC`
      );
      res.json({ users: result.rows });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "No se pudieron cargar los usuarios." });
    }
  }
);

app.get(
  "/api/admin/users/:id/photo",
  authenticate,
  loadCurrentUser,
  requireAdmin,
  adminLimiter,
  async (req, res) => {
    if (!validUUID(req.params.id)) {
      return res.status(400).json({ error: "Identificador de usuario inválido." });
    }
    try {
      const result = await pool.query(
        "SELECT photo_data, photo_mime_type FROM arguss_users WHERE id = $1 AND role = 'user'",
        [req.params.id]
      );
      const row = result.rows[0];
      if (!row || !row.photo_data) {
        return res.status(404).json({ error: "Fotografía no encontrada." });
      }
      res.set("Cache-Control", "private, no-store");
      res.type(row.photo_mime_type || "image/jpeg").send(row.photo_data);
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "No se pudo cargar la fotografía." });
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
    const department = Number(req.body.department);
    const pin = String(req.body.pin || "");
    const photo = parseResidentPhoto(req.body.photoData);

    if (!validEmail(email)) {
      return res.status(400).json({ error: "Ingresá un correo válido." });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: "La contraseña debe tener al menos 8 caracteres." });
    }
    if (!validDepartment(department)) {
      return res.status(400).json({ error: "Seleccioná un departamento válido." });
    }
    if (!validResidentPin(pin)) {
      return res.status(400).json({ error: "El PIN debe contener exactamente 6 números." });
    }
    if (!photo) {
      return res.status(400).json({ error: "Seleccioná una fotografía JPG, PNG o WEBP de hasta 3 MB." });
    }

    let client;
    try {
      client = await pool.connect();
      await client.query("BEGIN");

      const passwordHash = await bcrypt.hash(password, 12);
      const pinHash = await bcrypt.hash(pin, 12);

      const result = await client.query(
        `INSERT INTO arguss_users
           (email, password_hash, role, department, photo_data, photo_mime_type, pin_hash)
         VALUES ($1, $2, 'user', $3, $4, $5, $6)
         RETURNING id, email, department, role, created_at`,
        [email, passwordHash, department, photo.buffer, photo.mimeType, pinHash]
      );

      const user = result.rows[0];
      await createDefaultRooms(user.id, client);
      await client.query("COMMIT");

      res.status(201).json({ ok: true, user, message: "Residente creado con fotografía y PIN." });
    } catch (error) {
      if (client) await client.query("ROLLBACK").catch(() => { });
      if (error.code === "23505") {
        return res.status(409).json({ error: "Ese correo ya está registrado." });
      }
      console.error(error);
      res.status(500).json({ error: "No se pudo crear el usuario." });
    } finally {
      if (client) client.release();
    }
  }
); app.post(

  "/api/admin/users/:id/password",

  authenticate,

  loadCurrentUser,

  requireAdmin,

  adminLimiter,

  async (req, res) => {

    const userId = req.params.id;

    const password = String(req.body.password || "");



    if (!validUUID(userId)) {

      return res.status(400).json({

        error: "Identificador de usuario inválido."

      });

    }



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

    if (!validUUID(req.params.id)) {

      return res.status(400).json({

        error: "Identificador de usuario inválido."

      });

    }



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



    if (!/^[a-z0-9\_-]{1,50}$/.test(roomKey)) {

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

        await client.query("ROLLBACK").catch(() => { });

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

// ARGUSS - RECIBIR VISITA DESDE EL TÓTEM

// ========================================



app.post(

  "/api/totem/visits",

  totemLimiter,

  authenticateTotem,

  async (req, res) => {

    const department = Number(req.body.department);

    const visitorName = String(

      req.body.visitor_name || ""

    ).trim();



    const visitorReason = String(

      req.body.visitor_reason || ""

    ).trim();



    const photoStorageKey = req.body.photo_storage_key

      ? String(req.body.photo_storage_key).trim()

      : null;



    const photoMimeType = req.body.photo_mime_type

      ? String(req.body.photo_mime_type).trim()

      : null;



    if (!validDepartment(department)) {

      return res.status(400).json({

        error: "Departamento inválido."

      });

    }



    if (

      visitorName.length < 2 ||

      visitorName.length > 120

    ) {

      return res.status(400).json({

        error: "El nombre debe tener entre 2 y 120 caracteres."

      });

    }



    if (visitorReason.length > 500) {

      return res.status(400).json({

        error: "El motivo es demasiado largo."

      });

    }



    if (

      photoStorageKey &&

      photoStorageKey.length > 1000

    ) {

      return res.status(400).json({

        error: "Referencia de fotografía inválida."

      });

    }



    if (

      photoMimeType &&

      !["image/jpeg", "image/png", "image/webp"].includes(photoMimeType)

    ) {

      return res.status(400).json({

        error: "Formato de fotografía no permitido."

      });

    }



    let client;



    try {

      client = await pool.connect();

      await client.query("BEGIN");



      const visitResult = await client.query(

        `INSERT INTO arguss_visit_requests (

          department,

          visitor_name,

          visitor_reason,

          photo_storage_key,

          photo_mime_type,

          photo_captured_at

        )

        VALUES (

          $1, $2, $3, $4, $5,

          CASE WHEN $4::text IS NOT NULL THEN NOW()

          ELSE NULL END

        )

        RETURNING

          id, department, visitor_name,

          visitor_reason, status, created_at,

          expires_at`,

        [

          department,

          visitorName,

          visitorReason || null,

          photoStorageKey,

          photoMimeType

        ]

      );



      const visit = visitResult.rows[0];



      const usersResult = await client.query(

        `SELECT id

         FROM arguss_users

         WHERE department = $1`,

        [department]

      );



      for (const user of usersResult.rows) {

        await client.query(

          `INSERT INTO arguss_notifications (

            user_id,

            visit_request_id,

            notification_type,

            title,

            message

          )

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

        `INSERT INTO arguss_security_events (

          visit_request_id,

          event_type,

          details

        )

        VALUES ($1, 'visit_created', $2::jsonb)`,

        [

          visit.id,

          JSON.stringify({

            department,

            visitor_name: visitorName

          })

        ]

      );



      await client.query("COMMIT");



      res.status(201).json({

        ok: true,

        message: "Solicitud de visita registrada.",

        visit

      });



    } catch (error) {

      if (client) {

        await client.query("ROLLBACK").catch(() => { });

      }



      console.error("Error al registrar visita:", error);



      res.status(500).json({

        error: "No se pudo registrar la visita."

      });



    } finally {

      if (client) client.release();

    }

  }

);





// ========================================
// ARGUSS - INICIAR VIDEOLLAMADA UNIGUARD
// ========================================

app.post(
  "/api/visits/:id/call",
  authenticate,
  loadCurrentUser,
  async (req, res) => {
    const visitId = req.params.id;
    const uniguardVisitId = Number(req.body.uniguard_visit_id);
    if (!validUUID(visitId)) return res.status(400).json({ error: "Identificador de visita inválido." });
    if (!Number.isSafeInteger(uniguardVisitId) || uniguardVisitId < 1) return res.status(400).json({ error: "Falta el identificador numérico de visita de UniGuard." });
    if (!UNIGUARD_API_URL || !UNIGUARD_PUBLIC_WS_URL || !UNIGUARD_RESIDENT_TOKEN) return res.status(503).json({ error: "La conexión con UniGuard no está configurada en el servidor." });
    try {
      const visit = await pool.query(
        `SELECT id, department, status FROM arguss_visit_requests WHERE id = $1 AND department = $2 LIMIT 1`,
        [visitId, req.currentUser.department]
      );
      if (!visit.rows.length) return res.status(404).json({ error: "No se encontró la solicitud en tu departamento." });
      if (visit.rows[0].status !== "pending") return res.status(409).json({ error: "La solicitud ya fue respondida o venció." });
      const response = await fetch(`${UNIGUARD_API_URL}/api/calls`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-token": UNIGUARD_RESIDENT_TOKEN },
        body: JSON.stringify({ visit_id: uniguardVisitId }),
        signal: AbortSignal.timeout(15000)
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) return res.status(response.status).json({ error: data.detail || data.error || "UniGuard no pudo iniciar la llamada." });
      return res.json({ ok: true, call_id: data.call_id, ticket: data.resident_ticket, ws_url: `${UNIGUARD_PUBLIC_WS_URL}/ws/call/${encodeURIComponent(data.call_id)}?ticket=${encodeURIComponent(data.resident_ticket)}` });
    } catch (error) {
      console.error("Error al iniciar videollamada UniGuard:", error);
      return res.status(502).json({ error: "No se pudo conectar con UniGuard." });
    }
  }
);


// ========================================

// ARGUSS - CONSULTAR VISITAS

// ========================================



app.get(

  "/api/visits",

  authenticate,

  loadCurrentUser,

  async (req, res) => {

    try {

      const result = await pool.query(

        `SELECT

          id,

          department,

          visitor_name,

          visitor_reason,

          status,

          photo_storage_key,

          photo_mime_type,

          created_at,

          expires_at,

          responded_by,

          responded_at,

          response_note

         FROM arguss_visit_requests

         WHERE department = $1

         ORDER BY created_at DESC

         LIMIT 100`,

        [req.currentUser.department]

      );



      res.json({

        visits: result.rows

      });



    } catch (error) {

      console.error("Error al consultar visitas:", error);



      res.status(500).json({

        error: "No se pudieron cargar las visitas."

      });

    }

  }

);



// ========================================

// ARGUSS - ACEPTAR O RECHAZAR VISITA

// ========================================



app.patch(

  "/api/visits/:id/respond",

  authenticate,

  loadCurrentUser,

  async (req, res) => {

    const visitId = req.params.id;

    const decision = String(req.body.decision || "");



    if (!validUUID(visitId)) {

      return res.status(400).json({

        error: "Identificador de visita inválido."

      });

    }



    if (!["accepted", "rejected"].includes(decision)) {

      return res.status(400).json({

        error: "La respuesta debe ser accepted o rejected."

      });

    }



    let client;



    try {

      client = await pool.connect();

      await client.query("BEGIN");



      const visitResult = await client.query(

        `SELECT *

         FROM arguss_visit_requests

         WHERE id = $1

           AND department = $2

         FOR UPDATE`,

        [

          visitId,

          req.currentUser.department

        ]

      );



      const visit = visitResult.rows[0];



      if (!visit) {

        await client.query("ROLLBACK");



        return res.status(404).json({

          error: "Visita no encontrada."

        });

      }



      if (visit.status !== "pending") {

        await client.query("ROLLBACK");



        return res.status(409).json({

          error: "Esta visita ya fue respondida o no está pendiente.",

          status: visit.status

        });

      }



      if (new Date(visit.expires_at) <= new Date()) {

        await client.query(

          `UPDATE arguss_visit_requests

           SET status = 'expired'

           WHERE id = $1`,

          [visitId]

        );



        await client.query(

          `INSERT INTO arguss_security_events (

            visit_request_id,

            user_id,

            event_type

          )

          VALUES ($1, $2, 'visit_expired')`,

          [visitId, req.currentUser.id]

        );



        await client.query("COMMIT");



        return res.status(410).json({

          error: "La solicitud de visita venció."

        });

      }



      await client.query(

        `UPDATE arguss_visit_requests

         SET status = $1,

             responded_by = $2,

             responded_at = NOW()

         WHERE id = $3`,

        [

          decision,

          req.currentUser.id,

          visitId

        ]

      );



      await client.query(

        `INSERT INTO arguss_security_events (

          visit_request_id,

          user_id,

          event_type,

          details

        )

        VALUES ($1, $2, $3, $4::jsonb)`,

        [

          visitId,

          req.currentUser.id,

          decision === "accepted"

            ? "visit_accepted"

            : "visit_rejected",

          JSON.stringify({

            department: req.currentUser.department

          })

        ]

      );



      const usersResult = await client.query(

        `SELECT id

         FROM arguss_users

         WHERE department = $1

           AND id <> $2`,

        [

          req.currentUser.department,

          req.currentUser.id

        ]

      );



      const message = decision === "accepted"

        ? "La visita fue aceptada por un residente."

        : "La visita fue rechazada por un residente.";



      for (const user of usersResult.rows) {

        await client.query(

          `INSERT INTO arguss_notifications (

            user_id,

            visit_request_id,

            notification_type,

            title,

            message

          )

          VALUES ($1, $2, 'visit_response', $3, $4)`,

          [

            user.id,

            visitId,

            "Visita respondida",

            message

          ]

        );

      }



      await client.query("COMMIT");



      res.json({

        ok: true,

        message: decision === "accepted"

          ? "Visita aceptada."

          : "Visita rechazada.",

        status: decision

      });



    } catch (error) {

      if (client) {

        await client.query("ROLLBACK").catch(() => { });

      }



      console.error("Error al responder visita:", error);



      res.status(500).json({

        error: "No se pudo responder la visita."

      });



    } finally {

      if (client) client.release();

    }

  }

);



// ========================================

// ARGUSS - CONSULTAR NOTIFICACIONES

// ========================================



app.get(

  "/api/notifications",

  authenticate,

  loadCurrentUser,

  async (req, res) => {

    try {

      const result = await pool.query(

        `SELECT

          id,

          visit_request_id,

          notification_type,

          title,

          message,

          is_read,

          created_at

         FROM arguss_notifications

         WHERE user_id = $1

         ORDER BY created_at DESC

         LIMIT 100`,

        [req.currentUser.id]

      );



      res.json({

        notifications: result.rows,

        unread_count: result.rows.filter(

          notification => !notification.is_read

        ).length

      });



    } catch (error) {

      console.error("Error al cargar notificaciones:", error);



      res.status(500).json({

        error: "No se pudieron cargar las notificaciones."

      });

    }

  }

);



// ========================================

// ARGUSS - MARCAR NOTIFICACIÓN COMO LEÍDA

// ========================================



app.patch(

  "/api/notifications/:id/read",

  authenticate,

  loadCurrentUser,

  async (req, res) => {

    const notificationId = Number(req.params.id);



    if (!Number.isSafeInteger(notificationId) || notificationId < 1) {

      return res.status(400).json({

        error: "Identificador de notificación inválido."

      });

    }



    try {

      const result = await pool.query(

        `UPDATE arguss_notifications

         SET is_read = TRUE,

             read_at = NOW()

         WHERE id = $1

           AND user_id = $2

         RETURNING id`,

        [

          notificationId,

          req.currentUser.id

        ]

      );



      if (!result.rows[0]) {

        return res.status(404).json({

          error: "Notificación no encontrada."

        });

      }



      res.json({

        ok: true,

        message: "Notificación marcada como leída."

      });



    } catch (error) {

      console.error("Error al actualizar notificación:", error);



      res.status(500).json({

        error: "No se pudo actualizar la notificación."

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
