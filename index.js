// Servidor de autenticación: Express + MySQL
// -----------------------------------------------------------------------------
// Este archivo levanta un servidor HTTP con rutas para:
//  - /api/health            -> Comprobación de salud del servidor y la DB
//  - /api/auth/register     -> Registro de usuario (name, email, password)
//  - /api/auth/login        -> Inicio de sesión (email, password)
// Utiliza MySQL como base de datos, bcrypt para hash de contraseñas y CORS para
// permitir peticiones desde el frontend.
// -----------------------------------------------------------------------------

// 1) Importación de dependencias
// express  -> framework HTTP para definir rutas y middlewares
// cors     -> permite peticiones cross-origin (necesario para frontend separado)
// dotenv   -> carga variables de entorno desde un archivo .env
// mysql2   -> driver de MySQL con soporte de promesas
// bcryptjs -> librería para hashear y comparar contraseñas de forma segura
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';

// 2) Carga de variables de entorno (.env)
dotenv.config();

// 3) Inicialización de la app Express y middlewares globales
const app = express();

// Middleware que parsea automáticamente JSON en el body de las solicitudes
app.use(express.json());

// Middleware CORS: habilita el acceso desde otros orígenes (frontend)
// - origin: true       -> permite cualquier origen (o usa el que envía el navegador)
// - credentials: true  -> habilita envío de cookies/autenticación si se usa
app.use(cors({ origin: true, credentials: true }));

// 4) Variables de configuración (con valores por defecto para desarrollo)
// Estas variables se pueden definir en el .env para personalizar la conexión.
const DB_HOST = process.env.DB_HOST || process.env.MYSQLHOST || 'localhost';
const DB_PORT = Number(process.env.DB_PORT || process.env.MYSQLPORT || 3306);
const DB_USER = process.env.DB_USER || process.env.MYSQLUSER || 'root';
const DB_PASSWORD = process.env.DB_PASSWORD || process.env.MYSQLPASSWORD || '';
const DB_NAME = process.env.DB_NAME || process.env.MYSQLDATABASE || 'expense_tracker';
const PORT = process.env.PORT || 3000;
// Base pública del servidor para construir redirect_uri de OAuth
const SERVER_BASE_URL = process.env.SERVER_BASE_URL || `http://localhost:${PORT}`;
// Dónde redirigir al frontend tras OAuth si no se pasa ?redirect
const OAUTH_REDIRECT_DEFAULT = process.env.OAUTH_REDIRECT_DEFAULT || 'http://localhost:5173/auth';
// Credenciales OAuth
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const FACEBOOK_CLIENT_ID = process.env.FACEBOOK_CLIENT_ID || '';
const FACEBOOK_CLIENT_SECRET = process.env.FACEBOOK_CLIENT_SECRET || '';

// 5) Pool de conexiones MySQL (se inicializa en initDb)
// Se utiliza un pool para reutilizar conexiones y mejorar el rendimiento.
let pool;

// 6) Inicialización de base de datos y tablas necesarias
// - Crea la base de datos si no existe
// - Crea un pool de conexiones a esa base de datos
// - Asegura la existencia de la tabla 'users'
async function initDb() {
  // 6.1) Conexión temporal para crear la base de datos (si no existe)
  // En entornos gestionados (Railway) normalmente la DB ya existe y no se permiten CREATE DATABASE.
  // Si MYSQLDATABASE está presente, omitimos esta creación.
  if (!process.env.MYSQLDATABASE) {
    const connection = await mysql.createConnection({
      host: DB_HOST,
      port: DB_PORT,
      user: DB_USER,
      password: DB_PASSWORD,
      multipleStatements: true,
    });
    await connection.query(`CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\``);
    await connection.end();
  }

  // 6.2) Creamos un pool apuntando a la base de datos objetivo
  pool = mysql.createPool({
    host: DB_HOST,
    port: DB_PORT,
    user: DB_USER,
    password: DB_PASSWORD,
    database: DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    namedPlaceholders: true, // permite usar :param en las consultas
  });

  // 6.3) Creamos la tabla de usuarios si no existe
  // Campos:
  //  - id: clave primaria autoincremental
  //  - name: nombre visible del usuario
  //  - email: único por usuario (con índice UNIQUE)
  //  - password_hash: contraseña hasheada con bcrypt
  //  - created_at: marca de tiempo de creación
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      email VARCHAR(255) NOT NULL UNIQUE,
      password_hash VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  // 6.4) Creamos la tabla de gastos si no existe
  // Campos:
  //  - id: clave primaria autoincremental
  //  - user_id: referencia a users.id
  //  - amount: monto en guaraníes (entero)
  //  - category: categoría del gasto
  //  - description: descripción breve
  //  - date: fecha del gasto (YYYY-MM-DD)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS expenses (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      amount INT NOT NULL,
      category VARCHAR(50) NOT NULL,
      description VARCHAR(255) NOT NULL,
      date DATE NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT fk_expenses_user FOREIGN KEY (user_id)
        REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  // 6.5) Creamos la tabla de saldos (balances) por usuario si no existe
  //  - user_id: PK y FK hacia users.id
  //  - current_balance: saldo actual en guaraníes (entero, >= 0)
  //  - updated_at: última actualización automática
  await pool.query(`
    CREATE TABLE IF NOT EXISTS balances (
      user_id INT PRIMARY KEY,
      current_balance INT NOT NULL DEFAULT 0,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      CONSTRAINT fk_balances_user FOREIGN KEY (user_id)
        REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  // 6.6) Tabla de presupuestos mensuales por usuario
  await pool.query(`
    CREATE TABLE IF NOT EXISTS budgets (
      user_id INT NOT NULL,
      period CHAR(7) NOT NULL, -- YYYY-MM
      amount INT NOT NULL,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (user_id, period),
      CONSTRAINT fk_budgets_user FOREIGN KEY (user_id)
        REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);
}

// Helper: crear o recuperar usuario por email (para OAuth)
async function upsertSocialUser({ name, email }) {
  if (!email) throw new Error('Email requerido');
  let [rows] = await pool.query(
    'SELECT id, name, email FROM users WHERE email = :email LIMIT 1',
    { email }
  );
  if (Array.isArray(rows) && rows.length > 0) {
    return rows[0];
  }
  const random = Math.random().toString(36).slice(2);
  const password_hash = await bcrypt.hash(random, 10);
  const [insertUser] = await pool.query(
    'INSERT INTO users (name, email, password_hash) VALUES (:name, :email, :password_hash)',
    { name: name || (email.split('@')[0] || 'Usuario'), email, password_hash }
  );
  const userId = insertUser && insertUser.insertId ? insertUser.insertId : undefined;
  await pool.query(
    'INSERT INTO balances (user_id, current_balance) VALUES (:userId, 0)',
    { userId }
  );
  return { id: userId, name: name || email, email };
}

// 7) Ruta de salud para verificar que el servidor y la DB responden
// GET /api/health -> { ok: true, db: true/false }
app.get('/api/health', async (_req, res) => {
  try {
    // Consulta simple a la DB para validar conectividad
    const [rows] = await pool.query('SELECT 1 as ok');
    res.json({ ok: true, db: rows[0].ok === 1 });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'DB not reachable' });
  }
});

// 8) Registro de usuario
// POST /api/auth/register
// Body esperado: { name: string, email: string, password: string }
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body || {};

    // Validaciones básicas de campos requeridos
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Faltan campos requeridos' });
    }
    if (password.length < 6) {
      return res.status(400).json({ message: 'La contraseña debe tener al menos 6 caracteres' });
    }

    // Hasheo seguro de la contraseña (salt rounds = 10)
    const password_hash = await bcrypt.hash(password, 10);

    // Insert del nuevo usuario en la tabla
    const [insertUser] = await pool.query(
      'INSERT INTO users (name, email, password_hash) VALUES (:name, :email, :password_hash)',
      { name, email, password_hash }
    );
    const userId = insertUser && insertUser.insertId ? insertUser.insertId : undefined;
    // Inicializa el saldo del usuario en 0
    await pool.query(
      'INSERT INTO balances (user_id, current_balance) VALUES (:userId, 0)',
      { userId }
    );

    return res.status(201).json({ message: 'Usuario registrado correctamente' });
  } catch (err) {
    // Controlamos el error de entrada duplicada (email ya registrado)
    if (err && err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ message: 'El correo ya está registrado' });
    }
    // Otros errores del servidor
    console.error('Register error:', err);
    return res.status(500).json({ message: 'Error interno del servidor' });
  }
});

// 9) Login de usuario
// POST /api/auth/login
// Body esperado: { email: string, password: string }
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};

    // Validamos que vengan credenciales
    if (!email || !password) {
      return res.status(400).json({ message: 'Faltan credenciales' });
    }

    // Buscamos al usuario por email
    const [rows] = await pool.query(
      'SELECT id, name, email, password_hash FROM users WHERE email = :email LIMIT 1',
      { email }
    );
    const user = Array.isArray(rows) ? rows[0] : undefined;
    if (!user) {
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }

    // Comparamos la contraseña recibida con el hash almacenado
    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) {
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }

    // Respuesta de sesión simple (sin JWT por simplicidad)
    return res.json({
      message: 'Login exitoso',
      user: { id: user.id, name: user.name, email: user.email },
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ message: 'Error interno del servidor' });
  }
});

// 9.1) OAuth: Google
app.get('/api/auth/google/start', (req, res) => {
  try {
    const redirectFinal = req.query.redirect ? String(req.query.redirect) : OAUTH_REDIRECT_DEFAULT;
    const state = Buffer.from(JSON.stringify({ redirect: redirectFinal })).toString('base64url');
    const redirect_uri = `${SERVER_BASE_URL}/api/auth/google/callback`;
    const params = new URLSearchParams({
      client_id: GOOGLE_CLIENT_ID,
      redirect_uri,
      response_type: 'code',
      scope: 'openid email profile',
      access_type: 'online',
      state,
    });
    res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`);
  } catch (e) {
    console.error('Google start error:', e);
    res.status(500).send('OAuth start error');
  }
});

app.get('/api/auth/google/callback', async (req, res) => {
  try {
    const code = String(req.query.code || '');
    const stateRaw = req.query.state ? String(req.query.state) : '';
    const state = stateRaw ? JSON.parse(Buffer.from(stateRaw, 'base64url').toString('utf8')) : {};
    const redirectFinal = state.redirect || OAUTH_REDIRECT_DEFAULT;

    const redirect_uri = `${SERVER_BASE_URL}/api/auth/google/callback`;
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri,
        grant_type: 'authorization_code',
      }).toString(),
    });
    const tokenData = await tokenRes.json();
    if (!tokenRes.ok) throw new Error(tokenData?.error_description || 'Error al intercambiar código');

    const access_token = tokenData.access_token;
    const userRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${access_token}` },
    });
    const userInfo = await userRes.json();
    if (!userRes.ok || !userInfo || !userInfo.email) throw new Error('No se pudo obtener el perfil de Google');

    const dbUser = await upsertSocialUser({ name: userInfo.name, email: userInfo.email });
    const payload = Buffer.from(JSON.stringify({ user: { id: dbUser.id, name: dbUser.name, email: dbUser.email } })).toString('base64url');
    res.redirect(`${redirectFinal}#sso=${payload}`);
  } catch (e) {
    console.error('Google callback error:', e);
    res.status(500).send('OAuth error');
  }
});

// 9.2) OAuth: Facebook
app.get('/api/auth/facebook/start', (req, res) => {
  try {
    const redirectFinal = req.query.redirect ? String(req.query.redirect) : OAUTH_REDIRECT_DEFAULT;
    const state = Buffer.from(JSON.stringify({ redirect: redirectFinal })).toString('base64url');
    const redirect_uri = `${SERVER_BASE_URL}/api/auth/facebook/callback`;
    const params = new URLSearchParams({
      client_id: FACEBOOK_CLIENT_ID,
      redirect_uri,
      response_type: 'code',
      scope: 'email,public_profile',
      state,
    });
    res.redirect(`https://www.facebook.com/v18.0/dialog/oauth?${params.toString()}`);
  } catch (e) {
    console.error('Facebook start error:', e);
    res.status(500).send('OAuth start error');
  }
});

app.get('/api/auth/facebook/callback', async (req, res) => {
  try {
    const code = String(req.query.code || '');
    const stateRaw = req.query.state ? String(req.query.state) : '';
    const state = stateRaw ? JSON.parse(Buffer.from(stateRaw, 'base64url').toString('utf8')) : {};
    const redirectFinal = state.redirect || OAUTH_REDIRECT_DEFAULT;

    const redirect_uri = `${SERVER_BASE_URL}/api/auth/facebook/callback`;
    const tokenParams = new URLSearchParams({
      client_id: FACEBOOK_CLIENT_ID,
      client_secret: FACEBOOK_CLIENT_SECRET,
      redirect_uri,
      code,
    });
    const tokenRes = await fetch(`https://graph.facebook.com/v18.0/oauth/access_token?${tokenParams.toString()}`);
    const tokenData = await tokenRes.json();
    if (!tokenRes.ok) throw new Error(tokenData?.error?.message || 'Error al intercambiar código');

    const access_token = tokenData.access_token;
    const userRes = await fetch(`https://graph.facebook.com/me?fields=id,name,email&access_token=${encodeURIComponent(access_token)}`);
    const userInfo = await userRes.json();
    if (!userRes.ok || !userInfo || !(userInfo.email || userInfo.id)) throw new Error('No se pudo obtener el perfil de Facebook');

    const email = userInfo.email || `${userInfo.id}@facebook.local`;
    const dbUser = await upsertSocialUser({ name: userInfo.name, email });
    const payload = Buffer.from(JSON.stringify({ user: { id: dbUser.id, name: dbUser.name, email: dbUser.email } })).toString('base64url');
    res.redirect(`${redirectFinal}#sso=${payload}`);
  } catch (e) {
    console.error('Facebook callback error:', e);
    res.status(500).send('OAuth error');
  }
});

// 10) Rutas de gastos (CRUD mínimo)
// GET /api/expenses?userId=1 -> Lista gastos del usuario
app.get('/api/expenses', async (req, res) => {
  try {
    const userId = Number(req.query.userId);
    const from = req.query.from ? String(req.query.from) : undefined;
    const to = req.query.to ? String(req.query.to) : undefined;

    if (!userId) {
      return res.status(400).json({ message: 'userId es requerido' });
    }

    let sql = `SELECT 
         id,
         user_id as userId,
         amount,
         category,
         description,
         DATE_FORMAT(date, '%Y-%m-%d') as date
       FROM expenses
       WHERE user_id = :userId`;

    const params = { userId };

    if (from) {
      sql += ' AND date >= :from';
      params.from = from;
    }
    if (to) {
      sql += ' AND date <= :to';
      params.to = to;
    }

    sql += ' ORDER BY date DESC, id DESC';

    const [rows] = await pool.query(sql, params);
    return res.json({ expenses: rows });
  } catch (err) {
    console.error('GET /api/expenses error:', err);
    return res.status(500).json({ message: 'Error interno del servidor' });
  }
});

// POST /api/expenses -> Crea un gasto
// Body: { userId, amount, category, description, date }
app.post('/api/expenses', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const { userId, amount, category, description, date } = req.body || {};
    const amountNumber = Number(amount);

    if (!userId || Number.isNaN(amountNumber) || amountNumber <= 0 || !category || !description || !date) {
      conn.release();
      return res.status(400).json({ message: 'Datos inválidos' });
    }

    await conn.beginTransaction();

    // Bloqueamos/aseguramos el registro de saldo del usuario para control de concurrencia
    let [rows] = await conn.query(
      'SELECT current_balance FROM balances WHERE user_id = :userId FOR UPDATE',
      { userId }
    );

    if (!Array.isArray(rows) || rows.length === 0) {
      await conn.query(
        'INSERT INTO balances (user_id, current_balance) VALUES (:userId, 0)',
        { userId }
      );
      [rows] = await conn.query(
        'SELECT current_balance FROM balances WHERE user_id = :userId FOR UPDATE',
        { userId }
      );
    }

    // Ya no rechazamos por saldo insuficiente: permitimos saldo negativo

    const [insertExp] = await conn.query(
      `INSERT INTO expenses (user_id, amount, category, description, date)
       VALUES (:userId, :amount, :category, :description, :date)`,
      { userId, amount: amountNumber, category, description, date }
    );

    // Actualizamos saldo (puede ir negativo)
    await conn.query(
      'UPDATE balances SET current_balance = current_balance - :amount WHERE user_id = :userId',
      { amount: amountNumber, userId }
    );

    await conn.commit();
    conn.release();

    const id = insertExp && insertExp.insertId ? insertExp.insertId : undefined;
    return res.status(201).json({ expense: { id, userId, amount: amountNumber, category, description, date } });
  } catch (err) {
    try { await conn.rollback(); } catch {}
    conn.release();
    console.error('POST /api/expenses error:', err);
    return res.status(500).json({ message: 'Error interno del servidor' });
  }
});

// 10.1) Rutas de saldo
// GET /api/balance?userId=1 -> Obtiene el saldo actual del usuario
app.get('/api/balance', async (req, res) => {
  try {
    const userId = Number(req.query.userId);
    if (!userId) {
      return res.status(400).json({ message: 'userId es requerido' });
    }
    const [rows] = await pool.query(
      'SELECT current_balance as balance FROM balances WHERE user_id = :userId LIMIT 1',
      { userId }
    );
    if (!Array.isArray(rows) || rows.length === 0) {
      return res.json({ balance: 0 });
    }
    return res.json({ balance: rows[0].balance });
  } catch (err) {
    console.error('GET /api/balance error:', err);
    return res.status(500).json({ message: 'Error interno del servidor' });
  }
});

// POST /api/balance/deposit -> Aumenta el saldo disponible
// Body: { userId, amount }
app.post('/api/balance/deposit', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const { userId, amount } = req.body || {};
    const amountNumber = Number(amount);

    if (!userId || Number.isNaN(amountNumber) || amountNumber <= 0) {
      conn.release();
      return res.status(400).json({ message: 'Datos inválidos' });
    }

    await conn.beginTransaction();

    // Aseguramos existencia del registro de balance
    await conn.query(
      'INSERT INTO balances (user_id, current_balance) VALUES (:userId, 0) ON DUPLICATE KEY UPDATE current_balance = current_balance',
      { userId }
    );

    await conn.query(
      'UPDATE balances SET current_balance = current_balance + :amount WHERE user_id = :userId',
      { amount: amountNumber, userId }
    );

    const [rows] = await conn.query(
      'SELECT current_balance as balance FROM balances WHERE user_id = :userId',
      { userId }
    );

    await conn.commit();
    conn.release();

    return res.status(200).json({ balance: rows[0].balance });
  } catch (err) {
    try { await conn.rollback(); } catch {}
    conn.release();
    console.error('POST /api/balance/deposit error:', err);
    return res.status(500).json({ message: 'Error interno del servidor' });
  }
});

// 10.2) Presupuesto mensual (por periodo YYYY-MM)
app.get('/api/budget', async (req, res) => {
  try {
    const userId = Number(req.query.userId);
    const period = req.query.period ? String(req.query.period) : new Date().toISOString().slice(0, 7);
    if (!userId) {
      return res.status(400).json({ message: 'userId es requerido' });
    }
    const [rows] = await pool.query(
      'SELECT amount FROM budgets WHERE user_id = :userId AND period = :period LIMIT 1',
      { userId, period }
    );
    if (!Array.isArray(rows) || rows.length === 0) {
      return res.json({ amount: 0, period });
    }
    return res.json({ amount: rows[0].amount, period });
  } catch (err) {
    console.error('GET /api/budget error:', err);
    return res.status(500).json({ message: 'Error interno del servidor' });
  }
});

app.post('/api/budget', async (req, res) => {
  try {
    const { userId, period, amount } = req.body || {};
    const amountNumber = Number(amount);
    const p = period || new Date().toISOString().slice(0, 7);

    if (!userId || Number.isNaN(amountNumber) || amountNumber <= 0) {
      return res.status(400).json({ message: 'Datos inválidos' });
    }

    await pool.query(
      'INSERT INTO budgets (user_id, period, amount) VALUES (:userId, :period, :amount) ON DUPLICATE KEY UPDATE amount = :amount',
      { userId, period: p, amount: amountNumber }
    );

    return res.json({ amount: amountNumber, period: p });
  } catch (err) {
    console.error('POST /api/budget error:', err);
    return res.status(500).json({ message: 'Error interno del servidor' });
  }
});

// 11) Arranque del servidor
// - Primero inicializamos la DB (creación de base, pool y tablas)
// - Luego levantamos el servidor HTTP en el puerto configurado
initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Servidor corriendo en el puerto ${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to initialize DB:', err);
    process.exit(1); // Terminamos el proceso si no se puede inicializar la DB
  });
