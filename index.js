// index.js
require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const { createServer } = require('http');
const { Server }       = require('socket.io');
const mysql    = require('mysql2/promise');
const bcrypt   = require('bcrypt');
const jwt      = require('jsonwebtoken');
const { z }    = require('zod');

const app        = express();
const httpServer = createServer(app);
const io         = new Server(httpServer, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());

// Pool de MySQL
const db = mysql.createPool({
  host:     process.env.DB_HOST,
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// Esquema Zod para login
const authSchema = z.object({
  email:    z.string().email(),
  password: z.string().min(6),
});

/**
 * POST /api/auth/register
 */
app.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // 1) Validaciones básicas
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Faltan campos obligatorios.' });
    }

    // 2) ¿Ya existe el usuario?
    const [existing] = await db.query(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );
    if (existing.length) {
      return res.status(409).json({ message: 'El email ya está en uso.' });
    }

    // 3) Hasheamos la contraseña
    const password_hash = await bcrypt.hash(password, 10);

    // 4) Insertamos en la tabla
    const [result] = await db.query(
      'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
      [name, email, password_hash]
    );

    // 5) Generamos token para autologin (opcional)
    const token = jwt.sign(
      { userId: result.insertId, email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    // 6) Respondemos
    res.status(201).json({
      message: 'Usuario creado correctamente.',
      user:    { id: result.insertId, name, email },
      token
    });

  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ message: 'Error interno del servidor.' });
  }
});

/**
 * POST /api/auth/login
 */
app.post('/login', async (req, res) => {
  // Validamos con Zod
  const parsed = authSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ errors: parsed.error.format() });
  }

  const { email, password } = parsed.data;

  try {
    const [rows] = await db.query(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );
    if (!rows.length) {
      return res.status(401).json({ message: 'Usuario no encontrado.' });
    }

    const user = rows[0];
    const ok   = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ message: 'Contraseña inválida.' });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Emitimos un evento global de “usuario logueado”
    io.emit('userLoggedIn', { userId: user.id, email: user.email });

    res.json({ token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Error interno del servidor.' });
  }
});

// Socket.IO: escucha conexiones
io.on('connection', socket => {
  console.log('Cliente conectado:', socket.id);
  socket.on('disconnect', () => {
    console.log('Cliente desconectado:', socket.id);
  });
});

// Levantamos el servidor
const PORT = process.env.PORT || 3001;
httpServer.listen(PORT, () => {
  console.log(`🚀 Petlink server corriendo en puerto ${PORT}`);
});
