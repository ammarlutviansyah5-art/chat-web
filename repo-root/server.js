
const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const nodemailer = require('nodemailer');
const { Server } = require('socket.io');
const Database = require('better-sqlite3');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: true, credentials: true }
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const SMTP_HOST = process.env.SMTP_HOST || '';
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_SECURE = String(process.env.SMTP_SECURE || 'false') === 'true';
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const SMTP_FROM = process.env.SMTP_FROM || SMTP_USER || 'no-reply@chatapp.local';

const baseDir = __dirname;
const dbPath = path.join(baseDir, 'chatapp.db');
const uploadDir = path.join(baseDir, 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });

const db = new Database(dbPath);
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_number TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  bio TEXT DEFAULT '',
  avatar_url TEXT DEFAULT '',
  last_seen INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS otp_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  purpose TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  payload_json TEXT DEFAULT '{}',
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS chats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  chat_key TEXT NOT NULL UNIQUE,
  user_a INTEGER NOT NULL,
  user_b INTEGER NOT NULL,
  last_message_id INTEGER DEFAULT 0,
  last_message_text TEXT DEFAULT '',
  last_message_time INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  chat_key TEXT NOT NULL,
  sender_id INTEGER NOT NULL,
  receiver_id INTEGER NOT NULL,
  type TEXT NOT NULL,
  content TEXT DEFAULT '',
  media_url TEXT DEFAULT '',
  caption TEXT DEFAULT '',
  file_name TEXT DEFAULT '',
  file_size TEXT DEFAULT '',
  duration TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'sent',
  created_at INTEGER NOT NULL,
  delivered_at INTEGER DEFAULT 0,
  read_at INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS statuses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  media_url TEXT NOT NULL,
  media_type TEXT NOT NULL,
  caption TEXT DEFAULT '',
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS blocks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  blocker_id INTEGER NOT NULL,
  blocked_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(blocker_id, blocked_id)
);
CREATE TABLE IF NOT EXISTS contacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  contact_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(user_id, contact_id)
);
`);

function now() { return Date.now(); }
function rand6() {
  return String(Math.floor(100000 + Math.random() * 900000));
}
function makeChatKey(a, b) {
  return [a, b].sort((x, y) => Number(x) - Number(y)).join(':');
}
function publicUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    userNumber: row.user_number,
    name: row.name,
    email: row.email,
    bio: row.bio || '',
    avatar: row.avatar_url || '',
    avatarLetter: (row.name || '?').trim().charAt(0).toUpperCase() || '?',
    lastSeen: row.last_seen || 0,
    online: !!onlineUsers.has(String(row.id))
  };
}
function fmtTime(ts) {
  try {
    return new Intl.DateTimeFormat('id-ID', { hour: '2-digit', minute: '2-digit' }).format(new Date(ts));
  } catch { return ''; }
}
function timeAgo(ts) {
  const diff = Math.max(0, Date.now() - Number(ts || 0));
  const m = Math.floor(diff / 60000);
  const h = Math.floor(diff / 3600000);
  const d = Math.floor(diff / 86400000);
  if (!ts) return 'Belum pernah online';
  if (m < 1) return 'baru saja';
  if (m < 60) return `Terakhir online ${m} menit lalu`;
  if (h < 24) return `Terakhir online ${h} jam lalu`;
  return `Terakhir online ${d} hari lalu`;
}
function issueJwt(user) {
  return jwt.sign({ sub: String(user.id), email: user.email, userNumber: user.user_number }, JWT_SECRET, { expiresIn: '30d' });
}
function authFromReq(req) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : req.cookies?.token;
  if (!token) return null;
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}
function getUserById(id) {
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
}
function getUserByEmail(email) {
  return db.prepare('SELECT * FROM users WHERE lower(email) = lower(?)').get(email);
}
function getUserByNumber(userNumber) {
  return db.prepare('SELECT * FROM users WHERE user_number = ?').get(userNumber);
}
function ensureContact(userId, contactId) {
  const stmt = db.prepare('INSERT OR IGNORE INTO contacts (user_id, contact_id, created_at) VALUES (?, ?, ?)');
  stmt.run(userId, contactId, now());
  stmt.run(contactId, userId, now());
}
function isBlocked(senderId, receiverId) {
  const row = db.prepare('SELECT 1 FROM blocks WHERE blocker_id = ? AND blocked_id = ?').get(receiverId, senderId);
  return !!row;
}
function getChatListFor(userId) {
  const messages = db.prepare(`
    SELECT * FROM messages
    WHERE sender_id = ? OR receiver_id = ?
    ORDER BY created_at DESC
  `).all(userId, userId);
  const map = new Map();
  for (const m of messages) {
    const otherId = Number(m.sender_id) === Number(userId) ? Number(m.receiver_id) : Number(m.sender_id);
    if (!map.has(otherId)) {
      map.set(otherId, {
        lastMsg: m.type === 'text' ? (m.content || '') : (m.type === 'image' ? '🖼️ Foto' : m.type === 'video' ? '🎬 Video' : m.type === 'document' ? '📎 Dokumen' : 'Pesan'),
        lastTime: fmtTime(m.created_at),
        unread: 0,
        messages: []
      });
    }
  }
  // unread counts
  const unreadRows = db.prepare(`
    SELECT sender_id, COUNT(*) as cnt
    FROM messages
    WHERE receiver_id = ? AND read_at = 0
    GROUP BY sender_id
  `).all(userId);
  const unreadMap = new Map(unreadRows.map(r => [Number(r.sender_id), Number(r.cnt)]));
  const entries = [...map.entries()].map(([otherId, chat]) => {
    chat.unread = unreadMap.get(otherId) || 0;
    return [otherId, chat];
  });
  return Object.fromEntries(entries);
}
function getMessages(userId, otherId) {
  const chatKey = makeChatKey(userId, otherId);
  const rows = db.prepare(`
    SELECT * FROM messages
    WHERE chat_key = ?
    ORDER BY created_at ASC, id ASC
  `).all(chatKey);
  return rows.map(m => ({
    id: String(m.id),
    from: Number(m.sender_id) === Number(userId) ? 'me' : String(m.sender_id),
    type: m.type,
    content: m.content || '',
    src: m.media_url || '',
    caption: m.caption || '',
    name: m.file_name || '',
    size: m.file_size || '',
    duration: m.duration || '',
    status: m.status || 'sent',
    time: fmtTime(m.created_at),
    ts: m.created_at,
  }));
}
function getStatusesFor(userId) {
  return db.prepare(`
    SELECT s.*, u.name, u.avatar_url, u.user_number
    FROM statuses s
    JOIN users u ON u.id = s.user_id
    WHERE s.expires_at > ? AND s.user_id != ?
    ORDER BY s.created_at DESC
  `).all(now(), userId).map(s => ({
    id: String(s.id),
    contactId: String(s.user_id),
    items: [{
      id: String(s.id),
      type: s.media_type,
      src: s.media_url,
      caption: s.caption || '',
      time: fmtTime(s.created_at),
      ts: s.created_at,
    }]
  }));
}
function getBootstrap(userId) {
  const meRow = getUserById(userId);
  const me = publicUser(meRow);
  const contactsRows = db.prepare(`
    SELECT u.*
    FROM users u
    WHERE u.id != ?
    ORDER BY COALESCE((SELECT MAX(created_at) FROM messages m WHERE (m.sender_id = u.id AND m.receiver_id = ?) OR (m.receiver_id = u.id AND m.sender_id = ?)), u.created_at) DESC
  `).all(userId, userId, userId);
  const contacts = contactsRows.map(row => {
    const blocked = !!db.prepare('SELECT 1 FROM blocks WHERE blocker_id = ? AND blocked_id = ?').get(userId, row.id);
    const chat = getChatListFor(userId)[row.id] || { unread: 0, lastMsg: '', lastTime: '', messages: [] };
    return {
      ...publicUser(row),
      blocked,
      online: onlineUsers.has(String(row.id)),
      lastSeenText: timeAgo(row.last_seen),
      ...chat
    };
  });
  const chats = getChatListFor(userId);
  const statuses = getStatusesFor(userId);
  return { me, contacts, chats, statuses };
}

async function sendMail({ to, subject, html, text }) {
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) {
    console.log('--- EMAIL FALLBACK ---');
    console.log('To:', to);
    console.log('Subject:', subject);
    console.log('Text:', text || html);
    console.log('----------------------');
    return;
  }
  const transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_SECURE,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
  await transporter.sendMail({ from: SMTP_FROM, to, subject, html, text });
}

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, uploadDir),
  filename: (_, file, cb) => {
    const ext = path.extname(file.originalname || '').toLowerCase() || '.bin';
    const safe = file.fieldname + '-' + Date.now() + '-' + crypto.randomBytes(6).toString('hex') + ext;
    cb(null, safe);
  }
});
const upload = multer({ storage, limits: { fileSize: 250 * 1024 * 1024 } });

app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));
app.use('/uploads', express.static(uploadDir));
app.use(express.static(baseDir));

app.get('/', (_req, res) => res.redirect('/login.html'));
app.get('/app', (_req, res) => res.sendFile(path.join(baseDir, 'index.html')));

function requireAuth(req, res, next) {
  const payload = authFromReq(req);
  if (!payload) return res.status(401).json({ error: 'Unauthorized' });
  req.auth = payload;
  next();
}

app.post('/api/auth/register-init', async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Nama, email, dan password wajib diisi.' });
  const normalized = String(email).trim().toLowerCase();
  if (getUserByEmail(normalized)) return res.status(409).json({ error: 'Email sudah terdaftar.' });
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const codeHash = await bcrypt.hash(code, 10);
  const payload = { name: String(name).trim(), email: normalized, password: String(password) };
  db.prepare('INSERT INTO otp_codes (email, purpose, code_hash, payload_json, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(normalized, 'register', codeHash, JSON.stringify(payload), now() + 10 * 60 * 1000, now());
  await sendMail({
    to: normalized,
    subject: 'Kode verifikasi pendaftaran ChatApp',
    text: `Kode verifikasi Anda: ${code}. Jangan beritahu kode ini kepada siapapun. Kode ini hanya berlaku selama beberapa menit. Jika Anda tidak meminta kode ini, abaikan pesan ini.`,
    html: `<div style="font-family:Arial,sans-serif;line-height:1.6;color:#111">
      <h2 style="margin:0 0 12px">Verifikasi pendaftaran ChatApp</h2>
      <p>Berikut kode verifikasi untuk menyelesaikan pendaftaran akun Anda:</p>
      <div style="font-size:28px;font-weight:700;letter-spacing:6px;padding:16px 18px;background:#f4f4f4;border-radius:12px;display:inline-block">${code}</div>
      <p style="margin-top:16px">Jangan beritahu kode ini kepada siapapun. Kode ini hanya berlaku selama beberapa menit. Jika Anda tidak meminta kode ini, abaikan pesan ini.</p>
      <p>Terima kasih,<br>Tim ChatApp</p>
    </div>`
  });
  res.json({ ok: true, needsOtp: true });
});

app.post('/api/auth/register-verify', async (req, res) => {
  const { email, code } = req.body || {};
  const normalized = String(email || '').trim().toLowerCase();
  const row = db.prepare('SELECT * FROM otp_codes WHERE email = ? AND purpose = ? AND consumed_at = 0 ORDER BY id DESC LIMIT 1').get(normalized, 'register');
  if (!row) return res.status(400).json({ error: 'Kode tidak ditemukan atau sudah kedaluwarsa.' });
  if (row.expires_at < now()) return res.status(400).json({ error: 'Kode OTP sudah kedaluwarsa.' });
  const match = await bcrypt.compare(String(code || ''), row.code_hash);
  if (!match) return res.status(400).json({ error: 'Kode OTP tidak valid.' });
  const payload = JSON.parse(row.payload_json || '{}');
  if (getUserByEmail(normalized)) return res.status(409).json({ error: 'Email sudah terdaftar.' });
  const passwordHash = await bcrypt.hash(payload.password, 12);
  let userNumber = rand6();
  while (getUserByNumber(userNumber)) userNumber = rand6();
  const ts = now();
  const info = db.prepare('INSERT INTO users (user_number, name, email, password_hash, bio, avatar_url, last_seen, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .run(userNumber, payload.name, normalized, passwordHash, '', '', 0, ts, ts);
  db.prepare('UPDATE otp_codes SET consumed_at = ? WHERE id = ?').run(ts, row.id);
  const user = getUserById(info.lastInsertRowid);
  const token = issueJwt(user);
  res.json({ ok: true, token, me: publicUser(user) });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const user = getUserByEmail(String(email || '').trim().toLowerCase());
  if (!user) return res.status(401).json({ error: 'Email atau password salah.' });
  const ok = await bcrypt.compare(String(password || ''), user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Email atau password salah.' });
  const token = issueJwt(user);
  res.json({ ok: true, token, me: publicUser(user) });
});

app.post('/api/auth/request-reset', async (req, res) => {
  const { email } = req.body || {};
  const normalized = String(email || '').trim().toLowerCase();
  const user = getUserByEmail(normalized);
  if (!user) return res.status(404).json({ error: 'Email tidak ditemukan.' });
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const codeHash = await bcrypt.hash(code, 10);
  db.prepare('INSERT INTO otp_codes (email, purpose, code_hash, payload_json, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(normalized, 'reset', codeHash, JSON.stringify({}), now() + 10 * 60 * 1000, now());
  await sendMail({
    to: normalized,
    subject: 'Kode reset password ChatApp',
    text: `Kode reset password Anda: ${code}. Jangan beritahu kode ini kepada siapapun. Kode ini hanya berlaku selama beberapa menit. Jika Anda tidak meminta kode ini, abaikan pesan ini.`,
    html: `<div style="font-family:Arial,sans-serif;line-height:1.6;color:#111">
      <h2 style="margin:0 0 12px">Reset password ChatApp</h2>
      <p>Gunakan kode berikut untuk melanjutkan proses penggantian kata sandi:</p>
      <div style="font-size:28px;font-weight:700;letter-spacing:6px;padding:16px 18px;background:#f4f4f4;border-radius:12px;display:inline-block">${code}</div>
      <p style="margin-top:16px">Jangan beritahu kode ini kepada siapapun. Kode ini hanya berlaku selama beberapa menit. Jika Anda tidak meminta kode ini, abaikan pesan ini.</p>
      <p>Terima kasih,<br>Tim ChatApp</p>
    </div>`
  });
  res.json({ ok: true, needsOtp: true });
});

app.post('/api/auth/reset-verify', async (req, res) => {
  const { email, code, newPassword } = req.body || {};
  const normalized = String(email || '').trim().toLowerCase();
  const row = db.prepare('SELECT * FROM otp_codes WHERE email = ? AND purpose = ? AND consumed_at = 0 ORDER BY id DESC LIMIT 1').get(normalized, 'reset');
  if (!row) return res.status(400).json({ error: 'Kode tidak ditemukan atau sudah kedaluwarsa.' });
  if (row.expires_at < now()) return res.status(400).json({ error: 'Kode OTP sudah kedaluwarsa.' });
  const match = await bcrypt.compare(String(code || ''), row.code_hash);
  if (!match) return res.status(400).json({ error: 'Kode OTP tidak valid.' });
  const user = getUserByEmail(normalized);
  if (!user) return res.status(404).json({ error: 'Email tidak ditemukan.' });
  const hash = await bcrypt.hash(String(newPassword || ''), 12);
  db.prepare('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?').run(hash, now(), user.id);
  db.prepare('UPDATE otp_codes SET consumed_at = ? WHERE id = ?').run(now(), row.id);
  res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const user = getUserById(req.auth.sub);
  if (!user) return res.status(404).json({ error: 'User tidak ditemukan.' });
  res.json({ ok: true, me: publicUser(user) });
});

app.get('/api/bootstrap', requireAuth, (req, res) => {
  res.json({ ok: true, ...getBootstrap(req.auth.sub) });
});

app.get('/api/chats/:contactId/messages', requireAuth, (req, res) => {
  const me = Number(req.auth.sub);
  const contact = getUserById(req.params.contactId) || getUserByNumber(req.params.contactId);
  if (!contact) return res.status(404).json({ error: 'Kontak tidak ditemukan.' });
  res.json({ ok: true, messages: getMessages(me, contact.id) });
});

app.put('/api/profile', requireAuth, upload.single('avatar'), async (req, res) => {
  const me = Number(req.auth.sub);
  const current = getUserById(me);
  if (!current) return res.status(404).json({ error: 'User tidak ditemukan.' });
  const name = String(req.body.name || current.name).trim() || current.name;
  const bio = String(req.body.bio || current.bio || '');
  let avatarUrl = current.avatar_url || '';
  if (req.file) avatarUrl = `/uploads/${req.file.filename}`;
  db.prepare('UPDATE users SET name = ?, bio = ?, avatar_url = ?, updated_at = ? WHERE id = ?')
    .run(name, bio, avatarUrl, now(), me);
  res.json({ ok: true, me: publicUser(getUserById(me)) });
  io.to(`user:${me}`).emit('profile:update', publicUser(getUserById(me)));
});

app.post('/api/block', requireAuth, (req, res) => {
  const me = Number(req.auth.sub);
  const target = Number(req.body.userId);
  const exists = db.prepare('SELECT 1 FROM blocks WHERE blocker_id = ? AND blocked_id = ?').get(me, target);
  if (exists) {
    db.prepare('DELETE FROM blocks WHERE blocker_id = ? AND blocked_id = ?').run(me, target);
    res.json({ ok: true, blocked: false });
  } else {
    db.prepare('INSERT OR IGNORE INTO blocks (blocker_id, blocked_id, created_at) VALUES (?, ?, ?)').run(me, target, now());
    res.json({ ok: true, blocked: true });
  }
});

app.post('/api/report', requireAuth, (req, res) => {
  console.log('REPORT', req.auth.sub, req.body);
  res.json({ ok: true });
});

app.post('/api/status/photo', requireAuth, upload.single('media'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'File foto wajib diunggah.' });
  const me = Number(req.auth.sub);
  const caption = String(req.body.caption || '');
  const ts = now();
  db.prepare('INSERT INTO statuses (user_id, media_url, media_type, caption, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(me, `/uploads/${req.file.filename}`, 'image', caption, ts, ts + 24 * 60 * 60 * 1000);
  const status = db.prepare('SELECT * FROM statuses WHERE id = last_insert_rowid()').get();
  io.emit('status:new', { userId: String(me), status: { id: String(status.id), contactId: String(me), items: [{ id: String(status.id), type: 'image', src: status.media_url, caption: status.caption || '', time: fmtTime(status.created_at), ts: status.created_at }] } });
  res.json({ ok: true });
});

app.post('/api/status/video', requireAuth, upload.single('media'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'File video wajib diunggah.' });
  const me = Number(req.auth.sub);
  const caption = String(req.body.caption || '');
  const ts = now();
  db.prepare('INSERT INTO statuses (user_id, media_url, media_type, caption, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(me, `/uploads/${req.file.filename}`, 'video', caption, ts, ts + 24 * 60 * 60 * 1000);
  const status = db.prepare('SELECT * FROM statuses WHERE id = last_insert_rowid()').get();
  io.emit('status:new', { userId: String(me), status: { id: String(status.id), contactId: String(me), items: [{ id: String(status.id), type: 'video', src: status.media_url, caption: status.caption || '', time: fmtTime(status.created_at), ts: status.created_at }] } });
  res.json({ ok: true });
});

app.get('/api/status', requireAuth, (req, res) => {
  res.json({ ok: true, statuses: getStatusesFor(Number(req.auth.sub)) });
});

app.post('/api/messages/media', requireAuth, upload.single('media'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Media wajib diunggah.' });
  const me = Number(req.auth.sub);
  const { receiverId, type, caption, name, size, duration } = req.body || {};
  const receiver = getUserById(receiverId) || getUserByNumber(receiverId);
  if (!receiver) return res.status(404).json({ error: 'Kontak tidak ditemukan.' });
  const chatKey = makeChatKey(me, receiver.id);
  const ts = now();
  const blocked = isBlocked(me, receiver.id);
  const status = blocked ? 'sent' : (onlineUsers.has(String(receiver.id)) ? 'delivered' : 'sent');
  const info = db.prepare('INSERT INTO messages (chat_key, sender_id, receiver_id, type, content, media_url, caption, file_name, file_size, duration, status, created_at, delivered_at, read_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .run(chatKey, me, receiver.id, type || 'image', '', `/uploads/${req.file.filename}`, caption || '', name || req.file.originalname, size || '', duration || '', status, ts, status !== 'sent' ? ts : 0, 0);
  ensureContact(me, receiver.id);
  const msg = {
    id: String(info.lastInsertRowid),
    from: 'me',
    type: type || 'image',
    content: '',
    src: `/uploads/${req.file.filename}`,
    caption: caption || '',
    name: name || req.file.originalname,
    size: size || '',
    duration: duration || '',
    status,
    time: fmtTime(ts),
    ts
  };
  res.json({ ok: true, message: msg });
  emitMessageToPeers(me, receiver.id, msg, { blocked });
});

app.post('/api/messages/audio', requireAuth, upload.single('media'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Audio wajib diunggah.' });
  const me = Number(req.auth.sub);
  const { receiverId, duration } = req.body || {};
  const receiver = getUserById(receiverId) || getUserByNumber(receiverId);
  if (!receiver) return res.status(404).json({ error: 'Kontak tidak ditemukan.' });
  const chatKey = makeChatKey(me, receiver.id);
  const ts = now();
  const blocked = isBlocked(me, receiver.id);
  const status = blocked ? 'sent' : (onlineUsers.has(String(receiver.id)) ? 'delivered' : 'sent');
  const info = db.prepare('INSERT INTO messages (chat_key, sender_id, receiver_id, type, media_url, duration, status, created_at, delivered_at, read_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .run(chatKey, me, receiver.id, 'audio', `/uploads/${req.file.filename}`, duration || '', status, ts, status !== 'sent' ? ts : 0, 0);
  ensureContact(me, receiver.id);
  const msg = { id: String(info.lastInsertRowid), from: 'me', type: 'audio', src: `/uploads/${req.file.filename}`, duration: duration || '', status, time: fmtTime(ts), ts };
  res.json({ ok: true, message: msg });
  emitMessageToPeers(me, receiver.id, msg, { blocked });
});

app.post('/api/messages/text', requireAuth, (req, res) => {
  const me = Number(req.auth.sub);
  const { receiverId, content } = req.body || {};
  const receiver = getUserById(receiverId) || getUserByNumber(receiverId);
  if (!receiver) return res.status(404).json({ error: 'Kontak tidak ditemukan.' });
  const text = String(content || '').trim();
  if (!text) return res.status(400).json({ error: 'Pesan kosong.' });
  const chatKey = makeChatKey(me, receiver.id);
  const ts = now();
  const blocked = isBlocked(me, receiver.id);
  const status = blocked ? 'sent' : (onlineUsers.has(String(receiver.id)) ? 'delivered' : 'sent');
  const info = db.prepare('INSERT INTO messages (chat_key, sender_id, receiver_id, type, content, status, created_at, delivered_at, read_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .run(chatKey, me, receiver.id, 'text', text, status, ts, status !== 'sent' ? ts : 0, 0);
  ensureContact(me, receiver.id);
  const msg = { id: String(info.lastInsertRowid), from: 'me', type: 'text', content: text, status, time: fmtTime(ts), ts };
  res.json({ ok: true, message: msg });
  emitMessageToPeers(me, receiver.id, msg, { blocked });
});

app.post('/api/chat/read', requireAuth, (req, res) => {
  const me = Number(req.auth.sub);
  const { contactId } = req.body || {};
  const contact = getUserById(contactId) || getUserByNumber(contactId);
  if (!contact) return res.status(404).json({ error: 'Kontak tidak ditemukan.' });
  const ts = now();
  db.prepare('UPDATE messages SET status = ?, read_at = ? WHERE sender_id = ? AND receiver_id = ? AND read_at = 0')
    .run('read', ts, contact.id, me);
  res.json({ ok: true });
  io.to(`user:${contact.id}`).emit('message:read', { contactId: String(me), readerId: String(me), status: 'read' });
});

app.post('/api/chat/clear', requireAuth, (req, res) => {
  const me = Number(req.auth.sub);
  const other = getUserById(req.body.contactId) || getUserByNumber(req.body.contactId);
  if (!other) return res.status(404).json({ error: 'Kontak tidak ditemukan.' });
  const key = makeChatKey(me, other.id);
  db.prepare('DELETE FROM messages WHERE chat_key = ?').run(key);
  res.json({ ok: true });
});

const onlineUsers = new Map();
const socketUser = new Map();

function emitPresence(userId, online) {
  const user = getUserById(userId);
  if (!user) return;
  io.emit('presence:update', {
    userId: String(userId),
    online,
    lastSeen: user.last_seen || 0,
    lastSeenText: timeAgo(user.last_seen || 0)
  });
}

function emitMessageToPeers(senderId, receiverId, baseMsg, { blocked = false } = {}) {
  const receiverSock = [...socketUser.entries()].find(([, uid]) => String(uid) === String(receiverId));
  const senderSock = [...socketUser.entries()].find(([, uid]) => String(uid) === String(senderId));
  const receiverOnline = !!receiverSock;
  const deliveredStatus = blocked ? 'sent' : (receiverOnline ? 'delivered' : 'sent');
  const payloadForSender = { ...baseMsg, status: deliveredStatus };
  const payloadForReceiver = { ...baseMsg, status: 'read', from: String(senderId) };
  if (senderSock) io.to(senderSock[0]).emit('message:status', { messageId: baseMsg.id, contactId: String(receiverId), status: deliveredStatus });
  if (receiverOnline && !blocked) {
    io.to(receiverSock[0]).emit('message:new', payloadForReceiver);
    io.to(receiverSock[0]).emit('toast', {
      title: 'Pesan baru',
      body: 'Ada pesan masuk',
      from: String(senderId)
    });
    if (senderSock) io.to(senderSock[0]).emit('message:status', { messageId: baseMsg.id, contactId: String(receiverId), status: 'delivered' });
  }
}

io.use((socket, next) => {
  const token = socket.handshake.auth?.token || socket.handshake.headers.authorization?.replace('Bearer ', '');
  if (!token) return next(new Error('Unauthorized'));
  try {
    socket.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    next(new Error('Unauthorized'));
  }
});

io.on('connection', (socket) => {
  const userId = Number(socket.user.sub);
  socketUser.set(socket.id, userId);
  onlineUsers.set(String(userId), socket.id);
  db.prepare('UPDATE users SET last_seen = ?, updated_at = ? WHERE id = ?').run(now(), now(), userId);
  socket.join(`user:${userId}`);
  emitPresence(userId, true);
  socket.emit('bootstrap', getBootstrap(userId));

  socket.on('disconnect', () => {
    socketUser.delete(socket.id);
    if ([...onlineUsers.values()].includes(socket.id)) {
      onlineUsers.delete(String(userId));
      db.prepare('UPDATE users SET last_seen = ?, updated_at = ? WHERE id = ?').run(now(), now(), userId);
      emitPresence(userId, false);
    }
  });

  socket.on('chat:read', ({ contactId }) => {
    const other = getUserById(contactId) || getUserByNumber(contactId);
    if (!other) return;
    const ts = now();
    db.prepare('UPDATE messages SET status = ?, read_at = ? WHERE sender_id = ? AND receiver_id = ? AND read_at = 0')
      .run('read', ts, other.id, userId);
    io.to(`user:${other.id}`).emit('message:read', { contactId: String(userId), readerId: String(userId), status: 'read' });
  });

  socket.on('message:send', ({ receiverId, content, type = 'text', caption = '', src = '', fileName = '', fileSize = '', duration = '' }, cb) => {
    const receiver = getUserById(receiverId) || getUserByNumber(receiverId);
    if (!receiver) return cb?.({ ok: false, error: 'Kontak tidak ditemukan.' });
    const me = userId;
    const key = makeChatKey(me, receiver.id);
    const ts = now();
    const blocked = isBlocked(me, receiver.id);
    const status = blocked ? 'sent' : (onlineUsers.has(String(receiver.id)) ? 'delivered' : 'sent');
    let info;
    if (type === 'text') {
      info = db.prepare('INSERT INTO messages (chat_key, sender_id, receiver_id, type, content, status, created_at, delivered_at, read_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
        .run(key, me, receiver.id, 'text', String(content || ''), status, ts, status !== 'sent' ? ts : 0, 0);
    } else {
      info = db.prepare('INSERT INTO messages (chat_key, sender_id, receiver_id, type, content, media_url, caption, file_name, file_size, duration, status, created_at, delivered_at, read_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
        .run(key, me, receiver.id, type, String(content || ''), String(src || ''), caption || '', fileName || '', fileSize || '', duration || '', status, ts, status !== 'sent' ? ts : 0, 0);
    }
    ensureContact(me, receiver.id);
    const msg = {
      id: String(info.lastInsertRowid),
      from: 'me',
      type,
      content: String(content || ''),
      src: String(src || ''),
      caption,
      name: fileName,
      size: fileSize,
      duration,
      status,
      time: fmtTime(ts),
      ts
    };
    cb?.({ ok: true, message: msg });
    emitMessageToPeers(me, receiver.id, msg, { blocked });
  });

  socket.on('status:create', ({ mediaUrl, mediaType, caption }, cb) => {
    const ts = now();
    const info = db.prepare('INSERT INTO statuses (user_id, media_url, media_type, caption, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(userId, mediaUrl, mediaType, caption || '', ts, ts + 24 * 60 * 60 * 1000);
    const status = { id: String(info.lastInsertRowid), contactId: String(userId), items: [{ id: String(info.lastInsertRowid), type: mediaType, src: mediaUrl, caption: caption || '', time: fmtTime(ts), ts }] };
    io.emit('status:new', { userId: String(userId), status });
    cb?.({ ok: true, status });
  });
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Server error' });
});

server.listen(PORT, () => {
  console.log(`ChatApp server running on http://localhost:${PORT}`);
});
