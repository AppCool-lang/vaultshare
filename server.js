/**
 * VaultShare — Backend API (v2)
 * - Auth réelle : e-mail + vérification + 2FA (SMTP)
 * - OAuth officiel Google & Apple (redirection + échange de code)
 * - VirusTotal, anti-multi-comptes, appairage web <-> Windows
 * - Base SQLite, fichiers sur disque
 */
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const multer = require('multer');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const db = require('./db');

const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;
const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY || '';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const GOOGLE_REDIRECT = process.env.GOOGLE_REDIRECT_URI || `${APP_URL}/api/auth/google/callback`;
const APPLE_CLIENT_ID = process.env.APPLE_CLIENT_ID || '';
const APPLE_TEAM_ID = process.env.APPLE_TEAM_ID || '';
const APPLE_KEY_ID = process.env.APPLE_KEY_ID || '';
const APPLE_PRIVATE_KEY = process.env.APPLE_PRIVATE_KEY_PATH || '';
const APPLE_REDIRECT = process.env.APPLE_REDIRECT_URI || `${APP_URL}/api/auth/apple/callback`;

const UPLOAD_DIR = path.join(__dirname, 'uploads');
const DOWNLOAD_DIR = path.join(__dirname, '..', 'downloads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
if (!fs.existsSync(DOWNLOAD_DIR)) fs.mkdirSync(DOWNLOAD_DIR, { recursive: true });

// ---------- E-mail ----------
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: Number(process.env.SMTP_PORT || 587),
  secure: false,
  auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
});
function genCode() { return String(Math.floor(100000 + Math.random() * 900000)); }
async function sendCodeEmail(to, code, type) {
  const subject = type === 'verify' ? 'VaultShare — Vérifiez votre adresse e-mail' : 'VaultShare — Code de sécurité de connexion';
  const html = `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;color:#111">
    <h2 style="color:#4f46e5">VaultShare</h2>
    <p>${type === 'verify' ? 'Bienvenue sur VaultShare ! Utilisez ce code pour vérifier votre adresse e-mail :' : 'Un code de sécurité a été demandé pour votre compte VaultShare :'}</p>
    <div style="font-size:34px;font-weight:900;letter-spacing:8px;text-align:center;padding:18px;background:#eef2ff;border-radius:14px;color:#312e81">${code}</div>
    <p style="color:#666;font-size:13px">Ce code expire dans 10 minutes. Si vous n'êtes pas à l'origine de cette demande, ignorez cet e-mail.</p></div>`;
  if (!process.env.SMTP_USER) { console.log(`[DEV — e-mail non configuré] ${type} pour ${to} : ${code}`); return; }
  await transporter.sendMail({ from: process.env.SMTP_FROM || 'VaultShare <no-reply@vaultshare.app>', to, subject, html });
}
function storeCode(email, code, type) {
  db.prepare('INSERT INTO email_codes (email, code, type, expires_at) VALUES (?, ?, ?, ?)').run(email.toLowerCase(), code, type, Date.now() + 10 * 60 * 1000);
}
function checkCode(email, code, type) {
  const row = db.prepare('SELECT * FROM email_codes WHERE email=? AND code=? AND type=? AND used=0 ORDER BY id DESC LIMIT 1').get(email.toLowerCase(), code, type);
  if (!row || Date.now() > row.expires_at) return false;
  db.prepare('UPDATE email_codes SET used=1 WHERE id=?').run(row.id);
  return true;
}

// ---------- Anti-multi-comptes ----------
function antiMultiCheck(device) {
  if (!device) return { blocked: false };
  const mine = db.prepare('SELECT * FROM users WHERE device_fingerprint=?').all(device);
  if (mine.length === 0) return { blocked: false };
  const banned = mine.filter(u => u.banned === 1).length;
  if (mine.length >= 2 && banned / mine.length >= 0.5) return { blocked: true, total: mine.length, banned };
  return { blocked: false, total: mine.length, banned };
}

// ---------- Helpers ----------
function publicUser(u) { return { id: u.id, name: u.name, email: u.email, verified: !!u.verified, provider: u.provider }; }
function signToken(u) { return jwt.sign({ id: u.id, email: u.email }, JWT_SECRET, { expiresIn: '7d' }); }
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!t) return res.status(401).json({ error: 'Non authentifié' });
  try { req.user = jwt.verify(t, JWT_SECRET); next(); } catch { return res.status(401).json({ error: 'Token invalide' }); }
}
function findOrCreateOAuthUser({ email, name, provider, sub, device, ip }) {
  let u = db.prepare('SELECT * FROM users WHERE email=?').get(email.toLowerCase());
  if (u) return u;
  const anti = antiMultiCheck(device);
  if (anti.blocked) throw Object.assign(new Error('Création bloquée : majorité de comptes bannis sur cet appareil.'), { status: 403, code: 'ANTI_MULTI' });
  const id = crypto.randomUUID();
  db.prepare('INSERT INTO users (id, name, email, password_hash, verified, provider, provider_sub, device_fingerprint, ip) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)')
    .run(id, name || email, email.toLowerCase(), '', provider, sub || '', device || '', ip || '');
  return db.prepare('SELECT * FROM users WHERE id=?').get(id);
}

// ---------- Config publique (pour le front : OAuth configuré ou non) ----------
app.get('/api/config', (req, res) => {
  res.json({
    google: { enabled: !!GOOGLE_CLIENT_ID, clientId: GOOGLE_CLIENT_ID },
    apple: { enabled: !!APPLE_CLIENT_ID, clientId: APPLE_CLIENT_ID },
    version: '2.0.0',
  });
});

// ================= AUTH E-MAIL =================
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, device } = req.body;
  if (!name || !email || !password || password.length < 8) return res.status(400).json({ error: 'Nom, e-mail et mot de passe (8 caractères min.) requis.' });
  const anti = antiMultiCheck(device || req.ip);
  if (anti.blocked) return res.status(403).json({ error: 'Création bloquée par le système anti-multi-comptes.', code: 'ANTI_MULTI' });
  const exists = db.prepare('SELECT id FROM users WHERE email=?').get(email.toLowerCase());
  if (exists) return res.status(409).json({ error: 'Un compte existe déjà avec cet e-mail.' });
  const id = crypto.randomUUID();
  const hash = await bcrypt.hash(password, 10);
  db.prepare('INSERT INTO users (id, name, email, password_hash, verified, provider, device_fingerprint, ip) VALUES (?, ?, ?, ?, 0, ?, ?, ?)')
    .run(id, name, email.toLowerCase(), hash, 'email', device || '', req.ip);
  const code = genCode(); storeCode(email, code, 'verify');
  await sendCodeEmail(email, code, 'verify');
  res.json({ message: 'Code de vérification envoyé par e-mail.', devCode: process.env.SMTP_USER ? null : code });
});

app.post('/api/auth/verify-email', (req, res) => {
  const { email, code } = req.body;
  if (!checkCode(email, code, 'verify')) return res.status(400).json({ error: 'Code invalide ou expiré.' });
  db.prepare('UPDATE users SET verified=1 WHERE email=?').run(email.toLowerCase());
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(email.toLowerCase());
  res.json({ token: signToken(u), user: publicUser(u) });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const u = db.prepare('SELECT * FROM users WHERE email=?').get((email || '').toLowerCase());
  if (!u) return res.status(401).json({ error: 'Identifiants invalides.' });
  if (u.banned) return res.status(403).json({ error: 'Ce compte a été banni.' });
  if (!u.verified) return res.status(403).json({ error: 'E-mail non vérifié. Inscrivez-vous pour recevoir un nouveau code.', code: 'UNVERIFIED' });
  const ok = await bcrypt.compare(password || '', u.password_hash || '');
  if (!ok) return res.status(401).json({ error: 'Identifiants invalides.' });
  const code = genCode(); storeCode(email, code, '2fa');
  await sendCodeEmail(email, code, '2fa');
  res.json({ need2fa: true, message: 'Code de sécurité envoyé par e-mail.', devCode: process.env.SMTP_USER ? null : code });
});

app.post('/api/auth/verify-2fa', (req, res) => {
  const { email, code } = req.body;
  if (!checkCode(email, code, '2fa')) return res.status(400).json({ error: 'Code 2FA invalide ou expiré.' });
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(email.toLowerCase());
  res.json({ token: signToken(u), user: publicUser(u) });
});

app.get('/api/auth/me', auth, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  if (!u) return res.status(404).json({ error: 'Introuvable' });
  res.json({ user: publicUser(u) });
});

// ================= OAUTH GOOGLE (officiel) =================
// Étape 1 : redirection vers la vraie page Google
app.get('/api/auth/google', (req, res) => {
  if (!GOOGLE_CLIENT_ID) return res.status(500).json({ error: 'Google OAuth non configuré (GOOGLE_CLIENT_ID manquant).' });
  const state = crypto.randomBytes(16).toString('hex');
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: GOOGLE_REDIRECT,
    response_type: 'code',
    scope: 'openid email profile',
    access_type: 'offline',
    prompt: 'consent',
    state,
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});
// Étape 2 : retour de Google avec le code -> échange contre tokens
app.get('/api/auth/google/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) return res.redirect(`${APP_URL}/?oauth_error=${encodeURIComponent(error || 'refusé')}`);
  try {
    const tok = await axios.post('https://oauth2.googleapis.com/token', new URLSearchParams({
      code, client_id: GOOGLE_CLIENT_ID, client_secret: GOOGLE_CLIENT_SECRET,
      redirect_uri: GOOGLE_REDIRECT, grant_type: 'authorization_code',
    }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
    const info = await axios.get('https://oauth2.googleapis.com/tokeninfo', { params: { id_token: tok.data.id_token } });
    const { email, name, sub } = info.data;
    const u = findOrCreateOAuthUser({ email, name, provider: 'google', sub, device: req.query.device || '', ip: req.ip });
    const token = signToken(u);
    // Redirection vers le front avec le token (le front le stocke puis nettoie l'URL)
    res.redirect(`${APP_URL}/?token=${encodeURIComponent(token)}`);
  } catch (e) {
    console.error('Google OAuth error:', e.response?.data || e.message);
    res.redirect(`${APP_URL}/?oauth_error=${encodeURIComponent('Échec de la connexion Google')}`);
  }
});
// Échange pour l'application Windows (code -> token, sans redirection navigateur)
app.post('/api/auth/google/exchange', async (req, res) => {
  const { code, redirectUri, device } = req.body;
  try {
    const tok = await axios.post('https://oauth2.googleapis.com/token', new URLSearchParams({
      code, client_id: GOOGLE_CLIENT_ID, client_secret: GOOGLE_CLIENT_SECRET,
      redirect_uri: redirectUri || GOOGLE_REDIRECT, grant_type: 'authorization_code',
    }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
    const info = await axios.get('https://oauth2.googleapis.com/tokeninfo', { params: { id_token: tok.data.id_token } });
    const u = findOrCreateOAuthUser({ email: info.data.email, name: info.data.name, provider: 'google', sub: info.data.sub, device, ip: req.ip });
    res.json({ token: signToken(u), user: publicUser(u) });
  } catch { res.status(400).json({ error: 'Code Google invalide.' }); }
});

// ================= OAUTH APPLE (officiel) =================
app.get('/api/auth/apple', (req, res) => {
  if (!APPLE_CLIENT_ID) return res.status(500).json({ error: 'Apple Sign In non configuré (APPLE_CLIENT_ID manquant).' });
  const state = crypto.randomBytes(16).toString('hex');
  const params = new URLSearchParams({
    client_id: APPLE_CLIENT_ID,
    redirect_uri: APPLE_REDIRECT,
    response_type: 'code id_token',
    scope: 'name email',
    response_mode: 'form_post',
    nonce: crypto.randomBytes(16).toString('hex'),
    state,
  });
  res.redirect(`https://appleid.apple.com/auth/authorize?${params}`);
});
app.post('/api/auth/apple/callback', async (req, res) => {
  const { code, error } = req.body;
  if (error || !code) return res.redirect(`${APP_URL}/?oauth_error=${encodeURIComponent('Connexion Apple refusée')}`);
  try {
    // Secret client Apple : JWT signé avec la clé .p8 (généré côté serveur)
    const jwt = require('jsonwebtoken');
    const privateKey = APPLE_PRIVATE_KEY && fs.existsSync(APPLE_PRIVATE_KEY) ? fs.readFileSync(APPLE_PRIVATE_KEY) : '';
    const clientSecret = jwt.sign({ iss: APPLE_TEAM_ID, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 3600, aud: 'https://appleid.apple.com', sub: APPLE_CLIENT_ID }, privateKey, { algorithm: 'ES256', keyid: APPLE_KEY_ID });
    const tok = await axios.post('https://appleid.apple.com/auth/token', new URLSearchParams({
      client_id: APPLE_CLIENT_ID, client_secret: clientSecret, code, grant_type: 'authorization_code',
    }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
    const payload = JSON.parse(Buffer.from(tok.data.id_token.split('.')[1], 'base64').toString());
    const email = payload.email || `apple-${payload.sub}@privaterelay.appleid.com`;
    const u = findOrCreateOAuthUser({ email, name: 'Utilisateur Apple', provider: 'apple', sub: payload.sub, device: '', ip: req.ip });
    res.redirect(`${APP_URL}/?token=${encodeURIComponent(signToken(u))}`);
  } catch (e) {
    console.error('Apple OAuth error:', e.response?.data || e.message);
    res.redirect(`${APP_URL}/?oauth_error=${encodeURIComponent('Échec de la connexion Apple')}`);
  }
});

// ================= APPAIRAGE WEB <-> WINDOWS =================
app.post('/api/devices/pair', auth, (req, res) => {
  const code = genCode();
  db.prepare('INSERT OR REPLACE INTO pairings (code, user_id, expires_at) VALUES (?, ?, ?)').run(code, req.user.id, Date.now() + 5 * 60 * 1000);
  res.json({ code, payload: `vaultshare://pair?code=${code}` });
});
app.post('/api/devices/link', (req, res) => {
  const { code } = req.body;
  const p = db.prepare('SELECT * FROM pairings WHERE code=?').get(code);
  if (!p || Date.now() > p.expires_at) return res.status(400).json({ error: 'Code d\'appairage invalide ou expiré.' });
  db.prepare('DELETE FROM pairings WHERE code=?').run(code);
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(p.user_id);
  res.json({ token: signToken(u), user: publicUser(u) });
});

// ================= FICHIERS + VIRUSTOTAL =================
const upload = multer({ storage: multer.diskStorage({ destination: UPLOAD_DIR, filename: (req, f, cb) => cb(null, Date.now() + '-' + f.originalname) }), limits: { fileSize: 500 * 1024 * 1024 } });

async function scanWithVirusTotal(filePath) {
  if (!VT_API_KEY) return { status: 'clean', note: 'Clé VirusTotal non configurée — scan simulé (démo)' };
  try {
    const FormData = require('form-data');
    const form = new FormData();
    form.append('file', fs.createReadStream(filePath));
    const up = await axios.post('https://www.virustotal.com/api/v3/files', form, { headers: { 'x-apikey': VT_API_KEY, ...form.getHeaders() } });
    await new Promise(r => setTimeout(r, 15000));
    const rep = await axios.get(`https://www.virustotal.com/api/v3/analyses/${up.data.data.id}`, { headers: { 'x-apikey': VT_API_KEY } });
    const stats = rep.data.data.attributes.stats;
    const bad = (stats.malicious || 0) + (stats.suspicious || 0);
    return { status: bad > 0 ? 'infected' : 'clean', stats };
  } catch (e) { console.error('VirusTotal:', e.message); return { status: 'scanning', note: 'Analyse en cours' }; }
}

app.post('/api/files/upload', auth, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Aucun fichier reçu.' });
  const id = crypto.randomUUID();
  db.prepare('INSERT INTO files (id, user_id, name, size, path, status) VALUES (?, ?, ?, ?, ?, ?)').run(id, req.user.id, req.file.originalname, req.file.size, req.file.path, 'scanning');
  scanWithVirusTotal(req.file.path).then(r => db.prepare('UPDATE files SET status=?, scan_result=? WHERE id=?').run(r.status, JSON.stringify(r), id));
  res.json({ file: { id, name: req.file.originalname, status: 'scanning' } });
});
app.get('/api/files', auth, (req, res) => {
  const rows = db.prepare('SELECT id, name, size, status, created_at FROM files WHERE user_id=? ORDER BY created_at DESC').all(req.user.id);
  res.json({ files: rows });
});
app.get('/api/files/public', (req, res) => {
  const rows = db.prepare("SELECT f.id, f.name, f.size, f.created_at, u.name AS owner FROM files f JOIN users u ON u.id=f.user_id WHERE f.status='clean' ORDER BY f.created_at DESC LIMIT 50").all();
  res.json({ files: rows });
});
app.get('/api/files/:id/download', (req, res) => {
  const f = db.prepare('SELECT * FROM files WHERE id=?').get(req.params.id);
  if (!f) return res.status(404).json({ error: 'Fichier introuvable.' });
  if (f.status !== 'clean') return res.status(403).json({ error: 'Fichier non vérifié ou infecté — téléchargement bloqué.' });
  if (!fs.existsSync(f.path)) return res.status(404).json({ error: 'Fichier absent du serveur (stockage réinitialisé). Veuillez le renvoyer.' });
  res.download(f.path, f.name);
});
app.delete('/api/files/:id', auth, (req, res) => {
  const f = db.prepare('SELECT * FROM files WHERE id=? AND user_id=?').get(req.params.id, req.user.id);
  if (!f) return res.status(404).json({ error: 'Introuvable' });
  try { fs.unlinkSync(f.path); } catch {}
  db.prepare('DELETE FROM files WHERE id=?').run(f.id);
  res.json({ ok: true });
});

// ================= TÉLÉCHARGEMENT APPLICATION WINDOWS =================
app.get('/api/downloads/windows', (req, res) => {
  const exe = path.join(DOWNLOAD_DIR, 'VaultShare-Setup.exe');
  if (fs.existsSync(exe)) return res.download(exe, 'VaultShare-Setup.exe');
  res.status(404).json({ error: 'Installeur Windows non hébergé sur ce serveur. Utilisez le lien direct (GitHub Release) dans config.js : VAULTSHARE_EXE_URL.' });
});
app.get('/api/downloads/info', (req, res) => {
  const exe = path.join(DOWNLOAD_DIR, 'VaultShare-Setup.exe');
  res.json({ version: '2.0.0', size: fs.existsSync(exe) ? fs.statSync(exe).size : 0, available: fs.existsSync(exe), updated: '2026-11-11' });
});

// ================= ADMIN =================
app.post('/api/admin/ban', auth, (req, res) => {
  const { userId } = req.body;
  db.prepare('UPDATE users SET banned=1 WHERE id=?').run(userId);
  res.json({ ok: true });
});

app.get('/health', (req, res) => res.json({ ok: true, service: 'VaultShare API v2' }));

// ---------- Front statique ----------
const dist = path.join(__dirname, '..', 'frontend', 'dist');
if (fs.existsSync(dist)) {
  app.use(express.static(dist));
  app.get('*', (req, res) => { if (!req.path.startsWith('/api/')) res.sendFile(path.join(dist, 'index.html')); });
}

app.listen(PORT, '0.0.0.0', () => console.log(`VaultShare API v2 sur http://0.0.0.0:${PORT} | Google: ${GOOGLE_CLIENT_ID ? 'configuré' : 'non configuré'} | Apple: ${APPLE_CLIENT_ID ? 'configuré' : 'non configuré'} | VirusTotal: ${VT_API_KEY ? 'configuré' : 'démo'}`));
