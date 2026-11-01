'use strict';
/* routes/users.js  --  Menu User (admin) + OTP pemulihan akun per user (berubah tiap 5 menit)
   Memakai koneksi mongoose yang SUDAH ada. Tanpa paket baru.
   Environment Render:
     MAIN_BOT_TOKEN / BOT_TOKEN   token bot mini app (validasi initData)
     ADMIN_IDS                    ID Telegram admin, pisahkan koma
     RECOVERY_SECRET              (disarankan) teks acak panjang khusus kode pemulihan; jika kosong memakai HASH_SALT
   Endpoint (dipasang di '/api'):
     POST /api/users/list     (admin)  body { initData, q?, limit? }        -> daftar user + status KYC wajah + email + OTP saat ini
     POST /api/users/otp      (admin)  body { initData, targetUid }         -> OTP saat ini milik 1 user
     POST /api/users/verify   (admin)  body { initData, targetUid, code }   -> cek kode yang disebut user
     POST /api/users/my-otp   (user)   body { initData }                    -> OTP milik user itu sendiri (untuk FAQ "Pulihkan Akun")
*/
const express = require('express');
const crypto = require('crypto');
const mongoose = require('mongoose');
const router = express.Router();

const E = process.env;
const MAIN_TOKEN = E.MAIN_BOT_TOKEN || E.BOT_TOKEN;
const ADMINS = String(E.ADMIN_IDS || '').split(',').map(function (s) { return s.trim(); }).filter(Boolean);
const STEP = 5 * 60 * 1000;                                   // kode berubah tiap 5 menit
const SECRET = String(E.RECOVERY_SECRET || E.HASH_SALT || '');
const UID_RE = /^[A-Za-z0-9_-]{3,40}$/;

function getDb() { return mongoose.connection && mongoose.connection.readyState === 1 ? mongoose.connection.db : null; }
function hmac(key, msg) { return crypto.createHmac('sha256', key).update(msg).digest(); }

/* validasi pengguna dari initData Telegram WebApp (sama dengan afexface.js) */
function tgUser(body) {
  if (!MAIN_TOKEN) {
    return (E.ALLOW_INSECURE_UID === 'true' && body.uid) ? { id: String(body.uid), username: String(body.username || '') } : null;
  }
  const initData = String(body.initData || ''); if (!initData) return null;
  const p = new URLSearchParams(initData), hash = p.get('hash'); if (!hash) return null;
  p.delete('hash');
  const dcs = Array.from(p.keys()).sort().map(function (k) { return k + '=' + p.get(k); }).join('\n');
  const calc = crypto.createHmac('sha256', hmac('WebAppData', MAIN_TOKEN)).update(dcs).digest('hex');
  const a = Buffer.from(calc), b = Buffer.from(hash);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  if (Math.abs(Date.now() / 1000 - Number(p.get('auth_date') || 0)) > 86400) return null;
  let u = {}; try { u = JSON.parse(p.get('user') || '{}'); } catch (e) {}
  return u.id ? { id: String(u.id), username: u.username || '' } : null;
}
function adminOnly(body) { const u = tgUser(body); return (u && ADMINS.indexOf(u.id) >= 0) ? u : null; }

/* ---------- OTP pemulihan: unik per user, ganti tiap 5 menit (berbasis jam server, tanpa simpan ke DB) ---------- */
function codeAt(uid, win) {
  const d = hmac(SECRET + '|afex-recovery', String(uid) + ':' + win);
  return String(d.readUInt32BE(0) % 1000000).padStart(6, '0');
}
function nowWin() { return Math.floor(Date.now() / STEP); }
function currentCode(uid) { const w = nowWin(); return { code: codeAt(uid, w), exp: (w + 1) * STEP }; }
function matches(uid, code) {
  const w = nowWin(), c = String(code || '').replace(/\s+/g, '');
  if (!/^\d{6}$/.test(c)) return false;
  const a = Buffer.from(c);
  return [w, w - 1].some(function (x) { const b = Buffer.from(codeAt(uid, x)); return a.length === b.length && crypto.timingSafeEqual(a, b); });
}
function esc(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

/* ---------- handlers ---------- */
async function list(b) {
  const u = adminOnly(b); if (!u) return { ok: false, error: 'unauthorized' };
  if (!SECRET) return { ok: false, error: 'no_secret' };
  const db = getDb(); if (!db) return { ok: false, error: 'server_error' };
  const limit = Math.min(Math.max(parseInt(b.limit, 10) || 100, 1), 200);
  const q = String(b.q || '').trim().slice(0, 60);

  let filter = {};
  if (q) {
    const rx = new RegExp(esc(q), 'i');
    const byMail = await db.collection('a2f_verified').find({ email: rx }).project({ uid: 1 }).limit(200).toArray();
    filter = { $or: [{ userId: rx }, { username: rx }, { userId: { $in: byMail.map(function (x) { return x.uid; }) } }] };
  }
  const users = db.collection('users');
  const total = await users.countDocuments(filter);
  const rows = await users.find(filter).project({ userId: 1, username: 1 }).sort({ _id: -1 }).limit(limit).toArray();
  const ids = rows.map(function (r) { return String(r.userId); });

  const mails = await db.collection('a2f_verified').find({ uid: { $in: ids } }).project({ uid: 1, email: 1, at: 1, revokedAt: 1 }).toArray();
  const faces = await db.collection('face_registry').find({ uid: { $in: ids } }).project({ uid: 1 }).toArray();
  const mailMap = {}, faceMap = {};
  mails.forEach(function (m) { mailMap[m.uid] = m; });
  faces.forEach(function (f) { faceMap[f.uid] = true; });

  const w = nowWin();
  return {
    ok: true, total: total, exp: (w + 1) * STEP, now: Date.now(),
    list: rows.map(function (r) {
      const id = String(r.userId), m = mailMap[id];
      return {
        uid: id, username: r.username || '',
        email: (m && m.email && !m.revokedAt) ? m.email : '',
        emailAt: m && m.at ? new Date(m.at).getTime() : 0,
        face: !!faceMap[id],
        otp: codeAt(id, w)
      };
    })
  };
}
async function otp(b) {
  const u = adminOnly(b); if (!u) return { ok: false, error: 'unauthorized' };
  if (!SECRET) return { ok: false, error: 'no_secret' };
  const t = String(b.targetUid || '').trim(); if (!UID_RE.test(t)) return { ok: false, error: 'bad_uid' };
  const c = currentCode(t); return { ok: true, code: c.code, exp: c.exp, now: Date.now() };
}
async function verify(b) {
  const u = adminOnly(b); if (!u) return { ok: false, error: 'unauthorized' };
  if (!SECRET) return { ok: false, error: 'no_secret' };
  const t = String(b.targetUid || '').trim(); if (!UID_RE.test(t)) return { ok: false, error: 'bad_uid' };
  return { ok: true, valid: matches(t, b.code) };
}
async function myOtp(b) {
  const u = tgUser(b); if (!u) return { ok: false, error: 'unauthorized' };
  if (!SECRET) return { ok: false, error: 'no_secret' };
  const c = currentCode(u.id); return { ok: true, code: c.code, exp: c.exp, now: Date.now() };
}

function wrap(fn) {
  return async function (req, res) {
    const body = (req.body && typeof req.body === 'object') ? req.body : {};
    try { res.json(await fn(body)); } catch (e) { console.error('[users] error', e && e.message); res.json({ ok: false, error: 'server_error' }); }
  };
}
router.post('/users/list', wrap(list));
router.post('/users/otp', wrap(otp));
router.post('/users/verify', wrap(verify));
router.post('/users/my-otp', wrap(myOtp));

if (!SECRET) console.warn('[users] RECOVERY_SECRET / HASH_SALT belum diisi: menu User & OTP pemulihan tidak aktif');
module.exports = router;
