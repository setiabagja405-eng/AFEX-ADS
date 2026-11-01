'use strict';
/* routes/team.js  --  Daftar TIM (nama + jabatan) yang tampil di menu About. Disimpan di MongoDB, dilihat semua user.
   Memakai koneksi mongoose yang SUDAH ada. Tanpa paket baru.
   Environment Render: MAIN_BOT_TOKEN / BOT_TOKEN (validasi initData) dan ADMIN_IDS (ID Telegram admin, pisahkan koma).
   Endpoint (dipasang di '/api'):
     POST /api/team/get    (semua user)  -> { ok, custom, list:[{name,role}] }   custom=false berarti belum pernah diatur admin
     POST /api/team/set    (admin)       body { initData, list:[{name,role}] }   -> simpan daftar
     POST /api/team/reset  (admin)       body { initData }                       -> kembali ke bawaan
*/
const express = require('express');
const crypto = require('crypto');
const mongoose = require('mongoose');
const router = express.Router();

const E = process.env;
const MAIN_TOKEN = E.MAIN_BOT_TOKEN || E.BOT_TOKEN;
const ADMINS = String(E.ADMIN_IDS || '').split(',').map(function (s) { return s.trim(); }).filter(Boolean);
const MAX_MEMBERS = 20, MAX_NAME = 60, MAX_ROLE = 90;

function getDb() { return mongoose.connection && mongoose.connection.readyState === 1 ? mongoose.connection.db : null; }
function hmac(key, msg) { return crypto.createHmac('sha256', key).update(msg).digest(); }

/* validasi pengguna dari initData Telegram WebApp (sama dengan afexface.js / users.js) */
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

/* bersihkan teks: tanpa karakter kontrol, spasi rapi, batasi panjang (tampilan di klien tetap di-escape) */
function clean(s, max) {
  return String(s == null ? '' : s).replace(/[\u0000-\u001f\u007f<>]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
}
function sanitize(list) {
  if (!Array.isArray(list)) return null;
  const out = [];
  for (const m of list.slice(0, MAX_MEMBERS)) {
    const name = clean(m && m.name, MAX_NAME), role = clean(m && m.role, MAX_ROLE);
    if (name) out.push({ name: name, role: role });
  }
  return out;
}

async function get() {
  const db = getDb(); if (!db) return { ok: false, error: 'server_error' };
  const d = await db.collection('team_members').findOne({ _id: 'about' });
  if (!d || !Array.isArray(d.list) || !d.list.length) return { ok: true, custom: false, list: [] };
  return { ok: true, custom: true, list: d.list, at: d.at ? new Date(d.at).getTime() : 0 };
}
async function set(b) {
  const u = adminOnly(b); if (!u) return { ok: false, error: 'unauthorized' };
  const db = getDb(); if (!db) return { ok: false, error: 'server_error' };
  const list = sanitize(b.list); if (!list) return { ok: false, error: 'bad_list' };
  if (!list.length) return { ok: false, error: 'empty' };
  await db.collection('team_members').replaceOne({ _id: 'about' }, { _id: 'about', list: list, at: new Date(), by: u.id }, { upsert: true });
  return { ok: true, list: list };
}
async function reset(b) {
  const u = adminOnly(b); if (!u) return { ok: false, error: 'unauthorized' };
  const db = getDb(); if (!db) return { ok: false, error: 'server_error' };
  await db.collection('team_members').deleteOne({ _id: 'about' });
  return { ok: true };
}

function wrap(fn) {
  return async function (req, res) {
    const body = (req.body && typeof req.body === 'object') ? req.body : {};
    try { res.json(await fn(body)); } catch (e) { console.error('[team] error', e && e.message); res.json({ ok: false, error: 'server_error' }); }
  };
}
router.post('/team/get', wrap(get));
router.post('/team/set', wrap(set));
router.post('/team/reset', wrap(reset));

module.exports = router;
