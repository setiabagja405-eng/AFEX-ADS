'use strict';
/* routes/users.js  --  Menu User (admin) + OTP pemulihan akun per user (berubah tiap 5 menit)
   Memakai koneksi mongoose yang SUDAH ada. Tanpa paket baru.
   Environment Render:
     MAIN_BOT_TOKEN / BOT_TOKEN   token bot mini app (validasi initData)
     ADMIN_IDS                    ID Telegram admin, pisahkan koma
     RECOVERY_SECRET              (disarankan) teks acak panjang khusus kode pemulihan; jika kosong memakai HASH_SALT
   Endpoint (dipasang di '/api'):
     POST /api/users/list     (admin)  body { initData, q?, limit?, skip? }        -> daftar user + status KYC wajah + email + OTP saat ini
     POST /api/users/otp      (admin)  body { initData, targetUid }         -> OTP saat ini milik 1 user
     POST /api/users/verify   (admin)  body { initData, targetUid, code }   -> cek kode yang disebut user
     POST /api/users/my-otp   (user)   body { initData }                    -> OTP milik user itu sendiri (untuk FAQ "Pulihkan Akun")
   UNDANGAN (referral) -- dicatat & divalidasi di SERVER (koleksi ref_invites), aturan hanya di konfigurasi REF_RULES di bawah:
     POST /api/users/ref-register (user)  body { initData, inviter, name, ads } -> catat teman yang masuk lewat link undangan
     POST /api/users/ref-activity (user)  body { initData, mined, ads }         -> laporan aktivitas teman (login/mining/iklan); server yang menilai valid
     POST /api/users/ref-mine     (user)  body { initData }                     -> daftar teman yang saya undang + status (realtime)
     POST /api/users/ref-claim    (user)  body { initData, friend }             -> klaim hadiah 1x per teman valid (atomik)
     POST /api/users/ref-counts   (admin) body { initData, uids }               -> jumlah valid/tidak valid/pending per user (menu User admin)
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

/* ---------- KONFIGURASI ATURAN UNDANGAN (tidak ditampilkan di aplikasi; bisa diubah lewat Environment Render) ---------- */
function numEnv(v, d) { const x = Number(v); return (v !== undefined && v !== '' && isFinite(x) && x >= 0) ? x : d; }
const REF_RULES = {
  loginDays: numEnv(E.REF_LOGIN_DAYS, 2),            // teman harus login di sedikitnya N hari berbeda
  mineOnce: E.REF_MINE_ONCE !== 'false',             // teman harus mining minimal sekali
  minAds: numEnv(E.REF_MIN_ADS, 30),                 // teman harus menonton minimal N iklan (setelah bergabung)
  inactiveHours: numEnv(E.REF_INACTIVE_HOURS, 48),   // belum valid & tidak aktif sekian jam -> tidak valid
  adsPerDay: numEnv(E.REF_ADS_PER_DAY, 25),          // batas wajar iklan per hari (batas harian aplikasi), dipakai membatasi laporan iklan
  tzOffset: numEnv(E.REF_TZ_OFFSET, 7)               // zona waktu pergantian hari (WIB = 7)
};
function dayKey(t) { return new Date(t + REF_RULES.tzOffset * 3600000).toISOString().slice(0, 10); }
function ruleMet(d) {
  const days = (d.days || []).length;
  const ads = Math.min(Math.max(0, (d.ads || 0) - (d.adsBase || 0)), REF_RULES.adsPerDay * days);
  return days >= REF_RULES.loginDays && (!REF_RULES.mineOnce || !!d.mined) && ads >= REF_RULES.minAds;
}
let lastExpire = 0;
async function expireStale(db, force) {
  const now = Date.now(); if (!force && now - lastExpire < 15000) return; lastExpire = now;
  const cutoff = new Date(now - REF_RULES.inactiveHours * 3600000);
  await db.collection('ref_invites').updateMany({ status: 'pending', lastSeen: { $lt: cutoff } }, { $set: { status: 'invalid', invalidAt: new Date() } });
}
async function countsFor(db, ids) {
  const out = {}; ids.forEach(function (i) { out[i] = { valid: 0, invalid: 0, pending: 0 }; });
  if (!ids.length) return out;
  await expireStale(db);
  const agg = await db.collection('ref_invites').aggregate([{ $match: { inviter: { $in: ids } } }, { $group: { _id: { i: '$inviter', s: '$status' }, n: { $sum: 1 } } }]).toArray();
  agg.forEach(function (g) { if (out[g._id.i] && out[g._id.i][g._id.s] !== undefined) out[g._id.i][g._id.s] = g.n; });
  return out;
}

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
  const skip = Math.min(Math.max(parseInt(b.skip, 10) || 0, 0), 100000);   // paginasi: klien memuat semua user bertahap
  const rows = await users.find(filter).project({ userId: 1, username: 1 }).sort({ _id: -1 }).skip(skip).limit(limit).toArray();
  const ids = rows.map(function (r) { return String(r.userId); });

  const mails = await db.collection('a2f_verified').find({ uid: { $in: ids } }).project({ uid: 1, email: 1, at: 1, revokedAt: 1 }).toArray();
  const faces = await db.collection('face_registry').find({ uid: { $in: ids } }).project({ uid: 1 }).toArray();
  const refCounts = await countsFor(db, ids);
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
        refValid: refCounts[id].valid,
        refInvalid: refCounts[id].invalid,
        refPending: refCounts[id].pending,
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

/* ---------- UNDANGAN: dicatat & dinilai di server ---------- */
function nInt(v, max) { const x = parseInt(v, 10); return (isFinite(x) && x >= 0 && x <= (max || 1000000)) ? x : null; }

async function refRegister(b) {
  const u = tgUser(b); if (!u) return { ok: false, error: 'unauthorized' };
  const db = getDb(); if (!db) return { ok: false, error: 'server_error' };
  const inviter = String(b.inviter || '').trim();
  if (!UID_RE.test(inviter) || inviter === u.id) return { ok: false, error: 'bad_inviter' };
  const ids = /^\d+$/.test(inviter) ? [inviter, Number(inviter)] : [inviter];
  const exists = await db.collection('users').findOne({ userId: { $in: ids } }, { projection: { _id: 1 } });
  if (!exists) return { ok: false, error: 'inviter_not_found' };
  const col = db.collection('ref_invites');
  const back = await col.findOne({ _id: inviter, inviter: u.id }, { projection: { _id: 1 } });   // cegah saling undang (A<->B)
  if (back) return { ok: false, error: 'loop' };
  const now = new Date(), name = String(b.name || '').replace(/[<>]/g, '').slice(0, 60);
  const uname = u.username ? '@' + u.username : (name || ('ID ' + u.id));
  await col.updateOne({ _id: u.id }, { $setOnInsert: {
    inviter: inviter, username: uname, at: now, lastSeen: now, days: [dayKey(now.getTime())], mined: false,
    ads: nInt(b.ads) || 0, adsBase: nInt(b.ads) || 0, status: 'pending', rewardClaimed: false
  } }, { upsert: true });
  return { ok: true };
}

async function refActivity(b) {
  const u = tgUser(b); if (!u) return { ok: false, error: 'unauthorized' };
  const db = getDb(); if (!db) return { ok: false, error: 'server_error' };
  const col = db.collection('ref_invites'), d = await col.findOne({ _id: u.id });
  if (!d) return { ok: true, registered: false };
  if (d.status !== 'pending') return { ok: true, registered: true, status: d.status };
  const now = Date.now();
  if (now - new Date(d.lastSeen).getTime() >= REF_RULES.inactiveHours * 3600000) {   // terlalu lama tidak aktif sebelum memenuhi syarat
    await col.updateOne({ _id: u.id, status: 'pending' }, { $set: { status: 'invalid', invalidAt: new Date() } });
    return { ok: true, registered: true, status: 'invalid' };
  }
  const days = (d.days || []).slice(), dk = dayKey(now); if (days.indexOf(dk) < 0) days.push(dk);
  const reported = nInt(b.ads);
  const nd = { days: days, mined: !!(d.mined || b.mined), ads: Math.max(d.ads || 0, reported === null ? 0 : reported), adsBase: d.adsBase || 0 };
  const status = ruleMet(nd) ? 'valid' : 'pending';
  const set = { lastSeen: new Date(now), mined: nd.mined, ads: nd.ads, days: nd.days, status: status };
  if (status === 'valid') set.validAt = new Date(now);
  await col.updateOne({ _id: u.id, status: 'pending' }, { $set: set });
  return { ok: true, registered: true, status: status };
}

async function refMine(b) {
  const u = tgUser(b); if (!u) return { ok: false, error: 'unauthorized' };
  const db = getDb(); if (!db) return { ok: false, error: 'server_error' };
  await expireStale(db);
  const rows = await db.collection('ref_invites').find({ inviter: u.id }).sort({ at: -1 }).limit(2000).toArray();
  return { ok: true, now: Date.now(), list: rows.map(function (r) {
    return { uid: String(r._id), username: r.username || '', status: r.status, at: r.at ? new Date(r.at).getTime() : 0, rewardClaimed: !!r.rewardClaimed };
  }) };
}

async function refClaim(b) {
  const u = tgUser(b); if (!u) return { ok: false, error: 'unauthorized' };
  const db = getDb(); if (!db) return { ok: false, error: 'server_error' };
  const uid = String(b.friend || '').trim(); if (!UID_RE.test(uid)) return { ok: false, error: 'bad_uid' };
  const r = await db.collection('ref_invites').updateOne({ _id: uid, inviter: u.id, status: 'valid', rewardClaimed: { $ne: true } }, { $set: { rewardClaimed: true, claimedAt: new Date() } });
  return { ok: true, claimed: (r.modifiedCount || 0) === 1 };
}

async function refCounts(b) {
  const u = adminOnly(b); if (!u) return { ok: false, error: 'unauthorized' };
  const db = getDb(); if (!db) return { ok: false, error: 'server_error' };
  const ids = (Array.isArray(b.uids) ? b.uids : []).slice(0, 200).map(String).filter(function (x) { return UID_RE.test(x); });
  return { ok: true, counts: await countsFor(db, ids) };
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
router.post('/users/ref-register', wrap(refRegister));
router.post('/users/ref-activity', wrap(refActivity));
router.post('/users/ref-mine', wrap(refMine));
router.post('/users/ref-claim', wrap(refClaim));
router.post('/users/ref-counts', wrap(refCounts));

if (!SECRET) console.warn('[users] RECOVERY_SECRET / HASH_SALT belum diisi: menu User & OTP pemulihan tidak aktif');
module.exports = router;
