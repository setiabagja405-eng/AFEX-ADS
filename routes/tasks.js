'use strict';
/* routes/tasks.js  --  TASK buatan admin (tambah / hapus / ubah hadiah) + override hadiah task bawaan. Disimpan di MongoDB.
   Mengikuti pola routes/refcfg.js: memakai koneksi mongoose yang SUDAH ada, tanpa paket baru.
   Environment Render: MAIN_BOT_TOKEN / BOT_TOKEN dan ADMIN_IDS.
   Pasang di server.js:   mountRoute('/api', './routes/tasks');
   Koleksi MongoDB:
     task_config  -> { _id:'SRV_...', kind:'custom', title, desc, link, answer, rtype, reward, at, by }   (task buatan admin)
                     { _id:'builtin:watch_ad', kind:'builtin', afex, speed, pts, at, by }                  (override hadiah task bawaan)
     task_claims  -> { _id:'<taskId>:<uid>', tid, uid, rtype, reward, at }  (_id unik = klaim hanya 1x per user, atomik)
   Endpoint:
     POST /api/tasks/get     (semua user)  body { initData? } -> { ok, tasks, builtin, claimed, admin }
     POST /api/tasks/claim   (user)        body { initData, id, proof } -> { ok, reward:{type,amount} }  | error: already_claimed / bad_answer / not_found
     POST /api/tasks/add     (admin)       body { initData, title, desc, link, answer?, rtype, reward }
     POST /api/tasks/set     (admin)       body { initData, id, title?, desc?, link?, answer? }
     POST /api/tasks/delete  (admin)       body { initData, id }
     POST /api/tasks/reward  (admin)       body { initData, id, rtype?, reward? }  /  task bawaan: { id:'watch_ad', afex, speed, pts }  atau { id:'watch_ad', reset:true } */
const express = require('express');
const crypto = require('crypto');
const mongoose = require('mongoose');
const router = express.Router();

const E = process.env;
const TOKENS = [E.MAIN_BOT_TOKEN, E.BOT_TOKEN].map(function (x) { return String(x || '').trim(); }).filter(function (x, i, a) { return x && a.indexOf(x) === i; });
const ADMINS = String(E.ADMIN_IDS || '').split(',').map(function (s) { return s.trim(); }).filter(Boolean);

/* hadiah bawaan task "Watch Ad" (sama dengan kode lama di index.html: 15 AFEX, 0.00001 USDT/jam, 1 poin) */
const BUILTIN = { watch_ad: { afex: 15, speed: 0.00001, pts: 1 } };
const RTYPES = ['afex', 'pts', 'usdt'];
const MAX_TASKS = 50;
const ID_RE = /^[A-Za-z0-9_-]{3,60}$/;
const LIM = { title: 60, desc: 200, link: 300, answer: 60 };

function getDb() { return mongoose.connection && mongoose.connection.readyState === 1 ? mongoose.connection.db : null; }
function verifyInitData(initData) {
  try {
    if (!TOKENS.length) return null;
    const p = new URLSearchParams(initData || ''), hash = p.get('hash'); if (!hash) return null;
    p.delete('hash');
    const dcs = Array.from(p.keys()).sort().map(function (k) { return k + '=' + p.get(k); }).join('\n');
    const ok = TOKENS.some(function (tok) {
      const secret = crypto.createHmac('sha256', 'WebAppData').update(tok).digest();
      return crypto.createHmac('sha256', secret).update(dcs).digest('hex') === hash;
    });
    if (!ok) return null;
    if (Date.now() / 1000 - Number(p.get('auth_date')) > 86400) return null;
    const u = JSON.parse(p.get('user'));
    return (u && u.id) ? u : null;
  } catch (e) { return null; }
}
function adminOnly(b) { const u = verifyInitData(b && b.initData); return (u && ADMINS.indexOf(String(u.id)) >= 0) ? u : null; }

/* ---------- validasi ---------- */
function num(v, min, max, dec) {
  if (typeof v !== 'number' && typeof v !== 'string') return null;
  if (typeof v === 'string' && !v.trim()) return null;
  const n = Number(v); if (!isFinite(n) || n < min || n > max) return null;
  const f = Math.pow(10, dec || 0); return Math.round(n * f) / f;
}
function txt(v, max, allowEmpty) {            // teks bersih: tanpa karakter kontrol, dipotong panjangnya, harus string
  if (typeof v !== 'string') return null;
  const s = v.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim();
  if (s.length > max) return null;
  if (!s && !allowEmpty) return null;
  return s;
}
function linkOk(v) {                           // kosong boleh; selain itu hanya http(s)
  const s = txt(v, LIM.link, true); if (s === null) return null;
  if (!s) return '';
  if (!/^https?:\/\/[^\s<>"'`\\]{3,}$/i.test(s)) return null;
  try { const u = new URL(s); if (u.protocol !== 'http:' && u.protocol !== 'https:') return null; } catch (e) { return null; }
  return s;
}
function amount(rtype, v) {
  if (rtype === 'pts') return num(v, 1, 100000, 0);
  if (rtype === 'afex') return num(v, 0.0001, 1000000, 4);
  if (rtype === 'usdt') return num(v, 0.0001, 100000, 4);
  return null;
}
function rtypeOk(v) { return (typeof v === 'string' && RTYPES.indexOf(v) >= 0) ? v : null; }
function newId() { return 'SRV_' + Date.now().toString(36) + crypto.randomBytes(3).toString('hex'); }

/* ---------- pembatas tebakan jawaban salah (memori proses; cukup untuk menahan brute force kode rahasia) ---------- */
const WRONG = new Map(), WRONG_MAX = 10, WRONG_WIN = 10 * 60 * 1000;
function wrongBlocked(k) { const r = WRONG.get(k); if (!r) return false; if (Date.now() - r.t > WRONG_WIN) { WRONG.delete(k); return false; } return r.n >= WRONG_MAX; }
function wrongHit(k) { const r = WRONG.get(k), now = Date.now(); if (!r || now - r.t > WRONG_WIN) WRONG.set(k, { n: 1, t: now }); else r.n++; if (WRONG.size > 5000) WRONG.clear(); }

/* ---------- snapshot daftar task ---------- */
async function snapshot(db, user, isAdmin) {
  const docs = await db.collection('task_config').find({}).toArray();
  const tasks = docs.filter(function (d) { return d.kind === 'custom'; })
    .sort(function (a, b) { return new Date(b.at || 0).getTime() - new Date(a.at || 0).getTime(); })
    .map(function (d) {
      const o = { id: String(d._id), title: d.title, desc: d.desc || '', link: d.link || '', rtype: d.rtype, reward: d.reward, hasAnswer: !!d.answer, at: d.at ? new Date(d.at).getTime() : 0 };
      if (isAdmin) o.answer = d.answer || '';     // jawaban hanya terlihat oleh admin
      return o;
    });
  const builtin = {};
  Object.keys(BUILTIN).forEach(function (k) {
    const d = docs.find(function (x) { return x._id === 'builtin:' + k; });
    builtin[k] = d ? { afex: d.afex, speed: d.speed, pts: d.pts, custom: true } : { afex: BUILTIN[k].afex, speed: BUILTIN[k].speed, pts: BUILTIN[k].pts, custom: false };
  });
  let claimed = [];
  if (user && tasks.length) {
    const ids = tasks.map(function (t) { return t.id; });
    const cl = await db.collection('task_claims').find({ uid: String(user.id), tid: { $in: ids } }).project({ tid: 1 }).toArray();
    claimed = cl.map(function (c) { return c.tid; });
  }
  return { ok: true, tasks: tasks, builtin: builtin, claimed: claimed, admin: !!isAdmin };
}

/* ---------- handler ---------- */
async function get(b) {
  const db = getDb(); if (!db) return { ok: false, error: 'server_error' };
  const u = verifyInitData(b && b.initData);
  const adm = !!(u && ADMINS.indexOf(String(u.id)) >= 0);
  return snapshot(db, u, adm);
}
async function add(b) {
  const u = adminOnly(b); if (!u) return { ok: false, error: 'unauthorized' };
  const db = getDb(); if (!db) return { ok: false, error: 'server_error' };
  const title = txt(b.title, LIM.title), desc = txt(b.desc, LIM.desc, true), link = linkOk(b.link === undefined ? '' : b.link);
  const answer = (b.answer === undefined || b.answer === null) ? '' : txt(String(b.answer), LIM.answer, true);
  const rtype = rtypeOk(b.rtype); const reward = rtype ? amount(rtype, b.reward) : null;
  if (title === null || desc === null || link === null || answer === null || !rtype || reward === null) return { ok: false, error: 'bad_input' };
  const col = db.collection('task_config');
  if (await col.countDocuments({ kind: 'custom' }) >= MAX_TASKS) return { ok: false, error: 'limit' };
  await col.insertOne({ _id: newId(), kind: 'custom', title: title, desc: desc, link: link, answer: answer, rtype: rtype, reward: reward, at: new Date(), by: String(u.id) });
  return snapshot(db, u, true);
}
async function set(b) {
  const u = adminOnly(b); if (!u) return { ok: false, error: 'unauthorized' };
  const db = getDb(); if (!db) return { ok: false, error: 'server_error' };
  const id = typeof b.id === 'string' ? b.id : ''; if (!ID_RE.test(id)) return { ok: false, error: 'bad_input' };
  const $set = {};
  if (b.title !== undefined) { const v = txt(b.title, LIM.title); if (v === null) return { ok: false, error: 'bad_input' }; $set.title = v; }
  if (b.desc !== undefined) { const v = txt(b.desc, LIM.desc, true); if (v === null) return { ok: false, error: 'bad_input' }; $set.desc = v; }
  if (b.link !== undefined) { const v = linkOk(b.link); if (v === null) return { ok: false, error: 'bad_input' }; $set.link = v; }
  if (b.answer !== undefined) { const v = b.answer === null ? '' : txt(String(b.answer), LIM.answer, true); if (v === null) return { ok: false, error: 'bad_input' }; $set.answer = v; }
  if (!Object.keys($set).length) return { ok: false, error: 'bad_input' };
  $set.at2 = new Date(); $set.by2 = String(u.id);
  const r = await db.collection('task_config').updateOne({ _id: id, kind: 'custom' }, { $set: $set });
  if (!r.matchedCount) return { ok: false, error: 'not_found' };
  return snapshot(db, u, true);
}
async function del(b) {
  const u = adminOnly(b); if (!u) return { ok: false, error: 'unauthorized' };
  const db = getDb(); if (!db) return { ok: false, error: 'server_error' };
  const id = typeof b.id === 'string' ? b.id : ''; if (!ID_RE.test(id)) return { ok: false, error: 'bad_input' };
  const r = await db.collection('task_config').deleteOne({ _id: id, kind: 'custom' });
  if (!r.deletedCount) return { ok: false, error: 'not_found' };
  await db.collection('task_claims').deleteMany({ tid: id });
  return snapshot(db, u, true);
}
async function reward(b) {
  const u = adminOnly(b); if (!u) return { ok: false, error: 'unauthorized' };
  const db = getDb(); if (!db) return { ok: false, error: 'server_error' };
  const id = typeof b.id === 'string' ? b.id : ''; if (!ID_RE.test(id)) return { ok: false, error: 'bad_input' };
  const col = db.collection('task_config');
  if (Object.prototype.hasOwnProperty.call(BUILTIN, id)) {                        // task bawaan: override 3 hadiahnya
    if (b.reset === true) { await col.deleteOne({ _id: 'builtin:' + id, kind: 'builtin' }); return snapshot(db, u, true); }
    const afex = num(b.afex, 0, 1000000, 4), speed = num(b.speed, 0, 1000, 8), pts = num(b.pts, 0, 100000, 0);
    if (afex === null || speed === null || pts === null) return { ok: false, error: 'bad_input' };
    await col.replaceOne({ _id: 'builtin:' + id }, { _id: 'builtin:' + id, kind: 'builtin', afex: afex, speed: speed, pts: pts, at: new Date(), by: String(u.id) }, { upsert: true });
    return snapshot(db, u, true);
  }
  const t = await col.findOne({ _id: id, kind: 'custom' });                        // task buatan admin: ubah tipe + jumlah
  if (!t) return { ok: false, error: 'not_found' };
  const rtype = b.rtype === undefined ? t.rtype : rtypeOk(b.rtype); if (!rtype) return { ok: false, error: 'bad_input' };
  const amt = amount(rtype, b.reward); if (amt === null) return { ok: false, error: 'bad_input' };
  await col.updateOne({ _id: id, kind: 'custom' }, { $set: { rtype: rtype, reward: amt, at2: new Date(), by2: String(u.id) } });
  return snapshot(db, u, true);
}
async function claim(b) {
  const u = verifyInitData(b && b.initData); if (!u) return { ok: false, error: 'unauthorized' };
  const db = getDb(); if (!db) return { ok: false, error: 'server_error' };
  const uid = String(u.id), id = typeof b.id === 'string' ? b.id : ''; if (!ID_RE.test(id)) return { ok: false, error: 'bad_input' };
  const t = await db.collection('task_config').findOne({ _id: id, kind: 'custom' });
  if (!t) return { ok: false, error: 'not_found' };
  const key = id + ':' + uid;
  if (await db.collection('task_claims').findOne({ _id: key }, { projection: { _id: 1 } })) return { ok: false, error: 'already_claimed' };
  if (t.answer) {
    if (wrongBlocked(key)) return { ok: false, error: 'too_many' };
    const proof = typeof b.proof === 'string' ? b.proof.trim().toLowerCase() : '';
    if (proof !== String(t.answer).trim().toLowerCase()) { wrongHit(key); return { ok: false, error: 'bad_answer' }; }
  }
  try {                                           // atomik: _id unik -> hanya satu klaim per (task, user), balapan permintaan pun hanya satu yang menang
    await db.collection('task_claims').insertOne({ _id: key, tid: id, uid: uid, rtype: t.rtype, reward: t.reward, at: new Date() });
  } catch (e) {
    if (e && e.code === 11000) return { ok: false, error: 'already_claimed' };
    throw e;
  }
  return { ok: true, id: id, reward: { type: t.rtype, amount: t.reward } };
}

function wrap(fn) {
  return async function (req, res) {
    const body = (req.body && typeof req.body === 'object') ? req.body : {};
    res.set('Cache-Control', 'no-store');
    try { res.json(await fn(body)); } catch (e) { console.error('[tasks] error', e && e.message); res.json({ ok: false, error: 'server_error' }); }
  };
}
router.post('/tasks/get', wrap(get));
router.post('/tasks/claim', wrap(claim));
router.post('/tasks/set', wrap(set));
router.post('/tasks/add', wrap(add));
router.post('/tasks/delete', wrap(del));
router.post('/tasks/reward', wrap(reward));

module.exports = router;
