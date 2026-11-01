'use strict';
/* routes/refcfg.js  --  Pengaturan hadiah REFERRAL & MILESTONE (diatur admin, berlaku untuk semua user). Disimpan di MongoDB.
   Memakai koneksi mongoose yang SUDAH ada. Tanpa paket baru. Environment Render: MAIN_BOT_TOKEN / BOT_TOKEN dan ADMIN_IDS.
   Pasang di server.js:   mountRoute('/api', './routes/refcfg');
   Endpoint:
     POST /api/refcfg/get    (semua user)  -> { ok, custom, cfg:{afex,pts,usdt,levels,milestones} }
     POST /api/refcfg/set    (admin)       body { initData, cfg }  -> simpan
     POST /api/refcfg/reset  (admin)       body { initData }       -> kembali ke bawaan */
const express = require('express');
const crypto = require('crypto');
const mongoose = require('mongoose');
const router = express.Router();

const E = process.env;
const TOKENS = [E.MAIN_BOT_TOKEN, E.BOT_TOKEN].map(function (x) { return String(x || '').trim(); }).filter(function (x, i, a) { return x && a.indexOf(x) === i; });
const ADMINS = String(E.ADMIN_IDS || '').split(',').map(function (s) { return s.trim(); }).filter(Boolean);
const DEFAULTS = {
  afex: 50, pts: 15, usdt: 0,
  levels: { 1: 2, 2: 3, 3: 4, 4: 5, 5: 6, 6: 8, 7: 10 },
  milestones: [{ count: 100, reward: 0.10 }, { count: 500, reward: 1 }, { count: 1000, reward: 5 }, { count: 2500, reward: 20 }, { count: 5000, reward: 50 }]
};

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
    return JSON.parse(p.get('user'));
  } catch (e) { return null; }
}
function adminOnly(b) { const u = verifyInitData(b && b.initData); return (u && ADMINS.indexOf(String(u.id)) >= 0) ? u : null; }

function num(v, min, max, dec) {
  const n = Number(v); if (!isFinite(n) || n < min || n > max) return null;
  const f = Math.pow(10, dec || 0); return Math.round(n * f) / f;
}
function sanitize(c) {
  if (!c || typeof c !== 'object') return null;
  const afex = num(c.afex, 0, 1000000, 4), pts = num(c.pts, 0, 100000, 0);
  const usdt = (c.usdt === undefined || c.usdt === null || c.usdt === '') ? 0 : num(c.usdt, 0, 100000, 4);   // hadiah USDT per referral valid (opsional)
  if (afex === null || pts === null || usdt === null) return null;
  const levels = {};
  for (let i = 1; i <= 7; i++) { const v = num(c.levels && c.levels[i], 0, 100, 2); if (v === null) return null; levels[i] = v; }
  if (!Array.isArray(c.milestones) || c.milestones.length < 1 || c.milestones.length > 8) return null;
  const ms = []; let prev = 0;
  for (const m of c.milestones) {
    const count = num(m && m.count, 1, 1000000, 0), reward = num(m && m.reward, 0, 100000, 4);
    if (count === null || reward === null || count <= prev) return null;   // jumlah orang harus naik berurutan
    prev = count; ms.push({ count: count, reward: reward });
  }
  return { afex: afex, pts: pts, usdt: usdt, levels: levels, milestones: ms };
}

async function get() {
  const db = getDb(); if (!db) return { ok: false, error: 'server_error' };
  const d = await db.collection('ref_config').findOne({ _id: 'main' });
  if (!d || !d.cfg) return { ok: true, custom: false, cfg: DEFAULTS };
  return { ok: true, custom: true, cfg: d.cfg, at: d.at ? new Date(d.at).getTime() : 0 };
}
async function set(b) {
  const u = adminOnly(b); if (!u) return { ok: false, error: 'unauthorized' };
  const db = getDb(); if (!db) return { ok: false, error: 'server_error' };
  const cfg = sanitize(b.cfg); if (!cfg) return { ok: false, error: 'bad_config' };
  await db.collection('ref_config').replaceOne({ _id: 'main' }, { _id: 'main', cfg: cfg, at: new Date(), by: String(u.id) }, { upsert: true });
  return { ok: true, cfg: cfg };
}
async function reset(b) {
  const u = adminOnly(b); if (!u) return { ok: false, error: 'unauthorized' };
  const db = getDb(); if (!db) return { ok: false, error: 'server_error' };
  await db.collection('ref_config').deleteOne({ _id: 'main' });
  return { ok: true, cfg: DEFAULTS };
}
function wrap(fn) {
  return async function (req, res) {
    const body = (req.body && typeof req.body === 'object') ? req.body : {};
    res.set('Cache-Control', 'no-store');
    try { res.json(await fn(body)); } catch (e) { console.error('[refcfg] error', e && e.message); res.json({ ok: false, error: 'server_error' }); }
  };
}
router.post('/refcfg/get', wrap(get));
router.post('/refcfg/set', wrap(set));
router.post('/refcfg/reset', wrap(reset));

module.exports = router;
