'use strict';
/* routes/afexface.js  --  OTP bot (5 menit), registry wajah anti akun ganda, status A2F
   Memakai koneksi mongoose yang SUDAH ada (tanpa koneksi baru, tanpa paket baru).
   POST /api/afex          body JSON (boleh Content-Type text/plain)
   POST /telegram/:secret  webhook bot OTP (/start) */
const express = require('express');
const crypto = require('crypto');
const mongoose = require('mongoose');
const router = express.Router();

const E = process.env;
const MAIN_TOKEN = E.MAIN_BOT_TOKEN || E.BOT_TOKEN;   // token bot mini app (sama dengan BOT_TOKEN di notify.js)
const TTL_MS = 5 * 60 * 1000, COOLDOWN_MS = 30 * 1000, MAX_TRIES = 5, MAX_REQ_HOUR = 6;
const FACE = { E: 0.50, C: 0.875 };           // ambang wajah ganda: Euclidean < 0.50 DAN Cosine >= 0.875
const ADMINS = String(E.ADMIN_IDS || '').split(',').map(function (s) { return s.trim(); }).filter(Boolean);
let db = null;
function getDb() { return mongoose.connection && mongoose.connection.readyState === 1 ? mongoose.connection.db : null; }

const sha = function (s) { return crypto.createHash('sha256').update(s, 'utf8').digest('hex'); };
const hmac = function (key, msg) { return crypto.createHmac('sha256', key).update(msg).digest(); };

/* ---------- validasi pengguna dari initData Telegram WebApp ---------- */
function tgUser(body) {
  if (!MAIN_TOKEN) {   // tidak aman; hanya untuk uji lokal
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

/* ---------- Telegram ---------- */
const OTP_TOKEN = String(E.OTP_BOT_TOKEN || '').trim();
const BASE_URL = String(E.PUBLIC_URL || E.RENDER_EXTERNAL_URL || '').trim().replace(/\/+$/, '');

/* panggilan umum ke Telegram Bot API (OTP bot). Tidak pernah melempar error; hasilnya selalu {ok, code, desc, data}. */
async function tgCall(method, payload) {
  if (!OTP_TOKEN) return { ok: false, code: 0, desc: 'OTP_BOT_TOKEN belum diisi di Environment Render' };
  if (typeof fetch !== 'function') return { ok: false, code: 0, desc: 'Node.js < 18 (fetch tidak ada). Set NODE_VERSION=20 di Render' };
  const ctl = new AbortController(), tm = setTimeout(function () { ctl.abort(); }, 10000);
  try {
    const r = await fetch('https://api.telegram.org/bot' + OTP_TOKEN + '/' + method, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload || {}), signal: ctl.signal
    });
    let data = null; try { data = await r.json(); } catch (e) {}
    return { ok: !!(r.ok && data && data.ok), code: r.status, desc: (data && data.description) || '', data: data && data.result };
  } catch (e) {
    return { ok: false, code: 0, desc: 'koneksi ke Telegram gagal: ' + (e && e.message) };
  } finally { clearTimeout(tm); }
}
async function tgSend(chatId, html) {
  const r = await tgCall('sendMessage', { chat_id: chatId, text: html, parse_mode: 'HTML', disable_web_page_preview: true });
  if (!r.ok) console.error('[OTP] sendMessage gagal -> kode ' + r.code + ': ' + r.desc);
  return { ok: r.ok, code: r.code, desc: r.desc };
}

/* daftarkan webhook bot OTP otomatis (sebelumnya tidak ada yang memanggil setWebhook, sehingga /start tidak pernah dibalas) */
async function setupWebhook() {
  if (!OTP_TOKEN || !E.WEBHOOK_SECRET || !BASE_URL) {
    console.warn('[OTP] Webhook TIDAK didaftarkan. Kurang: ' + [!OTP_TOKEN && 'OTP_BOT_TOKEN', !E.WEBHOOK_SECRET && 'WEBHOOK_SECRET', !BASE_URL && 'PUBLIC_URL/RENDER_EXTERNAL_URL'].filter(Boolean).join(', '));
    return { ok: false, desc: 'env kurang' };
  }
  if (MAIN_TOKEN && OTP_TOKEN === MAIN_TOKEN) {   // jangan rebut webhook bot utama (Fexboostbot)
    console.error('[OTP] OTP_BOT_TOKEN SAMA dengan BOT_TOKEN. Isi OTP_BOT_TOKEN dengan token bot OTP (@afexotpbot) dari BotFather. Webhook tidak dipasang.');
    return { ok: false, desc: 'OTP_BOT_TOKEN sama dengan BOT_TOKEN' };
  }
  const r = await tgCall('setWebhook', { url: BASE_URL + '/telegram/' + E.WEBHOOK_SECRET, allowed_updates: ['message'] });
  console.log('[OTP] setWebhook ' + (r.ok ? 'OK' : 'GAGAL (' + r.code + ') ' + r.desc));
  return r;
}

/* ---------- OTP ---------- */
async function otpRequest(b) {
  const u = tgUser(b);
  if (!u) {
    console.error('[OTP] unauthorized: ' + (!MAIN_TOKEN ? 'MAIN_BOT_TOKEN/BOT_TOKEN kosong di Render' : (b.initData ? 'initData tidak cocok dengan token bot mini app (token salah / bukan bot yang membuka mini app)' : 'initData kosong (mini app tidak dibuka lewat Telegram)')));
    return { ok: false, error: 'unauthorized' };
  }
  const email = String(b.email || '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return { ok: false, error: 'bad_email' };
  if (!OTP_TOKEN) { console.error('[OTP] OTP_BOT_TOKEN kosong di Environment Render'); return { ok: false, error: 'send_failed' }; }
  if (!E.HASH_SALT) console.warn('[OTP] HASH_SALT belum diisi (hash jadi lemah). Isi dengan teks acak panjang.');
  const emailHash = sha(E.HASH_SALT + email);
  const owner = await db.collection('a2f_verified').findOne({ emailHash: emailHash });
  if (owner && owner.uid !== u.id) return { ok: false, error: 'email_used' };

  const now = Date.now(), rates = db.collection('otp_rate');
  const rate = (await rates.findOne({ _id: u.id })) || { _id: u.id, cd: 0, hs: now, n: 0 };
  if (now < rate.cd) return { ok: false, error: 'cooldown', retryIn: Math.ceil((rate.cd - now) / 1000) };
  if (now - rate.hs > 3600000) { rate.hs = now; rate.n = 0; }
  if (rate.n >= MAX_REQ_HOUR) return { ok: false, error: 'too_many' };

  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  const sent = await tgSend(u.id,
    '\uD83D\uDD10 <b>AFEX OTP</b>\n\nKode OTP Anda: <b><code>' + code + '</code></b>\n' +
    'Untuk akun A2F: ' + (u.username ? '@' + u.username : u.id) + '\n' +
    '\u23F1 Berlaku <b>5 menit</b>. Jangan bagikan kode ini ke siapa pun.');
  if (!sent.ok) return { ok: false, error: sent.code === 403 ? 'need_start' : 'send_failed' };

  await db.collection('otp_codes').replaceOne({ _id: u.id },
    { _id: u.id, h: sha(E.HASH_SALT + u.id + email + code), email: email, exp: new Date(now + TTL_MS), tries: 0 }, { upsert: true });
  await rates.replaceOne({ _id: u.id }, { _id: u.id, cd: now + COOLDOWN_MS, hs: rate.hs, n: rate.n + 1 }, { upsert: true });
  return { ok: true, expiresAt: now + TTL_MS, ttl: 300 };
}
async function otpVerify(b) {
  const u = tgUser(b); if (!u) return { ok: false, error: 'unauthorized' };
  const email = String(b.email || '').trim().toLowerCase(), code = String(b.code || '').replace(/\s+/g, '');
  const otps = db.collection('otp_codes'), d = await otps.findOne({ _id: u.id });
  if (!d) return { ok: false, error: 'expired' };
  if (Date.now() > new Date(d.exp).getTime()) { await otps.deleteOne({ _id: u.id }); return { ok: false, error: 'expired' }; }
  if (d.email !== email) return { ok: false, error: 'invalid' };
  if (d.tries >= MAX_TRIES) { await otps.deleteOne({ _id: u.id }); return { ok: false, error: 'locked' }; }
  const want = Buffer.from(d.h), got = Buffer.from(sha(E.HASH_SALT + u.id + email + code));
  if (want.length !== got.length || !crypto.timingSafeEqual(want, got)) {
    const tries = d.tries + 1;
    if (tries >= MAX_TRIES) await otps.deleteOne({ _id: u.id }); else await otps.updateOne({ _id: u.id }, { $set: { tries: tries } });
    return { ok: false, error: 'invalid', left: Math.max(0, MAX_TRIES - tries) };
  }
  const del = await otps.deleteOne({ _id: u.id, h: d.h });          // sekali pakai (atomik)
  if (del.deletedCount !== 1) return { ok: false, error: 'expired' };
  try {
    await db.collection('a2f_verified').updateOne({ uid: u.id },
      { $set: { uid: u.id, email: email, emailHash: sha(E.HASH_SALT + email), at: new Date() } }, { upsert: true });
  } catch (e) { if (e && e.code === 11000) return { ok: false, error: 'email_used' }; throw e; }
  return { ok: true };
}
async function a2fStatus(b) {
  const u = tgUser(b); if (!u) return { ok: false, error: 'unauthorized' };
  const d = await db.collection('a2f_verified').findOne({ uid: u.id });
  return { ok: true, verified: !!d, at: d ? new Date(d.at).getTime() : 0 };
}

/* ---------- registry wajah (anti akun/mini app ganda) ---------- */
function okDesc(d) { return Array.isArray(d) && d.length === 128 && d.every(function (x) { return typeof x === 'number' && isFinite(x); }); }
function eu(a, b) { let s = 0; for (let i = 0; i < a.length; i++) { const t = a[i] - b[i]; s += t * t; } return Math.sqrt(s); }
function cosine(a, b) { let d = 0, na = 0, nb = 0; for (let i = 0; i < a.length; i++) { d += a[i] * b[i]; na += a[i] * a[i]; nb += b[i] * b[i]; } return d / (Math.sqrt(na * nb) || 1); }
async function findDup(uid, d) {
  const list = await db.collection('face_registry').find({ uid: { $ne: uid } }).project({ uid: 1, d: 1 }).toArray();
  let best = null;
  for (const x of list) {
    if (!okDesc(x.d)) continue;
    const e = eu(d, x.d), c = cosine(d, x.d);
    if (e < FACE.E && c >= FACE.C && (!best || e < best.dist)) best = { uid: x.uid, dist: e, cos: c };
  }
  return best;
}
async function faceCheck(b) {
  const u = tgUser(b); if (!u) return { ok: false, error: 'unauthorized' };
  if (!okDesc(b.d)) return { ok: false, error: 'bad_descriptor' };
  const dup = await findDup(u.id, b.d);
  return dup ? { ok: true, duplicate: true, uid: dup.uid, dist: dup.dist, cos: dup.cos } : { ok: true, duplicate: false };
}
async function faceRegister(b) {
  const u = tgUser(b); if (!u) return { ok: false, error: 'unauthorized' };
  if (!okDesc(b.d)) return { ok: false, error: 'bad_descriptor' };
  const dup = await findDup(u.id, b.d);
  if (dup) return { ok: false, error: 'duplicate', uid: dup.uid };
  await db.collection('face_registry').replaceOne({ uid: u.id },
    { uid: u.id, username: u.username, d: b.d.map(function (x) { return Math.round(x * 10000) / 10000; }), ts: new Date() }, { upsert: true });
  return { ok: true };
}
async function faceRemove(b) {   // hanya admin (ADMIN_IDS): dipakai saat admin membatalkan KYC wajah
  const u = tgUser(b); if (!u || ADMINS.indexOf(u.id) < 0) return { ok: false, error: 'unauthorized' };
  await db.collection('face_registry').deleteOne({ uid: String(b.targetUid || '') });
  return { ok: true };
}


/* ---------- pembatalan KYC / Founder oleh admin (disimpan di server agar sampai ke perangkat user) ---------- */
const REVOKE_KINDS = ['face', 'id', 'kyc_all', 'founder'];
async function revoke(b) {
  const u = tgUser(b); if (!u || ADMINS.indexOf(u.id) < 0) return { ok: false, error: 'unauthorized' };
  const target = String(b.targetUid || '').trim();
  if (!/^\d{3,20}$/.test(target)) return { ok: false, error: 'bad_uid' };
  if (REVOKE_KINDS.indexOf(b.kind) < 0) return { ok: false, error: 'bad_kind' };
  await db.collection('revocations').insertOne({ uid: target, kind: b.kind, ts: Date.now(), by: u.id });
  if (b.kind === 'face' || b.kind === 'kyc_all') await db.collection('face_registry').deleteOne({ uid: target });   // wajah bisa didaftarkan ulang
  if (b.kind === 'kyc_all') await db.collection('a2f_verified').updateOne({ uid: target }, { $set: { revokedAt: new Date() } }).catch(function () {});
  return { ok: true };
}
async function revocations(b) {
  const u = tgUser(b); if (!u) return { ok: false, error: 'unauthorized' };
  const list = await db.collection('revocations').find({ uid: u.id, ts: { $gt: Number(b.since) || 0 } }).sort({ ts: 1 }).limit(20).toArray();
  return { ok: true, list: list.map(function (x) { return { kind: x.kind, ts: x.ts }; }) };
}

async function handle(body) {
  switch (body && body.action) {
    case 'otp_request': return otpRequest(body);
    case 'otp_verify': return otpVerify(body);
    case 'a2f_status': return a2fStatus(body);
    case 'face_check': return faceCheck(body);
    case 'face_register': return faceRegister(body);
    case 'face_remove': return faceRemove(body);
    case 'revoke': return revoke(body);
    case 'revocations': return revocations(body);
    default: return { ok: false, error: 'unknown_action' };
  }
}

/* ---------- route ---------- */
router.use(express.text({ type: 'text/plain', limit: '100kb' }));
function parseBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  try { return JSON.parse(req.body || '{}'); } catch (e) { return null; }
}
router.post('/api/afex', async function (req, res) {
  const body = parseBody(req); if (!body) return res.json({ ok: false, error: 'bad_json' });
  db = getDb(); if (!db) return res.json({ ok: false, error: 'server_error' });
  try { res.json(await handle(body)); } catch (e) { console.error('afex api error', e && e.message); res.json({ ok: false, error: 'server_error' }); }
});
router.post('/telegram/:secret', async function (req, res) {
  if (!E.WEBHOOK_SECRET || req.params.secret !== E.WEBHOOK_SECRET) { console.warn('[OTP] webhook ditolak: secret tidak cocok / WEBHOOK_SECRET kosong'); return res.sendStatus(403); }
  try {
    const up = parseBody(req) || {}, m = up.message;
    if (m && m.chat) {   // balas SEMUA pesan pribadi (bukan hanya /start) supaya bot terasa hidup
      console.log('[OTP] pesan masuk dari chat ' + m.chat.id);
      await tgSend(m.chat.id, '\uD83D\uDC4B <b>Bot OTP AFEX</b>\n\nBuka mini app AFEX \u2192 menu <b>OTP (A2F)</b> \u2192 tekan <b>Get</b>. Kode 6 digit dikirim ke sini dan berlaku 5 menit.');
    }
  } catch (e) { console.error('[OTP] webhook error', e && e.message); }
  res.sendStatus(200);
});

/* diagnosa: buka https://<server>/api/afex/health di browser. Tidak menampilkan nilai rahasia. ?fix=1 = daftarkan ulang webhook */
router.get('/api/afex/health', async function (req, res) {
  const out = {
    node: process.version, fetch: typeof fetch,
    env: {
      MONGODB_URI: !!E.MONGODB_URI, OTP_BOT_TOKEN: !!OTP_TOKEN,
      MAIN_BOT_TOKEN_atau_BOT_TOKEN: !!MAIN_TOKEN, HASH_SALT: !!E.HASH_SALT,
      WEBHOOK_SECRET: !!E.WEBHOOK_SECRET, ADMIN_IDS: ADMINS.length, BASE_URL: BASE_URL || null
    },
    token_otp_sama_dengan_bot_utama: !!(MAIN_TOKEN && OTP_TOKEN && OTP_TOKEN === MAIN_TOKEN),
    mongo: getDb() ? 'terhubung' : 'TIDAK terhubung (readyState=' + (mongoose.connection && mongoose.connection.readyState) + ')'
  };
  if (OTP_TOKEN) {
    const me = await tgCall('getMe');
    out.otpBot = me.ok ? { ok: true, username: '@' + me.data.username } : { ok: false, kode: me.code, alasan: me.desc };
    if (req.query.fix === '1') { const f = await setupWebhook(); out.fixWebhook = f.ok ? 'OK' : f.desc; }
    const wi = await tgCall('getWebhookInfo');
    if (wi.ok) {
      const expected = E.WEBHOOK_SECRET && BASE_URL ? BASE_URL + '/telegram/' + E.WEBHOOK_SECRET : null;
      out.webhook = {
        terpasang: !!wi.data.url, cocok_dengan_server_ini: !!expected && wi.data.url === expected,
        update_tertunda: wi.data.pending_update_count, error_terakhir: wi.data.last_error_message || null
      };
    } else out.webhook = { ok: false, alasan: wi.desc };
  }
  res.json(out);
});

/* indeks dibuat sekali setelah mongoose tersambung */
async function initIndexes() {
  db = getDb(); if (!db) return;
  await db.collection('otp_codes').createIndex({ exp: 1 }, { expireAfterSeconds: 0 });
  await db.collection('a2f_verified').createIndex({ emailHash: 1 }, { unique: true });
  await db.collection('a2f_verified').createIndex({ uid: 1 }, { unique: true });
  await db.collection('face_registry').createIndex({ uid: 1 }, { unique: true });
  await db.collection('revocations').createIndex({ uid: 1, ts: 1 });
}
setTimeout(function () { setupWebhook().catch(function (e) { console.error('[OTP] setupWebhook error', e && e.message); }); }, 3000);
mongoose.connection.once('open', function () { initIndexes().catch(function (e) { console.error('afex index gagal:', e.message); }); });
if (mongoose.connection.readyState === 1) initIndexes().catch(function () {});

module.exports = router;
