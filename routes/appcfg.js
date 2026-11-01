// Konfigurasi global (lock menu Founder/OTP/KYC) + Founder Gacha sederhana, disimpan di MongoDB.
// Pola sama dengan gift.js / notify.js: verifyInitData + ADMIN_IDS. Tanpa dependensi baru.
// Pasang di server.js (sama seperti gift.js):   app.use('/api', require('./routes/appcfg'));
// Endpoint:
//   POST /api/cfg/get        (publik)  -> status lock + konfigurasi gacha (dipakai semua user)
//   POST /api/cfg/set        (admin)   -> simpan lock / targets / gacha
//   POST /api/founder/check  (user)    -> boleh klaim? dapat berapa? (tidak mengurangi jatah)
//   POST /api/founder/claim  (user)    -> catat 1x klaim (atomik, tidak bisa melebihi batas per ID & total penerima)
//   POST /api/founder/grant  (admin)   -> tambah jatah klaim untuk 1 UID
const express = require('express');
const crypto = require('crypto');
const mongoose = require('mongoose');

const router = express.Router();

const ADMIN_IDS = (process.env.ADMIN_IDS || '').split(',').map(x => x.trim()).filter(Boolean);
const FEATURES = ['founder', 'a2f', 'face', 'id'];
const TIERS = [5, 10, 20, 40, 60, 100];
const UID_RE = /^[A-Za-z0-9_-]{3,40}$/;

const cfgSchema = new mongoose.Schema({
    key: { type: String, unique: true, required: true },
    lock: { type: mongoose.Schema.Types.Mixed, default: {} },      // {founder:true,a2f:false,...}
    targets: { type: mongoose.Schema.Types.Mixed, default: {} },   // {founder:1798761599000,...}
    gacha: { type: mongoose.Schema.Types.Mixed, default: {} },     // {"20":{totalAfex,totalUsdt,recipients,maxPerUid,ts}}
    ver: { type: Number, default: 0 }
});
const AppCfg = mongoose.models.AppCfg || mongoose.model('AppCfg', cfgSchema);

// jatah klaim per UID per tier
const fcSchema = new mongoose.Schema({
    uid: { type: String, required: true },
    tier: { type: Number, required: true },
    n: { type: Number, default: 0 },        // sudah klaim berapa kali
    extra: { type: Number, default: 0 }     // tambahan jatah dari admin
});
fcSchema.index({ uid: 1, tier: 1 }, { unique: true });
const FounderClaim = mongoose.models.FounderClaim || mongoose.model('FounderClaim', fcSchema);

// berapa slot penerima yang sudah terpakai per tier (per batch konfigurasi)
const fpSchema = new mongoose.Schema({
    tier: { type: Number, unique: true, required: true },
    used: { type: Number, default: 0 }
});
const FounderPool = mongoose.models.FounderPool || mongoose.model('FounderPool', fpSchema);

// Token bot Mini App yang boleh memvalidasi initData. Bot OTP (OTP_BOT_TOKEN) SENGAJA tidak dipakai.
// MAIN_BOT_TOKEN dicoba lebih dulu (sama seperti afexface.js), lalu BOT_TOKEN.
const TOKENS = [process.env.MAIN_BOT_TOKEN, process.env.BOT_TOKEN].map(x => String(x || '').trim()).filter((x, i, a) => x && a.indexOf(x) === i);

function verifyInitData(initData) {
    try {
        if (!TOKENS.length) return null;
        const p = new URLSearchParams(initData || '');
        const hash = p.get('hash');
        if (!hash) return null;
        p.delete('hash');
        const dcs = [...p.entries()].map(([k, v]) => `${k}=${v}`).sort().join('\n');
        const ok = TOKENS.some(tok => {
            const secret = crypto.createHmac('sha256', 'WebAppData').update(tok).digest();
            return crypto.createHmac('sha256', secret).update(dcs).digest('hex') === hash;
        });
        if (!ok) return null;
        if (Date.now() / 1000 - Number(p.get('auth_date')) > 86400) return null;
        return JSON.parse(p.get('user'));
    } catch (e) { return null; }
}
const isAdmin = u => !!u && ADMIN_IDS.includes(String(u.id));

// hadiah per orang = total dibagi rata ke jumlah penerima (rasio 1:1 antar penerima)
function perPerson(c) {
    const r = Math.max(1, parseInt(c.recipients, 10) || 1);
    const afex = Math.floor(((Number(c.totalAfex) || 0) / r) * 1000) / 1000;
    const usdt = Math.floor(((Number(c.totalUsdt) || 0) / r) * 1e6) / 1e6;
    return { afex, usdt };
}

async function getCfg() {
    return (await AppCfg.findOne({ key: 'main' }).lean()) || { lock: {}, targets: {}, gacha: {}, ver: 0 };
}

// ---------- publik: ambil konfigurasi ----------
router.post('/cfg/get', async (req, res) => {
    try {
        const c = await getCfg();
        res.set('Cache-Control', 'no-store');
        res.json({ success: true, ver: c.ver || 0, lock: c.lock || {}, targets: c.targets || {}, gacha: c.gacha || {}, now: Date.now() });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ---------- admin: simpan konfigurasi ----------
router.post('/cfg/set', async (req, res) => {
    try {
        const u = verifyInitData(req.body.initData);
        if (!isAdmin(u)) return res.status(403).json({ success: false, error: 'bukan admin' });
        const set = {}, now = Date.now();

        if (req.body.lock && typeof req.body.lock === 'object') {
            FEATURES.forEach(f => { if (f in req.body.lock) set['lock.' + f] = !!req.body.lock[f]; });
        }
        if (req.body.targets && typeof req.body.targets === 'object') {
            FEATURES.forEach(f => {
                const v = Number(req.body.targets[f]);
                if (isFinite(v) && v > 0 && v < 4102444800000) set['targets.' + f] = v;
            });
        }
        const resetTiers = [];
        if (req.body.gacha && typeof req.body.gacha === 'object') {
            for (const k of Object.keys(req.body.gacha)) {
                const tier = parseInt(k, 10), g = req.body.gacha[k];
                if (!TIERS.includes(tier) || !g) continue;
                const totalAfex = Number(g.totalAfex) || 0, totalUsdt = Number(g.totalUsdt) || 0;
                const recipients = parseInt(g.recipients, 10), maxPerUid = parseInt(g.maxPerUid, 10);
                if (totalAfex < 0 || totalUsdt < 0 || (totalAfex <= 0 && totalUsdt <= 0)) return res.status(400).json({ success: false, error: 'total AFEX/USDT tidak valid' });
                if (!(recipients >= 1) || recipients > 1000000 || !(maxPerUid >= 1) || maxPerUid > 100) return res.status(400).json({ success: false, error: 'penerima / batas klaim tidak valid' });
                set['gacha.' + tier] = { totalAfex, totalUsdt, recipients, maxPerUid, ts: now };
                resetTiers.push(tier);
            }
        }
        if (!Object.keys(set).length) return res.status(400).json({ success: false, error: 'tidak ada perubahan' });
        set.ver = now;

        await AppCfg.updateOne({ key: 'main' }, { $set: set, $setOnInsert: { key: 'main' } }, { upsert: true });
        // konfigurasi gacha baru = batch baru: slot penerima dihitung ulang dari 0 (jatah per-ID user tetap tercatat)
        for (const t of resetTiers) await FounderPool.updateOne({ tier: t }, { $set: { used: 0 } }, { upsert: true });
        const c = await getCfg();
        res.json({ success: true, ver: c.ver, lock: c.lock, targets: c.targets, gacha: c.gacha });
    } catch (e) {
        console.error('cfg/set error:', e);
        res.status(500).json({ success: false, error: e.message });
    }
});

// info jatah satu UID untuk satu tier
async function quota(uid, tier, cfg) {
    const g = (cfg.gacha || {})[tier];
    if (!g) return { mode: 'none' };
    const pp = perPerson(g);
    const fc = (await FounderClaim.findOne({ uid, tier }).lean()) || { n: 0, extra: 0 };
    const pool = (await FounderPool.findOne({ tier }).lean()) || { used: 0 };
    const allowed = g.maxPerUid + (fc.extra || 0);
    const userLeft = Math.max(0, allowed - (fc.n || 0));
    const poolLeft = Math.max(0, g.recipients - (pool.used || 0));
    let reason = '';
    if (userLeft <= 0) reason = 'limit_per_id';
    else if (poolLeft <= 0) reason = 'pool_empty';
    return { mode: 'simple', eligible: !reason, reason, afex: pp.afex, usdt: pp.usdt, claimed: fc.n || 0, allowed, userLeft, poolLeft };
}

// ---------- user: cek jatah (tidak mengurangi apa pun) ----------
router.post('/founder/check', async (req, res) => {
    try {
        const u = verifyInitData(req.body.initData);
        if (!u) return res.status(401).json({ success: false, error: 'initData tidak valid' });
        const tier = parseInt(req.body.tier, 10);
        if (!TIERS.includes(tier)) return res.status(400).json({ success: false, error: 'tier tidak valid' });
        res.json(Object.assign({ success: true }, await quota(String(u.id), tier, await getCfg())));
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ---------- user: klaim 1x (atomik) ----------
router.post('/founder/claim', async (req, res) => {
    try {
        const u = verifyInitData(req.body.initData);
        if (!u) return res.status(401).json({ success: false, error: 'initData tidak valid' });
        const uid = String(u.id), tier = parseInt(req.body.tier, 10);
        if (!TIERS.includes(tier)) return res.status(400).json({ success: false, error: 'tier tidak valid' });
        const cfg = await getCfg(), g = (cfg.gacha || {})[tier];
        if (!g) return res.json({ success: true, mode: 'none' });

        // 1) jatah per-ID (atomik: n < maxPerUid + extra)
        await FounderClaim.updateOne({ uid, tier }, { $setOnInsert: { n: 0, extra: 0 } }, { upsert: true }).catch(e => { if (!(e && e.code === 11000)) throw e; });
        const mine = await FounderClaim.findOneAndUpdate(
            { uid, tier, $expr: { $lt: ['$n', { $add: [{ $literal: g.maxPerUid }, '$extra'] }] } },
            { $inc: { n: 1 } }, { new: true });
        if (!mine) return res.json({ success: false, error: 'limit_per_id' });

        // 2) slot total penerima (atomik: used < recipients)
        await FounderPool.updateOne({ tier }, { $setOnInsert: { used: 0 } }, { upsert: true }).catch(e => { if (!(e && e.code === 11000)) throw e; });
        const pool = await FounderPool.findOneAndUpdate({ tier, used: { $lt: g.recipients } }, { $inc: { used: 1 } }, { new: true });
        if (!pool) {
            await FounderClaim.updateOne({ uid, tier }, { $inc: { n: -1 } });   // kembalikan jatah user
            return res.json({ success: false, error: 'pool_empty' });
        }
        const pp = perPerson(g);
        res.json({ success: true, mode: 'simple', afex: pp.afex, usdt: pp.usdt, claimed: mine.n, userLeft: Math.max(0, g.maxPerUid + (mine.extra || 0) - mine.n), poolLeft: Math.max(0, g.recipients - pool.used) });
    } catch (e) {
        console.error('founder/claim error:', e);
        res.status(500).json({ success: false, error: e.message });
    }
});

// ---------- admin: tambah jatah klaim untuk 1 UID ----------
router.post('/founder/grant', async (req, res) => {
    try {
        const u = verifyInitData(req.body.initData);
        if (!isAdmin(u)) return res.status(403).json({ success: false, error: 'bukan admin' });
        const uid = String(req.body.uid || '').trim(), tier = parseInt(req.body.tier, 10), add = parseInt(req.body.add, 10);
        if (!UID_RE.test(uid) || !TIERS.includes(tier) || !(add >= 1) || add > 100) return res.status(400).json({ success: false, error: 'data tidak valid' });
        const r = await FounderClaim.findOneAndUpdate({ uid, tier }, { $inc: { extra: add }, $setOnInsert: { n: 0 } }, { new: true, upsert: true });
        res.json({ success: true, uid, tier, claimed: r.n, extra: r.extra });
    } catch (e) {
        console.error('founder/grant error:', e);
        res.status(500).json({ success: false, error: e.message });
    }
});

module.exports = router;
module.exports.perPerson = perPerson;
