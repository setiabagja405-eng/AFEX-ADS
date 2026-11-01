// Hadiah massal (Kirim Hadiah dari Panel Admin) - disimpan di MongoDB, tanpa dependensi baru
// Environment Variables di Render (sama dengan notify.js):
//   MAIN_BOT_TOKEN / BOT_TOKEN   token bot Mini App (untuk memvalidasi initData); token bot OTP tidak dipakai
//   ADMIN_IDS   ID Telegram admin yang boleh mengirim hadiah, pisahkan koma
// Endpoint (dipasang di '/api'):
//   POST /api/gift/send  (admin)  body { amt, max, uids, cur?: 'usdt'|'afex', lock?: boolean } -> kirim hadiah ke banyak UID, otomatis lewati UID yang sudah dapat hadiah < 24 jam
//   POST /api/gift/list  (user)   -> daftar hadiah milik user + berapa kali sudah dibuka
//   POST /api/gift/open  (user)   -> catat 1x pembukaan hadiah (atomik, tidak bisa melebihi batas)
const express = require('express');
const crypto = require('crypto');
const mongoose = require('mongoose');

const router = express.Router();

const ADMIN_IDS = (process.env.ADMIN_IDS || '').split(',').map(x => x.trim()).filter(Boolean);
const DAY = 24 * 3600 * 1000;
const MAX_UIDS = 1000;
const UID_RE = /^[A-Za-z0-9_-]{3,40}$/;

const giftSchema = new mongoose.Schema({
    gid: { type: String, unique: true, required: true },
    amt: Number,
    max: Number,
    ts: Number,
    by: String,
    cur: { type: String, default: 'usdt' },      // 'usdt' | 'afex'  (hadiah lama tanpa field ini = usdt)
    lock: { type: Boolean, default: false },     // hanya untuk usdt: true = masuk seperti deposit (terkunci)
    uids: { type: [String], index: true }
});
const Gift = mongoose.models.Gift || mongoose.model('Gift', giftSchema);

// catatan kapan terakhir sebuah UID diberi hadiah (untuk aturan 24 jam)
const giftLogSchema = new mongoose.Schema({
    uid: { type: String, unique: true, required: true },
    ts: Number
});
const GiftLog = mongoose.models.GiftLog || mongoose.model('GiftLog', giftLogSchema);

// berapa kali tiap user sudah membuka tiap hadiah
const giftOpenSchema = new mongoose.Schema({
    gid: { type: String, required: true },
    uid: { type: String, required: true },
    n: { type: Number, default: 0 }
});
giftOpenSchema.index({ gid: 1, uid: 1 }, { unique: true });
const GiftOpen = mongoose.models.GiftOpen || mongoose.model('GiftOpen', giftOpenSchema);

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

// ambil slot 24 jam untuk satu UID. true = boleh diberi hadiah, false = sudah diberi < 24 jam
async function claimSlot(uid, now) {
    try {
        const old = await GiftLog.findOneAndUpdate({ uid, ts: { $lte: now - DAY } }, { $set: { ts: now } });
        if (old) return true;
        await GiftLog.create({ uid, ts: now });
        return true;
    } catch (e) {
        if (e && e.code === 11000) return false;
        throw e;
    }
}

// ---------- ADMIN: kirim hadiah ----------
router.post('/gift/send', async (req, res) => {
    try {
        const u = verifyInitData(req.body.initData);
        if (!u || !ADMIN_IDS.includes(String(u.id))) return res.status(403).json({ success: false, error: 'bukan admin' });

        const amt = Number(req.body.amt), max = parseInt(req.body.max, 10);
        let uids = Array.isArray(req.body.uids) ? req.body.uids.map(String) : [];
        uids = [...new Set(uids.map(x => x.trim()).filter(x => UID_RE.test(x)))];
        if (!uids.length) return res.status(400).json({ success: false, error: 'uids kosong' });
        if (uids.length > MAX_UIDS) return res.status(400).json({ success: false, error: 'maksimal ' + MAX_UIDS + ' UID per kirim' });
        if (!(amt > 0) || !isFinite(amt) || amt > 1000000 || !(max >= 1) || max > 100) return res.status(400).json({ success: false, error: 'jumlah/batas tidak valid' });
        const curIn = req.body.cur === undefined ? 'usdt' : String(req.body.cur).toLowerCase();
        if (curIn !== 'usdt' && curIn !== 'afex') return res.status(400).json({ success: false, error: 'jenis hadiah tidak valid' });
        const cur = curIn;
        const lock = cur === 'usdt' && (req.body.lock === true || req.body.lock === 'true' || req.body.lock === 1);   // lock hanya berlaku untuk USDT

        const now = Date.now();
        const sent = [], skipped = [];
        for (let i = 0; i < uids.length; i += 25) {
            const chunk = uids.slice(i, i + 25);
            const ok = await Promise.all(chunk.map(uid => claimSlot(uid, now)));
            chunk.forEach((uid, k) => (ok[k] ? sent : skipped).push(uid));
        }

        let gid = null;
        if (sent.length) {
            gid = 'g' + now.toString(36) + crypto.randomBytes(3).toString('hex');
            await Gift.create({ gid, amt, max, cur, lock, ts: now, by: String(u.id), uids: sent });
        }
        res.json({ success: true, giftId: gid, amt, max, cur, lock, ts: now, sent, skipped });
    } catch (e) {
        console.error('gift/send error:', e);
        res.status(500).json({ success: false, error: e.message });
    }
});

// ---------- USER: daftar hadiah ----------
router.post('/gift/list', async (req, res) => {
    try {
        const u = verifyInitData(req.body.initData);
        if (!u) return res.status(401).json({ success: false, error: 'initData tidak valid' });
        const uid = String(u.id);
        const gifts = await Gift.find({ uids: uid, ts: { $gt: Date.now() - 30 * DAY } }).sort({ ts: 1 }).lean();
        const opens = gifts.length ? await GiftOpen.find({ uid, gid: { $in: gifts.map(g => g.gid) } }).lean() : [];
        const op = {}; opens.forEach(o => { op[o.gid] = o.n; });
        res.json({ success: true, uid, gifts: gifts.map(g => ({ id: g.gid, amt: g.amt, max: g.max, cur: g.cur === 'afex' ? 'afex' : 'usdt', lock: !!g.lock && g.cur !== 'afex', ts: g.ts, opened: op[g.gid] || 0 })) });
    } catch (e) {
        console.error('gift/list error:', e);
        res.status(500).json({ success: false, error: e.message });
    }
});

// ---------- USER: buka hadiah (1x per panggilan) ----------
router.post('/gift/open', async (req, res) => {
    try {
        const u = verifyInitData(req.body.initData);
        if (!u) return res.status(401).json({ success: false, error: 'initData tidak valid' });
        const uid = String(u.id), gid = String(req.body.giftId || '');
        const gift = await Gift.findOne({ gid, uids: uid }).lean();
        if (!gift) return res.status(404).json({ success: false, error: 'hadiah tidak ditemukan' });
        try {
            const r = await GiftOpen.findOneAndUpdate(
                { gid, uid, n: { $lt: gift.max } },
                { $inc: { n: 1 } },
                { new: true, upsert: true, setDefaultsOnInsert: true }
            );
            return res.json({ success: true, n: r.n, amt: gift.amt, cur: gift.cur === 'afex' ? 'afex' : 'usdt', lock: !!gift.lock && gift.cur !== 'afex', left: Math.max(0, gift.max - r.n) });
        } catch (e) {
            if (e && e.code === 11000) return res.json({ success: false, error: 'max_reached' });   // sudah mencapai batas buka
            throw e;
        }
    } catch (e) {
        console.error('gift/open error:', e);
        res.status(500).json({ success: false, error: e.message });
    }
});

module.exports = router;
