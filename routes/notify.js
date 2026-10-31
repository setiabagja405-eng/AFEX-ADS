// Notifikasi bot Telegram untuk Withdraw & Deposit (disimpan di MongoDB, tanpa dependensi baru)
// Environment Variables di Render:
//   BOT_TOKEN       token dari @BotFather
//   ADMIN_CHAT_ID   (opsional) chat/grup admin yang ikut menerima notifikasi
//   ADMIN_IDS       ID Telegram admin yang boleh mengubah status, pisahkan koma
const express = require('express');
const crypto = require('crypto');
const mongoose = require('mongoose');

const router = express.Router();

const BOT_TOKEN = process.env.BOT_TOKEN;
const ADMIN_CHAT_ID = process.env.ADMIN_CHAT_ID || '';
const ADMIN_IDS = (process.env.ADMIN_IDS || '').split(',').map(x => x.trim()).filter(Boolean);
const NETWORKS = ['BEP-20', 'TRC-20', 'TON', 'ERC-20'];

const noticeSchema = new mongoose.Schema({
    requestId: { type: String, unique: true, required: true },
    type: String,                       // 'withdraw' | 'deposit'
    userId: String,
    username: String,
    address: String,
    network: String,
    amount: Number,
    netReceive: Number,
    txHash: String,
    status: { type: String, default: 'pending' },   // pending | success | rejected
    messages: [{ chatId: String, messageId: Number }],
    createdAt: { type: Date, default: Date.now }
});
const Notice = mongoose.models.Notice || mongoose.model('Notice', noticeSchema);

// ---------- validasi initData Telegram Mini App ----------
function verifyInitData(initData) {
    try {
        if (!BOT_TOKEN) return null;
        const p = new URLSearchParams(initData || '');
        const hash = p.get('hash');
        if (!hash) return null;
        p.delete('hash');
        const dcs = [...p.entries()].map(([k, v]) => `${k}=${v}`).sort().join('\n');
        const secret = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
        const calc = crypto.createHmac('sha256', secret).update(dcs).digest('hex');
        if (calc !== hash) return null;
        if (Date.now() / 1000 - Number(p.get('auth_date')) > 86400) return null;
        return JSON.parse(p.get('user'));
    } catch (e) { return null; }
}

// ---------- Telegram API ----------
async function tg(method, body) {
    try {
        const r = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/${method}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        const j = await r.json();
        if (!j.ok) console.warn('Telegram', method, 'gagal:', j.description);
        return j;
    } catch (e) {
        console.warn('Telegram', method, 'error:', e.message);
        return { ok: false };
    }
}

const esc = s => String(s ?? '').replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
const STATUS = { pending: '⏳ Pending', success: '✅ Sukses', rejected: '❌ Ditolak' };

function buildText(n) {
    const lines = [
        n.type === 'withdraw' ? '💸 <b>WITHDRAW</b>' : '💰 <b>DEPOSIT</b>',
        `Username: ${esc(n.username)}`,
        `ID: <code>${esc(n.userId)}</code>`
    ];
    if (n.type === 'withdraw') lines.push(`Alamat wallet: <code>${esc(n.address)}</code>`);
    lines.push(`Jaringan: ${esc(n.network)}`);
    lines.push(`Nominal: ${Number(n.amount).toFixed(2)} USDT`);
    if (n.type === 'withdraw' && n.netReceive != null) lines.push(`Diterima (setelah fee): ${Number(n.netReceive).toFixed(2)} USDT`);
    if (n.txHash && n.txHash !== 'Pending Admin Input') lines.push(`TxHash: <code>${esc(n.txHash)}</code>`);
    lines.push(`Status: <b>${STATUS[n.status] || esc(n.status)}</b>`);
    lines.push(`Request: <code>${esc(n.requestId)}</code>`);
    return lines.join('\n');
}

async function sendNew(n) {
    const targets = [n.userId, ADMIN_CHAT_ID].filter(Boolean);
    const messages = [];
    for (const chatId of targets) {
        const j = await tg('sendMessage', { chat_id: chatId, text: buildText(n), parse_mode: 'HTML' });
        if (j.ok) messages.push({ chatId: String(chatId), messageId: j.result.message_id });
    }
    n.messages = messages;
    await n.save();
}

// ---------- ROUTES ----------
function requireUser(req, res) {
    const u = verifyInitData(req.body.initData);
    if (!u || String(u.id) !== String(req.body.userId)) {
        res.status(401).json({ success: false, error: 'initData tidak valid' });
        return null;
    }
    return u;
}

async function createNotice(res, data) {
    try {
        const n = await Notice.create(data);
        await sendNew(n);
        res.json({ success: true });
    } catch (e) {
        if (e.code === 11000) return res.json({ success: true, duplicate: true });   // requestId sudah ada
        console.error('Notify error:', e);
        res.status(500).json({ success: false, error: e.message });
    }
}

router.post('/withdraw', async (req, res) => {
    if (!requireUser(req, res)) return;
    const b = req.body;
    const amount = Number(b.amount);
    if (!b.requestId || !b.recipientAddress || !NETWORKS.includes(b.network) || !(amount > 0) || !isFinite(amount)) {
        return res.status(400).json({ success: false, error: 'Data withdraw tidak valid' });
    }
    // TODO: cek saldo & proses penarikan sebenarnya di sini
    await createNotice(res, {
        requestId: String(b.requestId), type: 'withdraw', userId: String(b.userId),
        username: String(b.username || ''), address: String(b.recipientAddress),
        network: b.network, amount, netReceive: Number(b.netReceive), status: 'pending'
    });
});

router.post('/deposit', async (req, res) => {
    if (!requireUser(req, res)) return;
    const b = req.body;
    const amount = Number(b.amount);
    if (!b.requestId || !NETWORKS.includes(b.network) || !(amount > 0) || !isFinite(amount)) {
        return res.status(400).json({ success: false, error: 'Data deposit tidak valid' });
    }
    await createNotice(res, {
        requestId: String(b.requestId), type: 'deposit', userId: String(b.userId),
        username: String(b.username || ''), network: b.network, amount,
        txHash: String(b.txHash || ''), status: b.status === 'success' ? 'success' : 'pending'
    });
});

// Hanya admin (ID Telegram ada di ADMIN_IDS) yang boleh mengubah status
router.post('/status', async (req, res) => {
    try {
        const u = verifyInitData(req.body.initData);
        if (!u || !ADMIN_IDS.includes(String(u.id))) return res.status(403).json({ success: false, error: 'bukan admin' });
        if (!['success', 'rejected'].includes(req.body.status)) return res.status(400).json({ success: false, error: 'status salah' });

        const n = await Notice.findOne({ requestId: String(req.body.requestId) });
        if (!n) return res.status(404).json({ success: false, error: 'request tidak ditemukan' });
        if (n.status !== 'pending') return res.json({ success: true, unchanged: true });   // sudah final

        n.status = req.body.status;
        if (req.body.txHash) n.txHash = String(req.body.txHash);
        await n.save();

        for (const m of n.messages) {
            await tg('editMessageText', { chat_id: m.chatId, message_id: m.messageId, text: buildText(n), parse_mode: 'HTML' });
        }
        // pesan baru agar user mendapat notifikasi push saat status berubah
        await tg('sendMessage', {
            chat_id: n.userId,
            text: `${n.type === 'withdraw' ? 'Withdraw' : 'Deposit'} ${Number(n.amount).toFixed(2)} USDT: ${STATUS[n.status]}`
        });
        res.json({ success: true });
    } catch (e) {
        console.error('Status error:', e);
        res.status(500).json({ success: false, error: e.message });
    }
});

module.exports = router;
