// routes/referral.js  --  kirim foto banner + caption referral ke chat pengguna lewat bot (menggantikan /referral di Termux)
// Environment Variables di Render:
//   BOT_TOKEN          token bot mini app (sudah ada)
//   BANNER_IMAGE_URL   link gambar banner (wajib diisi, mis. https://i.postimg.cc/.../banner.jpg)
//   BOT_USERNAME       (opsional) default: Fexboostbot
//   WEBAPP_URL         (opsional) default: https://afex-ads.vercel.app/
const express = require('express');
const crypto = require('crypto');
const router = express.Router();

const BOT_TOKEN = process.env.BOT_TOKEN;
const BANNER = process.env.BANNER_IMAGE_URL || '';
const BOT_USERNAME = (process.env.BOT_USERNAME || 'Fexboostbot').replace(/^@/, '');
const WEBAPP_URL = process.env.WEBAPP_URL || 'https://afex-ads.vercel.app/';
const COOLDOWN_MS = 30 * 1000;
const last = new Map();   // userId -> waktu kirim terakhir

function verifyInitData(initData) {
    try {
        if (!BOT_TOKEN) return null;
        const p = new URLSearchParams(initData || '');
        const hash = p.get('hash'); if (!hash) return null;
        p.delete('hash');
        const dcs = [...p.entries()].map(([k, v]) => `${k}=${v}`).sort().join('\n');
        const secret = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
        const calc = crypto.createHmac('sha256', secret).update(dcs).digest('hex');
        if (calc !== hash) return null;
        if (Date.now() / 1000 - Number(p.get('auth_date')) > 86400) return null;
        return JSON.parse(p.get('user'));
    } catch (e) { return null; }
}

async function tg(method, body) {
    try {
        const r = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/${method}`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
        });
        return await r.json();
    } catch (e) { return { ok: false, description: e.message }; }
}

const esc = s => String(s ?? '').replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));

function buildCaption(name, link) {
    return [
        '🌟 <b>WELCOME TO THE FUTURE OF WEB3 MINING!</b>',
        '',
        `Hi ${esc(name)}! Dive into the <b>AFEX Mining Gold Edition</b> ecosystem and collect free tokens and USDT.`,
        '',
        '💎 <b>Why Join AFEX Today?</b>',
        '• 🚀 <b>12-Hour Auto Mining:</b> Generate tokens around the clock.',
        '• 🎁 <b>Exclusive Rewards:</b> Claim daily bonuses and mystery gifts.',
        '• 🛡️ <b>Instant Payouts:</b> Direct multi-chain wallet integration.',
        '',
        '🔗 <b>Your Personal Invitation Link:</b>',
        `<code>${esc(link)}</code>`
    ].join('\n');
}

router.post('/referral/send', async (req, res) => {
    const u = verifyInitData(req.body && req.body.initData);
    if (!u) return res.status(401).json({ success: false, error: 'initData tidak valid' });

    const now = Date.now(), prev = last.get(u.id) || 0;
    if (now - prev < COOLDOWN_MS) return res.json({ success: false, error: 'cooldown', retryIn: Math.ceil((COOLDOWN_MS - (now - prev)) / 1000) });
    last.set(u.id, now);

    const link = `https://t.me/${BOT_USERNAME}?startapp=AFEX-${u.id}`;
    const caption = buildCaption(u.first_name || 'Crypto Miner', link);
    const shareUrl = `https://t.me/share/url?url=${encodeURIComponent(link)}&text=${encodeURIComponent('🚀 Join me on AFEX Mining and collect free tokens and USDT!')}`;
    const reply_markup = { inline_keyboard: [
        [{ text: '📤 Share to Friends & Groups', url: shareUrl }],
        [{ text: '⛏️ Launch Mining App', web_app: { url: WEBAPP_URL } }]
    ] };

    let j = BANNER ? await tg('sendPhoto', { chat_id: u.id, photo: BANNER, caption, parse_mode: 'HTML', reply_markup }) : { ok: false };
    if (!j.ok) j = await tg('sendMessage', { chat_id: u.id, text: caption, parse_mode: 'HTML', reply_markup, disable_web_page_preview: true });
    if (!j.ok) { last.delete(u.id); return res.json({ success: false, error: 'send_failed', detail: j.description }); }
    res.json({ success: true });
});

module.exports = router;
