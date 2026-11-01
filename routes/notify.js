// Notifikasi bot Telegram untuk Withdraw & Deposit (disimpan di MongoDB, tanpa dependensi baru)
// Environment Variables di Render:
//   BOT_TOKEN       token dari @BotFather
//   ADMIN_CHAT_ID   (opsional) chat/grup admin yang ikut menerima notifikasi
//   ADMIN_IDS       ID Telegram admin yang boleh mengubah status, pisahkan koma
//   ADMIN_LANG      (opsional) bahasa pesan di chat admin, default 'id'
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
    lang: { type: String, default: 'en' },           // bahasa yang dipilih user di mini app
    status: { type: String, default: 'pending' },   // pending | success | rejected
    messages: [{ chatId: String, messageId: Number, lang: String }],
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
const I18N = {
    en: {"withdraw": "WITHDRAW", "deposit": "DEPOSIT", "username": "Username", "wallet": "Wallet address", "network": "Network", "amount": "Amount", "received": "Received (after fee)", "status": "Status", "request": "Request", "pending": "⏳ Pending", "success": "✅ Success", "rejected": "❌ Rejected"},
    id: {"withdraw": "PENARIKAN", "deposit": "DEPOSIT", "username": "Username", "wallet": "Alamat wallet", "network": "Jaringan", "amount": "Nominal", "received": "Diterima (setelah fee)", "status": "Status", "request": "Request", "pending": "⏳ Pending", "success": "✅ Sukses", "rejected": "❌ Ditolak"},
    es: {"withdraw": "RETIRO", "deposit": "DEPÓSITO", "username": "Usuario", "wallet": "Dirección de wallet", "network": "Red", "amount": "Monto", "received": "Recibido (tras comisión)", "status": "Estado", "request": "Solicitud", "pending": "⏳ Pendiente", "success": "✅ Exitoso", "rejected": "❌ Rechazado"},
    de: {"withdraw": "AUSZAHLUNG", "deposit": "EINZAHLUNG", "username": "Benutzername", "wallet": "Wallet-Adresse", "network": "Netzwerk", "amount": "Betrag", "received": "Erhalten (nach Gebühr)", "status": "Status", "request": "Anfrage", "pending": "⏳ Ausstehend", "success": "✅ Erfolgreich", "rejected": "❌ Abgelehnt"},
    fr: {"withdraw": "RETRAIT", "deposit": "DÉPÔT", "username": "Nom d'utilisateur", "wallet": "Adresse du wallet", "network": "Réseau", "amount": "Montant", "received": "Reçu (après frais)", "status": "Statut", "request": "Demande", "pending": "⏳ En attente", "success": "✅ Réussi", "rejected": "❌ Refusé"},
    tr: {"withdraw": "ÇEKİM", "deposit": "YATIRMA", "username": "Kullanıcı adı", "wallet": "Cüzdan adresi", "network": "Ağ", "amount": "Miktar", "received": "Alınan (ücret sonrası)", "status": "Durum", "request": "Talep", "pending": "⏳ Beklemede", "success": "✅ Başarılı", "rejected": "❌ Reddedildi"},
    uz: {"withdraw": "YECHIB OLISH", "deposit": "DEPOZIT", "username": "Foydalanuvchi nomi", "wallet": "Hamyon manzili", "network": "Tarmoq", "amount": "Miqdor", "received": "Olinadi (komissiyadan keyin)", "status": "Holat", "request": "So'rov", "pending": "⏳ Kutilmoqda", "success": "✅ Muvaffaqiyatli", "rejected": "❌ Rad etildi"},
    ru: {"withdraw": "ВЫВОД", "deposit": "ДЕПОЗИТ", "username": "Имя пользователя", "wallet": "Адрес кошелька", "network": "Сеть", "amount": "Сумма", "received": "Получено (после комиссии)", "status": "Статус", "request": "Запрос", "pending": "⏳ В ожидании", "success": "✅ Успешно", "rejected": "❌ Отклонено"},
    vi: {"withdraw": "RÚT TIỀN", "deposit": "NẠP TIỀN", "username": "Tên người dùng", "wallet": "Địa chỉ ví", "network": "Mạng", "amount": "Số tiền", "received": "Nhận được (sau phí)", "status": "Trạng thái", "request": "Yêu cầu", "pending": "⏳ Đang chờ", "success": "✅ Thành công", "rejected": "❌ Bị từ chối"},
    tl: {"withdraw": "WITHDRAWAL", "deposit": "DEPOSITO", "username": "Username", "wallet": "Wallet address", "network": "Network", "amount": "Halaga", "received": "Natanggap (pagkatapos ng fee)", "status": "Katayuan", "request": "Request", "pending": "⏳ Naka-pending", "success": "✅ Matagumpay", "rejected": "❌ Tinanggihan"},
    th: {"withdraw": "ถอนเงิน", "deposit": "ฝากเงิน", "username": "ชื่อผู้ใช้", "wallet": "ที่อยู่กระเป๋า", "network": "เครือข่าย", "amount": "จำนวน", "received": "ได้รับ (หลังหักค่าธรรมเนียม)", "status": "สถานะ", "request": "คำขอ", "pending": "⏳ รอดำเนินการ", "success": "✅ สำเร็จ", "rejected": "❌ ถูกปฏิเสธ"},
    ms: {"withdraw": "PENGELUARAN", "deposit": "DEPOSIT", "username": "Nama pengguna", "wallet": "Alamat dompet", "network": "Rangkaian", "amount": "Jumlah", "received": "Diterima (selepas yuran)", "status": "Status", "request": "Permintaan", "pending": "⏳ Menunggu", "success": "✅ Berjaya", "rejected": "❌ Ditolak"},
    hi: {"withdraw": "निकासी", "deposit": "जमा", "username": "उपयोगकर्ता नाम", "wallet": "वॉलेट पता", "network": "नेटवर्क", "amount": "राशि", "received": "प्राप्त (शुल्क के बाद)", "status": "स्थिति", "request": "अनुरोध", "pending": "⏳ लंबित", "success": "✅ सफल", "rejected": "❌ अस्वीकृत"},
    ur: {"withdraw": "نکالنا", "deposit": "ڈپازٹ", "username": "صارف نام", "wallet": "والٹ ایڈریس", "network": "نیٹ ورک", "amount": "رقم", "received": "موصول (فیس کے بعد)", "status": "حیثیت", "request": "درخواست", "pending": "⏳ زیر التواء", "success": "✅ کامیاب", "rejected": "❌ مسترد"},
    zh: {"withdraw": "提款", "deposit": "充值", "username": "用户名", "wallet": "钱包地址", "network": "网络", "amount": "金额", "received": "到账（扣除手续费后）", "status": "状态", "request": "请求", "pending": "⏳ 待处理", "success": "✅ 成功", "rejected": "❌ 已拒绝"},
    ko: {"withdraw": "출금", "deposit": "입금", "username": "사용자 이름", "wallet": "지갑 주소", "network": "네트워크", "amount": "금액", "received": "수령액 (수수료 제외)", "status": "상태", "request": "요청", "pending": "⏳ 대기 중", "success": "✅ 성공", "rejected": "❌ 거절됨"},
    ja: {"withdraw": "出金", "deposit": "入金", "username": "ユーザー名", "wallet": "ウォレットアドレス", "network": "ネットワーク", "amount": "金額", "received": "受取額（手数料差引後）", "status": "ステータス", "request": "リクエスト", "pending": "⏳ 保留中", "success": "✅ 成功", "rejected": "❌ 拒否"},
    af: {"withdraw": "ONTTREKKING", "deposit": "DEPOSITO", "username": "Gebruikersnaam", "wallet": "Beursie-adres", "network": "Netwerk", "amount": "Bedrag", "received": "Ontvang (na fooi)", "status": "Status", "request": "Versoek", "pending": "⏳ Hangend", "success": "✅ Suksesvol", "rejected": "❌ Afgekeur"},
    ar: {"withdraw": "سحب", "deposit": "إيداع", "username": "اسم المستخدم", "wallet": "عنوان المحفظة", "network": "الشبكة", "amount": "المبلغ", "received": "المستلم (بعد الرسوم)", "status": "الحالة", "request": "الطلب", "pending": "⏳ قيد الانتظار", "success": "✅ ناجح", "rejected": "❌ مرفوض"},
};
const ADMIN_LANG = process.env.ADMIN_LANG || 'id';   // bahasa pesan di chat/grup admin
const normLang = l => { l = String(l || '').toLowerCase().slice(0, 2); return I18N[l] ? l : 'en'; };
const L = lang => I18N[normLang(lang)];

function buildText(n, lang) {
    const T = L(lang);
    const lines = [
        n.type === 'withdraw' ? `💸 <b>${T.withdraw}</b>` : `💰 <b>${T.deposit}</b>`,
        `${T.username}: ${esc(n.username)}`,
        `ID: <code>${esc(n.userId)}</code>`
    ];
    if (n.type === 'withdraw') lines.push(`${T.wallet}: <code>${esc(n.address)}</code>`);
    lines.push(`${T.network}: ${esc(n.network)}`);
    lines.push(`${T.amount}: ${Number(n.amount).toFixed(2)} USDT`);
    if (n.type === 'withdraw' && n.netReceive != null) lines.push(`${T.received}: ${Number(n.netReceive).toFixed(2)} USDT`);
    if (n.txHash && !/^Pending (Admin|Team) Input$/.test(String(n.txHash))) lines.push(`TxHash: <code>${esc(n.txHash)}</code>`);
    lines.push(`${T.status}: <b>${T[n.status] || esc(n.status)}</b>`);
    lines.push(`${T.request}: <code>${esc(n.requestId)}</code>`);
    return lines.join('\n');
}

// User menerima pesan dalam bahasa pilihannya di mini app; chat admin memakai ADMIN_LANG
async function sendNew(n) {
    const targets = [{ chatId: n.userId, lang: n.lang }];
    if (ADMIN_CHAT_ID && String(ADMIN_CHAT_ID) !== String(n.userId)) targets.push({ chatId: ADMIN_CHAT_ID, lang: ADMIN_LANG });
    const messages = [];
    for (const t of targets) {
        const j = await tg('sendMessage', { chat_id: t.chatId, text: buildText(n, t.lang), parse_mode: 'HTML' });
        if (j.ok) messages.push({ chatId: String(t.chatId), messageId: j.result.message_id, lang: normLang(t.lang) });
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
        username: String(b.username || ''), lang: normLang(b.lang), address: String(b.recipientAddress),
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
        username: String(b.username || ''), lang: normLang(b.lang), network: b.network, amount,
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
            await tg('editMessageText', { chat_id: m.chatId, message_id: m.messageId, text: buildText(n, m.lang), parse_mode: 'HTML' });
        }
        // pesan baru agar user mendapat notifikasi push saat status berubah
        await tg('sendMessage', {
            chat_id: n.userId,
            text: `${n.type === 'withdraw' ? L(n.lang).withdraw : L(n.lang).deposit} ${Number(n.amount).toFixed(2)} USDT: ${L(n.lang)[n.status]}`
        });
        res.json({ success: true });
    } catch (e) {
        console.error('Status error:', e);
        res.status(500).json({ success: false, error: e.message });
    }
});

module.exports = router;
