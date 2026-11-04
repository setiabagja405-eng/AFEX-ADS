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
const clean = function (v) { return String(v || '').trim().replace(/^["']+|["']+$/g, '').trim(); };   // buang spasi/kutip/CRLF yang sering ikut dari env Termux
const MAIN_TOKEN = clean(E.MAIN_BOT_TOKEN || E.BOT_TOKEN);   // token bot mini app (sama dengan BOT_TOKEN di notify.js)
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
const OTP_TOKEN = clean(E.OTP_BOT_TOKEN);
const BASE_URL = clean(E.PUBLIC_URL || E.RENDER_EXTERNAL_URL).replace(/\/+$/, '');
const WEBHOOK_SECRET = clean(E.WEBHOOK_SECRET);
/* Mode bot OTP: 'webhook' bila PUBLIC_URL + WEBHOOK_SECRET ada (Render); selain itu otomatis 'polling' (Termux / tunnel Cloudflare yang URL-nya berubah-ubah).
   Bisa dipaksa lewat OTP_MODE=polling atau OTP_MODE=webhook. */
const OTP_MODE = (function () { const m = String(E.OTP_MODE || '').trim().toLowerCase(); if (m === 'polling' || m === 'webhook') return m; return (BASE_URL && WEBHOOK_SECRET) ? 'webhook' : 'polling'; })();

/* panggilan umum ke Telegram Bot API (OTP bot). Tidak pernah melempar error; hasilnya selalu {ok, code, desc, data}. */
async function tgCall(method, payload, timeoutMs) {
  if (!OTP_TOKEN) return { ok: false, code: 0, desc: 'OTP_BOT_TOKEN belum diisi di Environment Render' };
  if (typeof fetch !== 'function') return { ok: false, code: 0, desc: 'Node.js < 18 (fetch tidak ada). Set NODE_VERSION=20 di Render' };
  const ctl = new AbortController(), tm = setTimeout(function () { ctl.abort(); }, timeoutMs || 10000);
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
/* Telegram membalas 403 (bot tidak boleh memulai chat / diblokir) ATAU 400 "chat not found" bila user belum pernah menekan Start di bot OTP.
   Versi lama hanya menganggap 403, jadi kasus 400 jatuh ke 'send_failed' dan OTP tidak pernah terkirim. */
function needsStart(r) {
  if (!r || r.ok) return false;
  const d = String(r.desc || '').toLowerCase();
  return r.code === 403 || (r.code === 400 && (d.indexOf('chat not found') >= 0 || d.indexOf('user not found') >= 0 || d.indexOf("can't initiate") >= 0)) || d.indexOf('bot was blocked') >= 0;
}
async function tgSend(chatId, html) {
  const r = await tgCall('sendMessage', { chat_id: chatId, text: html, parse_mode: 'HTML', disable_web_page_preview: true });
  if (!r.ok) console.error('[OTP] sendMessage gagal -> kode ' + r.code + ': ' + r.desc);
  return { ok: r.ok, code: r.code, desc: r.desc };
}

/* daftarkan webhook bot OTP otomatis (sebelumnya tidak ada yang memanggil setWebhook, sehingga /start tidak pernah dibalas) */
async function setupWebhook() {
  if (!OTP_TOKEN || !WEBHOOK_SECRET || !BASE_URL) {
    console.warn('[OTP] Webhook TIDAK didaftarkan. Kurang: ' + [!OTP_TOKEN && 'OTP_BOT_TOKEN', !WEBHOOK_SECRET && 'WEBHOOK_SECRET', !BASE_URL && 'PUBLIC_URL/RENDER_EXTERNAL_URL'].filter(Boolean).join(', '));
    return { ok: false, desc: 'env kurang' };
  }
  if (MAIN_TOKEN && OTP_TOKEN === MAIN_TOKEN) {   // jangan rebut webhook bot utama (Fexboostbot)
    console.error('[OTP] OTP_BOT_TOKEN SAMA dengan BOT_TOKEN. Isi OTP_BOT_TOKEN dengan token bot OTP (@afexotpbot) dari BotFather. Webhook tidak dipasang.');
    return { ok: false, desc: 'OTP_BOT_TOKEN sama dengan BOT_TOKEN' };
  }
  const r = await tgCall('setWebhook', { url: BASE_URL + '/telegram/' + WEBHOOK_SECRET, allowed_updates: ['message'] });
  console.log('[OTP] setWebhook ' + (r.ok ? 'OK' : 'GAGAL (' + r.code + ') ' + r.desc));
  return r;
}

/* ---------- Kamus 19 Bahasa untuk Pesan Bot OTP & Ganti Email ---------- */
const OTP_I18N = {
  en: {
    codeTitle: '\uD83D\uDD10 <b>AFEX OTP</b>\n\nYour OTP Code: <b><code>{code}</code></b>\nFor A2F account: {acc}\n\u23F1 Valid for <b>5 minutes</b>. Do not share this code with anyone.',
    returnApp: 'Return to the mini app, enter this code, and press verify.',
    emailUsed: '\u26A0\uFE0F This email is already used by another account. Change the email in the mini app and press <b>Get</b> again.',
    cooldown: '\u2705 OTP code was already sent above \u2B06\uFE0F\nFor a new code, wait <b>{sec} seconds</b> then send /otp again.',
    tooMany: '\u26D4 Too many OTP requests. Try again in 1 hour.',
    welcome: '\uD83D\uDC4B <b>AFEX OTP Bot</b>\n\nOpen the AFEX mini app \u2192 <b>OTP (A2F) / Change Email</b> menu \u2192 press <b>Get</b>. A 6-digit code will be sent here and is valid for 5 minutes.'
  },
  id: {
    codeTitle: '\uD83D\uDD10 <b>AFEX OTP</b>\n\nKode OTP Anda: <b><code>{code}</code></b>\nUntuk akun A2F: {acc}\n\u23F1 Berlaku <b>5 menit</b>. Jangan bagikan kode ini ke siapa pun.',
    returnApp: 'Kembali ke mini app, masukkan kode ini lalu tekan verifikasi.',
    emailUsed: '\u26A0\uFE0F Email ini sudah dipakai akun lain. Ganti email di mini app lalu tekan <b>Get</b> lagi.',
    cooldown: '\u2705 Kode OTP sudah dikirim di atas \u2B06\uFE0F\nUntuk kode baru, tunggu <b>{sec} detik</b> lalu kirim /otp lagi.',
    tooMany: '\u26D4 Terlalu banyak permintaan OTP. Coba lagi dalam 1 jam.',
    welcome: '\uD83D\uDC4B <b>Bot OTP AFEX</b>\n\nBuka mini app AFEX \u2192 menu <b>OTP (A2F)</b> \u2192 tekan <b>Get</b>. Kode 6 digit dikirim ke sini dan berlaku 5 menit.'
  },
  es: {
    codeTitle: '\uD83D\uDD10 <b>AFEX OTP</b>\n\nTu código OTP: <b><code>{code}</code></b>\nPara la cuenta A2F: {acc}\n\u23F1 Válido por <b>5 minutos</b>. No compartas este código con nadie.',
    returnApp: 'Vuelve a la mini app, ingresa este código y pulsa verificar.',
    emailUsed: '\u26A0\uFE0F Este correo ya está siendo usado por otra cuenta. Cambia el correo en la mini app y pulsa <b>Get</b> de nuevo.',
    cooldown: '\u2705 El código OTP ya fue enviado arriba \u2B06\uFE0F\nPara un código nuevo, espera <b>{sec} segundos</b> y envía /otp de nuevo.',
    tooMany: '\u26D4 Demasiadas solicitudes de OTP. Inténtalo de nuevo en 1 hora.',
    welcome: '\uD83D\uDC4B <b>Bot OTP AFEX</b>\n\nAbre la mini app AFEX \u2192 menú <b>OTP (A2F) / Cambiar correo</b> \u2192 pulsa <b>Get</b>. El código de 6 dígitos se enviará aquí y es válido por 5 minutos.'
  },
  de: {
    codeTitle: '\uD83D\uDD10 <b>AFEX OTP</b>\n\nDein OTP-Code: <b><code>{code}</code></b>\nFür A2F-Konto: {acc}\n\u23F1 Gültig für <b>5 Minuten</b>. Teile diesen Code mit niemandem.',
    returnApp: 'Kehre zur Mini-App zurück, gib diesen Code ein und tippe auf Verifizieren.',
    emailUsed: '\u26A0\uFE0F Diese E-Mail wird bereits von einem anderen Konto genutzt. Ändere die E-Mail in der Mini-App und tippe erneut auf <b>Get</b>.',
    cooldown: '\u2705 OTP-Code wurde bereits oben gesendet \u2B06\uFE0F\nFür einen neuen Code warte <b>{sec} Sekunden</b> und sende erneut /otp.',
    tooMany: '\u26D4 Zu viele OTP-Anfragen. Versuche es in 1 Stunde erneut.',
    welcome: '\uD83D\uDC4B <b>AFEX OTP-Bot</b>\n\nÖffne die AFEX Mini-App \u2192 Menü <b>OTP (A2F) / E-Mail ändern</b> \u2192 tippe auf <b>Get</b>. Ein 6-stelliger Code wird hierher gesendet (5 Min. gültig).'
  },
  fr: {
    codeTitle: '\uD83D\uDD10 <b>AFEX OTP</b>\n\nVotre code OTP : <b><code>{code}</code></b>\nPour le compte A2F : {acc}\n\u23F1 Valable <b>5 minutes</b>. Ne partagez ce code avec personne.',
    returnApp: 'Retournez dans la mini application, entrez ce code et appuyez sur vérifier.',
    emailUsed: '\u26A0\uFE0F Cet e-mail est déjà utilisé par un autre compte. Changez l’e-mail dans la mini app puis appuyez à nouveau sur <b>Get</b>.',
    cooldown: '\u2705 Le code OTP a déjà été envoyé ci-dessus \u2B06\uFE0F\nPour un nouveau code, attendez <b>{sec} secondes</b> puis renvoyez /otp.',
    tooMany: '\u26D4 Trop de demandes d’OTP. Réessayez dans 1 heure.',
    welcome: '\uD83D\uDC4B <b>Bot OTP AFEX</b>\n\nOuvrez la mini app AFEX \u2192 menu <b>OTP (A2F) / Changer d’e-mail</b> \u2192 appuyez sur <b>Get</b>. Un code à 6 chiffres sera envoyé ici (valable 5 minutes).'
  },
  tr: {
    codeTitle: '\uD83D\uDD10 <b>AFEX OTP</b>\n\nOTP Kodunuz: <b><code>{code}</code></b>\nA2F hesabı için: {acc}\n\u23F1 <b>5 dakika</b> geçerlidir. Bu kodu kimseyle paylaşmayın.',
    returnApp: 'Mini uygulamaya dönün, bu kodu girin ve doğrula düğmesine basın.',
    emailUsed: '\u26A0\uFE0F Bu e-posta başka bir hesap tarafından kullanılıyor. Mini uygulamada e-postayı değiştirip tekrar <b>Get</b> düğmesine basın.',
    cooldown: '\u2705 OTP kodu yukarıda zaten gönderildi \u2B06\uFE0F\nYeni kod için <b>{sec} saniye</b> bekleyip tekrar /otp gönderin.',
    tooMany: '\u26D4 Çok fazla OTP isteği. 1 saat sonra tekrar deneyin.',
    welcome: '\uD83D\uDC4B <b>AFEX OTP Botu</b>\n\nAFEX mini uygulamasını açın \u2192 <b>OTP (A2F) / E-postayı Değiştir</b> menüsü \u2192 <b>Get</b> düğmesine basın. 6 haneli kod buraya gönderilir ve 5 dakika geçerlidir.'
  },
  uz: {
    codeTitle: '\uD83D\uDD10 <b>AFEX OTP</b>\n\nSizning OTP kodingiz: <b><code>{code}</code></b>\nA2F hisobi uchun: {acc}\n\u23F1 <b>5 daqiqa</b> amal qiladi. Ushbu kodni hech kimga bermang.',
    returnApp: 'Mini ilovaga qayting, ushbu kodni kiriting va tasdiqlash tugmasini bosing.',
    emailUsed: '\u26A0\uFE0F Bu email boshqa hisob tomonidan ishlatilgan. Mini ilovada emailni o‘zgartiring va yana <b>Get</b> tugmasini bosing.',
    cooldown: '\u2705 OTP kodi yuqorida allaqachon yuborilgan \u2B06\uFE0F\nYangi kod uchun <b>{sec} soniya</b> kuting va yana /otp yuboring.',
    tooMany: '\u26D4 Juda ko‘p OTP so‘rovi. 1 soatdan keyin qayta urinib ko‘ring.',
    welcome: '\uD83D\uDC4B <b>AFEX OTP Boti</b>\n\nAFEX mini ilovasini oching \u2192 <b>OTP (A2F) / Emailni o‘zgartirish</b> menyusi \u2192 <b>Get</b> tugmasini bosing. 6 xonali kod shu yerga yuboriladi va 5 daqiqa amal qiladi.'
  },
  ru: {
    codeTitle: '\uD83D\uDD10 <b>AFEX OTP</b>\n\nВаш код OTP: <b><code>{code}</code></b>\nДля аккаунта A2F: {acc}\n\u23F1 Действителен <b>5 минут</b>. Никому не сообщайте этот код.',
    returnApp: 'Вернитесь в мини-приложение, введите этот код и нажмите подтвердить.',
    emailUsed: '\u26A0\uFE0F Этот email уже используется другим аккаунтом. Измените email в мини-приложении и снова нажмите <b>Get</b>.',
    cooldown: '\u2705 Код OTP уже отправлен выше \u2B06\uFE0F\nДля получения нового кода подождите <b>{sec} сек.</b> и отправьте /otp снова.',
    tooMany: '\u26D4 Слишком много запросов OTP. Попробуйте снова через 1 час.',
    welcome: '\uD83D\uDC4B <b>OTP-бот AFEX</b>\n\nОткройте мини-приложение AFEX \u2192 меню <b>OTP (A2F) / Сменить Email</b> \u2192 нажмите <b>Get</b>. 6-значный код придёт сюда и действует 5 минут.'
  },
  vi: {
    codeTitle: '\uD83D\uDD10 <b>AFEX OTP</b>\n\nMã OTP của bạn: <b><code>{code}</code></b>\nCho tài khoản A2F: {acc}\n\u23F1 Có hiệu lực trong <b>5 phút</b>. Không chia sẻ mã này cho bất kỳ ai.',
    returnApp: 'Quay lại mini app, nhập mã này và nhấn xác minh.',
    emailUsed: '\u26A0\uFE0F Email này đã được tài khoản khác sử dụng. Hãy đổi email trong mini app rồi nhấn <b>Get</b> lại.',
    cooldown: '\u2705 Mã OTP đã được gửi ở trên \u2B06\uFE0F\nĐể nhận mã mới, vui lòng đợi <b>{sec} giây</b> rồi gửi lại /otp.',
    tooMany: '\u26D4 Quá nhiều yêu cầu OTP. Vui lòng thử lại sau 1 giờ.',
    welcome: '\uD83D\uDC4B <b>Bot OTP AFEX</b>\n\nMở mini app AFEX \u2192 mục <b>OTP (A2F) / Đổi Email</b> \u2192 nhấn <b>Get</b>. Mã 6 chữ số sẽ được gửi vào đây và có hiệu lực 5 phút.'
  },
  tl: {
    codeTitle: '\uD83D\uDD10 <b>AFEX OTP</b>\n\nAng iyong OTP Code: <b><code>{code}</code></b>\nPara sa A2F account: {acc}\n\u23F1 Valid sa loob ng <b>5 minuto</b>. Huwag ibahagi ang code na ito kahit kanino.',
    returnApp: 'Bumalik sa mini app, ilagay ang code na ito, at pindutin ang verify.',
    emailUsed: '\u26A0\uFE0F Ginagamit na ng ibang account ang email na ito. Palitan ang email sa mini app at pindutin muli ang <b>Get</b>.',
    cooldown: '\u2705 Naipadala na sa itaas ang OTP code \u2B06\uFE0F\nPara sa bagong code, maghintay ng <b>{sec} segundo</b> at magpadala muli ng /otp.',
    tooMany: '\u26D4 Masyadong maraming kahilingan ng OTP. Subukan muli pagkalipas ng 1 oras.',
    welcome: '\uD83D\uDC4B <b>AFEX OTP Bot</b>\n\nBuksan ang AFEX mini app \u2192 menu na <b>OTP (A2F) / Palitan ang Email</b> \u2192 pindutin ang <b>Get</b>. Ipapadala rito ang 6-digit code na valid nang 5 minuto.'
  },
  th: {
    codeTitle: '\uD83D\uDD10 <b>AFEX OTP</b>\n\nรหัส OTP ของคุณ: <b><code>{code}</code></b>\nสำหรับบัญชี A2F: {acc}\n\u23F1 ใช้ได้ภายใน <b>5 นาที</b> อย่าแชร์รหัสนี้กับผู้อื่น',
    returnApp: 'กลับไปที่มินิแอป กรอกรหัสนี้แล้วกดยืนยัน',
    emailUsed: '\u26A0\uFE0F อีเมลนี้ถูกใช้โดยบัญชีอื่นแล้ว กรุณาเปลี่ยนอีเมลในมินิแอปแล้วกด <b>Get</b> อีกครั้ง',
    cooldown: '\u2705 ส่งรหัส OTP ด้านบนแล้ว \u2B06\uFE0F\nหากต้องการรหัสใหม่ โปรดรอ <b>{sec} วินาที</b> แล้วส่ง /otp อีกครั้ง',
    tooMany: '\u26D4 ขอ OTP บ่อยเกินไป โปรดลองใหม่ในอีก 1 ชั่วโมง',
    welcome: '\uD83D\uDC4B <b>บอท OTP AFEX</b>\n\nเปิดมินิแอป AFEX \u2192 เมนู <b>OTP (A2F) / เปลี่ยนอีเมล</b> \u2192 กด <b>Get</b> รหัส 6 หลักจะถูกส่งมาที่นี่และใช้ได้ 5 นาที'
  },
  ms: {
    codeTitle: '\uD83D\uDD10 <b>AFEX OTP</b>\n\nKod OTP Anda: <b><code>{code}</code></b>\nUntuk akaun A2F: {acc}\n\u23F1 Sah selama <b>5 minit</b>. Jangan kongsi kod ini dengan sesiapa.',
    returnApp: 'Kembali ke aplikasi mini, masukkan kod ini dan tekan sahkan.',
    emailUsed: '\u26A0\uFE0F E-mel ini telah digunakan oleh akaun lain. Tukar e-mel dalam aplikasi mini dan tekan <b>Get</b> semula.',
    cooldown: '\u2705 Kod OTP telah dihantar di atas \u2B06\uFE0F\nUntuk kod baharu, tunggu <b>{sec} saat</b> kemudian hantar /otp lagi.',
    tooMany: '\u26D4 Terlalu banyak permintaan OTP. Cuba lagi dalam 1 jam.',
    welcome: '\uD83D\uDC4B <b>Bot OTP AFEX</b>\n\nBuka aplikasi mini AFEX \u2192 menu <b>OTP (A2F) / Tukar E-mel</b> \u2192 tekan <b>Get</b>. Kod 6 digit dihantar ke sini dan sah selama 5 minit.'
  },
  hi: {
    codeTitle: '\uD83D\uDD10 <b>AFEX OTP</b>\n\nआपका OTP कोड: <b><code>{code}</code></b>\nA2F खाते के लिए: {acc}\n\u23F1 <b>5 मिनट</b> के लिए मान्य। यह कोड किसी के साथ साझा न करें।',
    returnApp: 'मिनी ऐप पर वापस जाएं, यह कोड दर्ज करें और सत्यापित करें दबाएं।',
    emailUsed: '\u26A0\uFE0F यह ईमेल पहले से किसी अन्य खाते द्वारा उपयोग किया जा रहा है। मिनी ऐप में ईमेल बदलें और फिर से <b>Get</b> दबाएं।',
    cooldown: '\u2705 OTP कोड ऊपर पहले ही भेजा जा चुका है \u2B06\uFE0F\nनए कोड के लिए <b>{sec} सेकंड</b> प्रतीक्षा करें और फिर से /otp भेजें।',
    tooMany: '\u26D4 बहुत अधिक OTP अनुरोध। 1 घंटे बाद पुनः प्रयास करें।',
    welcome: '\uD83D\uDC4B <b>AFEX OTP बॉट</b>\n\nAFEX मिनी ऐप खोलें \u2192 <b>OTP (A2F) / ईमेल बदलें</b> मेनू \u2192 <b>Get</b> दबाएं। 6 अंकों का कोड यहां भेजा जाएगा और 5 मिनट तक मान्य रहेगा।'
  },
  ur: {
    codeTitle: '\uD83D\uDD10 <b>AFEX OTP</b>\n\nآپ کا OTP کوڈ: <b><code>{code}</code></b>\nA2F اکاؤنٹ کے لیے: {acc}\n\u23F1 <b>5 منٹ</b> کے لیے درست ہے۔ یہ کوڈ کسی کے ساتھ شیئر نہ کریں۔',
    returnApp: 'منی ایپ پر واپس جائیں، یہ کوڈ درج کریں اور تصدیق دبائیں۔',
    emailUsed: '\u26A0\uFE0F یہ ای میل پہلے ہی کسی اور اکاؤنٹ میں استعمال ہو رہا ہے۔ منی ایپ میں ای میل تبدیل کریں اور دوبارہ <b>Get</b> دبائیں۔',
    cooldown: '\u2705 OTP کوڈ اوپر پہلے ہی بھیجا جا چکا ہے \u2B06\uFE0F\nنئے کوڈ کے لیے <b>{sec} سیکنڈ</b> انتظار کریں پھر دوبارہ /otp بھیجیں۔',
    tooMany: '\u26D4 بہت زیادہ OTP درخواستیں۔ 1 گھنٹے بعد دوبارہ کوشش کریں۔',
    welcome: '\uD83D\uDC4B <b>AFEX OTP بوٹ</b>\n\nAFEX منی ایپ کھولیں \u2192 <b>OTP (A2F) / ای میل تبدیل کریں</b> مینو \u2192 <b>Get</b> دبائیں۔ 6 ہندسوں کا کوڈ یہاں بھیجا جائے گا اور 5 منٹ تک درست رہے گا۔'
  },
  zh: {
    codeTitle: '\uD83D\uDD10 <b>AFEX OTP</b>\n\n您的 OTP 验证码：<b><code>{code}</code></b>\n用于 A2F 账号：{acc}\n\u23F1 有效期 <b>5 分钟</b>，请勿将此验证码透露给任何人。',
    returnApp: '请返回小程序，输入此验证码并点击验证。',
    emailUsed: '\u26A0\uFE0F 该邮箱已被其他账号使用。请在小程序中更换邮箱后再次点击 <b>Get</b>。',
    cooldown: '\u2705 OTP 验证码已在上方发送 \u2B06\uFE0F\n如需新验证码，请等待 <b>{sec} 秒</b>后再次发送 /otp。',
    tooMany: '\u26D4 OTP 请求过于频繁，请 1 小时后再试。',
    welcome: '\uD83D\uDC4B <b>AFEX OTP 机器人</b>\n\n打开 AFEX 小程序 \u2192 <b>OTP (A2F) / 更换邮箱</b>菜单 \u2192 点击 <b>Get</b>。6 位验证码将发送到此处，5 分钟内有效。'
  },
  ko: {
    codeTitle: '\uD83D\uDD10 <b>AFEX OTP</b>\n\n귀하의 OTP 코드: <b><code>{code}</code></b>\nA2F 계정: {acc}\n\u23F1 <b>5분</b> 동안 유효합니다. 이 코드를 누구에게도 공유하지 마세요.',
    returnApp: '미니앱으로 돌아가 이 코드를 입력하고 인증을 누르세요.',
    emailUsed: '\u26A0\uFE0F 이 이메일은 이미 다른 계정에서 사용 중입니다. 미니앱에서 이메일을 변경한 후 다시 <b>Get</b>을 누르세요.',
    cooldown: '\u2705 위에서 이미 OTP 코드가 전송되었습니다 \u2B06\uFE0F\n새 코드를 받으려면 <b>{sec}초</b> 기다린 후 /otp를 다시 보내세요.',
    tooMany: '\u26D4 OTP 요청이 너무 많습니다. 1시간 후에 다시 시도하세요.',
    welcome: '\uD83D\uDC4B <b>AFEX OTP 봇</b>\n\nAFEX 미니앱 열기 \u2192 <b>OTP (A2F) / 이메일 변경</b> 메뉴 \u2192 <b>Get</b> 누르기. 6자리 코드가 여기로 전송되며 5분간 유효합니다.'
  },
  ja: {
    codeTitle: '\uD83D\uDD10 <b>AFEX OTP</b>\n\nあなたのOTPコード: <b><code>{code}</code></b>\nA2Fアカウント: {acc}\n\u23F1 <b>5分間</b>有効です。このコードを他の人に教えないでください。',
    returnApp: 'ミニアプリに戻り、このコードを入力して認証を押してください。',
    emailUsed: '\u26A0\uFE0F このメールは既に別のアカウントで使用されています。ミニアプリでメールを変更してからもう一度 <b>Get</b> を押してください。',
    cooldown: '\u2705 OTPコードは既に上で送信されています \u2B06\uFE0F\n新しいコードを取得するには <b>{sec}秒</b> 待ってからもう一度 /otp を送信してください。',
    tooMany: '\u26D4 OTPリクエストが多すぎます。1時間後にもう一度お試しください。',
    welcome: '\uD83D\uDC4B <b>AFEX OTPボット</b>\n\nAFEXミニアプリを開く \u2192 <b>OTP (A2F) / メールアドレス変更</b>メニュー \u2192 <b>Get</b> を押す。6桁のコードがここに送信され、5分間有効です。'
  },
  af: {
    codeTitle: '\uD83D\uDD10 <b>AFEX OTP</b>\n\nJou OTP-kode: <b><code>{code}</code></b>\nVir A2F-rekening: {acc}\n\u23F1 Geldig vir <b>5 minute</b>. Moenie hierdie kode met enigiemand deel nie.',
    returnApp: 'Keer terug na die mini-app, voer hierdie kode in en druk verifieer.',
    emailUsed: '\u26A0\uFE0F Hierdie e-pos word reeds deur ’n ander rekening gebruik. Verander die e-pos in die mini-app en druk weer <b>Get</b>.',
    cooldown: '\u2705 OTP-kode is reeds hierbo gestuur \u2B06\uFE0F\nVir ’n nuwe kode, wag <b>{sec} sekondes</b> en stuur weer /otp.',
    tooMany: '\u26D4 Te veel OTP-versoeke. Probeer weer oor 1 uur.',
    welcome: '\uD83D\uDC4B <b>AFEX OTP-bot</b>\n\nMaak die AFEX mini-app oop \u2192 <b>OTP (A2F) / Verander E-pos</b>-kieslys \u2192 druk <b>Get</b>. ’n 6-syfer kode word hierheen gestuur en is 5 minute geldig.'
  },
  ar: {
    codeTitle: '\uD83D\uDD10 <b>AFEX OTP</b>\n\nرمز OTP الخاص بك: <b><code>{code}</code></b>\nلحساب A2F: {acc}\n\u23F1 صالح لمدة <b>5 دقائق</b>. لا تشارك هذا الرمز مع أي شخص.',
    returnApp: 'عد إلى التطبيق المصغر، أدخل هذا الرمز ثم اضغط على تحقق.',
    emailUsed: '\u26A0\uFE0F هذا البريد الإلكتروني مستخدم بالفعل في حساب آخر. غيّر البريد في التطبيق المصغر ثم اضغط <b>Get</b> مرة أخرى.',
    cooldown: '\u2705 تم إرسال رمز OTP أعلاه بالفعل \u2B06\uFE0F\nللحصول على رمز جديد، انتظر <b>{sec} ثانية</b> ثم أرسل /otp مرة أخرى.',
    tooMany: '\u26D4 طلبات OTP كثيرة جداً. حاول مرة أخرى بعد ساعة.',
    welcome: '\uD83D\uDC4B <b>بوت OTP AFEX</b>\n\nافتح تطبيق AFEX المصغر \u2192 قائمة <b>OTP (A2F) / تغيير البريد الإلكتروني</b> \u2192 اضغط <b>Get</b>. سيُرسل رمز من 6 أرقام إلى هنا ويكون صالحاً لمدة 5 دقائق.'
  }
};
function normOtpLang(l) {
  l = String(l || '').trim().toLowerCase();
  if (l === 'fil') return 'tl';
  l = l.slice(0, 2);
  return OTP_I18N[l] ? l : 'id';
}
function otpMsg(lang, key, vars) {
  const pack = OTP_I18N[normOtpLang(lang)] || OTP_I18N.id;
  let s = pack[key] || OTP_I18N.id[key] || '';
  if (vars) {
    Object.keys(vars).forEach(function (k) { s = s.split('{' + k + '}').join(String(vars[k])); });
  }
  return s;
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
  /* [PERBAIKAN] kode disimpan LEBIH DULU, baru dikirim. Jika pengiriman gagal, kode dibatalkan (tidak ada kode yatim). */
  const reqLang = normOtpLang(b.lang || (u && u.language_code) || 'id');
  const prev = await db.collection('otp_codes').findOne({ _id: u.id });
  await db.collection('otp_codes').replaceOne({ _id: u.id },
    { _id: u.id, h: sha(E.HASH_SALT + u.id + email + code), email: email, lang: reqLang, exp: new Date(now + TTL_MS), tries: 0 }, { upsert: true });
  const sent = await tgSend(u.id,
    otpMsg(reqLang, 'codeTitle', { code: code, acc: (u.username ? '@' + u.username : u.id) }));
  if (!sent.ok) {
    if (prev) await db.collection('otp_codes').replaceOne({ _id: u.id }, prev, { upsert: true }).catch(function () {});   // kode lama (jika masih berlaku) tetap sah
    else await db.collection('otp_codes').deleteOne({ _id: u.id }).catch(function () {});
    if (needsStart(sent)) { await savePendingOtp(u.id, email, reqLang); return { ok: false, error: 'need_start', pending: true, ttl: 300 }; }   // ingat permintaan; begitu user menekan Start di bot, kode langsung dikirim
    return { ok: false, error: 'send_failed' };
  }
  await rates.replaceOne({ _id: u.id }, { _id: u.id, cd: now + COOLDOWN_MS, hs: rate.hs, n: rate.n + 1 }, { upsert: true });
  await db.collection('otp_pending').deleteOne({ _id: u.id }).catch(function () {});
  return { ok: true, expiresAt: now + TTL_MS, ttl: 300 };
}
/* ---------- [PERBAIKAN] OTP langsung dari chat bot ----------
   Masalah lama: tombol Get membuka bot (?start=otp) tetapi bot hanya membalas teks petunjuk, TANPA kode. Jika user belum pernah
   menekan Start di bot, kode juga gagal terkirim (need_start) dan setelah Start tetap tidak ada kode.
   Sekarang: permintaan Get disimpan (otp_pending, 5 menit). Saat user menekan /start atau mengirim /otp ke bot OTP,
   bot membuat kode acak 6 digit baru untuk email yang sedang diminta dan mengirimnya ke chat itu. */
async function savePendingOtp(uid, email, lang) {
  try { await db.collection('otp_pending').replaceOne({ _id: uid }, { _id: uid, email: email, lang: normOtpLang(lang || 'id'), exp: new Date(Date.now() + TTL_MS) }, { upsert: true }); }
  catch (e) { console.error('[OTP] simpan pending gagal', e && e.message); }
}
async function botGiveOtp(m) {
  if (!m || !m.chat || m.chat.type !== 'private') return false;
  db = getDb(); if (!db) return false;
  const uid = String((m.from && m.from.id) || m.chat.id), uname = (m.from && m.from.username) || '';
  const text = String(m.text || '').trim().toLowerCase(), isCmd = /^\/(start|otp|get|kode)(@\w+)?(\s|$)/.test(text);
  const now = Date.now();
  let email = '', uLang = (m.from && m.from.language_code) || 'id';
  const pend = await db.collection('otp_pending').findOne({ _id: uid });
  if (pend && pend.exp && new Date(pend.exp).getTime() > now) { email = pend.email; if (pend.lang) uLang = pend.lang; }   // permintaan Get yang menunggu bot dibuka: pesan apa pun cukup
  if (!email && isCmd) {                                                            // sudah pernah Get: perintah di bot meminta kode baru
    const cur = await db.collection('otp_codes').findOne({ _id: uid });
    if (cur && cur.exp && new Date(cur.exp).getTime() > now) { email = cur.email; if (cur.lang) uLang = cur.lang; }
  }
  if (!email) return false;                                                         // tidak ada permintaan aktif -> balasan petunjuk bawaan
  uLang = normOtpLang(uLang);

  const owner = await db.collection('a2f_verified').findOne({ emailHash: sha(E.HASH_SALT + email) });
  if (owner && owner.uid !== uid) { await db.collection('otp_pending').deleteOne({ _id: uid }); await tgSend(m.chat.id, otpMsg(uLang, 'emailUsed')); return true; }

  const rates = db.collection('otp_rate'), rate = (await rates.findOne({ _id: uid })) || { _id: uid, cd: 0, hs: now, n: 0 };
  if (now < rate.cd) {   // kode baru saja dikirim (mis. dari tombol Get) -> jangan kirim ganda
    await db.collection('otp_pending').deleteOne({ _id: uid });
    await tgSend(m.chat.id, otpMsg(uLang, 'cooldown', { sec: Math.ceil((rate.cd - now) / 1000) }));
    return true;
  }
  if (now - rate.hs > 3600000) { rate.hs = now; rate.n = 0; }
  if (rate.n >= MAX_REQ_HOUR) { await tgSend(m.chat.id, otpMsg(uLang, 'tooMany')); return true; }

  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  await db.collection('otp_codes').replaceOne({ _id: uid },
    { _id: uid, h: sha(E.HASH_SALT + uid + email + code), email: email, lang: uLang, exp: new Date(now + TTL_MS), tries: 0 }, { upsert: true });
  const sent = await tgSend(m.chat.id,
    otpMsg(uLang, 'codeTitle', { code: code, acc: (uname ? '@' + uname : uid) }) + '\n\n' + otpMsg(uLang, 'returnApp'));
  if (!sent.ok) { await db.collection('otp_codes').deleteOne({ _id: uid }).catch(function () {}); return true; }
  await rates.replaceOne({ _id: uid }, { _id: uid, cd: now + COOLDOWN_MS, hs: rate.hs, n: rate.n + 1 }, { upsert: true });
  await db.collection('otp_pending').deleteOne({ _id: uid });
  return true;
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
      { $set: { uid: u.id, email: email, emailHash: sha(E.HASH_SALT + email), at: new Date() }, $unset: { revokedAt: '' } }, { upsert: true });   // [PERBAIKAN] $unset revokedAt: verifikasi ulang setelah pembatalan kembali tampil aktif
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
const REVOKE_KINDS = ['face', 'id', 'kyc_all', 'founder', 'a2f'];
async function revoke(b) {
  const u = tgUser(b); if (!u || ADMINS.indexOf(u.id) < 0) return { ok: false, error: 'unauthorized' };
  const target = String(b.targetUid || '').trim();
  if (!/^\d{3,20}$/.test(target)) return { ok: false, error: 'bad_uid' };
  if (REVOKE_KINDS.indexOf(b.kind) < 0) return { ok: false, error: 'bad_kind' };
  await db.collection('revocations').insertOne({ uid: target, kind: b.kind, ts: Date.now(), by: u.id });
  if (b.kind === 'face' || b.kind === 'kyc_all') await db.collection('face_registry').deleteOne({ uid: target });   // wajah bisa didaftarkan ulang
  if (b.kind === 'kyc_all') await db.collection('a2f_verified').updateOne({ uid: target }, { $set: { revokedAt: new Date() } }).catch(function () {});
  if (b.kind === 'a2f') {   // Batalkan A2F: hapus status terverifikasi + kode OTP tersisa, user wajib OTP ulang
    await db.collection('a2f_verified').deleteOne({ uid: target });
    await db.collection('otp_codes').deleteOne({ _id: target }).catch(function () {});
  }
  return { ok: true };
}
async function revocations(b) {
  const u = tgUser(b); if (!u) return { ok: false, error: 'unauthorized' };
  const filter = { uid: u.id, ts: { $gt: Number(b.since) || 0 } };
  if (b.a2f !== true) filter.kind = { $ne: 'a2f' };
  else {   // pembatalan A2F lama (sebelum user verifikasi ulang) tidak boleh mereset A2F yang sudah baru
    const ver = await db.collection('a2f_verified').findOne({ uid: u.id });
    const vts = ver && ver.at ? new Date(ver.at).getTime() : 0;
    if (vts) filter.$or = [{ kind: { $ne: 'a2f' } }, { kind: 'a2f', ts: { $gt: vts } }];
  }
  const list = await db.collection('revocations').find(filter).sort({ ts: 1 }).limit(20).toArray();
  return { ok: true, list: list.map(function (x) { return { kind: x.kind, ts: x.ts }; }) };
}

function maskEmail(e) {
  e = String(e || ''); const i = e.indexOf('@'); if (i < 1) return '***';
  return e.slice(0, 1) + '***' + e.slice(i);
}
async function a2fList(b) {   // admin saja: daftar UID dengan A2F aktif (email disamarkan)
  const u = tgUser(b); if (!u || ADMINS.indexOf(u.id) < 0) return { ok: false, error: 'unauthorized' };
  const rows = await db.collection('a2f_verified').find({ revokedAt: { $exists: false } }).sort({ at: -1 }).limit(200).project({ uid: 1, email: 1, at: 1 }).toArray();
  return { ok: true, list: rows.map(function (x) { return { uid: x.uid, email: maskEmail(x.email), at: x.at ? new Date(x.at).getTime() : 0 }; }) };
}
async function a2fMe(b) {   // user sendiri: email tersamar + tanggal verifikasi milik user itu sendiri (divalidasi initData)
  const u = tgUser(b); if (!u) return { ok: false, error: 'unauthorized' };
  const d = await db.collection('a2f_verified').findOne({ uid: u.id, revokedAt: { $exists: false } });
  if (!d) return { ok: true, verified: false, email: '', maskedEmail: '', at: 0, verifiedAt: 0 };
  const masked = maskEmail(d.email);
  const ts = d.at ? new Date(d.at).getTime() : 0;
  return { ok: true, verified: true, email: masked, maskedEmail: masked, at: ts, verifiedAt: ts };
}

/* ---------- [PERBAIKAN] BLOKIR AKUN: disimpan & ditegakkan di SERVER ----------
   Masalah lama: status blokir hanya ditulis ke antrean lokal admin + Google Apps Script (no-cors, tanpa bukti berhasil), tidak pernah sampai ke perangkat
   user yang diblokir dan tidak dicek server -> akun tetap bisa masuk & bertransaksi.
   Sekarang: koleksi MongoDB 'blocked_users' (_id = UID). Admin (ADMIN_IDS) memblokir lewat action block/unblock; user yang diblokir mendapat
   status lewat block_status (mini app mengunci layar), dan blockGuard menolak SEMUA API user (sync, update, withdraw, deposit, dst.) dengan HTTP 403. */
const blockCache = new Map();   // uid -> { v: boolean, t: ms }  (cache 10 dtk, dibersihkan saat block/unblock)
async function isBlocked(uid) {
  uid = String(uid || '');
  if (!uid || ADMINS.indexOf(uid) >= 0) return false;
  const c = blockCache.get(uid), now = Date.now();
  if (c && now - c.t < 10000) return c.v;
  const d = getDb(); if (!d) return c ? c.v : false;
  let v;
  try { v = !!(await d.collection('blocked_users').findOne({ _id: uid }, { projection: { _id: 1 } })); }
  catch (e) { return c ? c.v : false; }
  blockCache.set(uid, { v: v, t: now });
  return v;
}
async function blockSet(b, on) {
  const u = tgUser(b); if (!u || ADMINS.indexOf(u.id) < 0) return { ok: false, error: 'unauthorized' };
  const target = String(b.targetUid || '').trim();
  if (!/^\d{3,20}$/.test(target)) return { ok: false, error: 'bad_uid' };
  if (ADMINS.indexOf(target) >= 0) return { ok: false, error: 'admin_exempt' };
  const col = db.collection('blocked_users'), reason = String(b.reason || '').replace(/[<>]/g, '').slice(0, 120);
  if (on) {
    await col.updateOne({ _id: target }, { $set: { uid: target, reason: reason, username: String(b.username || '').replace(/[<>]/g, '').slice(0, 60), by: u.id, ts: Date.now() } }, { upsert: true });
  } else {
    await col.deleteOne({ _id: target });
  }
  blockCache.delete(target);
  db.collection('block_log').insertOne({ uid: target, action: on ? 'block' : 'unblock', reason: reason, by: u.id, ts: Date.now() }).catch(function () {});
  const now = !!(await col.findOne({ _id: target }, { projection: { _id: 1 } }));   // baca ulang: bukti nyata tersimpan
  if (now !== !!on) return { ok: false, error: 'not_saved' };
  return { ok: true, blocked: now, uid: target };
}
async function blockStatus(b) {
  const u = tgUser(b); if (!u) return { ok: false, error: 'unauthorized' };
  if (ADMINS.indexOf(u.id) >= 0) return { ok: true, blocked: false };
  const d = await db.collection('blocked_users').findOne({ _id: u.id });
  blockCache.set(u.id, { v: !!d, t: Date.now() });
  return d ? { ok: true, blocked: true, reason: d.reason || '', ts: d.ts || 0 } : { ok: true, blocked: false };
}
async function blockList(b) {
  const u = tgUser(b); if (!u || ADMINS.indexOf(u.id) < 0) return { ok: false, error: 'unauthorized' };
  const rows = await db.collection('blocked_users').find({}).sort({ ts: -1 }).limit(500).toArray();
  return { ok: true, list: rows.map(function (x) { return { uid: String(x._id), username: x.username || '', reason: x.reason || '', ts: x.ts || 0 }; }) };
}
/* middleware: dipasang di server.js SEBELUM route lain -> app.use('/api', blockGuard). /api/afex (status blokir, panel admin) tetap dilayani. */
function blockGuard(req, res, next) {
  (async function () {
    try {
      if (/^\/afex(\/|$)/.test(req.path) || !MAIN_TOKEN) return next();
      const init = String((req.headers && req.headers['x-telegram-init-data']) || (req.body && typeof req.body === 'object' && req.body.initData) || '');
      if (!init) return next();
      const u = tgUser({ initData: init });
      if (u && await isBlocked(u.id)) return res.status(403).json({ ok: false, success: false, blocked: true, error: 'account_blocked', message: 'Akun diblokir' });
    } catch (e) { console.error('[block] guard error', e && e.message); }
    next();
  })();
}

async function handle(body) {
  if (body && ['otp_request', 'otp_verify', 'face_check', 'face_register', 'a2f_status', 'a2f_me'].indexOf(body.action) >= 0) {
    const bu = tgUser(body);
    if (bu && await isBlocked(bu.id)) return { ok: false, error: 'blocked' };
  }
  switch (body && body.action) {
    case 'otp_request': return otpRequest(body);
    case 'otp_verify': return otpVerify(body);
    case 'a2f_status': return a2fStatus(body);
    case 'a2f_me': return a2fMe(body);
    case 'face_check': return faceCheck(body);
    case 'face_register': return faceRegister(body);
    case 'face_remove': return faceRemove(body);
    case 'revoke': return revoke(body);
    case 'revocations': return revocations(body);
    case 'a2f_list': return a2fList(body);
    case 'block': return blockSet(body, true);
    case 'unblock': return blockSet(body, false);
    case 'block_status': return blockStatus(body);
    case 'block_list': return blockList(body);
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
/* satu pintu untuk semua pesan masuk bot OTP (dipakai webhook DAN polling) */
async function handleUpdate(up) {
  const m = up && up.message;
  if (!m || !m.chat) return;
  console.log('[OTP] pesan masuk dari chat ' + m.chat.id);
  let given = false;   // jika ada permintaan OTP aktif, bot langsung memberi kode acak (bukan hanya petunjuk)
  try { given = await botGiveOtp(m); } catch (e) { console.error('[OTP] botGiveOtp error', e && e.message); }
  if (!given) await tgSend(m.chat.id, otpMsg((m.from && m.from.language_code) || 'id', 'welcome'));
}
router.post('/telegram/:secret', async function (req, res) {
  if (!WEBHOOK_SECRET || req.params.secret !== WEBHOOK_SECRET) { console.warn('[OTP] webhook ditolak: secret tidak cocok / WEBHOOK_SECRET kosong'); return res.sendStatus(403); }
  try { await handleUpdate(parseBody(req) || {}); } catch (e) { console.error('[OTP] webhook error', e && e.message); }
  res.sendStatus(200);
});

/* ---------- [PERBAIKAN] POLLING: bot OTP tetap membalas tanpa webhook ----------
   Di Termux + tunnel Cloudflare tidak ada PUBLIC_URL tetap, sehingga setWebhook tidak pernah dipasang dan /start tidak dibalas (OTP "tidak masuk").
   Mode polling menarik pesan langsung dari Telegram (getUpdates) sehingga tidak butuh URL publik sama sekali. */
let pollOn = false, pollOffset = 0, pollErr = '', pollLast = 0;
function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
async function startPolling() {
  if (pollOn || !OTP_TOKEN) return;
  if (MAIN_TOKEN && OTP_TOKEN === MAIN_TOKEN) { console.error('[OTP] OTP_BOT_TOKEN SAMA dengan BOT_TOKEN. Polling tidak dijalankan (akan merebut update bot utama).'); return; }
  pollOn = true;
  const del = await tgCall('deleteWebhook', { drop_pending_updates: false });   // getUpdates tidak jalan bila webhook masih terpasang
  console.log('[OTP] mode POLLING aktif (deleteWebhook ' + (del.ok ? 'OK' : 'gagal: ' + del.desc) + ')');
  (async function loop() {
    while (pollOn) {
      const r = await tgCall('getUpdates', { offset: pollOffset, timeout: 25, allowed_updates: ['message'] }, 35000);
      pollLast = Date.now();
      if (!r.ok) {
        pollErr = r.code + ' ' + r.desc;
        if (r.code === 409) await tgCall('deleteWebhook', { drop_pending_updates: false });   // ada webhook lama yang merebut
        await sleep(r.code === 401 ? 30000 : 4000);
        continue;
      }
      pollErr = '';
      const list = Array.isArray(r.data) ? r.data : [];
      for (const up of list) {
        pollOffset = Math.max(pollOffset, Number(up.update_id) + 1);
        try { await handleUpdate(up); } catch (e) { console.error('[OTP] polling handle error', e && e.message); }
      }
    }
  })().catch(function (e) { pollOn = false; console.error('[OTP] polling berhenti:', e && e.message); });
}

/* diagnosa: buka https://<server>/api/afex/health di browser. Tidak menampilkan nilai rahasia. ?fix=1 = daftarkan ulang webhook */
router.get('/api/afex/health', async function (req, res) {
  const out = {
    node: process.version, fetch: typeof fetch,
    env: {
      MONGODB_URI: !!E.MONGODB_URI, OTP_BOT_TOKEN: !!OTP_TOKEN,
      MAIN_BOT_TOKEN_atau_BOT_TOKEN: !!MAIN_TOKEN, HASH_SALT: !!E.HASH_SALT,
      WEBHOOK_SECRET: !!WEBHOOK_SECRET, ADMIN_IDS: ADMINS.length, BASE_URL: BASE_URL || null
    },
    mode_bot_otp: OTP_MODE, polling: { aktif: pollOn, error_terakhir: pollErr || null, terakhir_tarik: pollLast || null },
    token_otp_sama_dengan_bot_utama: !!(MAIN_TOKEN && OTP_TOKEN && OTP_TOKEN === MAIN_TOKEN),
    mongo: getDb() ? 'terhubung' : 'TIDAK terhubung (readyState=' + (mongoose.connection && mongoose.connection.readyState) + ')'
  };
  if (OTP_TOKEN) {
    const me = await tgCall('getMe');
    out.otpBot = me.ok ? { ok: true, username: '@' + me.data.username } : { ok: false, kode: me.code, alasan: me.desc };
    if (req.query.fix === '1') { if (OTP_MODE === 'webhook') { const f = await setupWebhook(); out.fixWebhook = f.ok ? 'OK' : f.desc; } else { await startPolling(); out.fixWebhook = 'mode polling: tidak perlu webhook'; } }
    const wi = await tgCall('getWebhookInfo');
    if (wi.ok) {
      const expected = WEBHOOK_SECRET && BASE_URL ? BASE_URL + '/telegram/' + WEBHOOK_SECRET : null;
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
  const jobs = [
    ['otp_codes', { exp: 1 }, { expireAfterSeconds: 0 }],
    ['a2f_verified', { emailHash: 1 }, { unique: true }],
    ['a2f_verified', { uid: 1 }, { unique: true }],
    ['face_registry', { uid: 1 }, { unique: true }],
    ['revocations', { uid: 1, ts: 1 }, {}],
    ['otp_pending', { exp: 1 }, { expireAfterSeconds: 0 }],   // permintaan OTP yang menunggu bot dibuka
    ['block_log', { uid: 1, ts: 1 }, {}]
  ];
  for (const j of jobs) {   // [PERBAIKAN] satu indeks gagal (mis. data ganda lama) tidak lagi menghentikan indeks sesudahnya
    try { await db.collection(j[0]).createIndex(j[1], j[2]); }
    catch (e) { console.error('afex index gagal (' + j[0] + ' ' + JSON.stringify(j[1]) + '): ' + (e && e.message)); }
  }
}
function bootBot() {
  if (OTP_MODE === 'polling') startPolling().catch(function (e) { console.error('[OTP] startPolling error', e && e.message); });
  else setupWebhook().catch(function (e) { console.error('[OTP] setupWebhook error', e && e.message); });
}
setTimeout(bootBot, 3000);
mongoose.connection.once('open', function () { initIndexes().catch(function (e) { console.error('afex index gagal:', e.message); }); });
if (mongoose.connection.readyState === 1) initIndexes().catch(function () {});

router.blockGuard = blockGuard;   // dipakai server.js: app.use('/api', require('./routes/afexface').blockGuard)
module.exports = router;