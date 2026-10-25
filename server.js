const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// 1. Rute Sambutan Utama (Agar tidak muncul "Cannot GET /" di browser)
app.get('/', (req, res) => {
    res.send('AFEX Backend API is Running Successfully!');
});

// 2. Ambil URI dari Environment Variable Render (MONGODB_URI)
const MONGODB_URI = process.env.MONGODB_URI;

// 3. Hubungkan ke MongoDB Atlas
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('Berhasil terhubung ke MongoDB Atlas!'))
.catch(err => console.error('Koneksi MongoDB gagal:', err));

// 4. Buat Skema Pengguna (Mongoose Schema)
const userSchema = new mongoose.Schema({
    userId: { type: String, required: true, unique: true },
    username: String,
    balanceAfex: { type: Number, default: 0 },
    usdtBalance: { type: Number, default: 0 },
    userPoints: { type: Number, default: 0 },
    lastCheckInTime: { type: Number, default: 0 },
    checkInDay: { type: Number, default: 1 },
    usdtSpeedBoost: { type: Number, default: 0 },
    isMining: { type: Boolean, default: false },
    miningStartTime: { type: Number, default: 0 },
    miningEndTime: { type: Number, default: 0 },
    tgTaskEndTime: { type: Number, default: 0 }
});

const User = mongoose.model('User', userSchema);

// 5. Route untuk Sync / Ambil Data Pengguna saat Buka Mini App
app.post('/api/user/sync', async (req, res) => {
    try {
        const { userId, username } = req.body;
        if (!userId) return res.status(400).json({ error: 'userId diperlukan' });

        let user = await User.findOne({ userId });
        if (!user) {
            user = new User({ userId, username });
            await user.save();
        }
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 6. Route untuk Update & Simpan Data Pengguna (Saat Absen, Mining, dll)
app.post('/api/user/update', async (req, res) => {
    try {
        const { 
            userId, username, balanceAfex, usdtBalance, userPoints, 
            lastCheckInTime, checkInDay, usdtSpeedBoost, isMining, 
            miningStartTime, miningEndTime, tgTaskEndTime 
        } = req.body;

        if (!userId) return res.status(400).json({ error: 'userId diperlukan' });

        const updatedUser = await User.findOneAndUpdate(
            { userId },
            { 
                username, balanceAfex, usdtBalance, userPoints, 
                lastCheckInTime, checkInDay, usdtSpeedBoost, isMining, 
                miningStartTime, miningEndTime, tgTaskEndTime 
            },
            { new: true, upsert: true }
        );

        res.json({ success: true, user: updatedUser });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// 7. Jalankan Server di Port Render
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server berjalan di port ${PORT}`);
});
