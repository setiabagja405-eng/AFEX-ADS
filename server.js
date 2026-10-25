const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// 1. Rute Sambutan Utama
app.get('/', (req, res) => {
    res.send('AFEX Backend API is Running Successfully!');
});

// 2. Ambil URI dari Environment Variable Render
const MONGODB_URI = process.env.MONGODB_URI;

// 3. Hubungkan ke MongoDB Atlas dengan konfigurasi stabil
mongoose.connect(MONGODB_URI, {
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
})
.then(() => console.log('Berhasil terhubung ke MongoDB Atlas!'))
.catch(err => console.error('Koneksi MongoDB gagal:', err));

// 4. Skema Pengguna yang Sesuai Presisi dengan Frontend
const userSchema = new mongoose.Schema({
    userId: { type: String, required: true, unique: true },
    username: { type: String, default: 'Tamu' },
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

// 5. Route untuk Sync / Ambil Data Pengguna
app.post('/api/user/sync', async (req, res) => {
    try {
        const { userId, username } = req.body;
        if (!userId) return res.status(400).json({ error: 'userId diperlukan' });

        let user = await User.findOne({ userId });
        if (!user) {
            user = new User({ userId, username: username || 'Tamu' });
            await user.save();
        }
        res.json(user);
    } catch (error) {
        console.error("Error Sync:", error);
        res.status(500).json({ error: error.message });
    }
});

// 6. Route untuk Update & Simpan Data Pengguna
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
                username, 
                balanceAfex: Number(balanceAfex) || 0, 
                usdtBalance: Number(usdtBalance) || 0, 
                userPoints: Number(userPoints) || 0, 
                lastCheckInTime: Number(lastCheckInTime) || 0, 
                checkInDay: Number(checkInDay) || 1, 
                usdtSpeedBoost: Number(usdtSpeedBoost) || 0, 
                isMining: Boolean(isMining), 
                miningStartTime: Number(miningStartTime) || 0, 
                miningEndTime: Number(miningEndTime) || 0, 
                tgTaskEndTime: Number(tgTaskEndTime) || 0 
            },
            { new: true, upsert: true, setDefaultsOnInsert: true }
        );

        res.json({ success: true, user: updatedUser });
    } catch (error) {
        console.error("Error Update:", error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// 7. Jalankan Server di Port Render
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server berjalan di port ${PORT}`);
});
