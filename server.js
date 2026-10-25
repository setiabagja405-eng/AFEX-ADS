const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Skema & Model Database User
const userSchema = new mongoose.Schema({
  userId: { type: String, required: true, unique: true },
  username: { type: String, default: 'Tamu' },
  balanceAfex: { type: Number, default: 0 },
  usdtBalance: { type: Number, default: 0 },
  userPoints: { type: Number, default: 0 },
  isMining: { type: Boolean, default: false },
  miningStartTime: { type: Number, default: 0 },
  miningEndTime: { type: Number, default: 0 }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// Koneksi ke MongoDB Atlas
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Koneksi MongoDB Berhasil!'))
  .catch(err => console.error('Koneksi MongoDB Gagal:', err));

// Endpoint Tes Server Active
app.get('/', (req, res) => {
  res.send({ status: 'AFEX MongoDB Backend Active', timestamp: Date.now() });
});

// Endpoint Sync User Data
app.post('/api/user/sync', async (req, res) => {
  const { userId, username } = req.body;
  if (!userId) return res.status(400).json({ error: 'userId wajib diisi' });

  try {
    let user = await User.findOne({ userId });
    if (!user) {
      user = await User.create({ userId, username });
    }
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server aktif di port ${PORT}`));
