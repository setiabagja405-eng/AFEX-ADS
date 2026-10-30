const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');

// Skema Deposit yang sama seperti di bot Termux
const depositSchema = new mongoose.Schema({
    userId: Number,
    txhash: String,
    amount: Number,
    status: { type: String, default: 'PENDING_APPROVAL' },
    timestamp: { type: Date, default: Date.now }
});
const Deposit = mongoose.model('Deposit', depositSchema);

// 1. Endpoint untuk Admin melihat daftar deposit yang perlu di-approve
router.get('/admin/deposits-pending', async (req, res) => {
    try {
        const pendingDeposits = await Deposit.find({ status: 'PENDING_APPROVAL' }).sort({ timestamp: -1 });
        res.json({ success: true, data: pendingDeposits });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// 2. Endpoint untuk Admin menekan tombol "Approve"
router.post('/admin/approve-deposit/:id', async (req, res) => {
    try {
        const depositId = req.params.id;
        const deposit = await Deposit.findById(depositId);

        if (!deposit) {
            return res.status(404).json({ success: false, message: 'Data deposit tidak ditemukan.' });
        }

        // Ubah status menjadi APPROVED
        deposit.status = 'APPROVED';
        await deposit.save();

        res.json({ success: true, message: 'Deposit berhasil disetujui (Approved)!' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

module.exports = router;
