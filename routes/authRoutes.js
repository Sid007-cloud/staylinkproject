const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { verifyToken } = require('../middleware/authMiddleware');

// PUBLIC ROUTES (anyone can access)

// Register new user
router.post('/register', authController.register);

// Login user
router.post('/login', authController.login);

// PROTECTED ROUTES (need token)

// Get my info
router.get('/me', verifyToken, authController.getMe);

// Logout
router.post('/logout', verifyToken, authController.logout);

// Verify Aadhaar
router.post('/verify-aadhaar', verifyToken, authController.verifyAadhaar);

// Update profile (display name)
router.put('/update-profile', verifyToken, authController.updateProfile);

module.exports = router;