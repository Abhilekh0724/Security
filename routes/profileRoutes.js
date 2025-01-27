const express = require('express');
const { uploadProfilePic, getUserInfo } = require('../controllers/profileControllers');
const { authGuard } = require('../middleware/authGuard'); // Import the authGuard middleware
const router = express.Router();

// Apply authGuard middleware to ensure only authenticated users can access these routes
router.post('/uploadProfilePic', authGuard, uploadProfilePic);
router.get('/info', authGuard, getUserInfo); // New route for getting user info

module.exports = router;
