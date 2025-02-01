const router = require('express').Router();
const { getAllLogs, getUserLogs, getLogStats } = require('../controllers/userLogController');
const { verifyToken, hasRole } = require('../middleware/authMiddleware');
const { ROLES } = require('../config/roles');

// All routes require admin role
router.use(verifyToken, hasRole(ROLES.ADMIN));

// Get all logs with filtering and pagination
router.get('/', getAllLogs);

// Get logs for a specific user
router.get('/user/:userId', getUserLogs);

// Get log statistics
router.get('/stats', getLogStats);

module.exports = router; 