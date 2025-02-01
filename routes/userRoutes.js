const router = require("express").Router();
const userControllers = require("../controllers/userControllers");
const { verifyToken, hasRole, hasPermission } = require('../middleware/authMiddleware');
const { PERMISSIONS } = require('../config/roles');
const { apiLimiter, passwordChangeLimiter } = require('../middleware/rateLimiter');
const accountLimiter = require('../middleware/accountLimiter');

// Public routes
router.post("/create", apiLimiter, userControllers.createUser);
router.post("/login", accountLimiter, userControllers.loginUser);

// Protected routes
router.post('/change-password', 
  verifyToken, 
  passwordChangeLimiter, 
  userControllers.changePassword
);

// Admin only routes
router.get('/users', 
  verifyToken, 
  hasRole('admin'),
  hasPermission(PERMISSIONS.VIEW_USERS),
  userControllers.getAllUsers
);

router.put('/user/role', 
  verifyToken, 
  hasRole('admin'),
  hasPermission(PERMISSIONS.UPDATE_USER),
  userControllers.updateUserRole
);

module.exports = router;
