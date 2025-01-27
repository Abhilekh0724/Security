const router = require("express").Router();
const userControllers = require("../controllers/userControllers");

// Create user API
router.post("/create", userControllers.createUser);

// Login user API
router.post("/login", userControllers.loginUser);

module.exports = router;
