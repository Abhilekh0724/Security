const userModel = require("../models/userModels");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const { ROLES, ROLE_PERMISSIONS } = require('../config/roles');
const UserLog = require('../models/userLogModel');

// Password strength validation
const isStrongPassword = (password) => {
  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

  return (
    password.length >= minLength &&
    hasUpperCase &&
    hasLowerCase &&
    hasNumbers &&
    hasSpecialChar
  );
};

// Verify Google reCAPTCHA
const verifyCaptcha = async (captchaToken) => {
  try {
    if (!process.env.RECAPTCHA_SECRET_KEY) {
      console.error("RECAPTCHA_SECRET_KEY is not configured in environment variables");
      return false;
    }

    const response = await axios.post(
      'https://www.google.com/recaptcha/api/siteverify',
      null,
      {
        params: {
          secret: process.env.RECAPTCHA_SECRET_KEY,
          response: captchaToken
        }
      }
    );

    if (!response.data.success) {
      console.error("Captcha verification failed:", response.data["error-codes"]);
      return false;
    }

    return true;
  } catch (error) {
    console.error("Captcha verification error:", error.message);
    return false;
  }
};

// Add password expiry check (90 days)
const isPasswordExpired = (lastPasswordChange) => {
  const ninetyDaysInMs = 90 * 24 * 60 * 60 * 1000;
  return Date.now() - new Date(lastPasswordChange).getTime() > ninetyDaysInMs;
};

// Create log entry function
const createLoginLog = async (userId, action, status, ipAddress, details = '') => {
  try {
    const log = new UserLog({
      userId,
      action,
      status,
      ipAddress,
      userAgent: 'Web Browser',
      details
    });
    await log.save();
  } catch (error) {
    console.error('Error creating log:', error);
  }
};

const createUser = async (req, res) => {
  const { firstName, lastName, email, password, role = 'user' } = req.body;
  
  if (!firstName || !lastName || !email || !password) {
    return res.json({
      success: false,
      message: "Please enter all fields!",
    });
  }

  // Check password strength
  if (!isStrongPassword(password)) {
    return res.json({
      success: false,
      message: "Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters",
    });
  }

  try {
    // Check if the requesting user has permission to create users with the specified role
    if (req.user && role !== 'user') {
      if (!req.user.hasRole('admin')) {
        return res.json({
          success: false,
          message: "You don't have permission to create users with this role",
        });
      }
    }

    const existingUser = await userModel.findOne({ email });
    if (existingUser) {
      return res.json({
        success: false,
        message: "User Already Exists!",
      });
    }

    const randomSalt = await bcrypt.genSalt();
    const hashPassword = await bcrypt.hash(password, randomSalt);

    const newUser = new userModel({
      firstName,
      lastName,
      email,
      password: hashPassword,
      role,
      permissions: ROLE_PERMISSIONS[role] || [],
      loginAttempts: 0,
      lockUntil: null,
      passwordHistory: [hashPassword], // Add initial password to history
      lastPasswordChange: Date.now()
    });

    await newUser.save();

    res.json({
      success: true,
      message: "User created successfully",
    });
  } catch (error) {
    console.log(error);
    res.json({
      success: false,
      message: "Internal server error",
    });
  }
};

const loginUser = async (req, res) => {
  const { email, password, captchaToken } = req.body;
  const ipAddress = req.ip || req.connection.remoteAddress;

  if (!email || !password) {
    return res.json({
      success: false,
      message: "Please enter email and password",
    });
  }

  if (!captchaToken) {
    return res.json({
      success: false,
      message: "Please complete the captcha verification",
    });
  }

  try {
    // Verify captcha first
    const isCaptchaValid = await verifyCaptcha(captchaToken);
    if (!isCaptchaValid) {
      return res.json({
        success: false,
        message: "Captcha verification failed. Please try again.",
      });
    }

    const user = await userModel.findOne({ email });

    if (!user) {
      return res.json({
        success: false,
        message: "User not found",
      });
    }

    // Check if account is locked
    if (user.lockUntil && user.lockUntil > Date.now()) {
      const remainingTime = Math.ceil((user.lockUntil - Date.now()) / 1000 / 60);
      await createLoginLog(user._id, 'failed_login', 'failure', ipAddress, 'Account locked');
      return res.json({
        success: false,
        message: `Account is locked. Try again in ${remainingTime} minutes`,
      });
    }

    // Check if password has expired
    if (isPasswordExpired(user.lastPasswordChange)) {
      await createLoginLog(user._id, 'failed_login', 'failure', ipAddress, 'Password expired');
      return res.json({
        success: false,
        message: "Password has expired. Please change your password.",
        requiresPasswordChange: true
      });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    
    if (!isValidPassword) {
      // Increment login attempts
      user.loginAttempts += 1;
      
      if (user.loginAttempts >= 5) {
        // Calculate lock duration based on previous locks
        let lockDuration = user.lockUntil && user.lockUntil > Date.now() - 24*60*60*1000 
          ? 60 * 60 * 1000  // 60 minutes if previously locked within 24 hours
          : 5 * 60 * 1000;  // 5 minutes for first lock

        user.lockUntil = Date.now() + lockDuration;
        user.loginAttempts = 0;
        
        await user.save();
        await createLoginLog(user._id, 'failed_login', 'failure', ipAddress, 'Too many failed attempts');
        
        return res.json({
          success: false,
          message: `Too many failed attempts. Account locked for ${lockDuration/1000/60} minutes`,
        });
      }
      
      await user.save();
      await createLoginLog(user._id, 'failed_login', 'failure', ipAddress, 'Invalid password');
      
      return res.json({
        success: false,
        message: `Incorrect password. ${5 - user.loginAttempts} attempts remaining`,
      });
    }

    // Reset login attempts on successful login
    user.loginAttempts = 0;
    user.lockUntil = null;
    await user.save();

    // Log successful login
    await createLoginLog(user._id, 'login', 'success', ipAddress, 'Login successful');

    const token = await jwt.sign(
      { id: user._id, isAdmin: user.isAdmin },
      process.env.JWT_SECRET
    );

    res.json({
      success: true,
      message: "User logged in successfully!",
      token,
      userData: user,
    });
  } catch (error) {
    console.error('Login error:', error);
    res.json({
      success: false,
      message: "Internal server error",
    });
  }
};

// Add changePassword function
const changePassword = async (req, res) => {
  const { userId, currentPassword, newPassword } = req.body;

  try {
    const user = await userModel.findById(userId);
    if (!user) {
      return res.json({
        success: false,
        message: "User not found",
      });
    }

    // Verify current password
    const isValidPassword = await bcrypt.compare(currentPassword, user.password);
    if (!isValidPassword) {
      return res.json({
        success: false,
        message: "Current password is incorrect",
      });
    }

    // Check password strength
    if (!isStrongPassword(newPassword)) {
      return res.json({
        success: false,
        message: "Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters",
      });
    }

    // Check if password was used before
    const isReused = await user.isPasswordReused(newPassword);
    if (isReused) {
      return res.json({
        success: false,
        message: "Cannot reuse any of your last 5 passwords",
      });
    }

    // Hash and save new password
    const randomSalt = await bcrypt.genSalt();
    const hashPassword = await bcrypt.hash(newPassword, randomSalt);

    // Update password history (keep last 5)
    user.passwordHistory.push(hashPassword);
    if (user.passwordHistory.length > 5) {
      user.passwordHistory.shift();
    }

    user.password = hashPassword;
    user.lastPasswordChange = Date.now();
    await user.save();

    res.json({
      success: true,
      message: "Password changed successfully",
    });
  } catch (error) {
    console.log(error);
    res.json({
      success: false,
      message: "Internal server error",
    });
  }
};

// Add admin-only endpoints
const getAllUsers = async (req, res) => {
  try {
    const users = await userModel.find({}, '-password');
    res.json({
      success: true,
      users
    });
  } catch (error) {
    res.json({
      success: false,
      message: "Error fetching users"
    });
  }
};

const updateUserRole = async (req, res) => {
  const { userId, newRole } = req.body;

  try {
    const user = await userModel.findById(userId);
    if (!user) {
      return res.json({
        success: false,
        message: "User not found"
      });
    }

    user.role = newRole;
    user.permissions = ROLE_PERMISSIONS[newRole] || [];
    await user.save();

    res.json({
      success: true,
      message: "User role updated successfully"
    });
  } catch (error) {
    res.json({
      success: false,
      message: "Error updating user role"
    });
  }
};

// Logout endpoint
const logoutUser = async (req, res) => {
  try {
    const userId = req.user?.id;
    const ipAddress = req.ip || req.connection.remoteAddress;

    if (userId) {
      await createLoginLog(userId, 'logout', 'success', ipAddress, 'User logged out');
    }

    res.json({
      success: true,
      message: "Logged out successfully"
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.json({
      success: false,
      message: "Error during logout"
    });
  }
};

module.exports = {
  createUser,
  loginUser,
  logoutUser,
  changePassword,
  getAllUsers,
  updateUserRole
};
