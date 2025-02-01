const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: true,
  },
  lastName: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  isAdmin: {
    type: Boolean,
    default: false,
  },
  loginAttempts: {
    type: Number,
    required: true,
    default: 0
  },
  lockUntil: {
    type: Date,
    default: null
  },
  passwordHistory: {
    type: [String],
    default: [],
    maxLength: 5  // Store last 5 passwords
  },
  lastPasswordChange: {
    type: Date,
    default: Date.now
  },
  role: {
    type: String,
    enum: ['admin', 'user', 'vendor'],
    default: 'user'
  },
  permissions: [{
    type: String
  }]
});

// Add a method to check password reuse
userSchema.methods.isPasswordReused = async function(password) {
  for (const oldPassword of this.passwordHistory) {
    if (await bcrypt.compare(password, oldPassword)) {
      return true;
    }
  }
  return false;
};

// Add method to check permissions
userSchema.methods.hasPermission = function(permission) {
  return this.permissions.includes(permission);
};

// Add method to check role
userSchema.methods.hasRole = function(role) {
  return this.role === role;
};

const User = mongoose.model('User', userSchema);
module.exports = User;
