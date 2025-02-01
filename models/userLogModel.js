const mongoose = require('mongoose');

const userLogSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  action: {
    type: String,
    required: true,
    enum: ['login', 'logout', 'failed_login', 'password_change', 'profile_update']
  },
  ipAddress: {
    type: String,
    required: true
  },
  userAgent: {
    type: String,
    required: true
  },
  status: {
    type: String,
    enum: ['success', 'failure'],
    required: true
  },
  details: {
    type: String
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
});

// Index for better query performance
userLogSchema.index({ userId: 1, timestamp: -1 });
userLogSchema.index({ action: 1, timestamp: -1 });

module.exports = mongoose.model('UserLog', userLogSchema); 