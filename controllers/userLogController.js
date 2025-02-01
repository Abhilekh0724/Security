const UserLog = require('../models/userLogModel');

// Create a new log entry
const createLog = async (userId, action, ipAddress, userAgent, status, details = '') => {
  try {
    const log = new UserLog({
      userId,
      action,
      ipAddress,
      userAgent,
      status,
      details
    });
    await log.save();
    return true;
  } catch (error) {
    console.error('Error creating log:', error);
    return false;
  }
};

// Get all logs (admin only)
const getAllLogs = async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const startDate = req.query.startDate ? new Date(req.query.startDate) : null;
    const endDate = req.query.endDate ? new Date(req.query.endDate) : null;
    const action = req.query.action;
    const userId = req.query.userId;
    const status = req.query.status;

    let query = {};

    // Apply filters if provided
    if (startDate && endDate) {
      query.timestamp = { $gte: startDate, $lte: endDate };
    }
    if (action) query.action = action;
    if (userId) query.userId = userId;
    if (status) query.status = status;

    const total = await UserLog.countDocuments(query);
    const logs = await UserLog.find(query)
      .populate('userId', 'firstName lastName email')
      .sort({ timestamp: -1 })
      .skip((page - 1) * limit)
      .limit(limit);

    res.json({
      success: true,
      logs,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(total / limit),
        totalLogs: total,
        hasMore: page * limit < total
      }
    });
  } catch (error) {
    console.error('Error fetching logs:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching logs'
    });
  }
};

// Get logs for a specific user
const getUserLogs = async (req, res) => {
  try {
    const userId = req.params.userId;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;

    const total = await UserLog.countDocuments({ userId });
    const logs = await UserLog.find({ userId })
      .sort({ timestamp: -1 })
      .skip((page - 1) * limit)
      .limit(limit);

    res.json({
      success: true,
      logs,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(total / limit),
        totalLogs: total,
        hasMore: page * limit < total
      }
    });
  } catch (error) {
    console.error('Error fetching user logs:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching user logs'
    });
  }
};

// Get log statistics
const getLogStats = async (req, res) => {
  try {
    const stats = await UserLog.aggregate([
      {
        $group: {
          _id: {
            action: '$action',
            status: '$status',
            date: { $dateToString: { format: '%Y-%m-%d', date: '$timestamp' } }
          },
          count: { $sum: 1 }
        }
      },
      {
        $group: {
          _id: '$_id.date',
          actions: {
            $push: {
              action: '$_id.action',
              status: '$_id.status',
              count: '$count'
            }
          }
        }
      },
      { $sort: { _id: -1 } },
      { $limit: 30 } // Last 30 days
    ]);

    res.json({
      success: true,
      stats
    });
  } catch (error) {
    console.error('Error fetching log statistics:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching log statistics'
    });
  }
};

module.exports = {
  createLog,
  getAllLogs,
  getUserLogs,
  getLogStats
}; 