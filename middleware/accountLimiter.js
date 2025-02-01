const accountLimiter = async (req, res, next) => {
  const { email } = req.body;
  
  if (!email) {
    return res.json({
      success: false,
      message: "Email is required"
    });
  }

  try {
    const user = await require('../models/userModels').findOne({ email });
    
    // If user doesn't exist, let the main login handler deal with it
    if (!user) {
      return next();
    }

    // Check if account is locked
    if (user.lockUntil && user.lockUntil > Date.now()) {
      const remainingTime = Math.ceil((user.lockUntil - Date.now()) / 1000 / 60);
      return res.json({
        success: false,
        message: `Account is locked. Try again in ${remainingTime} minutes`
      });
    }

    next();
  } catch (error) {
    console.error('Account limiter error:', error);
    next();
  }
};

module.exports = accountLimiter; 