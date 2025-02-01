const Redis = require('ioredis');
const redis = new Redis(); // Configure with your Redis connection details if needed

const BLOCK_DURATION = 24 * 60 * 60; // 24 hours in seconds
const SUSPICIOUS_THRESHOLD = 10; // Number of failed attempts before IP blocking

const ipBlocker = async (req, res, next) => {
  const ip = req.ip;
  const key = `blocked:${ip}`;

  try {
    // Check if IP is blocked
    const isBlocked = await redis.get(key);
    if (isBlocked) {
      return res.status(403).json({
        success: false,
        message: 'Your IP has been blocked due to suspicious activity. Please try again after 24 hours.'
      });
    }

    // Get failed attempts count
    const failedAttempts = await redis.get(`failed:${ip}`) || 0;

    if (parseInt(failedAttempts) >= SUSPICIOUS_THRESHOLD) {
      // Block the IP
      await redis.setex(key, BLOCK_DURATION, 'blocked');
      // Reset failed attempts
      await redis.del(`failed:${ip}`);
      
      return res.status(403).json({
        success: false,
        message: 'Your IP has been blocked due to suspicious activity. Please try again after 24 hours.'
      });
    }

    // Add response interceptor to track failed attempts
    const originalSend = res.json;
    res.json = async function(body) {
      if (body && body.success === false) {
        await redis.incr(`failed:${ip}`);
        // Set expiry for failed attempts counter
        await redis.expire(`failed:${ip}`, BLOCK_DURATION);
      } else if (body && body.success === true) {
        // Reset failed attempts on successful request
        await redis.del(`failed:${ip}`);
      }
      originalSend.call(this, body);
    };

    next();
  } catch (error) {
    console.error('IP Blocker Error:', error);
    next();
  }
};

module.exports = ipBlocker; 