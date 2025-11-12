const jwt = require('jsonwebtoken');

// Check if user is logged in (has valid token)
const verifyToken = (req, res, next) => {
  try {
    // Get token from header
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
      return res.status(401).json({
        success: false,
        message: '❌ No token provided. Please login first.'
      });
    }

    // Extract token (format: "Bearer TOKEN")
    const token = authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: '❌ Invalid token format'
      });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Add user info to request
    req.user = decoded;
    
    // Continue to next function
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: '❌ Token expired. Please login again.'
      });
    }

    return res.status(401).json({
      success: false,
      message: '❌ Invalid token: ' + error.message
    });
  }
};

module.exports = { verifyToken };