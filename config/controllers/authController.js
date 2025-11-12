const jwt = require('jsonwebtoken');
const pool = require('../database');

// REGISTER - Create new user
exports.register = async (req, res) => {
  console.log('📝 Registration request received:', req.body);
  
  try {
    const { aadhaar_key, full_name, contact_number, email } = req.body;

    // Check if all fields are provided
    if (!aadhaar_key || !full_name || !contact_number || !email) {
      return res.status(400).json({
        success: false,
        message: '❌ All fields required: aadhaar_key, full_name, contact_number, email'
      });
    }

    const client = await pool.connect();
    try {
      // Check if aadhaar already exists
      const checkAadhaar = await client.query(
        'SELECT * FROM users WHERE aadhaar_key = $1',
        [aadhaar_key]
      );

      if (checkAadhaar.rows.length > 0) {
        return res.status(400).json({
          success: false,
          message: '❌ Aadhaar key already registered'
        });
      }

      // Check if contact number already exists
      const checkContact = await client.query(
        'SELECT * FROM users WHERE contact_number = $1',
        [contact_number]
      );

      if (checkContact.rows.length > 0) {
        return res.status(400).json({
          success: false,
          message: '❌ Contact number already registered'
        });
      }

      // Insert new user
      const result = await client.query(
        'INSERT INTO users (aadhaar_key, full_name, contact_number, email) VALUES ($1, $2, $3, $4) RETURNING *',
        [aadhaar_key, full_name, contact_number, email]
      );

      const newUser = result.rows[0];

      // Create token
      const token = jwt.sign(
        { 
          userId: newUser.user_id, 
          email: newUser.email 
        },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );

      console.log('✅ User registered successfully:', newUser.user_id);

      res.status(201).json({
        success: true,
        message: '✅ Registration successful!',
        token,
        user: {
          user_id: newUser.user_id,
          full_name: newUser.full_name,
          contact_number: newUser.contact_number,
          email: newUser.email
        }
      });
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('❌ Registration error:', error);
    res.status(500).json({
      success: false,
      message: '❌ Server error: ' + error.message
    });
  }
};

// LOGIN - Authenticate user
exports.login = async (req, res) => {
  console.log('🔐 Login request received:', req.body);
  
  try {
    const { aadhaar_key, contact_number } = req.body;

    // Check if fields are provided
    if (!aadhaar_key || !contact_number) {
      return res.status(400).json({
        success: false,
        message: '❌ Aadhaar key and contact number required'
      });
    }

    const client = await pool.connect();
    try {
      // Find user
      const result = await client.query(
        'SELECT * FROM users WHERE aadhaar_key = $1 AND contact_number = $2',
        [aadhaar_key, contact_number]
      );

      if (result.rows.length === 0) {
        return res.status(401).json({
          success: false,
          message: '❌ Invalid credentials'
        });
      }

      const user = result.rows[0];

      // Create token
      const token = jwt.sign(
        { 
          userId: user.user_id, 
          email: user.email 
        },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );

      // Log login
      await client.query(
        'INSERT INTO audit_logs (user_id, action_type, details) VALUES ($1, $2, $3)',
        [user.user_id, 'LOGIN', JSON.stringify({ timestamp: new Date() })]
      );

      console.log('✅ Login successful:', user.user_id);

      res.json({
        success: true,
        message: '✅ Login successful!',
        token,
        user: {
          user_id: user.user_id,
          full_name: user.full_name,
          contact_number: user.contact_number,
          email: user.email
        }
      });
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({
      success: false,
      message: '❌ Server error: ' + error.message
    });
  }
};

// LOGOUT - Log user activity
exports.logout = async (req, res) => {
  console.log('👋 Logout request received');
  
  try {
    const userId = req.user.userId;

    const client = await pool.connect();
    try {
      // Log logout
      await client.query(
        'INSERT INTO audit_logs (user_id, action_type, details) VALUES ($1, $2, $3)',
        [userId, 'LOGOUT', JSON.stringify({ timestamp: new Date() })]
      );

      console.log('✅ Logout successful:', userId);

      res.json({
        success: true,
        message: '✅ Logged out successfully!'
      });
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('❌ Logout error:', error);
    res.status(500).json({
      success: false,
      message: '❌ Server error: ' + error.message
    });
  }
};

// GET ME - Get current user info
exports.getMe = async (req, res) => {
  console.log('👤 Get me request received');
  
  try {
    const userId = req.user.userId;

    const client = await pool.connect();
    try {
      const result = await client.query(
        'SELECT user_id, full_name, contact_number, email FROM users WHERE user_id = $1',
        [userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: '❌ User not found'
        });
      }

      console.log('✅ User data fetched:', userId);

      res.json({
        success: true,
        user: result.rows[0]
      });
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('❌ Get me error:', error);
    res.status(500).json({
      success: false,
      message: '❌ Server error: ' + error.message
    });
  }
};

// VERIFY AADHAAR - Placeholder for verification
exports.verifyAadhaar = async (req, res) => {
  console.log('🔍 Aadhaar verification request received');
  
  try {
    const { aadhaar_number } = req.body;

    if (!aadhaar_number) {
      return res.status(400).json({
        success: false,
        message: '❌ Aadhaar number required'
      });
    }

    // In production, call real Aadhaar API here
    
    res.json({
      success: true,
      message: '✅ Aadhaar verified successfully!',
      verified: true,
      timestamp: new Date()
    });
  } catch (error) {
    console.error('❌ Aadhaar verification error:', error);
    res.status(500).json({
      success: false,
      message: '❌ Server error: ' + error.message
    });
  }
};