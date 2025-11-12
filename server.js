const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

// Import database and routes
const pool = require('./config/database');
const authRoutes = require('./routes/authRoutes');
const { verifyToken } = require('./middleware/authMiddleware');

const app = express();

// ============ MIDDLEWARE ============
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Log all requests
app.use((req, res, next) => {
  console.log(`📨 ${req.method} ${req.path}`);
  next();
});

// ============ DB SCHEMA ENSURE ============
async function ensureSchema() {
  const client = await pool.connect();
  try {
    // Create users table if it doesn't exist
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        user_id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        name TEXT,
        password_hash TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // Ensure password_hash column exists (in case an older schema lacked it)
    await client.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_name = 'users' AND column_name = 'password_hash'
        ) THEN
          ALTER TABLE users ADD COLUMN password_hash TEXT;
        END IF;
      END$$;
    `);

    // Ensure name column exists
    await client.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_name = 'users' AND column_name = 'name'
        ) THEN
          ALTER TABLE users ADD COLUMN name TEXT;
        END IF;
      END$$;
    `);

    // Ensure unique index on email
    await client.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE c.relkind = 'i'
          AND c.relname = 'users_email_key'
        ) THEN
          CREATE UNIQUE INDEX users_email_key ON users (email);
        END IF;
      END$$;
    `);
  } catch (e) {
    console.error('Schema ensure error:', e.message);
  } finally {
    client.release();
  }
}

// ============ ROUTES ============

// Root helpers
app.get('/', (req, res) => {
  res.redirect('/api/health');
});

app.get('/api', (req, res) => {
  res.redirect('/api/health');
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: '✅ Server is running!',
    timestamp: new Date()
  });
});

// Authentication routes
app.use('/api/auth', authRoutes);

// Test routes (no authentication)
app.get('/api/test/users', async (req, res) => {
  try {
    const client = await pool.connect();
    try {
      const result = await client.query('SELECT * FROM users');
      res.json({
        success: true,
        count: result.rows.length,
        users: result.rows
      });
    } finally {
      client.release();
    }
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/test/hotels', async (req, res) => {
  try {
    const client = await pool.connect();
    try {
      const result = await client.query('SELECT * FROM hotels');
      res.json({
        success: true,
        count: result.rows.length,
        hotels: result.rows
      });
    } finally {
      client.release();
    }
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/test/rooms', async (req, res) => {
  try {
    const client = await pool.connect();
    try {
      const result = await client.query('SELECT * FROM rooms');
      res.json({
        success: true,
        count: result.rows.length,
        rooms: result.rows
      });
    } finally {
      client.release();
    }
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/test/bookings', async (req, res) => {
  try {
    const client = await pool.connect();
    try {
      const result = await client.query('SELECT * FROM bookings');
      res.json({
        success: true,
        count: result.rows.length,
        bookings: result.rows
      });
    } finally {
      client.release();
    }
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Hotels routes
app.get('/api/hotels', async (req, res) => {
  try {
    const client = await pool.connect();
    try {
      const result = await client.query('SELECT * FROM hotels WHERE is_active = true');
      res.json({ success: true, hotels: result.rows });
    } finally {
      client.release();
    }
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Rooms routes
app.get('/api/rooms', async (req, res) => {
  try {
    const client = await pool.connect();
    try {
      const result = await client.query('SELECT * FROM rooms');
      res.json({ success: true, rooms: result.rows });
    } finally {
      client.release();
    }
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Offers routes
app.get('/api/offers', async (req, res) => {
  try {
    const client = await pool.connect();
    try {
      const result = await client.query('SELECT * FROM offers WHERE valid_from <= CURRENT_DATE AND valid_to >= CURRENT_DATE');
      res.json({ success: true, offers: result.rows });
    } finally {
      client.release();
    }
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Room verification (QR Code)
app.post('/api/room/verify-access', async (req, res) => {
  const { user_id, qr_code_id } = req.body;

  if (!user_id || !qr_code_id) {
    return res.status(400).json({
      success: false,
      message: 'User ID and QR Code ID required'
    });
  }

  let client;
  try {
    client = await pool.connect();

    const result = await client.query(
      `SELECT b.booking_id, b.status, r.qr_code_id, bt.token_id, bt.digital_signature
       FROM bookings b
       JOIN rooms r ON b.room_id = r.room_id
       JOIN booking_tokens bt ON b.booking_id = bt.booking_id
       WHERE b.user_id = $1 AND r.qr_code_id = $2 AND bt.is_valid = true
       AND b.check_in_time <= NOW() AND NOW() <= b.check_out_time`,
      [user_id, qr_code_id]
    );

    if (result.rows.length === 0) {
      return res.status(403).json({
        success: false,
        message: 'Verification failed. Invalid or expired booking.'
      });
    }

    const booking = result.rows[0];
    res.json({
      success: true,
      message: 'Access granted!',
      booking_token: booking.token_id,
      digital_signature: booking.digital_signature
    });
  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({ success: false, message: error.message });
  } finally {
    if (client) client.release();
  }
});

// ============ ERROR HANDLING ============
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Route not found'
  });
});

app.use((error, req, res, next) => {
  console.error('❌ Server error:', error);
  res.status(500).json({
    success: false,
    error: 'Internal server error'
  });
});

// ============ START SERVER ============
if (require.main === module) {
  const PORT = process.env.PORT || 5000;
  ensureSchema().finally(() => {
    app.listen(PORT, () => {
      console.log('');
      console.log('🚀 ================================');
      console.log(`✅ Server running on port ${PORT}`);
      console.log(`🔗 Health: http://localhost:${PORT}/api/health`);
      console.log(`🔐 Auth: http://localhost:${PORT}/api/auth`);
      console.log('🚀 ================================');
      console.log('');
    });
  });
}

module.exports = app;