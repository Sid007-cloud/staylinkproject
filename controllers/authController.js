const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const pool = require('../config/database');
const crypto = require('crypto');

// Detect which ID column the users table has: 'id' or 'user_id'
let cachedUserIdColumn = null;
async function getUserIdColumn(client) {
  if (cachedUserIdColumn) return cachedUserIdColumn;
  const res = await client.query(
    `SELECT column_name FROM information_schema.columns WHERE table_name = 'users' AND column_name IN ('id','user_id')`
  );
  const col = res.rows?.[0]?.column_name || 'user_id';
  cachedUserIdColumn = col;
  return col;
}

// Build a safe created_at expression if the column exists
async function getCreatedAtExpr(client) {
  const res = await client.query(
    `SELECT column_name FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'created_at'`
  );
  return res.rows.length ? 'created_at' : 'NOW()';
}

// Build a safe name expression depending on available columns
async function getNameExpr(client) {
  const res = await client.query(
    `SELECT column_name FROM information_schema.columns WHERE table_name = 'users' AND column_name IN ('full_name','name')`
  );
  const cols = new Set(res.rows.map(r => r.column_name));
  if (cols.has('full_name') && cols.has('name')) return 'COALESCE(full_name, name)';
  if (cols.has('full_name')) return 'full_name';
  if (cols.has('name')) return 'name';
  return 'NULL';
}

const register = async (req, res) => {
  const { email, password, name } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email and password required' });
  }
  if (typeof password !== 'string' || password.length < 6) {
    return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
  }
  const normalizedEmail = String(email).toLowerCase();
  let client;
  try {
    client = await pool.connect();
    // Only check existence; don't select an id column that may not exist across schemas
    const existing = await client.query('SELECT 1 FROM users WHERE email = $1', [normalizedEmail]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ success: false, message: 'Email already registered' });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    const aadhaarKey = crypto.randomBytes(16).toString('hex');
    // Discover available columns in users table
    const colsRes = await client.query(
      `SELECT column_name, is_nullable, column_default
       FROM information_schema.columns
       WHERE table_name = 'users'`
    );
    const available = new Set(colsRes.rows.map(r => r.column_name));

    // Build insert columns dynamically to match schema
    const insertCols = [];
    const values = [];

    // Always include email if available
    if (available.has('email')) { insertCols.push('email'); values.push(normalizedEmail); }

    // Name mapping: prefer full_name, else name
    const nameValue = name || normalizedEmail.split('@')[0];
    if (available.has('full_name') && available.has('name')) {
      insertCols.push('full_name'); values.push(nameValue);
      insertCols.push('name'); values.push(nameValue);
    } else if (available.has('full_name')) {
      insertCols.push('full_name'); values.push(nameValue);
    } else if (available.has('name')) {
      insertCols.push('name'); values.push(nameValue);
    }

    // Password hash
    if (available.has('password_hash')) { insertCols.push('password_hash'); values.push(passwordHash); }

    // Aadhaar key
    if (available.has('aadhaar_key')) { insertCols.push('aadhaar_key'); values.push(aadhaarKey); }

    if (insertCols.length === 0) {
      throw new Error('No compatible columns found for users insert');
    }

    const placeholders = insertCols.map((_, i) => `$${i + 1}`).join(', ');
    const sql = `INSERT INTO users (${insertCols.join(', ')}) VALUES (${placeholders})`;
    await client.query(sql, values);
    return res.status(201).json({ success: true, message: 'Account created' });
  } catch (error) {
    // Handle duplicate key error if race or constraint triggers
    if (error && (error.code === '23505' || /duplicate key/i.test(error.message || ''))) {
      return res.status(409).json({ success: false, message: 'Email already registered' });
    }
    console.error('Register error:', error);
    const payload = { success: false, message: error?.message || 'Internal server error' };
    if (process.env.NODE_ENV !== 'production') {
      payload.code = error?.code;
      payload.detail = error?.detail;
    }
    return res.status(500).json(payload);
  } finally {
    if (client) client.release();
  }
};

const login = async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email and password required' });
  }
  const normalizedEmail = String(email).toLowerCase();
  let client;
  try {
    client = await pool.connect();
    const idCol = await getUserIdColumn(client);
    const nameExpr = await getNameExpr(client);
    const result = await client.query(`SELECT ${idCol} AS uid, email, ${nameExpr} AS name, password_hash FROM users WHERE email = $1`, [normalizedEmail]);
    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    const user = result.rows[0];
    const ok = user.password_hash ? await bcrypt.compare(password, user.password_hash) : false;
    if (!ok) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: user.uid }, process.env.JWT_SECRET, { expiresIn: '1h' });
    return res.json({ success: true, token });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  } finally {
    if (client) client.release();
  }
};

const getMe = async (req, res) => {
  if (!req.user?.userId) return res.status(401).json({ success: false, message: 'Unauthorized' });
  let client;
  try {
    client = await pool.connect();
    const idCol = await getUserIdColumn(client);
    const nameExpr = await getNameExpr(client);
    const createdExpr = await getCreatedAtExpr(client);
    const result = await client.query(`SELECT ${idCol} AS uid, email, ${nameExpr} AS name, ${createdExpr} AS created_at FROM users WHERE ${idCol} = $1`, [req.user.userId]);
    if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'User not found' });
    const u = result.rows[0];
    return res.json({ success: true, user: { id: u.uid, email: u.email, name: u.name, createdAt: u.created_at } });
  } catch (error) {
    console.error('GetMe error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  } finally {
    if (client) client.release();
  }
};

const logout = async (req, res) => {
  return res.json({ success: true, message: 'Logged out' });
};

const verifyAadhaar = async (req, res) => {
  return res.json({ success: true, message: 'Aadhaar verified (stub)' });
};

// Update profile display name
const updateProfile = async (req, res) => {
  if (!req.user?.userId) return res.status(401).json({ success: false, message: 'Unauthorized' });
  const { name } = req.body || {};
  if (!name || typeof name !== 'string') {
    return res.status(400).json({ success: false, message: 'Name is required' });
  }
  let client;
  try {
    client = await pool.connect();
    const idCol = await getUserIdColumn(client);
    const colsRes = await client.query(`SELECT column_name FROM information_schema.columns WHERE table_name = 'users' AND column_name IN ('full_name','name')`);
    const cols = new Set(colsRes.rows.map(r => r.column_name));

    if (!cols.size) {
      return res.status(400).json({ success: false, message: 'No updatable name column found' });
    }

    const sets = [];
    const vals = [];
    if (cols.has('full_name')) { sets.push('full_name = $' + (vals.length + 1)); vals.push(name); }
    if (cols.has('name')) { sets.push('name = $' + (vals.length + 1)); vals.push(name); }
    vals.push(req.user.userId);
    const sql = `UPDATE users SET ${sets.join(', ')} WHERE ${idCol} = $${vals.length}`;
    await client.query(sql, vals);

    return res.json({ success: true, message: 'Profile updated', name });
  } catch (error) {
    console.error('UpdateProfile error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  } finally {
    if (client) client.release();
  }
};

module.exports = { register, login, getMe, logout, verifyAadhaar, updateProfile };
