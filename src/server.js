const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'zenmoney_secret_jwt_key_2026';

app.use(cors());
app.use(express.json());

// Token verification middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// --- AUTH ROUTES ---

// Signup
app.post('/api/auth/signup', async (req, res) => {
  const { email, password, display_name, username } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    // Insert into public.users
    const userRes = await db.query(
      'INSERT INTO public.users (email, password_hash) VALUES ($1, $2) RETURNING id, email',
      [email.toLowerCase(), hashedPassword]
    );
    const user = userRes.rows[0];

    // Create profile
    await db.query(
      'INSERT INTO public.profiles (id, display_name, username) VALUES ($1, $2, $3)',
      [user.id, display_name || email, username || null]
    );

    res.status(201).json({ user });
  } catch (err) {
    console.error("Signup error:", err);
    if (err.code === '23505') {
      return res.status(400).json({ message: 'Email or username already exists' });
    }
    res.status(500).json({ message: 'Internal server error during signup' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  try {
    const userRes = await db.query(
      'SELECT id, email, password_hash FROM public.users WHERE LOWER(email) = $1',
      [email.toLowerCase()]
    );
    if (userRes.rows.length === 0) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }
    const user = userRes.rows[0];

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    // Get user profile
    const profileRes = await db.query(
      'SELECT * FROM public.profiles WHERE id = $1',
      [user.id]
    );
    const profile = profileRes.rows[0] || {};

    const tokenUser = { id: user.id, email: user.email };
    const token = jwt.sign(tokenUser, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        ...profile
      }
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: 'Internal server error during login' });
  }
});

// Change password (authenticated)
app.put('/api/auth/change-password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  try {
    const userRes = await db.query(
      'SELECT password_hash FROM public.users WHERE id = $1',
      [req.user.id]
    );
    const user = userRes.rows[0];
    const isMatch = await bcrypt.compare(currentPassword, user.password_hash);
    if (!isMatch) {
      return res.status(400).json({ message: 'Incorrect current password' });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    await db.query(
      'UPDATE public.users SET password_hash = $1 WHERE id = $2',
      [hashedNewPassword, req.user.id]
    );

    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to update password' });
  }
});

// Reset password by email (unauthenticated helper)
app.put('/api/auth/reset-password', async (req, res) => {
  const { email, newPassword } = req.body;
  try {
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    const result = await db.query(
      'UPDATE public.users SET password_hash = $1 WHERE LOWER(email) = $2 RETURNING id',
      [hashedNewPassword, email.toLowerCase()]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ message: 'Password reset successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to reset password' });
  }
});

// Check if username is available
app.get('/api/auth/check-username', async (req, res) => {
  const { val } = req.query;
  if (!val) {
    return res.json({ available: false });
  }
  try {
    const result = await db.query(
      'SELECT 1 FROM public.profiles WHERE LOWER(username) = $1',
      [val.toLowerCase()]
    );
    res.json({ available: result.rows.length === 0 });
  } catch (err) {
    console.error(err);
    res.json({ available: false });
  }
});

// Check if email is available
app.get('/api/auth/check-email', async (req, res) => {
  const { val } = req.query;
  if (!val) {
    return res.json({ available: false });
  }
  try {
    const result = await db.query(
      'SELECT 1 FROM public.users WHERE LOWER(email) = $1',
      [val.toLowerCase()]
    );
    res.json({ available: result.rows.length === 0 });
  } catch (err) {
    console.error(err);
    res.json({ available: false });
  }
});

// --- PROFILE SPECIFIC ROUTES ---

app.get('/api/profile/:id', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT * FROM public.profiles WHERE id = $1',
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Profile not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error retrieving profile' });
  }
});

app.put('/api/profile/:id', authenticateToken, async (req, res) => {
  const { username, display_name, avatar_url, ui_mode, monthly_budget, report_timezone, reports_enabled } = req.body;
  try {
    const result = await db.query(
      `UPDATE public.profiles 
       SET username = COALESCE($1, username), 
           display_name = COALESCE($2, display_name), 
           avatar_url = COALESCE($3, avatar_url), 
           ui_mode = COALESCE($4, ui_mode), 
           monthly_budget = COALESCE($5, monthly_budget), 
           report_timezone = COALESCE($6, report_timezone), 
           reports_enabled = COALESCE($7, reports_enabled),
           updated_at = now()
       WHERE id = $8 RETURNING *`,
      [username, display_name, avatar_url, ui_mode, monthly_budget, report_timezone, reports_enabled, req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Profile not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error updating profile' });
  }
});

// --- DUMMY EDGE FUNCTIONS ROUTE ---
app.post('/api/functions/:name', authenticateToken, async (req, res) => {
  res.json({ success: true, message: `Function ${req.params.name} simulated successfully` });
});

// --- GENERIC TABLE ROUTES ---

// GET /api/:table
app.get('/api/:table', authenticateToken, async (req, res) => {
  const { table } = req.params;
  const { userId, limit } = req.query;

  // Protect against SQL injection by checking allowed tables
  const allowedTables = ['profiles', 'groups', 'group_members', 'transactions', 'subscriptions', 'report_threads', 'report_runs'];
  if (!allowedTables.includes(table)) {
    return res.status(400).json({ message: 'Invalid table name' });
  }

  try {
    let queryText = `SELECT * FROM public.${table}`;
    const queryParams = [];

    // Filter by user_id or group membership
    if (userId) {
      if (table === 'profiles') {
        queryText += ' WHERE id = $1';
      } else {
        queryText += ' WHERE user_id = $1';
      }
      queryParams.push(userId);
    }

    // Default sorting to make responses consistent
    if (table === 'transactions' || table === 'subscriptions' || table === 'groups') {
      queryText += ' ORDER BY created_at DESC';
    }

    if (limit) {
      queryText += ` LIMIT $${queryParams.length + 1}`;
      queryParams.push(parseInt(limit));
    }

    const result = await db.query(queryText, queryParams);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: `Error retrieving data from ${table}` });
  }
});

// POST /api/:table
app.post('/api/:table', authenticateToken, async (req, res) => {
  const { table } = req.params;
  const allowedTables = ['profiles', 'groups', 'group_members', 'transactions', 'subscriptions', 'report_threads', 'report_runs'];
  if (!allowedTables.includes(table)) {
    return res.status(400).json({ message: 'Invalid table name' });
  }

  // Inject req.user.id into body if user_id field is expected and missing
  const payload = { ...req.body };
  if (table !== 'groups' && table !== 'profiles' && !payload.user_id) {
    payload.user_id = req.user.id;
  }
  if (table === 'groups' && !payload.created_by) {
    payload.created_by = req.user.id;
  }

  try {
    const keys = Object.keys(payload);
    const values = Object.values(payload);
    const placeholders = keys.map((_, i) => `$${i + 1}`).join(', ');
    const columns = keys.join(', ');

    const queryText = `INSERT INTO public.${table} (${columns}) VALUES (${placeholders}) RETURNING *`;
    const result = await db.query(queryText, values);

    // If a group was created, automatically add the creator as a member of that group
    if (table === 'groups') {
      const group = result.rows[0];
      await db.query(
        'INSERT INTO public.group_members (group_id, user_id, balance) VALUES ($1, $2, $3)',
        [group.id, req.user.id, 0]
      );
    }

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: `Error inserting into ${table}` });
  }
});

// PUT /api/:table/:id or PUT /api/:table
app.put(['/api/:table', '/api/:table/:id'], authenticateToken, async (req, res) => {
  const { table, id } = req.params;
  const allowedTables = ['profiles', 'groups', 'group_members', 'transactions', 'subscriptions', 'report_threads', 'report_runs'];
  if (!allowedTables.includes(table)) {
    return res.status(400).json({ message: 'Invalid table name' });
  }

  // Find update target ID (could be in URL params or body)
  const targetId = id || req.body.id;
  if (!targetId) {
    return res.status(400).json({ message: 'ID is required for updates' });
  }

  const payload = { ...req.body };
  delete payload.id; // Don't update the primary key

  try {
    const keys = Object.keys(payload);
    const values = Object.values(payload);

    const setClause = keys.map((key, i) => `${key} = $${i + 1}`).join(', ');
    const queryText = `UPDATE public.${table} SET ${setClause} WHERE id = $${keys.length + 1} RETURNING *`;
    
    const result = await db.query(queryText, [...values, targetId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Record not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: `Error updating ${table}` });
  }
});

// DELETE /api/:table/:id
app.delete('/api/:table/:id', authenticateToken, async (req, res) => {
  const { table, id } = req.params;
  const allowedTables = ['profiles', 'groups', 'group_members', 'transactions', 'subscriptions', 'report_threads', 'report_runs'];
  if (!allowedTables.includes(table)) {
    return res.status(400).json({ message: 'Invalid table name' });
  }

  try {
    const result = await db.query(`DELETE FROM public.${table} WHERE id = $1 RETURNING *`, [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Record not found' });
    }
    res.json({ message: 'Deleted successfully', record: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: `Error deleting from ${table}` });
  }
});

// Start server
db.initializeDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error("Failed to start server due to database initialization failure:", err);
    process.exit(1);
  });
