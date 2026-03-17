// netlify/functions/auth.js
const { getPool, ok, err, headers, JWT_SECRET, verifyToken } = require('./db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers, body: '' };
  const pool = getPool();
  const path = event.path.replace('/.netlify/functions/auth', '').replace('/api/auth', '');
  const body = event.body ? JSON.parse(event.body) : {};

  if (event.httpMethod === 'POST' && path === '/signup') {
    try {
      const { name, phone, password, school_name, class_name } = body;
      if (!name || !phone || !password || !school_name || !class_name)
        return err('सभी fields भरें');
      const school = await pool.query('SELECT id FROM schools WHERE name=$1', [school_name]);
      if (!school.rows.length) return err('School नहीं मिली');
      const cls = await pool.query('SELECT id FROM classes WHERE school_id=$1 AND name=$2', [school.rows[0].id, class_name]);
      if (!cls.rows.length) return err('Class नहीं मिली');
      const exists = await pool.query('SELECT id FROM users WHERE phone=$1', [phone]);
      if (exists.rows.length) return err('Phone already registered है');
      const hash = await bcrypt.hash(password, 10);
      const user = await pool.query(
        'INSERT INTO users(name,phone,password_hash,school_id,class_id,status) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,name,phone,status',
        [name, phone, hash, school.rows[0].id, cls.rows[0].id, 'pending']
      );
      const token = jwt.sign({ id: user.rows[0].id, phone }, JWT_SECRET, { expiresIn: '30d' });
      return ok({ user: { ...user.rows[0], school_name, class_name }, token });
    } catch (e) { console.error(e); return err('Server error', 500); }
  }

  if (event.httpMethod === 'POST' && path === '/login') {
    try {
      const { phone, password } = body;
      const result = await pool.query(
        `SELECT u.*,s.name as school_name,c.name as class_name
         FROM users u
         LEFT JOIN schools s ON u.school_id=s.id
         LEFT JOIN classes c ON u.class_id=c.id
         WHERE u.phone=$1`, [phone]
      );
      if (!result.rows.length) return err('Phone या Password गलत है');
      const user = result.rows[0];
      const match = await bcrypt.compare(password, user.password_hash);
      if (!match) return err('Phone या Password गलत है');
      const token = jwt.sign({ id: user.id, phone }, JWT_SECRET, { expiresIn: '30d' });
      const { password_hash, ...safe } = user;
      return ok({ user: safe, token });
    } catch (e) { return err('Server error', 500); }
  }

  if (event.httpMethod === 'GET' && path === '/me') {
    const decoded = verifyToken(event);
    if (!decoded) return err('Unauthorized', 401);
    try {
      const result = await pool.query(
        `SELECT u.id,u.name,u.phone,u.status,s.name as school_name,c.name as class_name
         FROM users u
         LEFT JOIN schools s ON u.school_id=s.id
         LEFT JOIN classes c ON u.class_id=c.id
         WHERE u.id=$1`, [decoded.id]
      );
      if (!result.rows.length) return err('User नहीं मिला', 404);
      return ok(result.rows[0]);
    } catch (e) { return err('Server error', 500); }
  }

  if (event.httpMethod === 'PUT' && path === '/me') {
    const decoded = verifyToken(event);
    if (!decoded) return err('Unauthorized', 401);
    try {
      const { name, school_name, class_name } = body;
      const cur = await pool.query('SELECT school_id,class_id FROM users WHERE id=$1', [decoded.id]);
      if (!cur.rows.length) return err('User नहीं मिला', 404);
      const school = await pool.query('SELECT id FROM schools WHERE name=$1', [school_name]);
      if (!school.rows.length) return err('School नहीं मिली');
      const cls = await pool.query('SELECT id FROM classes WHERE school_id=$1 AND name=$2', [school.rows[0].id, class_name]);
      if (!cls.rows.length) return err('Class नहीं मिली');
      const changed = cur.rows[0].school_id !== school.rows[0].id || cur.rows[0].class_id !== cls.rows[0].id;
      const newStatus = changed ? 'pending' : undefined;
      if (newStatus)
        await pool.query('UPDATE users SET name=$1,school_id=$2,class_id=$3,status=$4 WHERE id=$5', [name, school.rows[0].id, cls.rows[0].id, newStatus, decoded.id]);
      else
        await pool.query('UPDATE users SET name=$1,school_id=$2,class_id=$3 WHERE id=$4', [name, school.rows[0].id, cls.rows[0].id, decoded.id]);
      const updated = await pool.query(
        `SELECT u.id,u.name,u.phone,u.status,s.name as school_name,c.name as class_name
         FROM users u LEFT JOIN schools s ON u.school_id=s.id LEFT JOIN classes c ON u.class_id=c.id
         WHERE u.id=$1`, [decoded.id]
      );
      return ok({ user: updated.rows[0], reapprovalNeeded: !!newStatus });
    } catch (e) { return err('Server error', 500); }
  }

  return err('Not found', 404);
};
