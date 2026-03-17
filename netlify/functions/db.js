// netlify/functions/db.js — Database connection helper
const { Pool } = require('pg');

let pool;
function getPool() {
  if (!pool) {
    pool = new Pool({
      connectionString: process.env.NETLIFY_DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      max: 3
    });
  }
  return pool;
}

const headers = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Content-Type': 'application/json'
};

function ok(data, status = 200) {
  return { statusCode: status, headers, body: JSON.stringify(data) };
}
function err(msg, status = 400) {
  return { statusCode: status, headers, body: JSON.stringify({ error: msg }) };
}

const JWT_SECRET = process.env.JWT_SECRET || 'eduportal_secret_2024';

function verifyToken(event) {
  const auth = event.headers.authorization || event.headers.Authorization || '';
  const token = auth.replace('Bearer ', '');
  if (!token) return null;
  try {
    const jwt = require('jsonwebtoken');
    return jwt.verify(token, JWT_SECRET);
  } catch { return null; }
}

module.exports = { getPool, ok, err, headers, JWT_SECRET, verifyToken };
