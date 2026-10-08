require('dotenv').config();
const express = require('express'), { Pool } = require('pg'), bcrypt = require('bcryptjs'),
  jwt = require('jsonwebtoken'), path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const SECRET = process.env.JWT_SECRET || 'change-me';
const STATUSES = ['pending', 'paid', 'shipped', 'delivered', 'cancelled'];

const wrap = fn => (req, res) => fn(req, res).catch(e => { console.error(e); res.status(500).json({ error: 'Server error' }); });
const sign = u => jwt.sign({ id: u.id, role: u.role, name: u.name }, SECRET, { expiresIn: '7d' });
function auth(req, res, next) {
  try { req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET); next(); }
  catch { res.status(401).json({ error: 'Please log in' }); }
}
const admin = (req, res, next) => req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Admin only' });

/* ---------- AUTH ---------- */
app.post('/api/auth/register', wrap(async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password || password.length < 6) return res.status(400).json({ error: 'Name, email and a 6+ char password required' });
  const hash = await bcrypt.hash(password, 10);
  try {
    const { rows } = await pool.query('INSERT INTO users(name,email,password_hash) VALUES($1,$2,$3) RETURNING id,name,role', [name, email.toLowerCase(), hash]);
    res.json({ token: sign(rows[0]), user: rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Email already registered' });
    throw e;
  }
}));
app.post('/api/auth/login', wrap(async (req, res) => {
  const { email = '', password = '' } = req.body;
  const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [email.toLowerCase()]);
  if (!rows[0] || !(await bcrypt.compare(password, rows[0].password_hash))) return res.status(401).json({ error: 'Invalid email or password' });
  const u = { id: rows[0].id, name: rows[0].name, role: rows[0].role };
  res.json({ token: sign(u), user: u });
}));

/* ---------- PRODUCTS ---------- */
const cleanProduct = b => {
  const price = Number(b.price), stock = parseInt(b.stock, 10);
  if (!b.name || !(price >= 0) || !(stock >= 0)) return null;
  return [b.name, b.description || '', price, stock, b.image_url || ''];
};
app.get('/api/products', wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM products ORDER BY id DESC');
  res.json(rows.map(p => ({ ...p, price: Number(p.price) })));
}));
app.post('/api/products', auth, admin, wrap(async (req, res) => {
  const v = cleanProduct(req.body); if (!v) return res.status(400).json({ error: 'Invalid product data' });
  const { rows } = await pool.query('INSERT INTO products(name,description,price,stock,image_url) VALUES($1,$2,$3,$4,$5) RETURNING *', v);
  res.json(rows[0]);
}));
app.put('/api/products/:id', auth, admin, wrap(async (req, res) => {
  const v = cleanProduct(req.body); if (!v) return res.status(400).json({ error: 'Invalid product data' });
  const { rows } = await pool.query('UPDATE products SET name=$1,description=$2,price=$3,stock=$4,image_url=$5 WHERE id=$6 RETURNING *', [...v, req.params.id]);
  rows[0] ? res.json(rows[0]) : res.status(404).json({ error: 'Not found' });
}));
app.delete('/api/products/:id', auth, admin, wrap(async (req, res) => {
  await pool.query('DELETE FROM products WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
}));

/* ---------- ORDERS ---------- */
app.post('/api/orders', auth, wrap(async (req, res) => {
  const { items, address } = req.body;
  if (!Array.isArray(items) || !items.length || !address) return res.status(400).json({ error: 'Cart and address required' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    let total = 0; const lines = [];
    for (const it of items) {
      const qty = parseInt(it.qty, 10);
      if (!(qty > 0)) throw Object.assign(new Error('Invalid quantity'), { status: 400 });
      const { rows } = await client.query('SELECT * FROM products WHERE id=$1 FOR UPDATE', [it.id]);
      const p = rows[0];
      if (!p) throw Object.assign(new Error('Product no longer exists'), { status: 400 });
      if (p.stock < qty) throw Object.assign(new Error(`Only ${p.stock} left of ${p.name}`), { status: 400 });
      await client.query('UPDATE products SET stock=stock-$1 WHERE id=$2', [qty, p.id]);
      total += Number(p.price) * qty; lines.push([p.id, p.name, p.price, qty]); // price always from DB
    }
    const o = await client.query('INSERT INTO orders(user_id,total,address) VALUES($1,$2,$3) RETURNING id', [req.user.id, total.toFixed(2), address]);
    for (const l of lines) await client.query('INSERT INTO order_items(order_id,product_id,name,price,qty) VALUES($1,$2,$3,$4,$5)', [o.rows[0].id, ...l]);
    await client.query('COMMIT');
    res.json({ id: o.rows[0].id, total });
  } catch (e) {
    await client.query('ROLLBACK');
    if (e.status) return res.status(e.status).json({ error: e.message });
    throw e;
  } finally { client.release(); }
}));
app.get('/api/orders', auth, wrap(async (req, res) => {
  const isAdmin = req.user.role === 'admin';
  const { rows } = await pool.query(
    `SELECT o.id,o.total,o.status,o.address,o.created_at,u.name AS customer,
       COALESCE(json_agg(json_build_object('name',i.name,'price',i.price,'qty',i.qty)) FILTER (WHERE i.id IS NOT NULL),'[]') AS items
     FROM orders o JOIN users u ON u.id=o.user_id LEFT JOIN order_items i ON i.order_id=o.id
     ${isAdmin ? '' : 'WHERE o.user_id=$1'} GROUP BY o.id,u.name ORDER BY o.id DESC`, isAdmin ? [] : [req.user.id]);
  res.json(rows.map(r => ({ ...r, total: Number(r.total) })));
}));
app.patch('/api/orders/:id/status', auth, admin, wrap(async (req, res) => {
  if (!STATUSES.includes(req.body.status)) return res.status(400).json({ error: 'Invalid status' });
  await pool.query('UPDATE orders SET status=$1 WHERE id=$2', [req.body.status, req.params.id]);
  res.json({ ok: true });
}));

/* ---------- DB SETUP ---------- */
async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'user');
    CREATE TABLE IF NOT EXISTS products(id SERIAL PRIMARY KEY,name TEXT NOT NULL,description TEXT,price NUMERIC(10,2) NOT NULL,stock INT NOT NULL DEFAULT 0,image_url TEXT);
    CREATE TABLE IF NOT EXISTS orders(id SERIAL PRIMARY KEY,user_id INT REFERENCES users(id),total NUMERIC(10,2) NOT NULL,status TEXT NOT NULL DEFAULT 'pending',address TEXT,created_at TIMESTAMPTZ DEFAULT now());
    CREATE TABLE IF NOT EXISTS order_items(id SERIAL PRIMARY KEY,order_id INT REFERENCES orders(id) ON DELETE CASCADE,product_id INT,name TEXT,price NUMERIC(10,2),qty INT);`);
  const email = (process.env.ADMIN_EMAIL || 'admin@shop.com').toLowerCase();
  if (!(await pool.query('SELECT 1 FROM users WHERE email=$1', [email])).rowCount)
    await pool.query("INSERT INTO users(name,email,password_hash,role) VALUES('Admin',$1,$2,'admin')", [email, await bcrypt.hash(process.env.ADMIN_PASSWORD || 'admin123', 10)]);
  if (!(await pool.query('SELECT 1 FROM products LIMIT 1')).rowCount)
    await pool.query(`INSERT INTO products(name,description,price,stock) VALUES
      ('Wireless Headphones','Over-ear, 30h battery',2499,25),('Smart Watch','Fitness and sleep tracking',3999,15),
      ('Backpack','Water-resistant, 25L',1299,40),('Desk Lamp','Dimmable LED',899,30)`);
}
init().then(() => app.listen(process.env.PORT || 3000, () => console.log('Shop running on http://localhost:' + (process.env.PORT || 3000))))
  .catch(e => { console.error('DB init failed:', e.message); process.exit(1); });
