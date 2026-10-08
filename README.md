# ShopEasy – Full-Stack E-Commerce App

Node.js + Express REST API, PostgreSQL, JWT auth with Admin/User roles, vanilla JS frontend.

## Run locally
1. Install Node.js and PostgreSQL. Create a database: `CREATE DATABASE shop;`
2. Copy `.env.example` to `.env` and set `DATABASE_URL` (your Postgres password) and `JWT_SECRET`.
3. `npm install`
4. `npm start` → open http://localhost:3000

Tables, a sample catalog and the admin account (from `.env`) are created automatically on first start.

## API
| Method | Route | Access |
|---|---|---|
| POST | /api/auth/register, /api/auth/login | public |
| GET | /api/products | public |
| POST/PUT/DELETE | /api/products[/:id] | admin |
| POST | /api/orders | logged-in (price & stock checked server-side, in a transaction) |
| GET | /api/orders | user: own orders, admin: all |
| PATCH | /api/orders/:id/status | admin |
