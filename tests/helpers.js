'use strict';

const http = require('http');
const Database = require('better-sqlite3');
const { createApp } = require('../src/server');

/** Поднять приложение на случайном порту с БД в памяти. */
async function startServer() {
  // :memory: — свежая БД на каждый прогон тестов, боевую не трогаем.
  const db = new Database(':memory:');
  require('../src/db'); // гарантируем, что модуль загружен
  // Переиспользуем схему и сид из db.js через прямой вызов init-логики:
  initSchema(db);

  const app = createApp(db);
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, resolve));
  const { port } = server.address();
  return { server, db, base: `http://127.0.0.1:${port}` };
}

// Повтор схемы/сида (db.js не экспортирует init для :memory:, поэтому
// делаем то же самое здесь — так тесты не зависят от файла data.db).
function initSchema(db) {
  db.exec(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user'
    );
    CREATE TABLE comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      author TEXT NOT NULL,
      body TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
  const u = db.prepare('INSERT INTO users (username,password,role) VALUES (?,?,?)');
  u.run('admin', 'S3cretAdminPass!', 'admin');
  u.run('alice', 'alice123', 'user');
  const c = db.prepare('INSERT INTO comments (author,body) VALUES (?,?)');
  c.run('alice', 'Привет!');
}

/** Минимальный клиент с «банкой кук»: хранит sid между запросами. */
function makeClient(base) {
  let cookie = '';
  async function req(path, { method = 'GET', body, headers = {} } = {}) {
    const h = { ...headers };
    if (cookie) h.cookie = cookie;
    let payload;
    if (body && typeof body === 'object') {
      h['content-type'] = 'application/x-www-form-urlencoded';
      payload = new URLSearchParams(body).toString();
    }
    const res = await fetch(base + path, {
      method,
      headers: h,
      body: payload,
      redirect: 'manual',
    });
    const setCookies = res.headers.getSetCookie();
    for (const sc of setCookies) {
      const pair = sc.split(';')[0];
      if (pair.startsWith('sid=')) cookie = pair;
    }
    return { res, setCookies, text: () => res.text() };
  }
  return { req };
}

module.exports = { startServer, makeClient };
