'use strict';

/**
 * База данных стенда (SQLite через better-sqlite3).
 *
 * Здесь НЕТ уязвимостей — это просто хранилище и сид-данные.
 * Уязвимые запросы специально написаны в src/server.js, чтобы было
 * видно разницу между небезопасной конкатенацией строк и
 * параметризованными запросами.
 */

const path = require('path');
const Database = require('better-sqlite3');

// Файл БД рядом с исходниками. В тестах используется :memory:.
const DB_PATH = process.env.DB_PATH || path.join(__dirname, '..', 'data.db');

function createDb(location = DB_PATH) {
  const db = new Database(location);
  db.pragma('journal_mode = WAL');
  init(db);
  return db;
}

function init(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id       INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role     TEXT NOT NULL DEFAULT 'user'
    );

    CREATE TABLE IF NOT EXISTS comments (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      author    TEXT NOT NULL,
      body      TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  seedIfEmpty(db);
}

function seedIfEmpty(db) {
  const userCount = db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
  if (userCount === 0) {
    const insert = db.prepare(
      'INSERT INTO users (username, password, role) VALUES (?, ?, ?)'
    );
    // Учебные пароли в открытом виде — так проще показать SQL-инъекцию
    // в форме логина. В реальном приложении пароли только в виде хэшей.
    insert.run('admin', 'S3cretAdminPass!', 'admin');
    insert.run('alice', 'alice123', 'user');
    insert.run('bob', 'bob123', 'user');
  }

  const commentCount = db.prepare('SELECT COUNT(*) AS n FROM comments').get().n;
  if (commentCount === 0) {
    const insert = db.prepare(
      'INSERT INTO comments (author, body) VALUES (?, ?)'
    );
    insert.run('alice', 'Привет! Это учебная доска сообщений.');
    insert.run('bob', 'Пишите что угодно — всё хранится в SQLite.');
    insert.run('admin', 'Найдите уязвимости и почините их :)');
  }
}

module.exports = { createDb, DB_PATH };

// `npm run seed` — пересоздать боевую БД со стартовыми данными.
if (require.main === module && process.argv.includes('--seed')) {
  const fs = require('fs');
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(DB_PATH + suffix); } catch { /* файла нет — ок */ }
  }
  createDb();
  console.log('БД создана и заполнена:', DB_PATH);
}
