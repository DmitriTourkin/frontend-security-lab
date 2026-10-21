'use strict';

/**
 * Учебное приложение «DevBoard» — доска сообщений.
 *
 * ВНИМАНИЕ: приложение содержит НАМЕРЕННЫЕ уязвимости.
 * Запускать только локально. Никогда не выкладывать в интернет.
 *
 * Каждое уязвимое место помечено комментарием `VULN#N`.
 * Задача студента — найти их, воспроизвести атаку и починить.
 * Подсказки по исправлению: docs/TASKS.md.
 */

const crypto = require('crypto');
const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const { createDb } = require('./db');

function createApp(db = createDb()) {
  const app = express();

  app.use(express.urlencoded({ extended: false }));
  app.use(express.json());
  app.use(cookieParser());

  // Статика: страница профиля с клиентским JS (см. VULN#5 — DOM XSS).
  app.use('/static', express.static(path.join(__dirname, '..', 'public')));

  // --- Простейшие сессии в памяти: sid -> { username, role, csrf } ---
  const sessions = new Map();

  function currentUser(req) {
    const sid = req.cookies.sid;
    return sid ? sessions.get(sid) : undefined;
  }

  // ----------------------------------------------------------------------
  // VULN#6: Content-Security-Policy отсутствует.
  // После всех исправлений нужно добавить CSP так, чтобы встроенные
  // (inline) скрипты не исполнялись даже при оставленной XSS-уязвимости.
  // Делается здесь, одним middleware на все ответы.
  // ----------------------------------------------------------------------

  // ===================== Страницы =======================================

  app.get('/', (req, res) => {
    const user = currentUser(req);
    const q = typeof req.query.q === 'string' ? req.query.q : '';

    let comments;
    if (q) {
      // ------------------------------------------------------------------
      // VULN#1: SQL-инъекция в поиске. Значение q подставляется в текст
      // запроса конкатенацией. Пример: q = %' UNION SELECT ...
      // ------------------------------------------------------------------
      comments = db
        .prepare(`SELECT author, body, created_at FROM comments
                  WHERE body LIKE '%${q}%' ORDER BY id DESC`)
        .all();
    } else {
      comments = db
        .prepare('SELECT author, body, created_at FROM comments ORDER BY id DESC')
        .all();
    }

    res.send(renderBoard({ user, comments, q }));
  });

  app.post('/login', (req, res) => {
    const { username = '', password = '' } = req.body;

    // --------------------------------------------------------------------
    // VULN#2: SQL-инъекция в логине. Классический обход аутентификации:
    //   username = admin'--
    //   username = ' OR '1'='1
    // --------------------------------------------------------------------
    const row = db
      .prepare(`SELECT * FROM users
                WHERE username = '${username}' AND password = '${password}'`)
      .get();

    if (!row) {
      return res.status(401).send(renderLogin('Неверный логин или пароль'));
    }

    const sid = crypto.randomBytes(16).toString('hex');
    const csrf = crypto.randomBytes(16).toString('hex');
    sessions.set(sid, { username: row.username, role: row.role, csrf });

    // --------------------------------------------------------------------
    // VULN#3: небезопасные атрибуты cookie. Нет HttpOnly (куку видно из
    // document.cookie → её можно украсть через XSS) и нет SameSite
    // (куку шлёт браузер при межсайтовых запросах → работает CSRF).
    // --------------------------------------------------------------------
    res.cookie('sid', sid, { path: '/' });
    res.redirect('/');
  });

  app.post('/logout', (req, res) => {
    const sid = req.cookies.sid;
    if (sid) sessions.delete(sid);
    res.clearCookie('sid');
    res.redirect('/');
  });

  app.post('/comment', (req, res) => {
    const user = currentUser(req);
    if (!user) return res.status(401).send('Нужно войти');

    // --------------------------------------------------------------------
    // VULN#4: нет защиты от CSRF. Запрос, меняющий состояние, принимается
    // без проверки CSRF-токена. Вместе с VULN#3 (cookie без SameSite)
    // это позволяет чужому сайту отправлять сообщения от имени жертвы.
    // Токен уже генерируется в сессии (csrf) — его нужно начать проверять.
    // --------------------------------------------------------------------
    const body = String(req.body.body || '').slice(0, 1000);
    if (body.trim()) {
      db.prepare('INSERT INTO comments (author, body) VALUES (?, ?)')
        .run(user.username, body);
    }
    res.redirect('/');
  });

  app.post('/delete/:id', (req, res) => {
    const user = currentUser(req);
    if (!user || user.role !== 'admin') return res.status(403).send('Только админ');
    // VULN#4 (то же самое): удаление без CSRF-токена.
    db.prepare('DELETE FROM comments WHERE id = ?').run(req.params.id);
    res.redirect('/');
  });

  // Служебная ручка для автотестов: достать свой CSRF-токен.
  app.get('/csrf', (req, res) => {
    const user = currentUser(req);
    if (!user) return res.status(401).json({ error: 'not logged in' });
    res.json({ csrf: user.csrf });
  });

  app.get('/profile', (req, res) => {
    res.send(renderProfile());
  });

  return app;
}

// ======================= Шаблоны (ручной HTML) ==========================
//
// HTML собирается строками намеренно: так видно, где значение попадает
// в разметку без экранирования (VULN) и где достаточно обернуть его в
// esc(), чтобы закрыть Stored/Reflected XSS.

/** Экранирование HTML. Готовый помощник — используйте его при исправлении. */
function esc(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function layout(title, inner) {
  return `<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${esc(title)}</title>
  <style>
    body{font-family:system-ui,sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem;color:#1a1a1a}
    header{display:flex;justify-content:space-between;align-items:center;gap:1rem}
    .card{border:1px solid #ddd;border-radius:8px;padding:.75rem 1rem;margin:.5rem 0}
    .muted{color:#777;font-size:.85rem}
    input,button,textarea{font:inherit;padding:.4rem .6rem}
    form.inline{display:inline}
    nav a{margin-right:1rem}
  </style>
</head>
<body>
${inner}
</body>
</html>`;
}

function renderBoard({ user, comments, q }) {
  const loginBlock = user
    ? `<form class="inline" method="post" action="/logout">
         <span>Вы вошли как <b>${esc(user.username)}</b> (${esc(user.role)})</span>
         <button type="submit">Выйти</button>
       </form>`
    : `<form method="post" action="/login">
         <input name="username" placeholder="логин" autocomplete="off">
         <input name="password" type="password" placeholder="пароль">
         <button type="submit">Войти</button>
       </form>`;

  const commentForm = user
    ? `<form method="post" action="/comment">
         <textarea name="body" rows="2" cols="50" placeholder="Новое сообщение"></textarea><br>
         <button type="submit">Отправить</button>
       </form>`
    : `<p class="muted">Войдите, чтобы писать сообщения.</p>`;

  // VULN#1/#2 проявляются в данных; VULN стора XSS — здесь:
  // c.body и c.author вставляются в разметку БЕЗ esc().
  const list = comments.map((c) => `
    <div class="card">
      <div>${c.body}</div>
      <div class="muted">— ${c.author}, ${esc(c.created_at)}</div>
    </div>`).join('');

  return layout('DevBoard', `
    <header>
      <h1>DevBoard</h1>
      ${loginBlock}
    </header>
    <nav><a href="/">Доска</a><a href="/profile">Профиль</a></nav>

    <form method="get" action="/">
      <input name="q" value="${esc(q)}" placeholder="поиск по сообщениям">
      <button type="submit">Искать</button>
    </form>

    ${commentForm}
    <h2>Сообщения</h2>
    ${list || '<p class="muted">Пока пусто.</p>'}
  `);
}

function renderLogin(message) {
  return layout('Вход', `
    <h1>Вход</h1>
    <p style="color:#b00">${esc(message)}</p>
    <p><a href="/">← на доску</a></p>
  `);
}

function renderProfile() {
  // Страница читает имя из URL на клиенте (public/profile.js) — см. VULN#5.
  return layout('Профиль', `
    <h1>Профиль</h1>
    <p>Привет, <span id="name">гость</span>!</p>
    <p class="muted">Имя берётся из адреса: <code>/profile#name=Вася</code></p>
    <p><a href="/">← на доску</a></p>
    <script src="/static/profile.js"></script>
  `);
}

module.exports = { createApp, esc };

// Прямой запуск: поднять сервер.
if (require.main === module) {
  const port = process.env.PORT || 3000;
  createApp().listen(port, () => {
    console.log(`DevBoard на http://localhost:${port}`);
    console.log('Учётки: admin / S3cretAdminPass!, alice / alice123');
  });
}
