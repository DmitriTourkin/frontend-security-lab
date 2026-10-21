'use strict';

/**
 * Автотесты безопасности.
 *
 * Все тесты проверяют ПРАВИЛЬНОЕ (защищённое) поведение. На стартовом
 * уязвимом коде большинство из них ПАДАЕТ — это нормально. Цель студента:
 * починить приложение так, чтобы `npm test` стал полностью зелёным,
 * не ломая обычную работу доски.
 */

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startServer, makeClient } = require('./helpers');

let ctx;
before(async () => { ctx = await startServer(); });
after(() => ctx.server.close());

async function login(username, password) {
  const client = makeClient(ctx.base);
  const { res } = await client.req('/login', {
    method: 'POST',
    body: { username, password },
  });
  return { client, res };
}

// --- SQL-инъекции --------------------------------------------------------

test("SQLi: обход логина через ' OR '1'='1 не работает", async () => {
  const { res } = await login("' OR '1'='1", "' OR '1'='1");
  // Защищённый код: вход не удался → 401 (а не редирект 302 на доску).
  assert.equal(res.status, 401, 'инъекция в логине всё ещё проходит');
});

test('SQLi: обычный логин по-прежнему работает', async () => {
  const { res } = await login('alice', 'alice123');
  assert.equal(res.status, 302);
});

test('SQLi: UNION в поиске не выдаёт пароли из таблицы users', async () => {
  const client = makeClient(ctx.base);
  const payload = "%' UNION SELECT username, password, role FROM users -- ";
  const { res, text } = await client.req('/?q=' + encodeURIComponent(payload));
  const html = await text();
  assert.equal(res.status, 200, 'инъекция уронила запрос (значит, не параметризован)');
  assert.ok(!html.includes('S3cretAdminPass!'), 'поиск сливает пароли через UNION');
});

// --- XSS -----------------------------------------------------------------

test('Stored XSS: <script> в сообщении выводится экранированным', async () => {
  const { client } = await login('alice', 'alice123');
  // Берём CSRF-токен, чтобы тест работал и после починки CSRF (VULN#4).
  const { text: csrfText } = await client.req('/csrf');
  const { csrf } = JSON.parse(await csrfText());
  const payload = '<script>alert(1)</script>';
  await client.req('/comment', { method: 'POST', body: { body: payload, _csrf: csrf } });

  const { text } = await client.req('/');
  const html = await text();
  assert.ok(!html.includes(payload), 'тег <script> попадает в HTML как есть');
  assert.ok(html.includes('&lt;script&gt;'), 'вывод не экранируется');
});

// --- CSRF ----------------------------------------------------------------

test('CSRF: POST /comment без токена отклоняется (403)', async () => {
  const { client } = await login('alice', 'alice123');
  const { res } = await client.req('/comment', {
    method: 'POST',
    body: { body: 'без токена' },
  });
  assert.equal(res.status, 403, 'запрос без CSRF-токена всё ещё принимается');
});

test('CSRF: POST /comment с корректным токеном работает', async () => {
  const { client } = await login('alice', 'alice123');
  const { res: csrfRes, text } = await client.req('/csrf');
  const { csrf } = JSON.parse(await text());
  const { res } = await client.req('/comment', {
    method: 'POST',
    body: { body: 'с токеном', _csrf: csrf },
  });
  assert.ok([200, 302].includes(res.status), 'валидный токен должен приниматься');
});

// --- Атрибуты cookie -----------------------------------------------------

test('Cookie: sid помечена HttpOnly и SameSite', async () => {
  const { client } = await login('alice', 'alice123');
  const { setCookies } = await client.req('/csrf'); // любой ответ не нужен
  // Проверяем cookie из самого логина:
  const fresh = makeClient(ctx.base);
  const { setCookies: cookies } = await fresh.req('/login', {
    method: 'POST',
    body: { username: 'alice', password: 'alice123' },
  });
  const sid = cookies.find((c) => c.startsWith('sid='));
  assert.ok(sid, 'кука sid не выставлена');
  assert.match(sid, /HttpOnly/i, 'у cookie нет флага HttpOnly');
  assert.match(sid, /SameSite/i, 'у cookie нет атрибута SameSite');
});

// --- Content-Security-Policy ---------------------------------------------

test('CSP: заголовок присутствует и запрещает inline-скрипты', async () => {
  const client = makeClient(ctx.base);
  const { res } = await client.req('/');
  const csp = res.headers.get('content-security-policy');
  assert.ok(csp, 'заголовок Content-Security-Policy отсутствует');
  assert.match(csp, /script-src/i, 'в CSP нет директивы script-src');
  assert.ok(!/unsafe-inline/i.test(csp), 'script-src разрешает unsafe-inline');
});
