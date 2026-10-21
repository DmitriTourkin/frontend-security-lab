# Эталонное решение (для преподавателя / самопроверки)

Ниже — минимальные правки, доводящие `npm test` до зелёного и
закрывающие все уязвимости. Строки/имена соответствуют стартовому коду.
Открывайте только после собственной попытки.

---

## VULN#1 — SQL-инъекция в поиске (`src/server.js`, `GET /`)

Было:
```js
comments = db
  .prepare(`SELECT author, body, created_at FROM comments
            WHERE body LIKE '%${q}%' ORDER BY id DESC`)
  .all();
```
Стало:
```js
comments = db
  .prepare(`SELECT author, body, created_at FROM comments
            WHERE body LIKE ? ORDER BY id DESC`)
  .all(`%${q}%`);
```
Значение уходит в движок как параметр; символы `'`, `--`, `UNION`
трактуются как часть искомого текста, а не как SQL.

## VULN#2 — SQL-инъекция в логине (`POST /login`)

Было:
```js
const row = db
  .prepare(`SELECT * FROM users
            WHERE username = '${username}' AND password = '${password}'`)
  .get();
```
Стало:
```js
const row = db
  .prepare('SELECT * FROM users WHERE username = ? AND password = ?')
  .get(username, password);
```
(В реальности пароль дополнительно хранился бы как хэш и сверялся,
например, через `bcrypt.compare`.)

## VULN#3 — атрибуты cookie (`POST /login`)

Было:
```js
res.cookie('sid', sid, { path: '/' });
```
Стало:
```js
res.cookie('sid', sid, {
  path: '/',
  httpOnly: true,                 // недоступна из document.cookie
  sameSite: 'lax',                // не шлётся при межсайтовом POST
  secure: process.env.NODE_ENV === 'production', // только по HTTPS в проде
});
```

## VULN#4 — CSRF (`POST /comment`, `POST /delete/:id`)

Токен уже генерируется в сессии при логине. Добавьте проверку и
прокидывайте токен в формы.

Проверка (в начале обоих обработчиков, после получения `user`):
```js
const token = req.body._csrf || req.get('x-csrf-token');
if (!token || token !== user.csrf) {
  return res.status(403).send('Неверный CSRF-токен');
}
```

Токен в формы (в `renderBoard` нужно пробросить `user.csrf`):
```js
// в commentForm и в форме logout/delete добавить скрытое поле:
<input type="hidden" name="_csrf" value="${esc(csrf)}">
```
Передайте `csrf` в `renderBoard({ user, comments, q, csrf: user?.csrf })`
и используйте его в формах.

## VULN#5 — DOM XSS (`public/profile.js`)

Было:
```js
document.getElementById('name').innerHTML = name;
```
Стало:
```js
document.getElementById('name').textContent = name;
```
`textContent` вставляет строку как текст, а не как разметку.

## VULN#6 — Stored/Reflected XSS (`src/server.js`, `renderBoard`)

Было:
```js
const list = comments.map((c) => `
  <div class="card">
    <div>${c.body}</div>
    <div class="muted">— ${c.author}, ${esc(c.created_at)}</div>
  </div>`).join('');
```
Стало — обернуть пользовательские данные в `esc()`:
```js
const list = comments.map((c) => `
  <div class="card">
    <div>${esc(c.body)}</div>
    <div class="muted">— ${esc(c.author)}, ${esc(c.created_at)}</div>
  </div>`).join('');
```
Поле поиска `q` в разметку уже выводится через `esc(q)` — это образец.

## VULN#7 — Content-Security-Policy

Добавьте middleware до маршрутов (там, где комментарий про VULN#6/CSP):
```js
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self'; " +      // без 'unsafe-inline' — inline-JS не исполняется
    "object-src 'none'; " +
    "base-uri 'self'; " +
    "frame-ancestors 'none'"
  );
  next();
});
```
`frame-ancestors 'none'` заодно защищает от кликджекинга.

### Демонстрация CSP как второго рубежа

1. Оставьте `VULN#6` непочиненной, добавьте только CSP.
2. Отправьте `<img src=x onerror=alert(1)>`.
3. Браузер заблокирует обработчик `onerror` и напишет в консоль
   что-то вроде *«Refused to execute inline event handler because it
   violates the following Content Security Policy directive…»*.
4. Нагрузка в HTML есть, но не выполняется — CSP сработала.

---

## Проверка

```bash
npm test     # всё зелёное
npm start    # доска работает: вход, сообщения, поиск, удаление у админа
```

Соответствие тестов и правок:

| Тест | Закрывает |
|------|-----------|
| обход логина → 401 | VULN#2 |
| обычный логин → 302 | регрессия VULN#2 |
| UNION в поиске без утечки | VULN#1 |
| `<script>` экранируется | VULN#6 |
| `POST /comment` без токена → 403 | VULN#4 |
| `POST /comment` с токеном → ок | регрессия VULN#4 |
| cookie HttpOnly+SameSite | VULN#3 |
| есть CSP без unsafe-inline | VULN#7 |
