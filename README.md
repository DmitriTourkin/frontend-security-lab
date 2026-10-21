# Frontend Security Lab — XSS, CSRF, SQL-инъекции и CSP

Учебный стенд для знакомства с уязвимостями веб-приложений, доступными
через клиентский ввод, и способами защиты от них.

В репозитории — маленькое приложение на Node.js (**DevBoard**, доска
сообщений) с **намеренно внесёнными уязвимостями**, отдельный стенд
«атакующего сайта» и набор автотестов. Задача — найти уязвимости,
воспроизвести атаки на локальном стенде и устранить их.

> ⚠️ Приложение уязвимо специально. Запускайте только локально и никогда
> не публикуйте в интернет.

---

## Что внутри

| Путь | Что это |
|------|---------|
| `src/server.js` | Уязвимое приложение DevBoard. Все уязвимости помечены `VULN#N`. |
| `src/db.js` | SQLite-хранилище и стартовые данные (без уязвимостей). |
| `public/profile.js` | Клиентский скрипт страницы профиля (DOM XSS). |
| `attacker/server.js` | Стенд «атакующего сайта» (CSRF + доставка XSS). |
| `tests/security.test.js` | Автотесты. Проверяют защищённое поведение. |
| `docs/INSTRUCTION.md` | **Пошаговая инструкция по выполнению проекта.** |
| `docs/TASKS.md` | Задания с подсказками по каждой уязвимости. |
| `docs/VULNERABILITIES.md` | Шаблон отчёта об уязвимостях (заполняет студент). |
| `docs/GRADING.md` | **Критерии оценки: уровни Б / П / Э.** |

## Карта уязвимостей

| # | Класс | Где | Как чинится |
|---|-------|-----|-------------|
| 1 | SQL-инъекция | поиск, `GET /` | параметризованный запрос |
| 2 | SQL-инъекция | логин, `POST /login` | параметризованный запрос |
| 3 | Небезопасная cookie | `POST /login` | `HttpOnly`, `SameSite`, `secure` |
| 4 | CSRF | `POST /comment`, `/delete` | проверка CSRF-токена |
| 5 | DOM-based XSS | `public/profile.js` | `textContent` вместо `innerHTML` |
| 6 | Stored/Reflected XSS | рендер сообщений, `src/server.js` | экранирование вывода `esc()` |
| 7 | Нет CSP | заголовки ответа | `Content-Security-Policy` |

---

## Инструменты и материалы

**Что используется в проекте** (всё ставится одной командой `npm install`,
отдельно скачивать ничего не нужно):

- [Node.js](https://nodejs.org/) ≥ 18 — среда выполнения JavaScript.
- [Express](https://expressjs.com/ru/) — веб-фреймворк (маршруты, запросы).
- [better-sqlite3](https://github.com/WiseLibs/better-sqlite3) — встроенная
  база данных SQLite (на ней показаны SQL-инъекции и их исправление).
- [cookie-parser](https://github.com/expressjs/cookie-parser) — чтение cookie.
- [node:test](https://nodejs.org/api/test.html) — встроенный тест-раннер
  Node.js (автотесты, без сторонних зависимостей).

**Справочные материалы** (рекомендуется держать под рукой):

- OWASP Top 10 — обзор классов уязвимостей:
  <https://owasp.org/www-project-top-ten/>
- Шпаргалки OWASP по защите:
  [XSS](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) ·
  [CSRF](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) ·
  [SQL Injection](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- MDN:
  [Content-Security-Policy](https://developer.mozilla.org/ru/docs/Web/HTTP/CSP) ·
  [Set-Cookie (HttpOnly, SameSite)](https://developer.mozilla.org/ru/docs/Web/HTTP/Headers/Set-Cookie)
- Классификация CWE:
  [CWE-79 (XSS)](https://cwe.mitre.org/data/definitions/79.html) ·
  [CWE-89 (SQLi)](https://cwe.mitre.org/data/definitions/89.html) ·
  [CWE-352 (CSRF)](https://cwe.mitre.org/data/definitions/352.html)

---

## Установка

Нужен Node.js ≥ 18.

```bash
npm install
```

> `better-sqlite3` собирает нативный модуль — для этого нужны инструменты
> сборки (на macOS — Xcode Command Line Tools). Обычно ставится из
> готовых бинарников без дополнительных действий.

## Запуск приложения

```bash
npm start
```

Откройте <http://localhost:3000>. Учётные записи:

- `admin` / `S3cretAdminPass!` — администратор (может удалять сообщения)
- `alice` / `alice123`, `bob` / `bob123` — обычные пользователи

## Запуск стенда атакующего

В отдельном терминале:

```bash
npm run attacker
```

Откройте <http://localhost:4000>, **будучи залогиненным** на DevBoard, —
и посмотрите, что произойдёт с доской.

## Автотесты

```bash
npm test
```

На стартовом (уязвимом) коде тесты **падают** — это ожидаемо. По мере
исправления уязвимостей они становятся зелёными. Готовое решение — когда
`npm test` проходит полностью, а доска продолжает нормально работать.

---

## Рекомендуемый порядок работы

> Подробный разбор каждого шага — в [docs/INSTRUCTION.md](docs/INSTRUCTION.md).

1. Прочитайте `docs/TASKS.md`.
2. Запустите `npm test` и посмотрите, что падает.
3. Для каждой уязвимости: **сначала воспроизведите атаку** (руками в
   браузере и/или через стенд атакующего), запишите наблюдение в
   `docs/VULNERABILITIES.md`, **потом чините**.
4. После каждого исправления перезапускайте `npm test`.
5. Отдельно: оставьте одну XSS-уязвимость «как есть», включите CSP и
   убедитесь, что атака больше не срабатывает — CSP служит вторым рубежом.
6. Запишите видеоотчёт: атака «до» → исправление → атака «после».

## Что сдаётся

- Исправленное приложение, проходящее `npm test`.
- Заполненный отчёт `docs/VULNERABILITIES.md`.
- Видеоотчёт с демонстрацией атак до и после исправления.

## Как оценивается

Работа оценивается по уровням **Б** (базовый), **П** (продвинутый) и
**Э** (экспертный) — они позже переводятся в числовые баллы. Уровни
накопительные: сначала базовый, затем усиление.

| Уровень | Коротко |
|---------|---------|
| **Б** | Все 7 уязвимостей закрыты, `npm test` зелёный, CSP работает, отчёт и видео сданы. |
| **П** | Базовый уровень + «боевые» практики: хэширование паролей, ужесточённая CSP с приёмом отчётов, собственные тесты, CWE в отчёте. |
| **Э** | Продвинутый уровень + системная защита: безопасность по умолчанию, CSP на nonce/Trusted Types, security-тесты в CI, аналитическая записка. |

Полные критерии со всеми пунктами и градациями (Б−, Б, Б+) —
в [docs/GRADING.md](docs/GRADING.md).
