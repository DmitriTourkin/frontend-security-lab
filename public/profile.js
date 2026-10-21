'use strict';

// Клиентский скрипт страницы профиля.
//
// VULN#5: DOM-based XSS. Имя берётся из части URL после # и вставляется
// в страницу через innerHTML. Значение из #name=... попадает в DOM как
// разметка, поэтому срабатывает, например:
//   /profile#name=<img src=x onerror=alert(document.cookie)>
//
// Важно: сервер этот кусок URL даже не видит (браузер не шлёт часть
// после #), поэтому серверная проверка ввода тут бессильна —
// чинить нужно на клиенте (textContent вместо innerHTML).

(function () {
  const params = new URLSearchParams(location.hash.slice(1));
  const name = params.get('name') || 'гость';
  document.getElementById('name').innerHTML = name;
})();
