import { books } from './books.js';

export function escapeHtml(value = '') {
  return String(value).replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]);
}

const statusLabels = { planned: 'Хочу прочитать', reading: 'Читаю', read: 'Прочитано' };

function bookCover(book) {
  const tone = books.indexOf(book) % 4;
  const label = /^\d+$/.test(book.title) ? book.title : book.title.split(' ')
    .filter((word) => word.length > 2).slice(0, 2).map((word) => word[0]).join('').toUpperCase();
  return `<div class="book-cover tone-${tone}" aria-hidden="true"><span>${escapeHtml(label)}</span></div>`;
}

export function layout({ title, content, user, csrf, authProvider = 'yandex', identity = false, appUrl = '', current = '' }) {
  const links = [['/', 'Каталог'], ['/shelf', 'Моя полка'], ['/profile', 'Профиль']];
  const navigation = links.map(([href, label]) => `<a href="${href}"${href === current ? ' aria-current="page"' : ''}>${label}</a>`).join(' ');
  const account = user
    ? `<div class="account"><span class="account-name">${escapeHtml(user.name || user.username)}</span>
        <form class="inline" method="post" action="/auth/logout">
          <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
          <button class="secondary" type="submit">Выйти</button>
        </form></div>`
    : `<a class="button" href="/auth/login?returnTo=%2Fshelf">${authProvider === 'yandex' ? 'Войти через Яндекс' : 'Войти'}</a>`;
  return `<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} — Полка</title>
  <link rel="icon" href="/assets/favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body${identity ? ' class="identity-page"' : ''}>
  <header class="site-header">
    <div class="header-content">
      <a class="site-name" href="${escapeHtml(appUrl)}/"><img src="/assets/favicon.svg" width="32" height="32" alt="">Полка</a>
      ${identity ? '<span class="muted">Учётная запись</span>' : `<nav aria-label="Разделы сайта">${navigation}</nav>${account}`}
    </div>
  </header>
  <main>
    <h1>${escapeHtml(title)}</h1>
    ${content}
  </main>
</body>
</html>`;
}

export function homePage(user, csrf, loggedOut = false, authProvider = 'yandex', shelf = {}) {
  const items = books.map((book) => {
    const action = !user ? '' : shelf[book.id]
      ? `<span class="status">${statusLabels[shelf[book.id]]}</span><a class="shelf-link" href="/shelf">На моей полке</a>`
      : `<form class="inline" method="post" action="/shelf/${escapeHtml(book.id)}">
          <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
          <input type="hidden" name="status" value="planned">
          <input type="hidden" name="returnTo" value="/">
          <button type="submit" aria-label="Добавить «${escapeHtml(book.title)}» на полку">Добавить на полку</button>
        </form>`;
    return `<li class="book-card">${bookCover(book)}<div class="book-copy">
      <h2>${escapeHtml(book.title)}</h2><p class="book-author">${escapeHtml(book.author)}</p>
      ${action ? `<div class="book-actions">${action}</div>` : ''}
    </div></li>`;
  }).join('\n');
  return layout({ title: 'Каталог книг', user, csrf, authProvider, current: '/',
    content: `${loggedOut ? `<p class="notice" role="status">${authProvider === 'yandex' ? 'Вы вышли из приложения.' : 'Вы вышли из приложения и сервера авторизации.'}</p>` : ''}
      <p class="page-intro">Выбирайте книги и сохраняйте их на свою полку.</p>
      ${user ? '' : '<p class="notice">Чтобы добавлять книги и отмечать прочитанное, войдите в свой аккаунт.</p>'}
      <ul class="book-grid">${items}</ul>`,
  });
}

export function shelfPage(user, csrf, shelf, authProvider) {
  const items = books.filter((book) => shelf[book.id]).map((book) => {
    const options = Object.entries(statusLabels).map(([value, label]) =>
      `<option value="${value}"${shelf[book.id] === value ? ' selected' : ''}>${label}</option>`).join('');
    return `<li class="book-card">${bookCover(book)}<div class="book-copy">
      <h2>${escapeHtml(book.title)}</h2><p class="book-author">${escapeHtml(book.author)}</p>
      <form class="shelf-controls" method="post" action="/shelf/${escapeHtml(book.id)}">
        <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
        <label for="status-${escapeHtml(book.id)}">Статус:</label>
        <select id="status-${escapeHtml(book.id)}" name="status">${options}<option value="">Убрать с полки</option></select>
        <button type="submit">Сохранить</button>
      </form></div>
    </li>`;
  }).join('\n');
  return layout({ title: 'Моя полка', user, csrf, authProvider, current: '/shelf',
    content: items
      ? `<p class="page-intro">Ваш список книг. Выберите статус и нажмите «Сохранить».</p><ul class="book-grid">${items}</ul>`
      : `<p class="page-intro">Здесь будут книги, которые вы сохранили.</p>
        <div class="empty-state"><h2>На полке пока нет книг</h2>
          <p>Выберите в каталоге то, что хотите прочитать.</p><a class="button" href="/">Выбрать книги</a></div>`,
  });
}

export function profilePage(user, csrf, authProvider) {
  return layout({ title: 'Профиль', user, csrf, authProvider, current: '/profile',
    content: `<p class="page-intro">Данные вашего аккаунта.</p><section class="panel profile-panel"><dl class="profile-data">
      <dt>Имя</dt><dd>${escapeHtml(user.name)}</dd>
      <dt>Логин</dt><dd>${escapeHtml(user.username)}</dd>
      <dt>Почта</dt><dd>${escapeHtml(user.email || 'Не указана')}</dd>
    </dl>
    <a class="button secondary" href="/shelf">Перейти к моим книгам</a></section>`,
  });
}

export function loginPage(uid, csrf, username, error = '') {
  return layout({ title: 'Вход', identity: true,
    content: `<p>Войдите, чтобы открыть свою полку.</p>
      ${error ? `<p class="error" role="alert">${escapeHtml(error)}</p>` : ''}
      <form method="post" action="/interaction/${escapeHtml(uid)}/login">
        <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
        <p><label for="username">Логин</label><br>
          <input id="username" name="username" autocomplete="username" maxlength="128" value="${escapeHtml(username)}" required autofocus></p>
        <p><label for="password">Пароль</label><br>
          <input id="password" type="password" name="password" autocomplete="current-password" maxlength="256" required></p>
        <button type="submit">Войти</button>
      </form>
      <form method="post" action="/interaction/${escapeHtml(uid)}/abort">
        <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
        <button class="secondary" type="submit">Отменить вход</button>
      </form>`,
  });
}

export function consentPage(uid, csrf, username) {
  return layout({ title: 'Разрешение доступа', identity: true,
    content: `<p>Вы вошли как ${escapeHtml(username)}.</p>
      <p>Разрешить приложению «Полка» получить ваше имя, логин и почту?</p>
      <form method="post" action="/interaction/${escapeHtml(uid)}/confirm">
        <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
        <button type="submit">Разрешить доступ</button>
      </form>
      <form method="post" action="/interaction/${escapeHtml(uid)}/abort">
        <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
        <button class="secondary" type="submit">Отменить</button>
      </form>`,
  });
}

export function logoutPage(form) {
  return layout({ title: 'Выход', identity: true,
    content: `<p>Сеанс в приложении завершён. Подтвердите выход из сервера авторизации.</p>
      ${form}<button type="submit" form="op.logoutForm" name="logout" value="yes">Подтвердить выход</button>`,
  });
}

export function errorPage(title, message, identity = false, appUrl = '') {
  return layout({ title, identity, appUrl,
    content: `<p class="error">${escapeHtml(message)}</p><p><a href="${escapeHtml(appUrl)}/">На главную</a></p>`,
  });
}
