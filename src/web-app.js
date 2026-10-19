import { randomBytes } from 'node:crypto';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import express from 'express';
import session from 'express-session';
import * as oidc from 'openid-client';
import { createOAuthProvider } from './oauth-provider.js';
import { allowedReturnTo, equalSecrets, noStore, securityHeaders } from './security.js';
import { errorPage, homePage, profilePage, shelfPage } from './views.js';
import { books, bookIds, shelfStatuses } from './books.js';
import { ShelfStore, shelfUserKey } from './shelf-store.js';

export async function createWebApp(config, providerOptions, { shelfStore = new ShelfStore() } = {}) {
  const provider = await createOAuthProvider(config, providerOptions);
  const app = express();
  const store = new session.MemoryStore();
  const https = new URL(config.appUrl).protocol === 'https:';
  const cookieOptions = { httpOnly: true, sameSite: 'lax', secure: https, path: '/' };
  if (https) app.set('trust proxy', 'loopback');
  app.disable('x-powered-by');
  app.use(securityHeaders(config));
  app.use('/assets', express.static(fileURLToPath(new URL('../public/', import.meta.url))));
  app.use(noStore);
  app.use(session({
    name: 'app.sid', secret: config.sessionSecret, store,
    resave: false, saveUninitialized: false,
    cookie: { ...cookieOptions, maxAge: config.sessionLifetimeMs },
  }));
  app.use(express.urlencoded({ extended: false, limit: '8kb', parameterLimit: 10 }));
  app.use(express.json({ limit: '4kb' }));

  const saveSession = (req) => promisify(req.session.save).call(req.session);
  const destroySession = (req) => promisify(req.session.destroy).call(req.session);

  app.use(async (req, res, next) => {
    if (req.session.user && req.session.expiresAt <= Date.now()) {
      await destroySession(req);
      res.clearCookie('app.sid', cookieOptions);
    }
    next();
  });

  app.get('/health', (_req, res) => res.json({ status: 'ok', service: 'web-app' }));
  app.get('/', async (req, res) => {
    const shelf = req.session?.user ? await shelfStore.get(userKey(req)) : {};
    return res.send(homePage(req.session?.user, req.session?.csrf, req.query.loggedOut === '1', provider.name, shelf));
  });
  app.get('/shelf', requirePageUser, async (req, res) => {
    const shelf = await shelfStore.get(userKey(req));
    return res.send(shelfPage(req.session.user, req.session.csrf, shelf, provider.name));
  });
  app.get('/profile', requirePageUser, (req, res) => res.send(profilePage(req.session.user, req.session.csrf, provider.name)));
  app.get('/dashboard', (_req, res) => res.redirect('/shelf'));
  app.get('/api/books', (_req, res) => res.json({ books }));
  app.get('/api/me', (req, res) => {
    if (!req.session?.user) return res.status(401).json({ error: 'unauthorized' });
    return res.json({ user: req.session.user });
  });

  function requireApiUser(req, res, next) {
    if (!req.session?.user) return res.status(401).json({ error: 'unauthorized' });
    return next();
  }

  function requirePageUser(req, res, next) {
    if (!req.session?.user) return res.redirect(`/auth/login?returnTo=${encodeURIComponent(allowedReturnTo(req.path))}`);
    return next();
  }

  function checkShelfMutation(req, res, next) {
    if (req.get('origin') !== config.appUrl || !equalSecrets(req.get('x-csrf-token'), req.session.csrf)) {
      return res.status(403).json({ error: 'forbidden' });
    }
    if (!bookIds.has(req.params.bookId)) return res.status(404).json({ error: 'book_not_found' });
    return next();
  }

  const userKey = (req) => shelfUserKey(provider.name, req.session.user.sub);
  app.get('/api/shelf', requireApiUser, async (req, res) => res.json({ shelf: await shelfStore.get(userKey(req)) }));
  app.put('/api/shelf/:bookId', requireApiUser, checkShelfMutation, async (req, res) => {
    if (!shelfStatuses.has(req.body?.status)) return res.status(400).json({ error: 'invalid_status' });
    return res.json({ shelf: await shelfStore.set(userKey(req), req.params.bookId, req.body.status) });
  });
  app.delete('/api/shelf/:bookId', requireApiUser, checkShelfMutation, async (req, res) => {
    return res.json({ shelf: await shelfStore.set(userKey(req), req.params.bookId, null) });
  });

  app.post('/shelf/:bookId', requirePageUser, async (req, res) => {
    if (req.get('origin') !== config.appUrl || !equalSecrets(req.body?.csrf, req.session.csrf)) {
      return res.status(403).send(errorPage('Запрос отклонён', 'Обновите страницу и повторите действие.'));
    }
    if (!bookIds.has(req.params.bookId)) return res.status(404).send(errorPage('Книга не найдена', 'Выберите книгу из каталога.'));
    const status = req.body?.status;
    if (status !== '' && !shelfStatuses.has(status)) {
      return res.status(400).send(errorPage('Неверный статус', 'Выберите статус из списка на странице полки.'));
    }
    await shelfStore.set(userKey(req), req.params.bookId, status === '' ? null : status);
    return res.redirect(303, req.body.returnTo === '/' ? '/' : '/shelf');
  });

  app.get('/auth/login', async (req, res) => {
    if (!provider.configured) {
      return res.status(503).send(errorPage('Вход временно недоступен', 'Вход через Google ещё не настроен администратором приложения.'));
    }
    const returnTo = allowedReturnTo(req.query.returnTo);
    if (req.session?.user) return res.redirect(returnTo);
    if (!req.session) return res.redirect('/auth/login');
    const codeVerifier = oidc.randomPKCECodeVerifier();
    const state = oidc.randomState();
    const pending = { codeVerifier, state, returnTo, createdAt: Date.now() };
    if (provider.usesNonce) pending.nonce = oidc.randomNonce();
    req.session.authRequest = pending;
    await saveSession(req);
    try {
      const authorizationUrl = await provider.authorizationUrl(pending);
      return res.redirect(authorizationUrl.href);
    } catch {
      delete req.session.authRequest;
      await saveSession(req);
      return res.status(503).send(errorPage('Вход временно недоступен', 'Не удалось связаться с сервером авторизации. Попробуйте позже.'));
    }
  });

  app.get('/auth/callback', async (req, res) => {
    const pending = req.session?.authRequest;
    if (!pending || Date.now() - pending.createdAt > config.authRequestLifetimeMs) {
      return res.status(400).send(errorPage('Вход не завершён', 'Запрос входа отсутствует или устарел. Начните вход заново.'));
    }
    // Consume the request before exchanging the single-use authorization code.
    delete req.session.authRequest;
    await saveSession(req);
    try {
      const identity = await provider.authenticate(new URL(req.originalUrl, config.appUrl), pending);
      await promisify(req.session.regenerate).call(req.session);
      req.session.user = identity.user;
      if (identity.idToken) req.session.idToken = identity.idToken;
      req.session.expiresAt = identity.expiresAt;
      req.session.csrf = randomBytes(32).toString('base64url');
      await saveSession(req);
      return res.redirect(pending.returnTo);
    } catch (error) {
      const cancelled = error instanceof oidc.AuthorizationResponseError && error.error === 'access_denied';
      return res.status(cancelled ? 403 : 400).send(errorPage(
        cancelled ? 'Вход отменён' : 'Не удалось войти',
        cancelled ? 'Доступ к приложению не был разрешён. Можно попробовать снова.' : 'Ответ сервера авторизации отклонён. Начните вход заново.',
      ));
    }
  });

  app.post('/auth/logout', async (req, res) => {
    if (!req.session?.user) return res.redirect(303, '/');
    if (req.get('origin') !== config.appUrl || !equalSecrets(req.body?.csrf, req.session.csrf)) {
      return res.status(403).send(errorPage('Запрос отклонён', 'Повторите выход с помощью кнопки в приложении.'));
    }
    const logoutUrl = provider.logoutUrl(req.session);
    await destroySession(req);
    res.clearCookie('app.sid', cookieOptions);
    return res.redirect(303, logoutUrl);
  });

  app.get('/auth/logged-out', (req, res) => {
    if (req.session?.user) return res.redirect('/');
    return res.redirect('/?loggedOut=1');
  });
  app.use((_req, res) => res.status(404).send(errorPage('Страница не найдена', 'Проверьте адрес или перейдите на главную.')));
  app.use((error, req, res, _next) => {
    const status = error.status ?? 500;
    if (status === 500) console.error('Ошибка веб-приложения:', error.name);
    if (req.path.startsWith('/api/')) return res.status(status).json({ error: status === 500 ? 'server_error' : 'invalid_request' });
    res.status(status).send(errorPage('Ошибка запроса', 'Повторите действие со страницы приложения.'));
  });
  return { app, store };
}
