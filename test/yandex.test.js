import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { promisify } from 'node:util';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { before, after, afterEach, test } from 'node:test';
import express from 'express';
import { loadConfig } from '../src/config.js';
import { createWebApp } from '../src/web-app.js';
import { ShelfStore, shelfUserKey } from '../src/shelf-store.js';

let config;
let appServer;
let mockServer;
let store;
let shelfStore;
let storageDirectory;
let tokenRequests = 0;
let tokenFailure = false;
let profileFailure = false;
let invalidProfile = false;
const codes = new Map();
const accessTokens = new Set();
const clientId = 'a'.repeat(32);
const clientSecret = 'private-test-yandex-secret';
const profile = { id: '123456789', login: 'student-yandex', real_name: 'Студент Яндекса', default_email: 'student@yandex.ru', client_id: clientId };
let activeProfile = profile;

function listen(app) {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, '127.0.0.1', () => resolve(server));
    server.once('error', reject);
  });
}

async function close(server) {
  if (!server) return;
  const closing = new Promise((resolve) => server.close(resolve));
  server.closeAllConnections();
  await closing;
}

class Browser {
  cookie = '';
  async request(url, options = {}) {
    const response = await fetch(url, {
      ...options, redirect: 'manual', signal: AbortSignal.timeout(5000),
      headers: { cookie: this.cookie, ...options.headers },
    });
    for (const header of response.headers.getSetCookie()) {
      if (header.startsWith('app.sid=')) this.cookie = header.split(';')[0];
    }
    return response;
  }
}

before(async () => {
  storageDirectory = await mkdtemp(join(tmpdir(), 'polka-test-'));
  shelfStore = new ShelfStore(join(storageDirectory, 'shelves.json'));
  const mock = express();
  mock.use(express.urlencoded({ extended: false }));
  mock.post('/token', (req, res) => {
    tokenRequests++;
    const [encodedId, encodedSecret] = Buffer.from(req.get('authorization').slice(6), 'base64').toString().split(':');
    assert.equal(decodeURIComponent(encodedId), clientId);
    assert.equal(decodeURIComponent(encodedSecret), clientSecret);
    assert.equal(req.body.grant_type, 'authorization_code');
    assert.equal(req.body.redirect_uri, `${config.appUrl}/auth/callback`);
    const code = codes.get(req.body.code);
    const actualChallenge = createHash('sha256').update(req.body.code_verifier).digest('base64url');
    if (tokenFailure || !code || actualChallenge !== code.challenge) return res.status(400).json({ error: 'invalid_grant' });
    codes.delete(req.body.code);
    const accessToken = `private-test-access-token-${req.body.code}`;
    accessTokens.add(accessToken);
    return res.json({ token_type: 'bearer', access_token: accessToken, expires_in: 1800 });
  });
  mock.get('/info', (req, res) => {
    const token = req.get('authorization')?.replace(/^OAuth /, '');
    assert.ok(accessTokens.has(token));
    assert.equal(req.query.format, 'json');
    assert.equal(req.query.oauth_token, undefined, 'Token must be in the header, not in the URL');
    if (profileFailure) return res.status(401).json({ error: 'invalid_token' });
    return res.json(invalidProfile ? { ...activeProfile, client_id: 'another-client' } : activeProfile);
  });
  mockServer = await listen(mock);
  const mockOrigin = `http://127.0.0.1:${mockServer.address().port}`;
  const portProbe = await listen(express());
  const appPort = portProbe.address().port;
  await close(portProbe);
  config = loadConfig({
    APP_PORT: String(appPort),
    HOST: '127.0.0.1', APP_URL: `http://localhost:${appPort}/`,
    AUTH_PROVIDER: 'yandex', SESSION_SECRET: randomBytes(32).toString('hex'),
    YANDEX_CLIENT_ID: clientId, YANDEX_CLIENT_SECRET: clientSecret,
  });
  const { app: realApp, store: realStore } = await createWebApp(config, {
    async fetchImplementation(url, options) {
      const target = new URL(url);
      if (target.origin === 'https://oauth.yandex.ru' && target.pathname === '/token') return fetch(`${mockOrigin}/token`, options);
      if (target.origin === 'https://login.yandex.ru' && target.pathname === '/info') return fetch(`${mockOrigin}/info${target.search}`, options);
      throw new Error('Unexpected external request during test');
    },
  }, { shelfStore });
  appServer = await new Promise((resolve, reject) => {
    const server = realApp.listen(new URL(config.appUrl).port, '127.0.0.1', () => resolve(server));
    server.once('error', reject);
  });
  store = realStore;
});

after(async () => { await Promise.all([close(appServer), close(mockServer)]); await rm(storageDirectory, { recursive: true, force: true }); });
afterEach(() => { tokenFailure = false; profileFailure = false; invalidProfile = false; activeProfile = profile; });

async function begin(browser, returnTo = '/shelf') {
  const response = await browser.request(`${config.appUrl}/auth/login?returnTo=${encodeURIComponent(returnTo)}`);
  assert.equal(response.status, 302);
  const authorizationUrl = new URL(response.headers.get('location'));
  const code = randomBytes(16).toString('hex');
  codes.set(code, { challenge: authorizationUrl.searchParams.get('code_challenge') });
  const callback = new URL(`${config.appUrl}/auth/callback`);
  callback.searchParams.set('code', code);
  callback.searchParams.set('state', authorizationUrl.searchParams.get('state'));
  return { authorizationUrl, callback };
}

test('Yandex redirect uses OAuth code, PKCE, state and limited profile scopes', async () => {
  const browser = new Browser();
  const { authorizationUrl } = await begin(browser);
  assert.equal(authorizationUrl.origin, 'https://oauth.yandex.ru');
  assert.equal(authorizationUrl.pathname, '/authorize');
  assert.equal(authorizationUrl.searchParams.get('client_id'), clientId);
  assert.equal(authorizationUrl.searchParams.get('response_type'), 'code');
  assert.equal(authorizationUrl.searchParams.get('scope'), 'login:info login:email');
  assert.equal(authorizationUrl.searchParams.get('redirect_uri'), `${config.appUrl}/auth/callback`);
  assert.equal(new URL(authorizationUrl.searchParams.get('redirect_uri')).hostname, 'localhost');
  assert.equal(authorizationUrl.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(authorizationUrl.searchParams.get('force_confirm'), 'yes');
  assert.ok(authorizationUrl.searchParams.get('state'));
  assert.equal(authorizationUrl.searchParams.has('client_secret'), false);
  assert.equal(authorizationUrl.searchParams.has('nonce'), false);
});

test('Yandex callback exchanges code, loads profile, rotates session and hides tokens', async () => {
  const browser = new Browser();
  const { callback } = await begin(browser);
  const previousCookie = browser.cookie;
  const response = await browser.request(callback);
  assert.equal(response.status, 302);
  assert.equal(response.headers.get('location'), '/shelf');
  assert.notEqual(browser.cookie, previousCookie);
  const api = await browser.request(`${config.appUrl}/api/me`);
  assert.equal(api.status, 200);
  assert.deepEqual(await api.json(), { user: { sub: profile.id, username: profile.login, name: profile.real_name, email: profile.default_email } });
  for (const path of ['/', '/shelf', '/profile']) {
    const html = await (await browser.request(`${config.appUrl}${path}`)).text();
    assert.match(html, /Студент Яндекса/);
    assert.ok(!html.includes('private-test-access-token'));
    assert.ok(!html.includes(clientSecret));
  }
  const signedCookie = decodeURIComponent(browser.cookie.slice('app.sid='.length));
  const id = signedCookie.slice(2, signedCookie.lastIndexOf('.'));
  const session = await promisify(store.get).call(store, id);
  assert.equal(session.accessToken, undefined);
  assert.equal(session.idToken, undefined);
  assert.ok(session.expiresAt <= Date.now() + 1800_000);
  assert.equal((await browser.request(callback)).status, 400);
});

test('forged Yandex state is rejected before token exchange', async () => {
  const browser = new Browser();
  const { callback } = await begin(browser);
  const count = tokenRequests;
  callback.searchParams.set('state', 'forged');
  assert.equal((await browser.request(callback)).status, 400);
  assert.equal(tokenRequests, count);
  assert.equal((await browser.request(`${config.appUrl}/api/me`)).status, 401);
});

test('denying Yandex consent does not create a session', async () => {
  const browser = new Browser();
  const { callback } = await begin(browser);
  callback.searchParams.delete('code');
  callback.searchParams.set('error', 'access_denied');
  const response = await browser.request(callback);
  assert.equal(response.status, 403);
  assert.match(await response.text(), /Вход отменён/);
  assert.equal((await browser.request(`${config.appUrl}/api/me`)).status, 401);
});

test('Yandex token or profile errors and mismatched client ID keep private pages closed', async () => {
  for (const failure of ['token', 'profile', 'client']) {
    tokenFailure = failure === 'token'; profileFailure = failure === 'profile'; invalidProfile = failure === 'client';
    const browser = new Browser();
    const { callback } = await begin(browser);
    assert.equal((await browser.request(callback)).status, 400);
    assert.equal((await browser.request(`${config.appUrl}/api/me`)).status, 401);
  }
});

test('Yandex session logout is protected by CSRF and invalidates the previous cookie', async () => {
  const browser = new Browser();
  const { callback } = await begin(browser);
  assert.equal((await browser.request(callback)).status, 302);
  const html = await (await browser.request(config.appUrl)).text();
  const csrf = html.match(/name="csrf" value="([^"]+)"/)[1];
  const post = (value) => browser.request(`${config.appUrl}/auth/logout`, {
    method: 'POST', body: new URLSearchParams({ csrf: value }), headers: { origin: config.appUrl },
  });
  assert.equal((await post('invalid')).status, 403);
  const oldBrowser = new Browser();
  oldBrowser.cookie = browser.cookie;
  const response = await post(csrf);
  assert.equal(response.status, 303);
  assert.equal(response.headers.get('location'), '/auth/logged-out');
  assert.equal((await oldBrowser.request(`${config.appUrl}/api/me`)).status, 401);
  const redirect = await browser.request(`${config.appUrl}/auth/logged-out`);
  assert.equal(redirect.headers.get('location'), '/?loggedOut=1');
  const landing = await browser.request(new URL(redirect.headers.get('location'), config.appUrl));
  const loggedOutHtml = await landing.text();
  assert.match(loggedOutHtml, /Вы вышли из приложения\./);
  assert.ok(!loggedOutHtml.includes('Вы вышли из приложения и сервера авторизации'));
});

test('unconfigured Yandex mode serves public pages and refuses login without a local fallback', async () => {
  const { app } = await createWebApp(loadConfig({ SESSION_SECRET: 's'.repeat(32) }));
  const server = await listen(app);
  try {
    const origin = `http://127.0.0.1:${server.address().port}`;
    const browser = new Browser();
    const page = await browser.request(origin);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /Войти через Яндекс/);
    const response = await browser.request(`${origin}/auth/login`);
    assert.equal(response.status, 503);
    assert.equal(response.headers.get('location'), null);
    assert.equal((await browser.request(`${origin}/api/me`)).status, 401);
  } finally { await close(server); }
});

async function reader(subject) {
  activeProfile = { ...profile, id: subject };
  const browser = new Browser();
  const { callback } = await begin(browser);
  assert.equal((await browser.request(callback)).status, 302);
  const html = await (await browser.request(config.appUrl)).text();
  browser.csrf = html.match(/name="csrf" value="([^"]+)"/)[1];
  return browser;
}

function changeBook(browser, bookId, status, headers = {}) {
  return browser.request(`${config.appUrl}/api/shelf/${bookId}`, {
    method: status === null ? 'DELETE' : 'PUT',
    headers: { origin: config.appUrl, 'content-type': 'application/json', 'x-csrf-token': browser.csrf, ...headers },
    ...(status === null ? {} : { body: JSON.stringify({ status }) }),
  });
}

test('catalogue is public while shelf reads and writes require an authenticated session', async () => {
  const browser = new Browser();
  const catalogue = await browser.request(`${config.appUrl}/api/books`);
  assert.equal(catalogue.status, 200);
  const { books } = await catalogue.json();
  assert.equal(books.length, 8);
  assert.equal(new Set(books.map((book) => book.id)).size, 8);
  assert.equal((await browser.request(`${config.appUrl}/api/shelf`)).status, 401);
  assert.equal((await changeBook(browser, books[0].id, 'planned')).status, 401);
  assert.equal((await changeBook(browser, books[0].id, null)).status, 401);
});

test('personal shelf persists across login and store recreation; concurrent writes and user isolation work', async () => {
  const first = await reader('reader-one');
  assert.deepEqual(await (await first.request(`${config.appUrl}/api/shelf`)).json(), { shelf: {} });
  const changes = await Promise.all([
    changeBook(first, 'little-prince', 'planned'),
    changeBook(first, '1984', 'reading'),
    changeBook(first, 'alice', 'read'),
  ]);
  for (const response of changes) assert.equal(response.status, 200);
  const expected = { 'little-prince': 'planned', '1984': 'reading', alice: 'read' };
  assert.deepEqual(await (await first.request(`${config.appUrl}/api/shelf`)).json(), { shelf: expected });
  const reopenedStore = new ShelfStore(shelfStore.filename);
  assert.deepEqual(await reopenedStore.get(shelfUserKey('yandex', 'reader-one')), expected);
  const nextLogin = await reader('reader-one');
  assert.deepEqual(await (await nextLogin.request(`${config.appUrl}/api/shelf`)).json(), { shelf: expected });
  const other = await reader('reader-two');
  assert.deepEqual(await (await other.request(`${config.appUrl}/api/shelf`)).json(), { shelf: {} });
  assert.equal((await changeBook(other, 'seneca', 'planned')).status, 200);
  assert.deepEqual(await (await first.request(`${config.appUrl}/api/shelf`)).json(), { shelf: expected });
  const update = await changeBook(first, 'little-prince', 'read');
  assert.equal((await update.json()).shelf['little-prince'], 'read');
  const removed = await changeBook(first, '1984', null);
  assert.equal(removed.status, 200);
  assert.deepEqual((await removed.json()).shelf, { 'little-prince': 'read', alice: 'read' });
});

test('shelf mutations reject forged requests, unknown books and invalid statuses without changing saved data', async () => {
  const browser = await reader('reader-security');
  assert.equal((await changeBook(browser, 'alice', 'planned', { 'x-csrf-token': 'forged' })).status, 403);
  assert.equal((await changeBook(browser, 'alice', 'planned', { origin: 'https://example.invalid' })).status, 403);
  assert.equal((await changeBook(browser, 'alice', 'planned', { origin: `http://127.0.0.1:${config.appPort}` })).status, 403);
  assert.equal((await changeBook(browser, 'alice', 'planned', { origin: '' })).status, 403);
  assert.equal((await changeBook(browser, 'alice', 'anything')).status, 400);
  assert.equal((await changeBook(browser, 'unknown-book', 'planned')).status, 404);
  assert.deepEqual(await (await browser.request(`${config.appUrl}/api/shelf`)).json(), { shelf: {} });
  assert.equal((await changeBook(browser, 'alice', 'planned')).status, 200);
  assert.equal((await changeBook(browser, 'alice', null, { 'x-csrf-token': 'wrong' })).status, 403);
  assert.deepEqual(await (await browser.request(`${config.appUrl}/api/shelf`)).json(), { shelf: { alice: 'planned' } });
});

test('HTML forms add, update and remove books while rejecting forged submissions', async () => {
  const browser = await reader('reader-html-forms');
  const html = await (await browser.request(config.appUrl)).text();
  const form = html.match(/<form[^>]*action="\/shelf\/alice"[^>]*>([\s\S]*?)<\/form>/);
  assert.ok(form, 'Catalogue must contain an ordinary add-book form');
  const fields = new URLSearchParams([...form[1].matchAll(/name="([^"]+)" value="([^"]*)"/g)].map((match) => [match[1], match[2]]));
  const post = (bookId, body = fields, headers = {}) => browser.request(`${config.appUrl}/shelf/${bookId}`, {
    method: 'POST', body, headers: { origin: config.appUrl, ...headers },
  });
  const forged = new URLSearchParams(fields);
  forged.set('csrf', 'invalid');
  assert.equal((await post('alice', forged)).status, 403);
  assert.equal((await post('alice', fields, { origin: 'https://example.invalid' })).status, 403);
  assert.equal((await post('unknown-book')).status, 404);
  const invalid = new URLSearchParams(fields);
  invalid.set('status', 'unknown');
  assert.equal((await post('alice', invalid)).status, 400);
  assert.deepEqual(await (await browser.request(`${config.appUrl}/api/shelf`)).json(), { shelf: {} });

  const added = await post('alice');
  assert.equal(added.status, 303);
  assert.equal(added.headers.get('location'), '/');
  let shelf = await (await browser.request(`${config.appUrl}/shelf`)).text();
  assert.match(shelf, /Алиса в Стране чудес/);
  assert.match(shelf, /value="planned" selected/);

  fields.set('returnTo', '/shelf');
  fields.set('status', 'reading');
  const updated = await post('alice');
  assert.equal(updated.status, 303);
  assert.equal(updated.headers.get('location'), '/shelf');
  shelf = await (await browser.request(`${config.appUrl}/shelf`)).text();
  assert.match(shelf, /value="reading" selected/);
  assert.deepEqual(await (await browser.request(`${config.appUrl}/api/shelf`)).json(), { shelf: { alice: 'reading' } });

  fields.set('status', '');
  assert.equal((await post('alice')).status, 303);
  shelf = await (await browser.request(`${config.appUrl}/shelf`)).text();
  assert.match(shelf, /На полке пока нет книг/);
  assert.deepEqual(await (await browser.request(`${config.appUrl}/api/shelf`)).json(), { shelf: {} });
});
