import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
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
let mockOrigin;
let store;
let shelfStore;
let storageDirectory;
let tokenRequests = 0;
let tokenFailure = false;
let tokenMode = 'valid';
let privateKey;
let wrongPrivateKey;
const codes = new Map();
const clientId = 'test-client.apps.googleusercontent.com';
const clientSecret = 'private-test-google-secret';
const profile = { sub: '123456789', name: 'Студент Google', email: 'student@gmail.com', email_verified: true };
let activeProfile = profile;

async function googleFetch(url, options) {
  const target = new URL(url);
  if (target.href === 'https://accounts.google.com/.well-known/openid-configuration') return fetch(`${mockOrigin}/discovery`, options);
  if (target.href === 'https://oauth2.googleapis.com/token') return fetch(`${mockOrigin}/token`, options);
  if (target.href === 'https://www.googleapis.com/oauth2/v3/certs') return fetch(`${mockOrigin}/certs`, options);
  throw new Error(`Unexpected external request during test: ${target.origin}${target.pathname}`);
}

function createIdToken(code, accessToken) {
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    ...activeProfile, iss: 'https://accounts.google.com', aud: clientId, iat: now, exp: now + 1800,
    nonce: code.nonce, at_hash: createHash('sha256').update(accessToken).digest().subarray(0, 16).toString('base64url'),
  };
  if (tokenMode === 'audience') claims.aud = 'another-client';
  if (tokenMode === 'issuer') claims.iss = 'https://example.invalid';
  if (tokenMode === 'expired') claims.exp = now - 120;
  if (tokenMode === 'short-lived') claims.exp = now + 90;
  if (tokenMode === 'nonce') claims.nonce = 'forged-nonce';
  if (tokenMode === 'unverified-email') claims.email_verified = false;
  if (tokenMode === 'missing-email') delete claims.email;
  if (tokenMode === 'missing-subject') delete claims.sub;
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'google-test-key' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const input = `${header}.${payload}`;
  const signature = sign('RSA-SHA256', Buffer.from(input), tokenMode === 'signature' ? wrongPrivateKey : privateKey);
  return `${input}.${signature.toString('base64url')}`;
}

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
  const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
  privateKey = keys.privateKey;
  wrongPrivateKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
  const jwk = { ...keys.publicKey.export({ format: 'jwk' }), alg: 'RS256', use: 'sig', kid: 'google-test-key' };
  mock.get('/discovery', (_req, res) => res.json({
    issuer: 'https://accounts.google.com', authorization_endpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
    token_endpoint: 'https://oauth2.googleapis.com/token', jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs',
    response_types_supported: ['code'], subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'], token_endpoint_auth_methods_supported: ['client_secret_post'],
    code_challenge_methods_supported: ['S256'],
  }));
  mock.get('/certs', (_req, res) => res.json({ keys: [jwk] }));
  mock.post('/token', (req, res) => {
    tokenRequests++;
    assert.equal(req.body.client_id, clientId);
    assert.equal(req.body.client_secret, clientSecret);
    assert.equal(req.body.grant_type, 'authorization_code');
    assert.equal(req.body.redirect_uri, `${config.appUrl}/auth/callback`);
    const code = codes.get(req.body.code);
    const actualChallenge = createHash('sha256').update(req.body.code_verifier).digest('base64url');
    if (tokenFailure || !code || actualChallenge !== code.challenge) return res.status(400).json({ error: 'invalid_grant' });
    codes.delete(req.body.code);
    const accessToken = `private-test-access-token-${req.body.code}`;
    return res.json({ token_type: 'bearer', access_token: accessToken, expires_in: 1800,
      ...(tokenMode === 'missing-id-token' ? {} : { id_token: createIdToken(code, accessToken) }),
    });
  });
  mockServer = await listen(mock);
  mockOrigin = `http://127.0.0.1:${mockServer.address().port}`;
  const portProbe = await listen(express());
  const appPort = portProbe.address().port;
  await close(portProbe);
  config = loadConfig({
    APP_PORT: String(appPort),
    HOST: '127.0.0.1', APP_URL: `http://localhost:${appPort}/`,
    AUTH_PROVIDER: 'google', SESSION_SECRET: randomBytes(32).toString('hex'),
    GOOGLE_CLIENT_ID: clientId, GOOGLE_CLIENT_SECRET: clientSecret,
  });
  const { app: realApp, store: realStore } = await createWebApp(config, { fetchImplementation: googleFetch }, { shelfStore });
  appServer = await new Promise((resolve, reject) => {
    const server = realApp.listen(new URL(config.appUrl).port, '127.0.0.1', () => resolve(server));
    server.once('error', reject);
  });
  store = realStore;
});

after(async () => { await Promise.all([close(appServer), close(mockServer)]); await rm(storageDirectory, { recursive: true, force: true }); });
afterEach(() => { tokenFailure = false; tokenMode = 'valid'; activeProfile = profile; });

async function begin(browser, returnTo = '/shelf') {
  const response = await browser.request(`${config.appUrl}/auth/login?returnTo=${encodeURIComponent(returnTo)}`);
  assert.equal(response.status, 302);
  const authorizationUrl = new URL(response.headers.get('location'));
  const code = randomBytes(16).toString('hex');
  codes.set(code, { challenge: authorizationUrl.searchParams.get('code_challenge'), nonce: authorizationUrl.searchParams.get('nonce') });
  const callback = new URL(`${config.appUrl}/auth/callback`);
  callback.searchParams.set('code', code);
  callback.searchParams.set('state', authorizationUrl.searchParams.get('state'));
  return { authorizationUrl, callback };
}

test('Google redirect uses OAuth code, PKCE, state, nonce and limited profile scopes', async () => {
  const browser = new Browser();
  const { authorizationUrl } = await begin(browser);
  assert.equal(authorizationUrl.origin, 'https://accounts.google.com');
  assert.equal(authorizationUrl.pathname, '/o/oauth2/v2/auth');
  assert.equal(authorizationUrl.searchParams.get('client_id'), clientId);
  assert.equal(authorizationUrl.searchParams.get('response_type'), 'code');
  assert.equal(authorizationUrl.searchParams.get('scope'), 'openid profile email');
  assert.equal(authorizationUrl.searchParams.get('redirect_uri'), `${config.appUrl}/auth/callback`);
  assert.equal(new URL(authorizationUrl.searchParams.get('redirect_uri')).hostname, 'localhost');
  assert.equal(authorizationUrl.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(authorizationUrl.searchParams.get('prompt'), 'select_account');
  assert.equal(authorizationUrl.searchParams.has('access_type'), false);
  assert.ok(authorizationUrl.searchParams.get('state'));
  assert.equal(authorizationUrl.searchParams.has('client_secret'), false);
  assert.ok(authorizationUrl.searchParams.get('nonce'));
});

test('Google callback validates a signed ID token, rotates the session and hides tokens', async () => {
  const browser = new Browser();
  const { callback } = await begin(browser);
  const previousCookie = browser.cookie;
  const response = await browser.request(callback);
  assert.equal(response.status, 302);
  assert.equal(response.headers.get('location'), '/shelf');
  assert.notEqual(browser.cookie, previousCookie);
  const api = await browser.request(`${config.appUrl}/api/me`);
  assert.equal(api.status, 200);
  assert.deepEqual(await api.json(), { user: { sub: profile.sub, username: profile.email, name: profile.name, email: profile.email } });
  for (const path of ['/', '/shelf', '/profile']) {
    const html = await (await browser.request(`${config.appUrl}${path}`)).text();
    assert.match(html, /Студент Google/);
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

test('forged Google state is rejected before token exchange', async () => {
  const browser = new Browser();
  const { callback } = await begin(browser);
  const count = tokenRequests;
  callback.searchParams.set('state', 'forged');
  assert.equal((await browser.request(callback)).status, 400);
  assert.equal(tokenRequests, count);
  assert.equal((await browser.request(`${config.appUrl}/api/me`)).status, 401);
});

test('Google rejects an authorization code with a different PKCE challenge', async () => {
  const browser = new Browser();
  const { callback } = await begin(browser);
  codes.get(callback.searchParams.get('code')).challenge = 'forged-challenge';
  assert.equal((await browser.request(callback)).status, 400);
  assert.equal((await browser.request(`${config.appUrl}/api/me`)).status, 401);
});

test('Google profile falls back to email when the name is absent and caps the session at ID token expiry', async () => {
  activeProfile = { ...profile, name: undefined };
  tokenMode = 'short-lived';
  const browser = new Browser();
  const { callback } = await begin(browser);
  assert.equal((await browser.request(callback)).status, 302);
  const { user } = await (await browser.request(`${config.appUrl}/api/me`)).json();
  assert.equal(user.name, profile.email);
  const signedCookie = decodeURIComponent(browser.cookie.slice('app.sid='.length));
  const id = signedCookie.slice(2, signedCookie.lastIndexOf('.'));
  const session = await promisify(store.get).call(store, id);
  assert.ok(session.expiresAt <= Date.now() + 90_000);
});

test('denying Google consent does not create a session', async () => {
  const browser = new Browser();
  const { callback } = await begin(browser);
  callback.searchParams.delete('code');
  callback.searchParams.set('error', 'access_denied');
  const response = await browser.request(callback);
  assert.equal(response.status, 403);
  assert.match(await response.text(), /Вход отменён/);
  assert.equal((await browser.request(`${config.appUrl}/api/me`)).status, 401);
});

test('invalid Google tokens cannot authenticate a user', async () => {
  for (const failure of ['token', 'audience', 'issuer', 'expired', 'nonce', 'signature', 'missing-id-token', 'unverified-email', 'missing-email', 'missing-subject']) {
    tokenFailure = failure === 'token'; tokenMode = failure;
    const browser = new Browser();
    const { callback } = await begin(browser);
    assert.equal((await browser.request(callback)).status, 400);
    assert.equal((await browser.request(`${config.appUrl}/api/me`)).status, 401);
  }
});

test('Google session logout is protected by CSRF and invalidates the previous cookie', async () => {
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

test('unconfigured Google mode serves public pages and refuses login without a local fallback', async () => {
  const { app } = await createWebApp(loadConfig({ SESSION_SECRET: 's'.repeat(32) }));
  const server = await listen(app);
  try {
    const origin = `http://127.0.0.1:${server.address().port}`;
    const browser = new Browser();
    const page = await browser.request(origin);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /Войти через Google/);
    const response = await browser.request(`${origin}/auth/login`);
    assert.equal(response.status, 503);
    assert.equal(response.headers.get('location'), null);
    assert.equal((await browser.request(`${origin}/api/me`)).status, 401);
  } finally { await close(server); }
});

test('Google discovery failure keeps public pages available and a later login retries discovery', async () => {
  let requests = 0;
  const { app } = await createWebApp(config, {
    async fetchImplementation(url, options) {
      requests++;
      if (requests === 1) throw new Error('Google temporarily unavailable');
      return googleFetch(url, options);
    },
  });
  assert.equal(requests, 0);
  const server = await listen(app);
  try {
    const origin = `http://127.0.0.1:${server.address().port}`;
    const browser = new Browser();
    assert.equal((await browser.request(origin)).status, 200);
    assert.equal(requests, 0);
    assert.equal((await browser.request(`${origin}/auth/login`)).status, 503);
    assert.equal((await browser.request(`${origin}/api/me`)).status, 401);
    assert.equal((await browser.request(`${origin}/auth/login`)).status, 302);
    assert.equal((await browser.request(`${origin}/auth/login`)).status, 302);
    assert.equal(requests, 2, 'Successful discovery should be cached');
  } finally { await close(server); }
});

test('HTTPS origins use a Secure session cookie behind a loopback reverse proxy', async () => {
  const { app } = await createWebApp({ ...config, appUrl: 'https://polka.example' }, { fetchImplementation: googleFetch });
  const server = await listen(app);
  try {
    const origin = `http://127.0.0.1:${server.address().port}`;
    const response = await new Browser().request(`${origin}/auth/login`, { headers: { 'x-forwarded-proto': 'https' } });
    assert.equal(response.status, 302);
    assert.equal(new URL(response.headers.get('location')).searchParams.get('redirect_uri'), 'https://polka.example/auth/callback');
    const cookie = response.headers.get('set-cookie');
    assert.match(cookie, /; Secure/);
    assert.match(cookie, /; HttpOnly/);
    assert.match(cookie, /; SameSite=Lax/);
    const insecure = await new Browser().request(`${origin}/auth/login`);
    assert.equal(insecure.headers.get('set-cookie'), null);
  } finally { await close(server); }
});

async function reader(subject) {
  activeProfile = { ...profile, sub: subject };
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
  assert.deepEqual(await reopenedStore.get(shelfUserKey('google', 'reader-one')), expected);
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
