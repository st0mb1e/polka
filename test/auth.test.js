import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { randomBytes } from 'node:crypto';
import { promisify } from 'node:util';
import { after, before, test } from 'node:test';
import { loadConfig } from '../src/config.js';
import { startServers } from '../src/server.js';

async function freePort() {
  const server = createServer();
  await new Promise((resolve, reject) => server.listen(0, '127.0.0.1', resolve).once('error', reject));
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return port;
}

// HTTP test client with separate browser sessions and path-scoped cookies.
class Browser {
  cookies = new Map();

  async request(url, options = {}) {
    url = new URL(url);
    const cookies = [...this.cookies.values()]
      .filter((cookie) => cookie.host === url.hostname && cookie.expires > Date.now()
        && (url.pathname === cookie.path || url.pathname.startsWith(cookie.path.endsWith('/') ? cookie.path : `${cookie.path}/`)))
      .sort((a, b) => b.path.length - a.path.length)
      .map((cookie) => `${cookie.name}=${cookie.value}`).join('; ');
    const response = await fetch(url, {
      ...options, redirect: 'manual', signal: AbortSignal.timeout(5000),
      headers: { cookie: cookies, ...options.headers },
    });
    for (const header of response.headers.getSetCookie()) {
      const [pair, ...attributes] = header.split(';').map((part) => part.trim());
      const split = pair.indexOf('=');
      const cookie = { name: pair.slice(0, split), value: pair.slice(split + 1), host: url.hostname, path: '/', expires: Infinity };
      for (const attribute of attributes) {
        const [name, value] = attribute.split('=');
        if (name.toLowerCase() === 'path') cookie.path = value;
        if (name.toLowerCase() === 'expires') cookie.expires = Date.parse(value);
        if (name.toLowerCase() === 'max-age') cookie.expires = Date.now() + Number(value) * 1000;
      }
      const key = `${cookie.host}:${cookie.path}:${cookie.name}`;
      if (cookie.expires <= Date.now()) this.cookies.delete(key);
      else this.cookies.set(key, cookie);
    }
    return response;
  }

  async follow(response, url, stopAtCallback = false) {
    for (let count = 0; count < 12; count++) {
      if (![302, 303, 307, 308].includes(response.status)) {
        return { response, url: new URL(url), html: await response.text() };
      }
      url = new URL(response.headers.get('location'), url);
      if (stopAtCallback && url.pathname === '/auth/callback') return { response, url };
      response = await this.request(url);
    }
    throw new Error('Too many redirects');
  }

  post(url, values, origin = config.issuer) {
    return this.request(url, { method: 'POST', body: new URLSearchParams(values), headers: { origin } });
  }
}

function hidden(html, name) {
  const match = html.match(new RegExp(`<input[^>]*name="${name}"[^>]*value="([^"]*)"`));
  assert.ok(match, `Missing hidden input: ${name}`);
  return match[1];
}

function action(html, base) {
  const match = html.match(/<form[^>]*action="([^"]*)"/);
  assert.ok(match, 'Missing form');
  return new URL(match[1], base);
}

let config;
let servers;

before(async () => {
  const appPort = await freePort();
  let authPort = await freePort();
  while (authPort === appPort) authPort = await freePort();
  config = loadConfig({
    AUTH_PROVIDER: 'local',
    APP_PORT: String(appPort), AUTH_PORT: String(authPort),
    CLIENT_SECRET: randomBytes(32).toString('hex'),
    SESSION_SECRET: randomBytes(32).toString('hex'),
    AUTH_COOKIE_SECRET: randomBytes(32).toString('hex'),
    DEMO_USERNAME: 'student', DEMO_PASSWORD: 'Test-Only-Password-123!',
    DEMO_NAME: 'Студент', DEMO_EMAIL: 'student@example.local',
  });
  servers = await startServers(config);
});

after(async () => { await servers?.close(); });

async function loginForm(browser, returnTo = '/shelf') {
  const url = `${config.appUrl}/auth/login?returnTo=${encodeURIComponent(returnTo)}`;
  const response = await browser.request(url);
  assert.equal(response.status, 302);
  const authorizationUrl = new URL(response.headers.get('location'));
  assert.equal(authorizationUrl.origin, config.issuer);
  assert.equal(authorizationUrl.searchParams.get('response_type'), 'code');
  assert.equal(authorizationUrl.searchParams.get('code_challenge_method'), 'S256');
  for (const name of ['state', 'nonce', 'code_challenge']) assert.ok(authorizationUrl.searchParams.get(name));
  const form = await browser.follow(response, url);
  assert.equal(form.response.status, 200);
  assert.match(form.html, /name="password"/);
  return { ...form, authorizationUrl };
}

async function authorizationCode(browser, returnTo = '/shelf') {
  const form = await loginForm(browser, returnTo);
  const response = await browser.post(action(form.html, form.url), {
    username: config.username, password: config.password, csrf: hidden(form.html, 'csrf'),
  });
  assert.equal(response.status, 303);
  const consent = await browser.follow(response, form.url, true);
  assert.equal(consent.response.status, 200);
  assert.match(consent.html, /Разрешить доступ/);
  const confirmed = await browser.post(action(consent.html, consent.url), { csrf: hidden(consent.html, 'csrf') });
  const callback = await browser.follow(confirmed, consent.url, true);
  assert.equal(callback.url.pathname, '/auth/callback');
  assert.ok(callback.url.searchParams.get('code'));
  return callback.url;
}

async function signedIn(browser, returnTo = '/shelf') {
  const callback = await authorizationCode(browser, returnTo);
  const response = await browser.request(callback);
  assert.equal(response.status, 302);
  assert.equal(response.headers.get('location'), returnTo);
  return callback;
}

async function storedSession(browser) {
  const cookie = [...browser.cookies.values()].find((value) => value.name === 'app.sid');
  assert.ok(cookie);
  const signedValue = decodeURIComponent(cookie.value);
  const id = signedValue.slice(2, signedValue.lastIndexOf('.'));
  return { id, data: await promisify(servers.store.get).call(servers.store, id) };
}

test('catalogue is public, removed pages return 404 and personal pages require login', async () => {
  const browser = new Browser();
  for (const [path, title] of [['/', 'Каталог книг']]) {
    const response = await browser.request(`${config.appUrl}${path}`);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.equal(response.headers.get('referrer-policy'), 'strict-origin');
    assert.ok(response.headers.get('content-security-policy'));
    const html = await response.text();
    assert.ok(html.includes(`<h1>${title}</h1>`));
    assert.ok(!html.includes('href="/about"'));
  }
  assert.equal((await browser.request(`${config.appUrl}/about`)).status, 404);
  for (const path of ['/shelf', '/profile']) {
    const response = await browser.request(`${config.appUrl}${path}`);
    assert.equal(response.status, 302);
    assert.equal(response.headers.get('location'), `/auth/login?returnTo=${encodeURIComponent(path)}`);
  }
  const legacy = await browser.request(`${config.appUrl}/dashboard`);
  assert.equal(legacy.headers.get('location'), '/shelf');
  assert.equal((await browser.request(`${config.appUrl}/api/me`)).status, 401);
  assert.equal((await browser.request(`${config.appUrl}/api/shelf`)).status, 401);
});

test('discovery advertises OAuth code flow, S256 PKCE and signed keys', async () => {
  const browser = new Browser();
  const metadata = await (await browser.request(`${config.issuer}/.well-known/openid-configuration`)).json();
  assert.equal(metadata.issuer, config.issuer);
  assert.deepEqual(metadata.response_types_supported, ['code']);
  assert.ok(metadata.code_challenge_methods_supported.includes('S256'));
  const jwks = await (await browser.request(metadata.jwks_uri)).json();
  assert.equal(jwks.keys[0].alg, 'RS256');
  assert.equal(jwks.keys[0].d, undefined, 'Private signing key must not be published');
});

test('complete OAuth flow opens personal shelf, rotates session and hides tokens', async () => {
  const browser = new Browser();
  const callback = await authorizationCode(browser, '/shelf');
  const previous = await storedSession(browser);
  const response = await browser.request(callback);
  assert.equal(response.status, 302);
  assert.equal(response.headers.get('location'), '/shelf');
  const current = await storedSession(browser);
  assert.notEqual(previous.id, current.id, 'Session ID must change after login');
  assert.equal(await promisify(servers.store.get).call(servers.store, previous.id), undefined);
  for (const [path, title] of [['/', 'Каталог книг'], ['/shelf', 'Моя полка'], ['/profile', 'Профиль']]) {
    const page = await browser.request(`${config.appUrl}${path}`);
    assert.equal(page.status, 200);
    const html = await page.text();
    assert.ok(html.includes(`<h1>${title}</h1>`));
    assert.match(html, /Студент/);
    assert.ok(!html.includes(current.data.idToken));
  }
  const api = await browser.request(`${config.appUrl}/api/me`);
  assert.deepEqual(await api.json(), { user: { sub: 'student', username: 'student', name: 'Студент', email: 'student@example.local' } });
  const cookie = response.headers.getSetCookie().find((value) => value.startsWith('app.sid='));
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Lax/);
  assert.equal((await browser.request(callback)).status, 400, 'Callback must be single use');
});

test('wrong password and login-form CSRF do not create an application session', async () => {
  const browser = new Browser();
  const form = await loginForm(browser);
  const url = action(form.html, form.url);
  const wrong = await browser.post(url, { username: config.username, password: 'wrong-password', csrf: hidden(form.html, 'csrf') });
  assert.equal(wrong.status, 401);
  assert.match(await wrong.text(), /Неверный логин или пароль/);
  const csrf = await browser.post(url, { username: config.username, password: config.password, csrf: 'forged' });
  assert.equal(csrf.status, 403);
  assert.equal((await browser.request(`${config.appUrl}/api/me`)).status, 401);
});

test('callback without a pending request and forged state are rejected', async () => {
  const browser = new Browser();
  assert.equal((await browser.request(`${config.appUrl}/auth/callback?code=fake&state=fake`)).status, 400);
  const callback = await authorizationCode(browser);
  const correct = new URL(callback);
  callback.searchParams.set('state', 'forged-state');
  assert.equal((await browser.request(callback)).status, 400);
  assert.equal((await browser.request(correct)).status, 400);
  assert.equal((await browser.request(`${config.appUrl}/api/me`)).status, 401);
});

test('ID-token nonce mismatch is rejected', async () => {
  const browser = new Browser();
  const callback = await authorizationCode(browser);
  const { id, data } = await storedSession(browser);
  data.authRequest.nonce = 'different-nonce';
  await promisify(servers.store.set).call(servers.store, id, data);
  assert.equal((await browser.request(callback)).status, 400);
  assert.equal((await browser.request(`${config.appUrl}/api/me`)).status, 401);
});

test('token endpoint rejects incorrect client secret and PKCE verifier', async () => {
  const browser = new Browser();
  const callback = await authorizationCode(browser);
  const { data } = await storedSession(browser);
  const tokenBody = new URLSearchParams({
    grant_type: 'authorization_code', code: callback.searchParams.get('code'),
    redirect_uri: `${config.appUrl}/auth/callback`, code_verifier: data.authRequest.codeVerifier,
  });
  const tokenRequest = (secret) => browser.request(`${config.issuer}/token`, {
    method: 'POST', body: tokenBody,
    headers: { authorization: `Basic ${Buffer.from(`${config.clientId}:${secret}`).toString('base64')}` },
  });
  const wrongClient = await tokenRequest('wrong-secret');
  assert.equal(wrongClient.status, 401);
  assert.equal((await wrongClient.json()).error, 'invalid_client');
  tokenBody.set('code_verifier', 'x'.repeat(43));
  const wrongVerifier = await tokenRequest(config.clientSecret);
  assert.equal(wrongVerifier.status, 400);
  assert.equal((await wrongVerifier.json()).error, 'invalid_grant');
  assert.equal((await browser.request(`${config.appUrl}/api/me`)).status, 401);
});

test('authorization server requires PKCE and rejects unregistered redirect URIs', async () => {
  const browser = new Browser();
  const form = await loginForm(browser);
  const missingPkce = new URL(form.authorizationUrl);
  missingPkce.searchParams.delete('code_challenge');
  missingPkce.searchParams.delete('code_challenge_method');
  const response = await browser.request(missingPkce);
  assert.ok([302, 303].includes(response.status));
  assert.equal(new URL(response.headers.get('location')).searchParams.get('error'), 'invalid_request');
  const invalidRedirect = new URL(form.authorizationUrl);
  invalidRedirect.searchParams.set('redirect_uri', 'https://example.invalid/stolen');
  const rejected = await browser.request(invalidRedirect);
  assert.equal(rejected.status, 400);
  assert.equal(rejected.headers.get('location'), null);
});

test('cancelling consent returns an error and keeps protected pages closed', async () => {
  const browser = new Browser();
  const form = await loginForm(browser);
  const login = await browser.post(action(form.html, form.url), {
    username: config.username, password: config.password, csrf: hidden(form.html, 'csrf'),
  });
  const consent = await browser.follow(login, form.url);
  const wrongCsrf = await browser.post(action(consent.html, consent.url), { csrf: 'wrong' });
  assert.equal(wrongCsrf.status, 403);
  const denied = await browser.post(`${consent.url}/abort`, { csrf: hidden(consent.html, 'csrf') });
  const callback = await browser.follow(denied, consent.url, true);
  assert.equal(callback.url.searchParams.get('error'), 'access_denied');
  const response = await browser.request(callback.url);
  assert.equal(response.status, 403);
  assert.match(await response.text(), /Вход отменён/);
  assert.equal((await browser.request(`${config.appUrl}/api/me`)).status, 401);
});

test('return URL is restricted to application pages', async () => {
  for (const [returnTo, expected] of [['https://example.invalid/redirect', '/shelf'], ['/profile', '/profile'], ['/about', '/shelf']]) {
    const browser = new Browser();
    const callback = await authorizationCode(browser, returnTo);
    const response = await browser.request(callback);
    assert.equal(response.headers.get('location'), expected);
  }
});

test('expired authentication request and expired application session are rejected', async () => {
  const browser = new Browser();
  const callback = await authorizationCode(browser);
  const pending = await storedSession(browser);
  pending.data.authRequest.createdAt = Date.now() - config.authRequestLifetimeMs - 1;
  await promisify(servers.store.set).call(servers.store, pending.id, pending.data);
  assert.equal((await browser.request(callback)).status, 400);

  const second = new Browser();
  await signedIn(second);
  const active = await storedSession(second);
  active.data.expiresAt = Date.now() - 1;
  await promisify(servers.store.set).call(servers.store, active.id, active.data);
  assert.equal((await second.request(`${config.appUrl}/api/me`)).status, 401);
  assert.equal(await promisify(servers.store.get).call(servers.store, active.id), undefined);
});

test('logout rejects CSRF, clears old session and also terminates provider session', async () => {
  const browser = new Browser();
  await signedIn(browser);
  const dashboard = await browser.request(config.appUrl);
  const csrf = hidden(await dashboard.text(), 'csrf');
  const wrongCsrf = await browser.post(`${config.appUrl}/auth/logout`, { csrf: 'wrong' }, config.appUrl);
  assert.equal(wrongCsrf.status, 403);
  assert.equal((await browser.request(`${config.appUrl}/api/me`)).status, 200);
  const wrongOrigin = await browser.post(`${config.appUrl}/auth/logout`, { csrf }, 'https://example.invalid');
  assert.equal(wrongOrigin.status, 403);
  const oldSession = new Browser();
  oldSession.cookies = new Map(browser.cookies);
  const logout = await browser.post(`${config.appUrl}/auth/logout`, { csrf }, config.appUrl);
  assert.equal(logout.status, 303);
  assert.equal((await oldSession.request(`${config.appUrl}/api/me`)).status, 401);
  const confirmation = await browser.follow(logout, config.appUrl);
  assert.match(confirmation.html, /Подтвердить выход/);
  const confirmed = await browser.post(action(confirmation.html, confirmation.url), {
    xsrf: hidden(confirmation.html, 'xsrf'), logout: 'yes',
  });
  const landing = await browser.follow(confirmed, confirmation.url);
  assert.equal(landing.response.status, 200);
  assert.equal(landing.url.pathname, '/');
  assert.equal(landing.url.searchParams.get('loggedOut'), '1');
  assert.equal((await browser.request(`${config.appUrl}/api/me`)).status, 401);
  // A new authorization request must ask for a password again.
  await loginForm(browser);
});

test('repeated incorrect passwords are rate limited', async () => {
  const browser = new Browser();
  const form = await loginForm(browser);
  let status;
  for (let count = 0; count < 11 && status !== 429; count++) {
    const response = await browser.post(action(form.html, form.url), {
      username: config.username, password: 'incorrect', csrf: hidden(form.html, 'csrf'),
    });
    status = response.status;
    assert.ok([401, 429].includes(status));
    await response.text();
  }
  assert.equal(status, 429);
});
