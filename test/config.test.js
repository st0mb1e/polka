import assert from 'node:assert/strict';
import { test } from 'node:test';
import { loadConfig } from '../src/config.js';

const defaults = {
  AUTH_PROVIDER: 'local',
  CLIENT_SECRET: 'c'.repeat(32), SESSION_SECRET: 's'.repeat(32),
  AUTH_COOKIE_SECRET: 'a'.repeat(32), DEMO_PASSWORD: 'Long-Test-Password',
};

test('configuration rejects missing secrets, weak password and invalid ports', () => {
  assert.throws(() => loadConfig({ AUTH_PROVIDER: 'local' }), /DEMO_PASSWORD/);
  assert.throws(() => loadConfig({ ...defaults, CLIENT_SECRET: '' }), /CLIENT_SECRET/);
  assert.throws(() => loadConfig({ ...defaults, APP_PORT: '0' }), /APP_PORT/);
  assert.throws(() => loadConfig({ ...defaults, APP_PORT: '3000', AUTH_PORT: '3000' }), /должны отличаться/);
});

test('Yandex is the default and only requires the application session secret to start', () => {
  const config = loadConfig({ SESSION_SECRET: 's'.repeat(32) });
  assert.equal(config.authProvider, 'yandex');
  assert.equal(config.yandexClientId, '');
  assert.equal(config.yandexClientSecret, '');
  assert.equal(config.clientSecret, undefined);
  assert.throws(() => loadConfig({ ...defaults, AUTH_PROVIDER: 'unknown' }), /AUTH_PROVIDER/);
});

test('local HTTP issuer and application always use loopback addresses', () => {
  const config = loadConfig(defaults);
  assert.equal(config.host, '127.0.0.1');
  assert.equal(config.appUrl, 'http://127.0.0.1:3000');
  assert.equal(config.issuer, 'http://127.0.0.1:3001');
});
