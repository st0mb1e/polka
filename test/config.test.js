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

test('default bind host and public URLs use loopback addresses', () => {
  const config = loadConfig(defaults);
  assert.equal(config.host, '127.0.0.1');
  assert.equal(config.appUrl, 'http://127.0.0.1:3000');
  assert.equal(config.issuer, 'http://127.0.0.1:3001');
});

test('public application and issuer URLs follow HOST and their own ports', () => {
  for (const [host, urlHost] of [['192.0.2.10', '192.0.2.10'], ['polka.example', 'polka.example'], ['::1', '[::1]']]) {
    const config = loadConfig({ ...defaults, HOST: host, APP_PORT: '8080', AUTH_PORT: '8081' });
    assert.equal(config.host, host);
    assert.equal(config.appUrl, `http://${urlHost}:8080`);
    assert.equal(config.issuer, `http://${urlHost}:8081`);
  }
});

test('wildcard bind addresses use reachable loopback URLs by default', () => {
  for (const [host, urlHost] of [['0.0.0.0', '127.0.0.1'], ['::', '[::1]']]) {
    const config = loadConfig({ ...defaults, HOST: host });
    assert.equal(config.host, host);
    assert.equal(config.appUrl, `http://${urlHost}:3000`);
    assert.equal(config.issuer, `http://${urlHost}:3001`);
  }
});

test('explicit public URLs are canonical origins independent of bind address and ports', () => {
  const config = loadConfig({
    ...defaults, HOST: '0.0.0.0', APP_PORT: '8080', AUTH_PORT: '8081',
    APP_URL: ' https://POLKA.example:443/ ', AUTH_URL: 'https://login.polka.example:8443/',
  });
  assert.equal(config.host, '0.0.0.0');
  assert.equal(config.appPort, 8080);
  assert.equal(config.authPort, 8081);
  assert.equal(config.appUrl, 'https://polka.example');
  assert.equal(config.issuer, 'https://login.polka.example:8443');
});

test('public URL configuration rejects invalid origins before starting OAuth', () => {
  const invalid = [
    'polka.example', 'ftp://polka.example', 'javascript:alert(1)',
    'https://polka.example/shelf', 'https://user:password@polka.example',
    'https://polka.example/?query=1', 'https://polka.example/#fragment',
    'http://0.0.0.0:3000', 'http://[::]:3000',
  ];
  for (const name of ['APP_URL', 'AUTH_URL']) {
    for (const value of invalid) {
      assert.throws(() => loadConfig({ ...defaults, [name]: value }), new RegExp(name));
    }
  }
});
