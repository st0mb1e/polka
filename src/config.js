function port(value, fallback, name) {
  const result = Number(value ?? fallback);
  if (!Number.isInteger(result) || result < 1024 || result > 65535) {
    throw new Error(`${name} должен быть целым числом от 1024 до 65535.`);
  }
  return result;
}

function secret(env, name) {
  if (typeof env[name] !== 'string' || env[name].length < 32) {
    throw new Error(`${name} должен содержать не менее 32 символов. Выполните npm run setup.`);
  }
  return env[name];
}

export function loadConfig(env = process.env) {
  const authProvider = env.AUTH_PROVIDER || 'yandex';
  if (!['local', 'yandex'].includes(authProvider)) {
    throw new Error('AUTH_PROVIDER должен быть yandex или local.');
  }
  const appPort = port(env.APP_PORT, 3000, 'APP_PORT');
  const authPort = port(env.AUTH_PORT, 3001, 'AUTH_PORT');
  if (appPort === authPort) throw new Error('APP_PORT и AUTH_PORT должны отличаться.');
  if (authProvider === 'local' && (!env.DEMO_PASSWORD || env.DEMO_PASSWORD.length < 12)) {
    throw new Error('DEMO_PASSWORD должен содержать не менее 12 символов.');
  }
  return Object.freeze({
    host: env.HOST?.trim() || '127.0.0.1',
    authProvider,
    yandexClientId: env.YANDEX_CLIENT_ID?.trim() || '',
    yandexClientSecret: env.YANDEX_CLIENT_SECRET?.trim() || '',
    appPort,
    authPort,
    appUrl: `http://127.0.0.1:${appPort}`,
    issuer: `http://127.0.0.1:${authPort}`,
    clientId: env.CLIENT_ID || 'lab-web-app',
    clientSecret: authProvider === 'local' ? secret(env, 'CLIENT_SECRET') : undefined,
    sessionSecret: secret(env, 'SESSION_SECRET'),
    authCookieSecret: authProvider === 'local' ? secret(env, 'AUTH_COOKIE_SECRET') : undefined,
    username: env.DEMO_USERNAME || 'student',
    password: env.DEMO_PASSWORD,
    name: env.DEMO_NAME || 'Студент',
    email: env.DEMO_EMAIL || 'student@example.local',
    sessionLifetimeMs: 60 * 60 * 1000,
    authRequestLifetimeMs: 5 * 60 * 1000,
  });
}
