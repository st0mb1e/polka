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

function publicOrigin(value, fallback, name) {
  let url;
  try {
    url = new URL(value?.trim() || fallback);
  } catch {
    throw new Error(`${name} должен быть полным адресом сайта, например http://192.168.1.10:3000.`);
  }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password
    || url.pathname !== '/' || url.search || url.hash) {
    throw new Error(`${name} должен содержать только протокол, хост и порт, без пути, параметров и учётных данных.`);
  }
  if (['0.0.0.0', '[::]'].includes(url.hostname)) {
    throw new Error(`${name} должен содержать адрес, доступный браузеру, а не 0.0.0.0 или ::.`);
  }
  // Browser Origin headers omit trailing slashes and default ports.
  return url.origin;
}

export function loadConfig(env = process.env) {
  const authProvider = env.AUTH_PROVIDER || 'yandex';
  if (!['local', 'yandex'].includes(authProvider)) {
    throw new Error('AUTH_PROVIDER должен быть yandex или local.');
  }
  const appPort = port(env.APP_PORT, 3000, 'APP_PORT');
  const authPort = port(env.AUTH_PORT, 3001, 'AUTH_PORT');
  if (appPort === authPort) throw new Error('APP_PORT и AUTH_PORT должны отличаться.');
  const host = env.HOST?.trim() || '127.0.0.1';
  // Wildcard addresses bind network interfaces but cannot identify an OAuth site.
  const addressHost = host === '0.0.0.0' ? '127.0.0.1' : host === '::' ? '::1' : host;
  const urlHost = addressHost.includes(':') && !addressHost.startsWith('[') ? `[${addressHost}]` : addressHost;
  const appUrl = publicOrigin(env.APP_URL, `http://${urlHost}:${appPort}`, 'APP_URL');
  const issuer = publicOrigin(env.AUTH_URL, `http://${urlHost}:${authPort}`, 'AUTH_URL');
  if (authProvider === 'local' && (!env.DEMO_PASSWORD || env.DEMO_PASSWORD.length < 12)) {
    throw new Error('DEMO_PASSWORD должен содержать не менее 12 символов.');
  }
  return Object.freeze({
    host,
    authProvider,
    yandexClientId: env.YANDEX_CLIENT_ID?.trim() || '',
    yandexClientSecret: env.YANDEX_CLIENT_SECRET?.trim() || '',
    appPort,
    authPort,
    appUrl,
    issuer,
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
