import { setup, envPath } from './setup.js';
import { loadConfig } from '../src/config.js';
import { startServers } from '../src/server.js';

try {
  await setup();
  process.loadEnvFile(envPath);
  const config = loadConfig();
  const servers = await startServers(config);
  console.log(`Веб-приложение: ${config.appUrl}`);
  if (config.authProvider === 'local') console.log(`Сервер авторизации: ${config.issuer}`);
  else {
    console.log('Авторизация: Google OAuth / OpenID Connect.');
    console.log(`Redirect URI для Google: ${config.appUrl}/auth/callback`);
    if (!config.googleClientId || !config.googleClientSecret) {
      console.log('Для включения входа заполните GOOGLE_CLIENT_ID и GOOGLE_CLIENT_SECRET в .env.');
    }
  }
  console.log('Для остановки нажмите Ctrl+C.');
  let closing = false;
  const stop = async () => {
    if (closing) return;
    closing = true;
    await servers.close();
  };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
} catch (error) {
  console.error(`Не удалось запустить сервер: ${error.message}`);
  process.exitCode = 1;
}
