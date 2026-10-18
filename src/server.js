import { createAuthServer } from './auth-server.js';
import { createWebApp } from './web-app.js';

function listen(app, port, host) {
  return new Promise((resolve, reject) => {
    const server = app.listen(port, host, () => resolve(server));
    server.once('error', reject);
  });
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
    server.closeAllConnections();
  });
}

export async function startServers(config, appOptions) {
  if (config.authProvider === 'yandex') {
    const { app, store } = await createWebApp(config, undefined, appOptions);
    const appServer = await listen(app, config.appPort, config.host);
    return { appServer, store, async close() { await closeServer(appServer); } };
  }
  const { app: authApp, provider } = await createAuthServer(config);
  const authServer = await listen(authApp, config.authPort, config.host);
  try {
    const { app: webApp, store } = await createWebApp(config, undefined, appOptions);
    const appServer = await listen(webApp, config.appPort, config.host);
    return {
      appServer, authServer, provider, store,
      async close() {
        await Promise.all([closeServer(appServer), closeServer(authServer)]);
      },
    };
  } catch (error) {
    await closeServer(authServer);
    throw error;
  }
}
