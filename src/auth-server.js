import { generateKeyPairSync, randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { rateLimit } from 'express-rate-limit';
import { Provider, errors } from 'oidc-provider';
import { equalSecrets, interactionCsrf, noStore, securityHeaders } from './security.js';
import { consentPage, errorPage, loginPage, logoutPage } from './views.js';

const scrypt = promisify(scryptCallback);

export async function createAuthServer(config) {
  const salt = randomBytes(32);
  const passwordHash = await scrypt(config.password, salt, 64);
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...privateKey.export({ format: 'jwk' }), use: 'sig', alg: 'RS256', kid: randomBytes(16).toString('hex') };
  const provider = new Provider(config.issuer, {
    clients: [{
      client_id: config.clientId,
      client_secret: config.clientSecret,
      client_name: 'Полка',
      redirect_uris: [`${config.appUrl}/auth/callback`],
      post_logout_redirect_uris: [`${config.appUrl}/auth/logged-out`],
      grant_types: ['authorization_code'],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_basic',
    }],
    jwks: { keys: [jwk] },
    responseTypes: ['code'],
    claims: { openid: ['sub'], profile: ['name', 'preferred_username'], email: ['email'] },
    scopes: ['openid', 'profile', 'email'],
    pkce: { required: () => true },
    cookies: {
      keys: [config.authCookieSecret],
      names: { session: 'auth.session', interaction: 'auth.interaction', resume: 'auth.resume' },
      long: { httpOnly: true, sameSite: 'lax', secure: false },
      short: { httpOnly: true, sameSite: 'lax', secure: false },
    },
    ttl: { AccessToken: 3600, AuthorizationCode: 60, Grant: 3600, IdToken: 3600, Interaction: 300, Session: 3600 },
    features: {
      devInteractions: { enabled: false },
      rpInitiatedLogout: {
        enabled: true,
        logoutSource: async (ctx, form) => { ctx.body = logoutPage(form); },
        postLogoutSuccessSource: async (ctx) => {
          ctx.body = errorPage('Вы вышли', 'Сеанс авторизации завершён.', true, config.appUrl);
        },
      },
    },
    interactions: { url: (_ctx, interaction) => `/interaction/${interaction.uid}` },
    async findAccount(_ctx, accountId) {
      if (accountId !== config.username) return undefined;
      return {
        accountId,
        async claims() {
          return { sub: accountId, name: config.name, preferred_username: config.username, email: config.email };
        },
      };
    },
    async renderError(ctx) {
      ctx.type = 'html';
      ctx.body = errorPage('Ошибка авторизации', 'Запрос отклонён. Вернитесь в приложение и начните вход заново.', true, config.appUrl);
    },
  });

  const app = express();
  app.disable('x-powered-by');
  app.use(securityHeaders(config));
  app.use('/assets', express.static(fileURLToPath(new URL('../public/', import.meta.url))));
  app.use(noStore);
  app.get('/', (_req, res) => res.send(errorPage('Сервер авторизации', 'Для входа откройте приложение «Полка».', true, config.appUrl)));
  app.get('/health', (_req, res) => res.json({ status: 'ok', service: 'authorization-server' }));
  const body = express.urlencoded({ extended: false, limit: '8kb', parameterLimit: 10 });

  async function getInteraction(req, res) {
    const details = await provider.interactionDetails(req, res);
    if (details.uid !== req.params.uid) throw new errors.InvalidRequest('interaction mismatch');
    return details;
  }

  function validForm(req, details) {
    return req.get('origin') === config.issuer
      && equalSecrets(req.body?.csrf, interactionCsrf(config.authCookieSecret, details.uid));
  }

  function rejectForm(res) {
    return res.status(403).send(errorPage('Форма отклонена', 'Откройте страницу входа заново и повторите действие.', true, config.appUrl));
  }

  app.get('/interaction/:uid', async (req, res) => {
    const details = await getInteraction(req, res);
    const csrf = interactionCsrf(config.authCookieSecret, details.uid);
    if (details.prompt.name === 'login') return res.send(loginPage(details.uid, csrf, config.username));
    if (details.prompt.name === 'consent') return res.send(consentPage(details.uid, csrf, config.username));
    return res.status(400).send(errorPage('Вход недоступен', 'Начните вход заново.', true, config.appUrl));
  });

  const loginLimiter = rateLimit({
    windowMs: 60_000, limit: 10, standardHeaders: 'draft-8', legacyHeaders: false,
    skipSuccessfulRequests: true,
    handler: (_req, res) => res.status(429).send(errorPage('Слишком много попыток', 'Подождите минуту и повторите вход.', true, config.appUrl)),
  });

  app.post('/interaction/:uid/login', loginLimiter, body, async (req, res) => {
    const details = await getInteraction(req, res);
    if (!validForm(req, details)) return rejectForm(res);
    if (details.prompt.name !== 'login') return rejectForm(res);
    const { username, password } = req.body;
    if (typeof username !== 'string' || typeof password !== 'string' || username.length > 128 || password.length > 256) {
      return res.status(400).send(loginPage(details.uid, interactionCsrf(config.authCookieSecret, details.uid), '', 'Проверьте логин и пароль.'));
    }
    const candidate = await scrypt(password, salt, 64);
    const passwordMatches = timingSafeEqual(candidate, passwordHash);
    if (username !== config.username || !passwordMatches) {
      return res.status(401).send(loginPage(details.uid, interactionCsrf(config.authCookieSecret, details.uid), username, 'Неверный логин или пароль.'));
    }
    return provider.interactionFinished(req, res, {
      login: { accountId: config.username, amr: ['pwd'], remember: false },
    }, { mergeWithLastSubmission: false });
  });

  app.post('/interaction/:uid/confirm', body, async (req, res) => {
    const interaction = await getInteraction(req, res);
    if (!validForm(req, interaction)) return rejectForm(res);
    const { prompt, params, session, grantId } = interaction;
    if (prompt.name !== 'consent' || session?.accountId !== config.username) return rejectForm(res);
    let grant = grantId ? await provider.Grant.find(grantId) : undefined;
    grant ??= new provider.Grant({ accountId: session.accountId, clientId: params.client_id });
    if (prompt.details.missingOIDCScope) grant.addOIDCScope(prompt.details.missingOIDCScope.join(' '));
    if (prompt.details.missingOIDCClaims) grant.addOIDCClaims(prompt.details.missingOIDCClaims);
    const savedGrantId = await grant.save();
    return provider.interactionFinished(req, res, { consent: { grantId: savedGrantId } }, { mergeWithLastSubmission: true });
  });

  app.post('/interaction/:uid/abort', body, async (req, res) => {
    const details = await getInteraction(req, res);
    if (!validForm(req, details)) return rejectForm(res);
    return provider.interactionFinished(req, res, {
      error: 'access_denied', error_description: 'The user cancelled sign-in.',
    }, { mergeWithLastSubmission: false });
  });

  app.use(provider.callback());
  app.use((error, _req, res, _next) => {
    const status = error instanceof errors.SessionNotFound ? 400 : error.status ?? 500;
    if (status === 500) console.error('Ошибка сервера авторизации:', error.name);
    res.status(status).send(errorPage('Сеанс недоступен', 'Страница входа устарела. Вернитесь в приложение и начните заново.', true, config.appUrl));
  });
  return { app, provider };
}
