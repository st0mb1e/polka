import * as oidc from 'openid-client';

export function createYandexProvider(config, { fetchImplementation = fetch } = {}) {
  const configured = Boolean(config.yandexClientId && config.yandexClientSecret);
  const client = configured ? new oidc.Configuration({
    issuer: 'https://oauth.yandex.ru',
    authorization_endpoint: 'https://oauth.yandex.ru/authorize',
    token_endpoint: 'https://oauth.yandex.ru/token',
  }, config.yandexClientId, config.yandexClientSecret, oidc.ClientSecretBasic(config.yandexClientSecret)) : undefined;
  if (client) {
    client[oidc.customFetch] = fetchImplementation;
    client.timeout = 10;
  }

  return {
    name: 'yandex', configured, usesNonce: false,
    async authorizationUrl(pending) {
      if (!configured) throw new Error('Настройте YANDEX_CLIENT_ID и YANDEX_CLIENT_SECRET в .env.');
      return oidc.buildAuthorizationUrl(client, {
        redirect_uri: `${config.appUrl}/auth/callback`, scope: 'login:info login:email',
        state: pending.state, code_challenge: await oidc.calculatePKCECodeChallenge(pending.codeVerifier),
        code_challenge_method: 'S256', force_confirm: 'yes',
      });
    },
    async authenticate(callbackUrl, pending) {
      const tokens = await oidc.authorizationCodeGrant(client, callbackUrl, {
        pkceCodeVerifier: pending.codeVerifier, expectedState: pending.state,
      });
      // Yandex ID uses its own profile API rather than an OIDC UserInfo response.
      const response = await fetchImplementation('https://login.yandex.ru/info?format=json', {
        headers: { authorization: `OAuth ${tokens.access_token}`, accept: 'application/json' },
        redirect: 'error', signal: AbortSignal.timeout(10_000),
      });
      if (!response.ok) throw new Error('Яндекс ID не вернул профиль пользователя.');
      const profile = await response.json();
      if (typeof profile.id !== 'string' || !profile.id || typeof profile.login !== 'string'
        || !profile.login || profile.client_id !== config.yandexClientId) {
        throw new Error('Яндекс ID вернул недопустимый профиль пользователя.');
      }
      return {
        user: {
          sub: profile.id, username: profile.login,
          name: profile.real_name || profile.display_name || profile.login,
          email: typeof profile.default_email === 'string' ? profile.default_email : '',
        },
        expiresAt: Date.now() + Math.min(config.sessionLifetimeMs, (tokens.expires_in ?? 3600) * 1000),
      };
    },
    logoutUrl() { return '/auth/logged-out'; },
  };
}

export async function createOAuthProvider(config, options) {
  if (config.authProvider === 'yandex') return createYandexProvider(config, options);
  const client = await oidc.discovery(
    new URL(config.issuer), config.clientId, config.clientSecret,
    oidc.ClientSecretBasic(config.clientSecret),
    { execute: [oidc.allowInsecureRequests, oidc.enableNonRepudiationChecks], timeout: 5 },
  );
  return {
    name: 'local', configured: true, usesNonce: true,
    async authorizationUrl(pending) {
      return oidc.buildAuthorizationUrl(client, {
        redirect_uri: `${config.appUrl}/auth/callback`, scope: 'openid profile email',
        state: pending.state, nonce: pending.nonce,
        code_challenge: await oidc.calculatePKCECodeChallenge(pending.codeVerifier), code_challenge_method: 'S256',
      });
    },
    async authenticate(callbackUrl, pending) {
      const tokens = await oidc.authorizationCodeGrant(client, callbackUrl, {
        pkceCodeVerifier: pending.codeVerifier, expectedState: pending.state,
        expectedNonce: pending.nonce, idTokenExpected: true,
      });
      const claims = tokens.claims();
      const profile = await oidc.fetchUserInfo(client, tokens.access_token, claims.sub);
      return {
        user: {
          sub: claims.sub, username: profile.preferred_username || claims.sub,
          name: profile.name || profile.preferred_username || claims.sub, email: profile.email || '',
        },
        idToken: tokens.id_token,
        expiresAt: Math.min(claims.exp * 1000, Date.now() + config.sessionLifetimeMs),
      };
    },
    logoutUrl(session) {
      return oidc.buildEndSessionUrl(client, {
        id_token_hint: session.idToken, post_logout_redirect_uri: `${config.appUrl}/auth/logged-out`,
      }).href;
    },
  };
}
