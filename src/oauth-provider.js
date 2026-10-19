import * as oidc from 'openid-client';

export function createGoogleProvider(config, { fetchImplementation = fetch } = {}) {
  const configured = Boolean(config.googleClientId && config.googleClientSecret);
  let client;
  function getClient() {
    if (!configured) throw new Error('Настройте GOOGLE_CLIENT_ID и GOOGLE_CLIENT_SECRET в .env.');
    // Discover lazily so public pages do not depend on Google's availability.
    client ??= oidc.discovery(
      new URL('https://accounts.google.com'), config.googleClientId,
      { client_secret: config.googleClientSecret, id_token_signed_response_alg: 'RS256' },
      oidc.ClientSecretPost(config.googleClientSecret),
      { [oidc.customFetch]: fetchImplementation, execute: [oidc.enableNonRepudiationChecks], timeout: 10 },
    ).catch((error) => { client = undefined; throw error; });
    return client;
  }

  return {
    name: 'google', configured, usesNonce: true,
    async authorizationUrl(pending) {
      return oidc.buildAuthorizationUrl(await getClient(), {
        redirect_uri: `${config.appUrl}/auth/callback`, scope: 'openid profile email',
        state: pending.state, nonce: pending.nonce,
        code_challenge: await oidc.calculatePKCECodeChallenge(pending.codeVerifier),
        code_challenge_method: 'S256', prompt: 'select_account',
      });
    },
    async authenticate(callbackUrl, pending) {
      const tokens = await oidc.authorizationCodeGrant(await getClient(), callbackUrl, {
        pkceCodeVerifier: pending.codeVerifier, expectedState: pending.state,
        expectedNonce: pending.nonce, idTokenExpected: true,
      });
      const claims = tokens.claims();
      if (typeof claims.sub !== 'string' || !claims.sub || typeof claims.email !== 'string'
        || !claims.email || claims.email_verified !== true) {
        throw new Error('Google не вернул подтверждённую учётную запись пользователя.');
      }
      return {
        user: {
          sub: claims.sub, username: claims.email,
          name: typeof claims.name === 'string' && claims.name ? claims.name : claims.email,
          email: claims.email,
        },
        expiresAt: Math.min(claims.exp * 1000, Date.now() + config.sessionLifetimeMs,
          Date.now() + (tokens.expires_in ?? 3600) * 1000),
      };
    },
    logoutUrl() { return '/auth/logged-out'; },
  };
}

export async function createOAuthProvider(config, options) {
  if (config.authProvider === 'google') return createGoogleProvider(config, options);
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
