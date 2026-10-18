import { createHmac, timingSafeEqual } from 'node:crypto';
import helmet from 'helmet';

export function equalSecrets(actual, expected) {
  if (typeof actual !== 'string' || typeof expected !== 'string') return false;
  const left = Buffer.from(actual);
  const right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
}

export function interactionCsrf(secret, uid) {
  return createHmac('sha256', secret).update(`interaction:${uid}`).digest('base64url');
}

export function securityHeaders(config) {
  return helmet({
    // no-referrer makes native form POST requests send Origin: null.
    // Keep the origin for CSRF checks without disclosing paths or query strings.
    referrerPolicy: { policy: 'strict-origin' },
    // The lab listens only on loopback over HTTP; do not upgrade it to HTTPS.
    strictTransportSecurity: false,
    contentSecurityPolicy: {
      directives: {
        'default-src': ["'self'"],
        'script-src': ["'self'"],
        'style-src': ["'self'"],
        'form-action': ["'self'", config.appUrl, config.issuer],
        'frame-ancestors': ["'none'"],
        'upgrade-insecure-requests': null,
      },
    },
  });
}

export function noStore(_req, res, next) {
  res.set('Cache-Control', 'no-store');
  next();
}

export function allowedReturnTo(value) {
  const pages = ['/', '/shelf', '/profile'];
  return pages.includes(value) ? value : '/shelf';
}
