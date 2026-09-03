import { Request, Response } from 'express';
import crypto from 'crypto';
import { db } from './db';
import { RP_ID, PORT, ISSUER } from './config';

/**
 * GET /oauth/authorize
 * Directs user to the AuthTab WebAuthn login UI.
 * Passes all provided query parameters through to login.html for client-side evaluation.
 */
export function authorizeEndpoint(req: Request, res: Response) {
  const queryEntries = Object.entries(req.query);

  if (queryEntries.length === 0) {
    // If no query parameters are passed, redirect to bare login.html (shows App Download view)
    return res.redirect('/login.html');
  }

  // Forward standard parameters to login.html
  const params = new URLSearchParams();
  for (const [key, value] of queryEntries) {
    if (typeof value === 'string') {
      params.append(key, value);
    }
  }

  const loginUrl = `/login.html?${params.toString()}`;
  return res.redirect(loginUrl);
}

/**
 * POST /oauth/token
 * Standard OAuth2 Token Endpoint for code exchange.
 * Enforces PKCE (RFC 7636) and Client ID verification.
 */
export function tokenEndpoint(req: Request, res: Response) {
  const grantType = req.body.grant_type || req.query.grant_type;

  if (grantType === 'authorization_code') {
    const code = req.body.code || req.query.code;
    const clientId = req.body.client_id || req.query.client_id;
    const redirectUri = req.body.redirect_uri || req.query.redirect_uri;
    const codeVerifier = req.body.code_verifier || req.query.code_verifier;

    if (!code) {
      return res.status(400).json({ error: 'invalid_request', error_description: 'Missing code' });
    }

    const authCode = db.consumeAuthCode(code);
    if (!authCode) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid or expired authorization code' });
    }

    // 1. Verify Client ID match (client authentication omitted, but client_id must match authorization request)
    if (!clientId || clientId !== authCode.clientId) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Client ID mismatch between authorization request and token request',
      });
    }

    // 2. Verify Redirect URI match if present in authCode
    if (authCode.redirectUri && redirectUri !== authCode.redirectUri) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Redirect URI mismatch between authorization request and token request',
      });
    }

    // 3. Verify PKCE (RFC 7636)
    if (authCode.codeChallenge) {
      if (!codeVerifier) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing code_verifier for PKCE validation',
        });
      }

      if (authCode.codeChallengeMethod === 'S256') {
        const computedChallenge = crypto
          .createHash('sha256')
          .update(codeVerifier)
          .digest('base64url');

        if (computedChallenge !== authCode.codeChallenge) {
          return res.status(400).json({
            error: 'invalid_grant',
            error_description: 'PKCE code_verifier does not match code_challenge',
          });
        }
      } else if (authCode.codeChallengeMethod === 'plain') {
        if (codeVerifier !== authCode.codeChallenge) {
          return res.status(400).json({
            error: 'invalid_grant',
            error_description: 'PKCE code_verifier does not match code_challenge (plain)',
          });
        }
      } else {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: `Unsupported code_challenge_method: ${authCode.codeChallengeMethod}`,
        });
      }
    }

    const user = db.getUserById(authCode.userId);
    if (!user) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'User not found' });
    }

    const tokens = db.createTokenPair(user.id);

    // Mock minimal ID token
    const idTokenHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const idTokenPayload = Buffer.from(JSON.stringify({
      iss: ISSUER,
      sub: user.id,
      aud: clientId,
      exp: Math.floor(tokens.expiresAt / 1000),
      iat: Math.floor(Date.now() / 1000),
      preferred_username: user.username,
      name: user.displayName,
    })).toString('base64url');
    const idToken = `${idTokenHeader}.${idTokenPayload}.`;

    console.log(`[OIDC TOKEN ISSUED] User: ${user.username}, ClientId: ${clientId}, AccessToken: ${tokens.accessToken}`);

    return res.json({
      access_token: tokens.accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: tokens.refreshToken,
      id_token: idToken,
      scope: 'openid profile',
    });
  }

  return res.status(400).json({ error: 'unsupported_grant_type' });
}

/**
 * GET /.well-known/openid-configuration
 */
export function openIdConfigEndpoint(req: Request, res: Response) {
  const issuer = ISSUER;
  return res.json({
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    userinfo_endpoint: `${issuer}/oauth/userinfo`,
    jwks_uri: `${issuer}/oauth/jwks`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['none'],
    scopes_supported: ['openid', 'profile'],
    code_challenge_methods_supported: ['S256', 'plain'],
  });
}

/**
 * GET /oauth/userinfo
 */
export function userInfoEndpoint(req: Request, res: Response) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  const token = authHeader.substring(7);
  const tokenRecord = db.getTokenByAccessToken(token);
  if (!tokenRecord) {
    return res.status(401).json({ error: 'invalid_token' });
  }

  const user = db.getUserById(tokenRecord.userId);
  if (!user) {
    return res.status(404).json({ error: 'user_not_found' });
  }

  return res.json({
    sub: user.id,
    preferred_username: user.username,
    name: user.displayName,
  });
}
