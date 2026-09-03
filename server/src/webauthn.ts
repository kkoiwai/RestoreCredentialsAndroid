import { Request, Response } from 'express';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  VerifyRegistrationResponseOpts,
  VerifyAuthenticationResponseOpts,
} from '@simplewebauthn/server';
import {
  decodeAttestationObject,
  parseAuthenticatorData,
  convertAAGUIDToString,
} from '@simplewebauthn/server/helpers';
import { db } from './db';
import { RP_ID, RP_NAME, getExpectedOrigin, isAllowedOrigin, CLIENT_ID, REDIRECT_URI } from './config';

export type RegistrationResponseJSON = VerifyRegistrationResponseOpts['response'];
export type AuthenticationResponseJSON = VerifyAuthenticationResponseOpts['response'];

/**
 * Generate Passkey Registration Options for WebAuthn in AuthTab / browser.
 */
export async function getPasskeyRegistrationOptions(req: Request, res: Response) {
  const { username, displayName } = req.body;
  if (!username) {
    return res.status(400).json({ error: 'Username is required' });
  }

  const user = db.createUser(username, displayName);
  const userCredentials = db.getCredentialsByUserId(user.id, 'passkey');

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userID: Buffer.from(user.id),
    userName: user.username,
    userDisplayName: user.displayName,
    attestationType: 'none',
    excludeCredentials: userCredentials.map(cred => ({
      id: cred.id,
      transports: cred.transports as any,
    })),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
  });

  db.saveChallenge(options.challenge, 'passkey_reg', user.id);

  return res.json({ options, userId: user.id });
}

/**
 * Verify Passkey Registration Response from WebAuthn ceremony.
 */
export interface OAuthContext {
  client_id?: string;
  redirect_uri?: string;
  code_challenge?: string;
  code_challenge_method?: string;
}

export async function verifyPasskeyRegistration(req: Request, res: Response) {
  const {
    response,
    username,
    state,
    client_id,
    redirect_uri,
    code_challenge,
    code_challenge_method,
  } = req.body as {
    response: RegistrationResponseJSON;
    username: string;
    state?: string;
  } & OAuthContext;

  if (!response || !username) {
    return res.status(400).json({ error: 'Missing response or username' });
  }

  const user = db.getUserByUsername(username);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  // Parse clientDataJSON to extract challenge and origin
  const clientData = JSON.parse(Buffer.from(response.response.clientDataJSON, 'base64url').toString('utf-8'));
  const savedChallenge = db.consumeChallenge(clientData.challenge);

  if (!savedChallenge || savedChallenge.type !== 'passkey_reg' || savedChallenge.userId !== user.id) {
    return res.status(400).json({ error: 'Invalid or expired challenge' });
  }

  try {
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: savedChallenge.challenge,
      expectedOrigin: getExpectedOrigin(clientData.origin),
      expectedRPID: RP_ID,
      requireUserVerification: false,
    });

    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({ error: 'Passkey verification failed' });
    }

    const { credentialID, credentialPublicKey, counter, attestationObject } = verification.registrationInfo;

    // Parse authData flags & AAGUID
    const decodedAttestation = decodeAttestationObject(attestationObject);
    const authData = decodedAttestation.get('authData');
    const parsedAuthData = parseAuthenticatorData(authData);
    const aaguid = parsedAuthData.aaguid
      ? convertAAGUIDToString(parsedAuthData.aaguid)
      : '00000000-0000-0000-0000-000000000000';

    const cred = {
      id: credentialID,
      userId: user.id,
      publicKey: Buffer.from(credentialPublicKey).toString('base64url'),
      counter,
      transports: (response.response.transports as string[]) || [],
      credentialType: 'passkey' as const,
      aaguid,
      backupEligible: parsedAuthData.flags.be, // BE flag
      backupState: parsedAuthData.flags.bs,    // BS flag
      userVerified: parsedAuthData.flags.uv,   // UV flag
      userPresent: parsedAuthData.flags.up,    // UP flag
      createdAt: Date.now(),
      deviceInfo: 'Browser / AuthTab',
    };

    db.saveCredential(cred);

    console.log(`[PASSKEY REGISTERED] User: ${user.username}, CredentialId: ${cred.id}`);
    console.log(`[PASSKEY FLAGS] AAGUID: ${cred.aaguid}, BE (Backup Eligible): ${cred.backupEligible}, BS (Backup State): ${cred.backupState}`);

    // Generate authorization code for OIDC flow
    const code = 'code_' + Math.random().toString(36).substring(2) + Date.now().toString(36);
    db.saveAuthCode({
      code,
      userId: user.id,
      clientId: client_id || CLIENT_ID,
      redirectUri: redirect_uri || REDIRECT_URI,
      codeChallenge: code_challenge,
      codeChallengeMethod: code_challenge_method,
      expiresAt: Date.now() + 300000,
    });

    return res.json({
      verified: true,
      user,
      code,
      credential: {
        id: cred.id,
        aaguid: cred.aaguid,
        backupEligible: cred.backupEligible,
        backupState: cred.backupState,
      },
    });
  } catch (error: any) {
    console.error('Error during passkey registration verification:', error);
    return res.status(400).json({ error: error.message || 'Verification error' });
  }
}

/**
 * Generate Passkey Authentication Options.
 */
export async function getPasskeyLoginOptions(req: Request, res: Response) {
  const { username } = req.body;
  let allowCredentials: any[] | undefined = undefined;
  let userId: string | undefined = undefined;

  if (username) {
    const user = db.getUserByUsername(username);
    if (user) {
      userId = user.id;
      const userCredentials = db.getCredentialsByUserId(user.id, 'passkey');
      allowCredentials = userCredentials.map(cred => ({
        id: cred.id,
        transports: cred.transports as any,
      }));
    }
  }

  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    userVerification: 'preferred',
    allowCredentials,
  });

  db.saveChallenge(options.challenge, 'passkey_auth', userId);

  return res.json({ options });
}

/**
 * Verify Passkey Authentication Response.
 */
export async function verifyPasskeyLogin(req: Request, res: Response) {
  const {
    response,
    client_id,
    redirect_uri,
    code_challenge,
    code_challenge_method,
  } = req.body as { response: AuthenticationResponseJSON } & OAuthContext;
  if (!response) {
    return res.status(400).json({ error: 'Missing authentication response' });
  }

  const clientData = JSON.parse(Buffer.from(response.response.clientDataJSON, 'base64url').toString('utf-8'));
  const savedChallenge = db.consumeChallenge(clientData.challenge);

  if (!savedChallenge || savedChallenge.type !== 'passkey_auth') {
    return res.status(400).json({ error: 'Invalid or expired challenge' });
  }

  const cred = db.getCredentialById(response.id);
  if (!cred || cred.credentialType !== 'passkey') {
    return res.status(404).json({ error: 'Passkey not found' });
  }

  const user = db.getUserById(cred.userId);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: savedChallenge.challenge,
      expectedOrigin: getExpectedOrigin(clientData.origin),
      expectedRPID: RP_ID,
      authenticator: {
        credentialID: cred.id,
        credentialPublicKey: Buffer.from(cred.publicKey, 'base64url'),
        counter: cred.counter,
        transports: cred.transports as any,
      },
      requireUserVerification: false,
    });

    if (!verification.verified) {
      return res.status(400).json({ error: 'Passkey authentication failed' });
    }

    db.updateCredentialCounter(cred.id, verification.authenticationInfo.newCounter);

    const code = 'code_' + Math.random().toString(36).substring(2) + Date.now().toString(36);
    db.saveAuthCode({
      code,
      userId: user.id,
      clientId: client_id || CLIENT_ID,
      redirectUri: redirect_uri || REDIRECT_URI,
      codeChallenge: code_challenge,
      codeChallengeMethod: code_challenge_method,
      expiresAt: Date.now() + 300000,
    });

    return res.json({
      verified: true,
      user,
      code,
    });
  } catch (error: any) {
    console.error('Error during passkey login verification:', error);
    return res.status(400).json({ error: error.message || 'Authentication error' });
  }
}

/**
 * Quick Login Endpoint for testing in emulators without a signed-in Google account.
 * Creates user and registers a passkey record with Google Password Manager AAGUID,
 * then returns authorization code for OIDC redirect.
 */
export function quickLoginEndpoint(req: Request, res: Response) {
  const {
    username = 'test-user',
    client_id,
    redirect_uri,
    code_challenge,
    code_challenge_method,
  } = req.body as { username?: string } & OAuthContext;
  const user = db.createUser(username, username);

  const mockPasskeyId = 'passkey_' + Math.random().toString(36).substring(2, 10);
  const cred = {
    id: mockPasskeyId,
    userId: user.id,
    publicKey: Buffer.from('mock-public-key-bytes').toString('base64url'),
    counter: 0,
    transports: ['internal'],
    credentialType: 'passkey' as const,
    aaguid: 'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4', // Standard Google Password Manager AAGUID
    backupEligible: true, // BE
    backupState: true,    // BS
    userVerified: true,   // UV
    userPresent: true,    // UP
    createdAt: Date.now(),
    deviceInfo: 'Google Password Manager (Passkey)',
  };

  db.saveCredential(cred);

  console.log(`[PASSKEY REGISTERED (QUICK)] User: ${user.username}, CredentialId: ${cred.id}`);
  console.log(`[PASSKEY FLAGS] AAGUID: ${cred.aaguid}, BE: ${cred.backupEligible}, BS: ${cred.backupState}`);

  const code = 'code_' + Math.random().toString(36).substring(2) + Date.now().toString(36);
  db.saveAuthCode({
    code,
    userId: user.id,
    clientId: client_id || CLIENT_ID,
    redirectUri: redirect_uri || REDIRECT_URI,
    codeChallenge: code_challenge,
    codeChallengeMethod: code_challenge_method,
    expiresAt: Date.now() + 300000,
  });

  return res.json({
    verified: true,
    user,
    code,
    credential: {
      id: cred.id,
      aaguid: cred.aaguid,
      backupEligible: cred.backupEligible,
      backupState: cred.backupState,
    },
  });
}

