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
import { RP_ID, RP_NAME, getExpectedOrigin, isAllowedOrigin, CLIENT_ID } from './config';

export type RegistrationResponseJSON = VerifyRegistrationResponseOpts['response'];
export type AuthenticationResponseJSON = VerifyAuthenticationResponseOpts['response'];

/**
 * Helper to get authenticated user from Bearer token
 */
function getAuthenticatedUser(req: Request) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  const token = authHeader.substring(7);
  const tokenRecord = db.getTokenByAccessToken(token);
  if (!tokenRecord) return null;
  return db.getUserById(tokenRecord.userId);
}

/**
 * Generate Registration Options for Android CreateRestoreCredentialRequest.
 * Requires Bearer access_token.
 */
export async function getRestoreRegistrationOptions(req: Request, res: Response) {
  const user = getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({ error: 'Unauthorized: valid access token required' });
  }

  const existingRestoreKeys = db.getCredentialsByUserId(user.id, 'restore_key');

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userID: Buffer.from(user.id),
    userName: user.username,
    userDisplayName: user.displayName,
    attestationType: 'none',
    excludeCredentials: existingRestoreKeys.map(k => ({
      id: k.id,
      transports: k.transports as any,
    })),
    authenticatorSelection: {
      residentKey: 'required',
      userVerification: 'preferred',
    },
  });

  db.saveChallenge(options.challenge, 'restore_reg', user.id);

  console.log(`[RESTORE] Generated restore credential creation challenge for user: ${user.username}`);
  return res.json({ options, userId: user.id });
}

/**
 * Verify Registration Response from CreateRestoreCredentialResponse.responseJson.
 * Requires Bearer access_token.
 */
export async function verifyRestoreRegistration(req: Request, res: Response) {
  const user = getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({ error: 'Unauthorized: valid access token required' });
  }

  const { response } = req.body as { response: RegistrationResponseJSON };
  if (!response) {
    return res.status(400).json({ error: 'Missing registration response JSON' });
  }

  const clientData = JSON.parse(Buffer.from(response.response.clientDataJSON, 'base64url').toString('utf-8'));
  console.log(`[RESTORE REGISTRATION] Origin: ${clientData.origin}`);

  if (!isAllowedOrigin(clientData.origin)) {
    console.error(`[RESTORE REGISTRATION REJECTED] Origin is not authorized: ${clientData.origin}`);
    return res.status(403).json({ error: `Unauthorized origin: ${clientData.origin}` });
  }

  const savedChallenge = db.consumeChallenge(clientData.challenge);

  if (!savedChallenge || savedChallenge.type !== 'restore_reg' || savedChallenge.userId !== user.id) {
    return res.status(400).json({ error: 'Invalid or expired restore registration challenge' });
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
      return res.status(400).json({ error: 'Restore credential verification failed' });
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
      credentialType: 'restore_key' as const,
      aaguid,
      backupEligible: parsedAuthData.flags.be, // BE flag (Backup Eligibility)
      backupState: parsedAuthData.flags.bs,    // BS flag (Backup State)
      userVerified: parsedAuthData.flags.uv,   // UV flag
      userPresent: parsedAuthData.flags.up,    // UP flag
      createdAt: Date.now(),
      deviceInfo: 'Android Credential Manager Restore Key',
    };

    db.saveCredential(cred);

    console.log(`=======================================================`);
    console.log(`[RESTORE KEY CREATED]`);
    console.log(`User:              ${user.username} (${user.id})`);
    console.log(`Credential ID:     ${cred.id}`);
    console.log(`AAGUID:            ${cred.aaguid}`);
    console.log(`BE (BackupEligible): ${cred.backupEligible}`);
    console.log(`BS (BackupState):    ${cred.backupState}`);
    console.log(`UV (UserVerified):   ${cred.userVerified}`);
    console.log(`=======================================================`);

    return res.json({
      verified: true,
      credential: {
        id: cred.id,
        aaguid: cred.aaguid,
        backupEligible: cred.backupEligible,
        backupState: cred.backupState,
        userVerified: cred.userVerified,
      },
    });
  } catch (error: any) {
    console.error('Error verifying restore registration:', error);
    return res.status(400).json({ error: error.message || 'Verification error' });
  }
}

/**
 * Generate Challenge for Android GetRestoreCredentialOption.
 * Called when opening app on new device (no authentication required).
 */
export async function getRestoreChallenge(req: Request, res: Response) {
  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    userVerification: 'preferred',
  });

  db.saveChallenge(options.challenge, 'restore_auth');
  console.log(`[RESTORE] Generated challenge for restore-credential: ${options.challenge}`);

  return res.json({ options });
}

/**
 * Dedicated REST endpoint to exchange RestoreCredential assertion for Access & Refresh Tokens.
 * POST /api/auth/restore-session
 */
export async function restoreSession(req: Request, res: Response) {
  const { assertion, client_id } = req.body as {
    assertion: AuthenticationResponseJSON;
    client_id?: string;
  };

  if (!client_id) {
    return res.status(400).json({ error: 'invalid_client', error_description: 'Missing client_id' });
  }

  if (client_id !== CLIENT_ID) {
    return res.status(400).json({ error: 'invalid_client', error_description: 'Invalid or unknown client_id' });
  }

  if (!assertion) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Missing assertion JSON from RestoreCredential' });
  }

  const clientData = JSON.parse(Buffer.from(assertion.response.clientDataJSON, 'base64url').toString('utf-8'));
  console.log(`[RESTORE SESSION] Origin: ${clientData.origin}`);

  if (!isAllowedOrigin(clientData.origin)) {
    console.error(`[RESTORE SESSION REJECTED] Origin is not authorized: ${clientData.origin}`);
    return res.status(403).json({ error: `Unauthorized origin: ${clientData.origin}` });
  }

  const savedChallenge = db.consumeChallenge(clientData.challenge);
  if (!savedChallenge || savedChallenge.type !== 'restore_auth') {
    return res.status(400).json({ error: 'Invalid or expired restore authentication challenge' });
  }

  const cred = db.getCredentialById(assertion.id);
  if (!cred) {
    return res.status(404).json({ error: 'Credential not found in database' });
  }

  if (cred.credentialType !== 'restore_key') {
    return res.status(403).json({ error: 'Credential is not a registered restore key' });
  }

  const user = db.getUserById(cred.userId);
  if (!user) {
    return res.status(404).json({ error: 'Associated user not found' });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response: assertion,
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
      return res.status(400).json({ error: 'Restore assertion cryptographic verification failed' });
    }

    db.updateCredentialCounter(cred.id, verification.authenticationInfo.newCounter);

    // Issue new token pair
    const tokens = db.createTokenPair(user.id);

    console.log(`=======================================================`);
    console.log(`[SESSION RESTORED SUCCESSFULLY VIA RESTORE CREDENTIAL]`);
    console.log(`User:          ${user.username} (${user.id})`);
    console.log(`Credential ID: ${cred.id}`);
    console.log(`AAGUID:        ${cred.aaguid}`);
    console.log(`BE (BackupEligible): ${cred.backupEligible}`);
    console.log(`BS (BackupState):    ${cred.backupState}`);
    console.log(`Access Token:  ${tokens.accessToken}`);
    console.log(`=======================================================`);

    return res.json({
      success: true,
      token_type: 'Bearer',
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
      expires_in: 3600,
      user: {
        id: user.id,
        username: user.username,
        displayName: user.displayName,
      },
      restoreInfo: {
        credentialId: cred.id,
        aaguid: cred.aaguid,
        backupEligible: cred.backupEligible,
        backupState: cred.backupState,
      },
    });
  } catch (error: any) {
    console.error('Error verifying restore session assertion:', error);
    return res.status(400).json({ error: error.message || 'Verification error' });
  }
}
