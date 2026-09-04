/**
 * Unit test script to verify server endpoints, PKCE, and Client ID checks
 * Uses in-memory mock Request/Response to run without requiring network sockets.
 */
import crypto from 'crypto';
import { Request, Response } from 'express';
import { db } from './db';
import {
  quickLoginEndpoint,
  getPasskeyRegistrationOptions,
} from './webauthn';
import {
  restoreSession,
  getRestoreRegistrationOptions,
} from './restore';
import {
  authorizeEndpoint,
  tokenEndpoint,
  openIdConfigEndpoint,
} from './oidc';

interface MockResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: any;
  redirectUrl?: string;
  status: (code: number) => MockResponse;
  json: (data: any) => MockResponse;
  redirect: (url: string) => MockResponse;
  setHeader: (key: string, val: string) => MockResponse;
}

function createMockResponse(): MockResponse {
  const res: MockResponse = {
    statusCode: 200,
    headers: {},
    body: null,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(data: any) {
      this.body = data;
      return this;
    },
    redirect(url: string) {
      this.statusCode = 302;
      this.redirectUrl = url;
      return this;
    },
    setHeader(key: string, val: string) {
      this.headers[key] = val;
      return this;
    },
  };
  return res;
}

function createMockRequest(options: {
  method?: string;
  query?: Record<string, any>;
  body?: Record<string, any>;
  headers?: Record<string, string>;
}): Request {
  return {
    method: options.method || 'GET',
    query: options.query || {},
    body: options.body || {},
    headers: options.headers || {},
  } as unknown as Request;
}

async function runDirectTests() {
  console.log('Running direct unit tests for PKCE, OAuth, and Client ID...');

  // 1. OpenID configuration test
  {
    const req = createMockRequest({});
    const res = createMockResponse();
    openIdConfigEndpoint(req, res as unknown as Response);
    console.log('1. OpenID config status:', res.statusCode, 'PKCE methods:', res.body?.code_challenge_methods_supported);
    if (res.statusCode !== 200 || !res.body?.code_challenge_methods_supported?.includes('S256')) {
      throw new Error('OpenID configuration test failed');
    }
  }

  // 2. Authorize Endpoint Redirects
  // 2a. Bare authorize (no params) -> /login.html
  {
    const req = createMockRequest({ query: {} });
    const res = createMockResponse();
    authorizeEndpoint(req, res as unknown as Response);
    console.log('2a. Bare authorize redirect:', res.statusCode, res.redirectUrl);
    if (res.statusCode !== 302 || res.redirectUrl !== '/login.html') {
      throw new Error(`Expected redirect to /login.html, got ${res.redirectUrl}`);
    }
  }

  // 2b. Authorize with params -> /login.html?params
  const codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

  {
    const req = createMockRequest({
      query: {
        client_id: 'android-poc-client',
        redirect_uri: 'restoreapp://auth-callback',
        scope: 'openid profile',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        state: 'xyz_state',
      },
    });
    const res = createMockResponse();
    authorizeEndpoint(req, res as unknown as Response);
    console.log('2b. Authorize with params redirect:', res.statusCode, res.redirectUrl);
    if (res.statusCode !== 302 || !res.redirectUrl?.includes('code_challenge=') || !res.redirectUrl?.includes('code_challenge_method=S256')) {
      throw new Error('Authorize with params failed to forward PKCE params');
    }
  }

  // Helper to issue fresh auth code for each token endpoint test
  function issueFreshAuthCode(): string {
    const req = createMockRequest({
      body: {
        username: 'test-user',
        client_id: 'android-poc-client',
        redirect_uri: 'restoreapp://auth-callback',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      },
    });
    const res = createMockResponse();
    quickLoginEndpoint(req, res as unknown as Response);
    return res.body?.code;
  }

  // 3. Quick Login with PKCE & OAuth context
  {
    const code = issueFreshAuthCode();
    console.log('3. Quick Login code issued:', code ? 'yes' : 'no');
    if (!code) {
      throw new Error('Quick login failed to issue authorization code');
    }
  }

  // 4. Token Endpoint Tests
  // 4a-1. Token exchange with unknown client_id
  {
    const code = issueFreshAuthCode();
    const req = createMockRequest({
      body: {
        grant_type: 'authorization_code',
        code,
        client_id: 'unknown-client',
        redirect_uri: 'restoreapp://auth-callback',
        code_verifier: codeVerifier,
      },
    });
    const res = createMockResponse();
    tokenEndpoint(req, res as unknown as Response);
    console.log('4a-1. Token exchange with unknown client_id:', res.statusCode, res.body?.error);
    if (res.statusCode !== 400 || res.body?.error !== 'invalid_client') {
      throw new Error('Expected 400 invalid_client for unknown client_id');
    }
  }

  // 4a-2. Token exchange with mismatched client_id (App B client requesting code issued to App A)
  {
    const code = issueFreshAuthCode();
    const req = createMockRequest({
      body: {
        grant_type: 'authorization_code',
        code,
        client_id: 'android-poc-client-b',
        redirect_uri: 'restoreapp://auth-callback',
        code_verifier: codeVerifier,
      },
    });
    const res = createMockResponse();
    tokenEndpoint(req, res as unknown as Response);
    console.log('4a-2. Token exchange with mismatched client_id:', res.statusCode, res.body?.error_description);
    if (res.statusCode !== 400 || res.body?.error !== 'invalid_grant' || !res.body?.error_description?.includes('Client ID mismatch')) {
      throw new Error('Expected 400 invalid_grant for Client ID mismatch');
    }
  }

  // 4b. Missing code_verifier test
  {
    const code = issueFreshAuthCode();
    const req = createMockRequest({
      body: {
        grant_type: 'authorization_code',
        code,
        client_id: 'android-poc-client',
        redirect_uri: 'restoreapp://auth-callback',
      },
    });
    const res = createMockResponse();
    tokenEndpoint(req, res as unknown as Response);
    console.log('4b. Token exchange with missing code_verifier:', res.statusCode, res.body?.error_description);
    if (res.statusCode !== 400 || res.body?.error !== 'invalid_request' || !res.body?.error_description?.includes('Missing code_verifier')) {
      throw new Error('Expected 400 invalid_request for missing code_verifier');
    }
  }

  // 4c. Wrong code_verifier test
  {
    const code = issueFreshAuthCode();
    const req = createMockRequest({
      body: {
        grant_type: 'authorization_code',
        code,
        client_id: 'android-poc-client',
        redirect_uri: 'restoreapp://auth-callback',
        code_verifier: 'invalid_verifier_00000000000000000000000000',
      },
    });
    const res = createMockResponse();
    tokenEndpoint(req, res as unknown as Response);
    console.log('4c. Token exchange with wrong code_verifier:', res.statusCode, res.body?.error_description);
    if (res.statusCode !== 400 || res.body?.error !== 'invalid_grant' || !res.body?.error_description?.includes('PKCE code_verifier does not match')) {
      throw new Error('Expected 400 invalid_grant for wrong code_verifier');
    }
  }

  // 4d. Successful Token Exchange with valid code_verifier & App A client_id
  {
    const code = issueFreshAuthCode();
    const req = createMockRequest({
      body: {
        grant_type: 'authorization_code',
        code,
        client_id: 'android-poc-client',
        redirect_uri: 'restoreapp://auth-callback',
        code_verifier: codeVerifier,
      },
    });
    const res = createMockResponse();
    tokenEndpoint(req, res as unknown as Response);
    console.log('4d. Token exchange App A success:', res.statusCode, 'token:', res.body?.access_token ? 'issued' : 'missing');
    if (res.statusCode !== 200 || !res.body?.access_token) {
      throw new Error('Token exchange failed with valid verifier for App A');
    }
  }

  // 4e. Successful Token Exchange with valid code_verifier & App B client_id
  {
    const reqCode = createMockRequest({
      body: {
        username: 'bob-user',
        client_id: 'android-poc-client-b',
        redirect_uri: 'restoreapp-b://auth-callback',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      },
    });
    const resCode = createMockResponse();
    quickLoginEndpoint(reqCode, resCode as unknown as Response);
    const codeB = resCode.body?.code;

    const req = createMockRequest({
      body: {
        grant_type: 'authorization_code',
        code: codeB,
        client_id: 'android-poc-client-b',
        redirect_uri: 'restoreapp-b://auth-callback',
        code_verifier: codeVerifier,
      },
    });
    const res = createMockResponse();
    tokenEndpoint(req, res as unknown as Response);
    console.log('4e. Token exchange App B success:', res.statusCode, 'token:', res.body?.access_token ? 'issued' : 'missing');
    if (res.statusCode !== 200 || !res.body?.access_token) {
      throw new Error('Token exchange failed with valid verifier for App B');
    }
  }

  // 5. Restore Registration Options (excludeCredentials should be empty)
  {
    const userAlice = db.createUser('alice_exclude_test', 'Alice Exclude Test');
    // Save an existing restore key for Alice
    db.saveCredential({
      id: 'alice_existing_key',
      userId: userAlice.id,
      publicKey: 'mock-pubkey',
      counter: 0,
      credentialType: 'restore_key',
      aaguid: '00000000-0000-0000-0000-000000000000',
      backupEligible: true,
      backupState: true,
      userVerified: true,
      userPresent: true,
      clientId: 'android-poc-client',
      createdAt: Date.now(),
    });

    const tokensAlice = db.createTokenPair(userAlice.id);

    const req = createMockRequest({
      headers: { authorization: `Bearer ${tokensAlice.accessToken}` },
    });
    const res = createMockResponse();
    await getRestoreRegistrationOptions(req, res as unknown as Response);
    const excludeCreds = res.body?.options?.excludeCredentials;
    console.log('5. getRestoreRegistrationOptions excludeCredentials:', excludeCreds);
    if (excludeCreds && excludeCreds.length > 0) {
      throw new Error(`Expected excludeCredentials to be empty, got ${excludeCreds.length} credentials`);
    }
  }

  // 6. restore-session Client ID validation & Cross-App Protection
  // 6a. Missing client_id
  {
    const req = createMockRequest({
      body: {
        assertion: { id: 'dummy', response: {} },
      },
    });
    const res = createMockResponse();
    await restoreSession(req, res as unknown as Response);
    console.log('6a. restore-session missing client_id:', res.statusCode, res.body?.error_description);
    if (res.statusCode !== 400 || res.body?.error !== 'invalid_client' || !res.body?.error_description?.includes('Missing client_id')) {
      throw new Error('Expected 400 invalid_client for missing client_id');
    }
  }

  // 6b. Invalid client_id
  {
    const req = createMockRequest({
      body: {
        client_id: 'unknown-client',
        assertion: { id: 'dummy', response: {} },
      },
    });
    const res = createMockResponse();
    await restoreSession(req, res as unknown as Response);
    console.log('6b. restore-session invalid client_id:', res.statusCode, res.body?.error_description);
    if (res.statusCode !== 400 || res.body?.error !== 'invalid_client' || !res.body?.error_description?.includes('Invalid or unknown client_id')) {
      throw new Error('Expected 400 invalid_client for unknown client_id');
    }
  }

  // 6c. Multi-App / Cross-App Protection Test
  {
    // Setup Alice (App A) and Bob (App B)
    const userAlice = db.createUser('alice_app_a', 'Alice App A');
    const userBob = db.createUser('bob_app_b', 'Bob App B');

    const aliceKeyId = 'alice_restore_key_123';
    const bobKeyId = 'bob_restore_key_456';

    db.saveCredential({
      id: aliceKeyId,
      userId: userAlice.id,
      publicKey: 'mock-alice-key',
      counter: 0,
      credentialType: 'restore_key',
      aaguid: '00000000-0000-0000-0000-000000000000',
      backupEligible: true,
      backupState: true,
      userVerified: true,
      userPresent: true,
      clientId: 'android-poc-client', // App A
      createdAt: Date.now(),
    });

    db.saveCredential({
      id: bobKeyId,
      userId: userBob.id,
      publicKey: 'mock-bob-key',
      counter: 0,
      credentialType: 'restore_key',
      aaguid: '00000000-0000-0000-0000-000000000000',
      backupEligible: true,
      backupState: true,
      userVerified: true,
      userPresent: true,
      clientId: 'android-poc-client-b', // App B
      createdAt: Date.now(),
    });

    // Generate mock clientDataJSON with valid challenge and origin
    const challenge = 'challenge_cross_app_test_' + Date.now();
    db.saveChallenge(challenge, 'restore_auth');

    const clientDataJSON = Buffer.from(JSON.stringify({
      type: 'webauthn.get',
      challenge: challenge,
      origin: 'android:apk-key-hash:Wgcrc1QhQAIvKXlPrMo3HbZlhGYdPEkZrob3i3rbz98',
    })).toString('base64url');

    // App B attempts to restore using Alice's key -> MUST BE REJECTED
    const reqCrossApp = createMockRequest({
      body: {
        client_id: 'android-poc-client-b',
        assertion: {
          id: aliceKeyId,
          response: {
            clientDataJSON: clientDataJSON,
          },
        },
      },
    });
    const resCrossApp = createMockResponse();
    await restoreSession(reqCrossApp, resCrossApp as unknown as Response);
    console.log('6c. Cross-app restore rejection:', resCrossApp.statusCode, resCrossApp.body?.error_description);
    if (resCrossApp.statusCode !== 400 || resCrossApp.body?.error !== 'invalid_grant' || !resCrossApp.body?.error_description?.includes('Client ID mismatch')) {
      throw new Error('Expected 400 invalid_grant for cross-app restore key abuse');
    }
  }

  console.log('\n🎉 ALL UNIT TESTS PASSED SUCCESSFULLY! 🎉');
}

runDirectTests().catch(err => {
  console.error('Test run failed:', err);
  process.exit(1);
});
