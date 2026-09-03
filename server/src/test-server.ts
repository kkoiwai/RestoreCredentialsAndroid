/**
 * Unit test script to verify server endpoints, PKCE, and Client ID checks
 * Uses in-memory mock Request/Response to run without requiring network sockets.
 */
import crypto from 'crypto';
import { Request, Response } from 'express';
import {
  quickLoginEndpoint,
  getPasskeyRegistrationOptions,
} from './webauthn';
import {
  restoreSession,
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
  // 4a. Client ID mismatch test
  {
    const code = issueFreshAuthCode();
    const req = createMockRequest({
      body: {
        grant_type: 'authorization_code',
        code,
        client_id: 'wrong-client',
        redirect_uri: 'restoreapp://auth-callback',
        code_verifier: codeVerifier,
      },
    });
    const res = createMockResponse();
    tokenEndpoint(req, res as unknown as Response);
    console.log('4a. Token exchange with wrong client_id:', res.statusCode, res.body?.error_description);
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

  // 4d. Successful Token Exchange with valid code_verifier & client_id
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
    console.log('4d. Token exchange success:', res.statusCode, 'token:', res.body?.access_token ? 'issued' : 'missing');
    if (res.statusCode !== 200 || !res.body?.access_token) {
      throw new Error('Token exchange failed with valid verifier');
    }
  }

  // 5. restore-session Client ID validation
  // 5a. Missing client_id
  {
    const req = createMockRequest({
      body: {
        assertion: { id: 'dummy', response: {} },
      },
    });
    const res = createMockResponse();
    await restoreSession(req, res as unknown as Response);
    console.log('5a. restore-session missing client_id:', res.statusCode, res.body?.error_description);
    if (res.statusCode !== 400 || res.body?.error !== 'invalid_client' || !res.body?.error_description?.includes('Missing client_id')) {
      throw new Error('Expected 400 invalid_client for missing client_id');
    }
  }

  // 5b. Invalid client_id
  {
    const req = createMockRequest({
      body: {
        client_id: 'unknown-client',
        assertion: { id: 'dummy', response: {} },
      },
    });
    const res = createMockResponse();
    await restoreSession(req, res as unknown as Response);
    console.log('5b. restore-session invalid client_id:', res.statusCode, res.body?.error_description);
    if (res.statusCode !== 400 || res.body?.error !== 'invalid_client' || !res.body?.error_description?.includes('Invalid or unknown client_id')) {
      throw new Error('Expected 400 invalid_client for unknown client_id');
    }
  }

  console.log('\n🎉 ALL UNIT TESTS PASSED SUCCESSFULLY! 🎉');
}

runDirectTests().catch(err => {
  console.error('Test run failed:', err);
  process.exit(1);
});
