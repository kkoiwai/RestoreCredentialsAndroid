export interface User {
  id: string; // Internal user ID
  username: string;
  displayName: string;
  createdAt: number;
}

export interface Credential {
  id: string; // Base64URL credential ID
  userId: string;
  publicKey: string; // Base64URL encoded public key bytes
  counter: number;
  transports?: string[];
  credentialType: 'passkey' | 'restore_key';
  aaguid: string;
  backupEligible: boolean; // BE flag (Bit 3)
  backupState: boolean;    // BS flag (Bit 4)
  userVerified: boolean;   // UV flag (Bit 2)
  userPresent: boolean;    // UP flag (Bit 0)
  deviceInfo?: string;
  clientId?: string; // Bound client ID (e.g. android-poc-client, android-poc-client-b)
  scope?: string;    // Authorized OAuth scopes (e.g. 'openid profile')
  createdAt: number;
}

export interface AuthCode {
  code: string;
  userId: string;
  clientId: string;
  redirectUri: string;
  scope?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  expiresAt: number;
}

export interface Token {
  accessToken: string;
  refreshToken: string;
  userId: string;
  scope?: string;
  clientId?: string;
  expiresAt: number;
}

export interface WebAuthnChallenge {
  challenge: string;
  userId?: string;
  type: 'passkey_reg' | 'passkey_auth' | 'restore_reg' | 'restore_auth';
  expiresAt: number;
}

// In-Memory Storage
export class Database {
  private users: Map<string, User> = new Map();
  private credentials: Map<string, Credential> = new Map(); // key: credential ID
  private authCodes: Map<string, AuthCode> = new Map();
  private tokens: Map<string, Token> = new Map(); // key: accessToken
  private refreshTokens: Map<string, Token> = new Map(); // key: refreshToken
  private challenges: Map<string, WebAuthnChallenge> = new Map(); // key: challenge

  // User operations
  createUser(username: string, displayName?: string): User {
    const existing = Array.from(this.users.values()).find(u => u.username === username);
    if (existing) return existing;

    const user: User = {
      id: 'usr_' + Math.random().toString(36).substring(2, 12),
      username,
      displayName: displayName || username,
      createdAt: Date.now(),
    };
    this.users.set(user.id, user);
    return user;
  }

  getUserById(id: string): User | undefined {
    return this.users.get(id);
  }

  getUserByUsername(username: string): User | undefined {
    return Array.from(this.users.values()).find(u => u.username === username);
  }

  // Credential operations (unified for both passkey and restore_key)
  saveCredential(cred: Credential): void {
    this.credentials.set(cred.id, cred);
  }

  getCredentialById(id: string): Credential | undefined {
    return this.credentials.get(id);
  }

  getCredentialsByUserId(userId: string, type?: 'passkey' | 'restore_key'): Credential[] {
    const list = Array.from(this.credentials.values()).filter(c => c.userId === userId);
    return type ? list.filter(c => c.credentialType === type) : list;
  }

  updateCredentialCounter(id: string, counter: number): void {
    const cred = this.credentials.get(id);
    if (cred) {
      cred.counter = counter;
    }
  }

  deleteCredentialsByUserId(userId: string, type?: 'passkey' | 'restore_key'): number {
    let count = 0;
    for (const [id, cred] of this.credentials.entries()) {
      if (cred.userId === userId && (!type || cred.credentialType === type)) {
        this.credentials.delete(id);
        count++;
      }
    }
    return count;
  }

  // Challenge operations
  saveChallenge(challenge: string, type: WebAuthnChallenge['type'], userId?: string, ttlMs = 300000): void {
    this.challenges.set(challenge, {
      challenge,
      userId,
      type,
      expiresAt: Date.now() + ttlMs,
    });
  }

  getChallenge(challenge: string): WebAuthnChallenge | undefined {
    const c = this.challenges.get(challenge);
    if (!c) return undefined;
    if (Date.now() > c.expiresAt) {
      this.challenges.delete(challenge);
      return undefined;
    }
    return c;
  }

  consumeChallenge(challenge: string): WebAuthnChallenge | undefined {
    const c = this.getChallenge(challenge);
    if (c) {
      this.challenges.delete(challenge);
    }
    return c;
  }

  // AuthCode operations
  saveAuthCode(code: AuthCode): void {
    this.authCodes.set(code.code, code);
  }

  consumeAuthCode(code: string): AuthCode | undefined {
    const ac = this.authCodes.get(code);
    if (!ac) return undefined;
    this.authCodes.delete(code);
    if (Date.now() > ac.expiresAt) return undefined;
    return ac;
  }

  // Token operations
  createTokenPair(userId: string, ttlSeconds = 3600, scope = 'openid profile', clientId?: string): Token {
    const accessToken = 'at_' + Math.random().toString(36).substring(2) + Date.now().toString(36);
    const refreshToken = 'rt_' + Math.random().toString(36).substring(2) + Date.now().toString(36);
    const token: Token = {
      accessToken,
      refreshToken,
      userId,
      scope,
      clientId,
      expiresAt: Date.now() + ttlSeconds * 1000,
    };
    this.tokens.set(accessToken, token);
    this.refreshTokens.set(refreshToken, token);
    return token;
  }

  getTokenByAccessToken(accessToken: string): Token | undefined {
    const t = this.tokens.get(accessToken);
    if (!t) return undefined;
    if (Date.now() > t.expiresAt) {
      this.tokens.delete(accessToken);
      return undefined;
    }
    return t;
  }

  getAllCredentials(): Credential[] {
    return Array.from(this.credentials.values());
  }
}

export const db = new Database();
