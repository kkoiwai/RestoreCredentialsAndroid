import express from 'express';
import cors from 'cors';
import path from 'path';
import { PORT } from './config';
import {
  getPasskeyRegistrationOptions,
  verifyPasskeyRegistration,
  getPasskeyLoginOptions,
  verifyPasskeyLogin,
  quickLoginEndpoint,
} from './webauthn';
import {
  getRestoreRegistrationOptions,
  verifyRestoreRegistration,
  getRestoreChallenge,
  restoreSession,
} from './restore';
import {
  authorizeEndpoint,
  tokenEndpoint,
  openIdConfigEndpoint,
  userInfoEndpoint,
} from './oidc';
import { getProfileService, createNoteService } from './service';

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static web pages (AuthTab Web UI)
app.use(express.static(path.join(__dirname, '../public')));

// OIDC / OAuth2 Endpoints
app.get('/oauth/authorize', authorizeEndpoint);
app.post('/oauth/token', tokenEndpoint);
app.get('/.well-known/openid-configuration', openIdConfigEndpoint);
app.get('/oauth/userinfo', userInfoEndpoint);

// Passkey (WebAuthn Browser) Endpoints
app.post('/api/passkey/register/options', getPasskeyRegistrationOptions);
app.post('/api/passkey/register/verify', verifyPasskeyRegistration);
app.post('/api/passkey/login/options', getPasskeyLoginOptions);
app.post('/api/passkey/login/verify', verifyPasskeyLogin);
app.post('/api/passkey/quick-login', quickLoginEndpoint);

// Restore Credential Endpoints
app.post('/api/restore/register/options', getRestoreRegistrationOptions);
app.post('/api/restore/register/verify', verifyRestoreRegistration);
app.post('/api/restore/challenge', getRestoreChallenge);
app.post('/api/auth/restore-session', restoreSession);

// Protected Mock Service Endpoints
app.get('/api/service/profile', getProfileService);
app.post('/api/service/notes', createNoteService);

// Root redirect and Download alias
app.get('/', (req, res) => {
  res.redirect('/login.html');
});
app.get('/download', (req, res) => {
  res.redirect('/RestoreCredentialsPoC.apk');
});

// Health Check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: Date.now() });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`=======================================================`);
  console.log(`🚀 Restore Credentials Server listening on port ${PORT}`);
  console.log(`📡 URL: http://localhost:${PORT}`);
  console.log(`🔑 AuthTab Login: http://localhost:${PORT}/login.html`);
  console.log(`=======================================================`);
});
