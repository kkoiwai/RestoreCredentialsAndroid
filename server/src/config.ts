import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';

dotenv.config();

export const PORT = parseInt(process.env.PORT || '8080', 10);
export const RP_NAME = process.env.RP_NAME || 'Restore Credentials PoC';
export const RP_ID = process.env.RP_ID || 'localhost';
export const ISSUER = process.env.ISSUER || (RP_ID === 'localhost' ? `http://${RP_ID}:${PORT}` : `https://${RP_ID}`);
export const CLIENT_ID = process.env.CLIENT_ID || 'android-poc-client';
export const REDIRECT_URI = process.env.REDIRECT_URI || 'restoreapp://auth-callback';

export const ALLOWED_ORIGINS = [
  'http://localhost:8080',
  'http://10.0.2.2:8080',
  'http://127.0.0.1:8080',
  `http://${RP_ID}:${PORT}`,
  `https://${RP_ID}`,
];

/**
 * Converts a SHA-256 certificate fingerprint (hex string with or without colons)
 * to standard Android WebAuthn origin format: `android:apk-key-hash:<base64url>`
 */
export function fingerprintHexToBase64Url(fingerprintHex: string): string {
  const cleanHex = fingerprintHex.replace(/[^0-9a-fA-F]/g, '');
  return Buffer.from(cleanHex, 'hex').toString('base64url');
}

/**
 * Loads allowed Android APK signing fingerprints from assetlinks.json and environment variables,
 * returning the list of valid `android:apk-key-hash:...` origin strings.
 */
export function getExpectedAndroidOrigins(): string[] {
  const origins: string[] = [];

  // 1. Read from public/.well-known/assetlinks.json
  try {
    const candidates = [
      path.join(__dirname, '../public/.well-known/assetlinks.json'),
      path.join(process.cwd(), 'public/.well-known/assetlinks.json'),
      path.join(process.cwd(), 'dist/public/.well-known/assetlinks.json'),
    ];
    for (const p of candidates) {
      if (fs.existsSync(p)) {
        const data = JSON.parse(fs.readFileSync(p, 'utf-8'));
        for (const entry of data) {
          const fingerprints = entry?.target?.sha256_cert_fingerprints || [];
          for (const fp of fingerprints) {
            const b64url = fingerprintHexToBase64Url(fp);
            const originStr = `android:apk-key-hash:${b64url}`;
            if (!origins.includes(originStr)) {
              origins.push(originStr);
            }
          }
        }
        break;
      }
    }
  } catch (err) {
    console.error('[CONFIG] Failed to parse assetlinks.json:', err);
  }

  // 2. Read from env var ANDROID_CERT_FINGERPRINTS if provided
  if (process.env.ANDROID_CERT_FINGERPRINTS) {
    const fps = process.env.ANDROID_CERT_FINGERPRINTS.split(',').map(s => s.trim());
    for (const fp of fps) {
      const b64url = fingerprintHexToBase64Url(fp);
      const originStr = `android:apk-key-hash:${b64url}`;
      if (!origins.includes(originStr)) {
        origins.push(originStr);
      }
    }
  }

  return origins;
}

/**
 * Validates whether the given origin is allowed.
 * For Android app origins (`android:apk-key-hash:...`), this strictly checks
 * that the hash matches the SHA-256 fingerprint of the authorized signing certificate!
 */
export function isAllowedOrigin(origin: string): boolean {
  if (ALLOWED_ORIGINS.includes(origin)) return true;

  // Strict Android Credential Manager origin verification:
  // Verifies the SHA-256 fingerprint inside `android:apk-key-hash:<sha256-base64url>`
  if (origin.startsWith('android:apk-key-hash:')) {
    const allowedAndroidOrigins = getExpectedAndroidOrigins();
    const isMatched = allowedAndroidOrigins.includes(origin);
    if (!isMatched) {
      console.warn(`[ORIGIN REJECTED] Android APK key hash fingerprint mismatch: "${origin}"`);
      console.warn(`[ORIGIN ALLOWED] Registered Android origins:`, allowedAndroidOrigins);
    } else {
      console.log(`[ORIGIN VERIFIED] Android APK key hash matched authorized fingerprint: "${origin}"`);
    }
    return isMatched;
  }

  // Support any Cloud Run origin (*.run.app)
  if (origin.endsWith('.run.app')) return true;

  if (process.env.ADDITIONAL_ORIGINS) {
    const additional = process.env.ADDITIONAL_ORIGINS.split(',').map(o => o.trim());
    if (additional.includes(origin)) return true;
  }

  return false;
}

export function getExpectedOrigin(origin: string): string | string[] {
  if (isAllowedOrigin(origin)) {
    return origin;
  }
  return ALLOWED_ORIGINS;
}
