/**
 * Utilities for extracting flags and AAGUID from WebAuthn authenticator data (authData).
 */

export interface AuthDataFlags {
  up: boolean; // User Present (Bit 0)
  uv: boolean; // User Verified (Bit 2)
  be: boolean; // Backup Eligibility (Bit 3)
  bs: boolean; // Backup State (Bit 4)
  at: boolean; // Attested Credential Data Present (Bit 6)
  ed: boolean; // Extension Data Present (Bit 7)
  rawByte: number;
}

export interface ParsedAuthData {
  rpIdHash: string; // hex
  flags: AuthDataFlags;
  signCount: number;
  aaguid?: string; // 8-4-4-4-12 hex UUID
}

export function parseAuthData(authData: Uint8Array): ParsedAuthData {
  if (authData.length < 37) {
    throw new Error(`authData is too short: ${authData.length} bytes`);
  }

  // rpIdHash (0..31)
  const rpIdHash = Buffer.from(authData.slice(0, 32)).toString('hex');

  // flags (32)
  const flagByte = authData[32];
  const flags: AuthDataFlags = {
    up: (flagByte & 0x01) !== 0,
    uv: (flagByte & 0x04) !== 0,
    be: (flagByte & 0x08) !== 0,
    bs: (flagByte & 0x10) !== 0,
    at: (flagByte & 0x40) !== 0,
    ed: (flagByte & 0x80) !== 0,
    rawByte: flagByte,
  };

  // signCount (33..36)
  const view = new DataView(authData.buffer, authData.byteOffset, authData.byteLength);
  const signCount = view.getUint32(33, false);

  let aaguid: string | undefined;
  // If AT flag is set, aaguid is at 37..52 (16 bytes)
  if (flags.at && authData.length >= 53) {
    const aaguidBytes = authData.slice(37, 53);
    const hex = Buffer.from(aaguidBytes).toString('hex');
    aaguid = [
      hex.substring(0, 8),
      hex.substring(8, 12),
      hex.substring(12, 16),
      hex.substring(16, 20),
      hex.substring(20, 32),
    ].join('-');
  }

  return {
    rpIdHash,
    flags,
    signCount,
    aaguid,
  };
}
