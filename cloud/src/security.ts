import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

import type {
  AuthenticatedPrincipal,
  CollectorCredential,
  Env,
} from "./types";

const encoder = new TextEncoder();
const MAX_CLOCK_SKEW_SECONDS = 300;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;

export class AuthenticationError extends Error {}

export function accessPrincipalFromPayload(payload: JWTPayload): AuthenticatedPrincipal {
  const email = typeof payload.email === "string" ? payload.email.trim().toLowerCase() : undefined;
  const subject = typeof payload.sub === "string" ? payload.sub : undefined;
  const principalId = email ?? subject;
  if (!principalId) throw new AuthenticationError("Access token has no stable subject");
  return { id: principalId, type: "access_user", ...(email ? { email } : {}) };
}

function bytesToHex(value: ArrayBuffer): string {
  return [...new Uint8Array(value)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value);
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export function base64UrlEncode(value: Uint8Array): string {
  return bytesToBase64(value).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export async function sha256Hex(value: string): Promise<string> {
  return bytesToHex(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

async function importKek(encodedKey: string): Promise<CryptoKey> {
  const raw = base64ToBytes(encodedKey);
  if (raw.byteLength !== 32) throw new Error("CREDENTIAL_KEK must decode to 32 bytes");
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function encryptCollectorSecret(
  secret: string,
  encodedKek: string,
): Promise<{ ciphertext: string; iv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    await importKek(encodedKek),
    encoder.encode(secret),
  );
  return {
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
    iv: bytesToBase64(iv),
  };
}

export async function decryptCollectorSecret(
  ciphertext: string,
  iv: string,
  encodedKek: string,
): Promise<string> {
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64ToBytes(iv) },
      await importKek(encodedKek),
      base64ToBytes(ciphertext),
    );
    return new TextDecoder().decode(plaintext);
  } catch {
    throw new AuthenticationError("collector credential could not be decrypted");
  }
}

export function constantTimeEqual(left: string, right: string): boolean {
  const leftBytes = encoder.encode(left);
  const rightBytes = encoder.encode(right);
  const maximum = Math.max(leftBytes.length, rightBytes.length);
  let difference = leftBytes.length ^ rightBytes.length;
  for (let index = 0; index < maximum; index += 1) {
    difference |= (leftBytes[index] ?? 0) ^ (rightBytes[index] ?? 0);
  }
  return difference === 0;
}

export async function hmacHex(secret: string, value: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return bytesToHex(await crypto.subtle.sign("HMAC", key, encoder.encode(value)));
}

export async function requireAnalyst(
  request: Request,
  env: Env,
): Promise<AuthenticatedPrincipal> {
  const accessConfigured = env.ACCESS_TEAM_DOMAIN.length > 0 && env.ACCESS_AUD.length > 0;
  if (accessConfigured) {
    const assertion = request.headers.get("cf-access-jwt-assertion");
    if (!assertion) throw new AuthenticationError("Cloudflare Access assertion is required");
    const issuer = `https://${env.ACCESS_TEAM_DOMAIN}`;
    const jwks = createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`));
    try {
      const { payload } = await jwtVerify(assertion, jwks, {
        issuer,
        audience: env.ACCESS_AUD,
        algorithms: ["RS256"],
      });
      return accessPrincipalFromPayload(payload);
    } catch (error) {
      if (error instanceof AuthenticationError) throw error;
      throw new AuthenticationError("Cloudflare Access assertion is invalid");
    }
  }

  const authorization = request.headers.get("authorization");
  const expected = `Bearer ${env.ADMIN_TOKEN}`;
  if (!authorization || env.ADMIN_TOKEN.length < 32 || !constantTimeEqual(authorization, expected)) {
    throw new AuthenticationError("analyst authentication failed");
  }
  return { id: "bootstrap-admin", type: "admin_token" };
}

function signatureHeaders(request: Request): {
  credentialId: string;
  nonce: string;
  signature: string;
  timestamp: string;
} {
  const credentialId = request.headers.get("x-controlforge-credential-id") ?? "";
  const timestamp = request.headers.get("x-controlforge-timestamp") ?? "";
  const nonce = request.headers.get("x-controlforge-nonce") ?? "";
  const signature = request.headers.get("x-controlforge-signature") ?? "";
  if (!credentialId || !timestamp || !NONCE_PATTERN.test(nonce) || !/^[a-f0-9]{64}$/u.test(signature)) {
    throw new AuthenticationError("collector signature headers are invalid");
  }
  return { credentialId, timestamp, nonce, signature };
}

export async function requireCollector(
  request: Request,
  body: string,
  env: Env,
): Promise<AuthenticatedPrincipal> {
  const headers = signatureHeaders(request);
  const timestampMs = Date.parse(headers.timestamp);
  if (!Number.isFinite(timestampMs)) throw new AuthenticationError("collector timestamp is invalid");
  const skew = Math.abs(Date.now() - timestampMs) / 1_000;
  if (skew > MAX_CLOCK_SKEW_SECONDS) throw new AuthenticationError("collector timestamp is stale");

  const credential = await env.DB.prepare(
    `SELECT c.credential_id, c.tenant_id, c.secret_ciphertext, c.secret_iv,
            c.expires_at, c.revoked_at, t.status AS tenant_status
       FROM collector_credentials c
       JOIN tenants t ON t.tenant_id = c.tenant_id
      WHERE c.credential_id = ?`,
  ).bind(headers.credentialId).first<CollectorCredential>();
  if (
    !credential || credential.revoked_at || credential.tenant_status !== "active" ||
    Date.parse(credential.expires_at) <= Date.now()
  ) {
    throw new AuthenticationError("collector credential is not active");
  }

  const requestUrl = new URL(request.url);
  const bodyHash = await sha256Hex(body);
  const canonical = [
    request.method.toUpperCase(),
    requestUrl.pathname,
    headers.timestamp,
    headers.nonce,
    bodyHash,
  ].join("\n");
  const secret = await decryptCollectorSecret(
    credential.secret_ciphertext,
    credential.secret_iv,
    env.CREDENTIAL_KEK,
  );
  const expected = await hmacHex(secret, canonical);
  if (!constantTimeEqual(headers.signature, expected)) {
    throw new AuthenticationError("collector signature verification failed");
  }

  const expiresAt = new Date(Date.now() + MAX_CLOCK_SKEW_SECONDS * 2_000).toISOString();
  const nonceResult = await env.DB.prepare(
    "INSERT OR IGNORE INTO ingestion_nonces(credential_id, nonce, expires_at) VALUES (?, ?, ?)",
  ).bind(credential.credential_id, headers.nonce, expiresAt).run();
  if (nonceResult.meta.changes !== 1) throw new AuthenticationError("collector request was replayed");
  await env.DB.prepare(
    "UPDATE collector_credentials SET last_used_at = ? WHERE credential_id = ?",
  ).bind(new Date().toISOString(), credential.credential_id).run();
  return {
    id: credential.credential_id,
    type: "collector",
    tenantId: credential.tenant_id,
    credentialId: credential.credential_id,
  };
}

export function generateSecret(byteLength = 32): string {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(byteLength)));
}
