import { describe, expect, it } from "vitest";

import {
  accessPrincipalFromPayload,
  AuthenticationError,
  constantTimeEqual,
  decryptCollectorSecret,
  encryptCollectorSecret,
  hmacHex,
  requireAnalyst,
} from "../src/security";
import type { Env } from "../src/types";

function environment(adminToken = "a".repeat(48)): Env {
  return {
    DB: {} as D1Database,
    EVENT_QUEUE: {} as Queue,
    ENVIRONMENT: "test",
    ADMIN_TOKEN: adminToken,
    CREDENTIAL_KEK: btoa(String.fromCharCode(...new Uint8Array(32).fill(7))),
    AUDIT_HMAC_SECRET: "audit-secret-that-is-long-enough",
    ACCESS_TEAM_DOMAIN: "",
    ACCESS_AUD: "",
    TRIAGE_PROVIDER: "meta",
    META_MODEL: "fixture-meta-model",
    GEMINI_MODEL: "fixture-model",
  };
}

describe("security primitives", () => {
  it("uses a normalized Access email as the stable tenant principal", () => {
    expect(accessPrincipalFromPayload({ sub: "provider-subject", email: " Analyst@Example.COM " }))
      .toEqual({
        id: "analyst@example.com",
        email: "analyst@example.com",
        type: "access_user",
      });
    expect(accessPrincipalFromPayload({ sub: "provider-subject" })).toMatchObject({
      id: "provider-subject",
      type: "access_user",
    });
    expect(() => accessPrincipalFromPayload({})).toThrow(AuthenticationError);
  });

  it("encrypts collector secrets with a unique IV and decrypts them", async () => {
    const env = environment();
    const first = await encryptCollectorSecret("collector-secret", env.CREDENTIAL_KEK);
    const second = await encryptCollectorSecret("collector-secret", env.CREDENTIAL_KEK);

    expect(first.ciphertext).not.toBe(second.ciphertext);
    await expect(decryptCollectorSecret(first.ciphertext, first.iv, env.CREDENTIAL_KEK))
      .resolves.toBe("collector-secret");
  });

  it("fails closed when ciphertext authentication fails", async () => {
    const env = environment();
    const encrypted = await encryptCollectorSecret("collector-secret", env.CREDENTIAL_KEK);
    const corrupted = `${encrypted.ciphertext.slice(0, -2)}AA`;

    await expect(decryptCollectorSecret(corrupted, encrypted.iv, env.CREDENTIAL_KEK))
      .rejects.toBeInstanceOf(AuthenticationError);
  });

  it("generates stable HMAC values and compares without early length exits", async () => {
    const first = await hmacHex("secret", "message");
    const second = await hmacHex("secret", "message");

    expect(first).toBe(second);
    expect(constantTimeEqual(first, second)).toBe(true);
    expect(constantTimeEqual(first, `${second}0`)).toBe(false);
  });

  it("requires a sufficiently strong exact administrator bearer token", async () => {
    const token = "z".repeat(48);
    const request = new Request("https://soc.example.test/v1/alerts", {
      headers: { authorization: `Bearer ${token}` },
    });
    await expect(requireAnalyst(request, environment(token))).resolves.toMatchObject({
      id: "bootstrap-admin",
      type: "admin_token",
    });

    await expect(requireAnalyst(
      new Request("https://soc.example.test", { headers: { authorization: "Bearer wrong" } }),
      environment(token),
    )).rejects.toBeInstanceOf(AuthenticationError);
  });
});
