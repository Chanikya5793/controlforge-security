import path from "node:path";
import { fileURLToPath } from "node:url";

import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

const directory = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [
    cloudflareTest(async () => ({
      main: "./src/index.ts",
      miniflare: {
        compatibilityDate: "2026-08-18",
        compatibilityFlags: ["nodejs_compat"],
        d1Databases: ["DB"],
        queueProducers: { EVENT_QUEUE: "controlforge-test-events" },
        bindings: {
          ENVIRONMENT: "test",
          ADMIN_TOKEN: "a".repeat(48),
          CREDENTIAL_KEK: Buffer.alloc(32, 7).toString("base64"),
          AUDIT_HMAC_SECRET: "audit-secret-for-test-environment-only",
          ACCESS_TEAM_DOMAIN: "",
          ACCESS_AUD: "",
          TRIAGE_PROVIDER: "meta",
          META_MODEL: "fixture-meta-model",
          GEMINI_MODEL: "fixture-model",
          TEST_MIGRATIONS: await readD1Migrations(path.join(directory, "migrations")),
        },
      },
    })),
  ],
  test: {
    setupFiles: ["./test/setup.ts"],
    coverage: {
      provider: "istanbul",
      reporter: ["text"],
      thresholds: {
        lines: 80,
        functions: 80,
        statements: 80,
        branches: 60,
      },
      include: ["src/**/*.ts"],
      exclude: ["src/types.ts", "src/dashboard.ts"],
    },
  },
});
