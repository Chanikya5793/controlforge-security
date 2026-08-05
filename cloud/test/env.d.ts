declare namespace Cloudflare {
  interface Env {
    DB: D1Database;
    EVENT_QUEUE: Queue;
    ENVIRONMENT: string;
    ADMIN_TOKEN: string;
    CREDENTIAL_KEK: string;
    AUDIT_HMAC_SECRET: string;
    ACCESS_TEAM_DOMAIN: string;
    ACCESS_AUD: string;
    TRIAGE_PROVIDER: string;
    META_MODEL: string;
    GEMINI_MODEL: string;
    TEST_MIGRATIONS: D1Migration[];
  }

  interface GlobalProps {
    mainModule: typeof import("../src/index");
  }
}
