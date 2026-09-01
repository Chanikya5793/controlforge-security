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
    EVENT_RETENTION_DAYS: string;
    RETENTION_BATCH_SIZE: string;
    RETENTION_MAX_BATCHES_PER_RUN: string;
    TENANT_INGEST_EVENTS_PER_MINUTE: string;
    DEVICE_INGEST_EVENTS_PER_MINUTE: string;
    D1_MAX_DATABASE_BYTES: string;
    D1_CAPACITY_WRITE_STOP_PERCENT: string;
    TEST_MIGRATIONS: D1Migration[];
  }

  interface GlobalProps {
    mainModule: typeof import("../src/index");
  }
}
