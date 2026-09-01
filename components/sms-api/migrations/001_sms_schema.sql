BEGIN;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS sms_accounts (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), kong_consumer_id text UNIQUE NOT NULL,
 customer_code text UNIQUE NOT NULL, status text NOT NULL CHECK(status IN ('active','disabled','suspended')),
 sms_entitled boolean NOT NULL DEFAULT false, currency char(3) NOT NULL DEFAULT 'USD',
 balance numeric(18,6) NOT NULL DEFAULT 0 CHECK(balance >= 0), created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sms_sender_profiles (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), account_id uuid NOT NULL REFERENCES sms_accounts(id),
 sender text NOT NULL, sender_type text NOT NULL CHECK(sender_type IN ('alphanumeric','numeric','shortcode')),
 status text NOT NULL DEFAULT 'active', country_codes text[] NOT NULL DEFAULT '{}', UNIQUE(account_id,sender)
);
CREATE TABLE IF NOT EXISTS sms_routes (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text UNIQUE NOT NULL, destination_prefix text NOT NULL,
 provider text NOT NULL, restricted_endpoint text NOT NULL, unit_price numeric(18,6) NOT NULL CHECK(unit_price >= 0),
 currency char(3) NOT NULL, enabled boolean NOT NULL DEFAULT true, synthetic_only boolean NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS sms_account_limits (
 account_id uuid PRIMARY KEY REFERENCES sms_accounts(id), messages_per_minute integer NOT NULL CHECK(messages_per_minute > 0),
 max_segments integer NOT NULL DEFAULT 6 CHECK(max_segments BETWEEN 1 AND 20), duplicate_window_seconds integer NOT NULL DEFAULT 300
);
CREATE TABLE IF NOT EXISTS sms_suppressions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), account_id uuid NOT NULL REFERENCES sms_accounts(id),
 destination text NOT NULL, reason text NOT NULL, active boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(account_id,destination)
);
CREATE TABLE IF NOT EXISTS sms_messages (
 id uuid PRIMARY KEY, account_id uuid NOT NULL REFERENCES sms_accounts(id), idempotency_key text NOT NULL,
 request_hash char(64) NOT NULL, duplicate_hash char(64) NOT NULL, destination text NOT NULL, sender text NOT NULL,
 content text NOT NULL, segments integer NOT NULL, route_id uuid NOT NULL REFERENCES sms_routes(id),
 status text NOT NULL, provider_status text, provider_message_id text, synthetic boolean NOT NULL DEFAULT false,
 total_price numeric(18,6) NOT NULL, currency char(3) NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(), UNIQUE(account_id,idempotency_key)
);
CREATE INDEX IF NOT EXISTS sms_messages_tenant_created_idx ON sms_messages(account_id,created_at DESC);
CREATE INDEX IF NOT EXISTS sms_messages_duplicate_idx ON sms_messages(account_id,duplicate_hash,created_at DESC);
CREATE TABLE IF NOT EXISTS sms_message_attempts (
 id bigserial PRIMARY KEY, message_id uuid NOT NULL REFERENCES sms_messages(id), attempt_no integer NOT NULL,
 route_id uuid NOT NULL REFERENCES sms_routes(id), outcome text NOT NULL, provider_response jsonb,
 created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(message_id,attempt_no)
);
CREATE TABLE IF NOT EXISTS sms_dlr_events (
 id bigserial PRIMARY KEY, message_id uuid NOT NULL REFERENCES sms_messages(id), provider_event_id text UNIQUE NOT NULL,
 canonical_status text NOT NULL, provider_status text NOT NULL, raw_payload jsonb NOT NULL,
 received_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sms_balance_ledger (
 id bigserial PRIMARY KEY, account_id uuid NOT NULL REFERENCES sms_accounts(id), message_id uuid REFERENCES sms_messages(id),
 entry_type text NOT NULL, amount numeric(18,6) NOT NULL, balance_after numeric(18,6) NOT NULL,
 destination text, sender text, route_id uuid REFERENCES sms_routes(id), segments integer,
 unit_price numeric(18,6), total_price numeric(18,6), currency char(3) NOT NULL,
 submitted_at timestamptz, final_status text, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sms_audit_events (
 id bigserial PRIMARY KEY, account_id uuid REFERENCES sms_accounts(id), event_type text NOT NULL,
 message_id uuid, correlation_id text, detail jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sms_internal_events (
 id bigserial PRIMARY KEY, account_id uuid NOT NULL REFERENCES sms_accounts(id), message_id uuid NOT NULL,
 event_type text NOT NULL, payload jsonb NOT NULL, published_at timestamptz, created_at timestamptz NOT NULL DEFAULT now()
);
COMMIT;

