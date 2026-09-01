BEGIN;

ALTER TABLE sms_sender_profiles
  ADD COLUMN IF NOT EXISTS provider_sender text;

UPDATE sms_sender_profiles
SET provider_sender = CASE
  WHEN sender = 'CODESTRA' AND account_id IN (
    SELECT id FROM sms_accounts WHERE customer_code LIKE 'SYNTHETIC-%'
  ) THEN 'TEST'
  ELSE sender
END
WHERE provider_sender IS NULL;

ALTER TABLE sms_sender_profiles
  ALTER COLUMN provider_sender SET NOT NULL;

ALTER TABLE sms_messages
  ADD COLUMN IF NOT EXISTS adapter_message_id text,
  ADD COLUMN IF NOT EXISTS correlation_id text,
  ADD COLUMN IF NOT EXISTS carrier_submitted boolean NOT NULL DEFAULT false;

CREATE UNIQUE INDEX IF NOT EXISTS sms_messages_adapter_message_id_uq
  ON sms_messages(adapter_message_id) WHERE adapter_message_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS sms_messages_provider_message_id_idx
  ON sms_messages(provider_message_id) WHERE provider_message_id IS NOT NULL;

ALTER TABLE sms_dlr_events
  ADD COLUMN IF NOT EXISTS payload_hash char(64),
  ADD COLUMN IF NOT EXISTS adapter_message_id text,
  ADD COLUMN IF NOT EXISTS customer_id uuid,
  ADD COLUMN IF NOT EXISTS correlation_id text,
  ADD COLUMN IF NOT EXISTS processing_state text NOT NULL DEFAULT 'processed';

UPDATE sms_dlr_events
SET payload_hash = encode(digest(raw_payload::text, 'sha256'), 'hex')
WHERE payload_hash IS NULL;
ALTER TABLE sms_dlr_events ALTER COLUMN payload_hash SET NOT NULL;

CREATE TABLE IF NOT EXISTS sms_dlr_dead_letters (
  id bigserial PRIMARY KEY,
  provider_event_id text,
  payload_hash char(64) NOT NULL,
  provider_message_id text,
  adapter_message_id text,
  middleware_message_id text,
  customer_code text,
  correlation_id text,
  provider_status text,
  reason text NOT NULL,
  retry_count integer NOT NULL DEFAULT 0,
  raw_payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sms_dlr_dead_letter_reason_idx
  ON sms_dlr_dead_letters(reason, created_at DESC);

ALTER TABLE sms_balance_ledger
  ADD COLUMN IF NOT EXISTS state text NOT NULL DEFAULT 'provisional',
  ADD COLUMN IF NOT EXISTS finalized_at timestamptz,
  ADD COLUMN IF NOT EXISTS released_at timestamptz;
CREATE UNIQUE INDEX IF NOT EXISTS sms_balance_ledger_message_uq
  ON sms_balance_ledger(message_id) WHERE message_id IS NOT NULL;

UPDATE sms_balance_ledger ledger
SET state = CASE
  WHEN NOT message.carrier_submitted THEN 'provisional'
  WHEN ledger.final_status IN ('delivered','sent') THEN 'finalized'
  WHEN ledger.final_status IN ('failed','rejected','expired') THEN 'released'
  ELSE 'provisional'
END
FROM sms_messages message
WHERE ledger.message_id = message.id AND ledger.state = 'provisional';

CREATE UNIQUE INDEX IF NOT EXISTS sms_internal_event_business_uq
  ON sms_internal_events(message_id, event_type);

COMMIT;
