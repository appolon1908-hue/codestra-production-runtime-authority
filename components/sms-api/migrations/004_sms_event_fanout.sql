BEGIN;

ALTER TABLE sms_internal_events
  ADD COLUMN IF NOT EXISTS event_id uuid,
  ADD COLUMN IF NOT EXISTS event_version text NOT NULL DEFAULT '1.0',
  ADD COLUMN IF NOT EXISTS correlation_id text,
  ADD COLUMN IF NOT EXISTS delivery_state text NOT NULL DEFAULT 'pending',
  ADD COLUMN IF NOT EXISTS attempt_count integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS last_error text,
  ADD COLUMN IF NOT EXISTS next_retry_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN IF NOT EXISTS processing_started_at timestamptz,
  ADD COLUMN IF NOT EXISTS delivered_at timestamptz,
  ADD COLUMN IF NOT EXISTS envelope_hash char(64);

UPDATE sms_internal_events event
SET event_id = gen_random_uuid(),
    correlation_id = COALESCE(message.correlation_id, event.payload->>'correlation_id', 'legacy-' || event.id::text),
    envelope_hash = encode(digest(event.payload::text, 'sha256'), 'hex')
FROM sms_messages message
WHERE event.message_id = message.id
  AND (event.event_id IS NULL OR event.correlation_id IS NULL OR event.envelope_hash IS NULL);

ALTER TABLE sms_internal_events
  ALTER COLUMN event_id SET NOT NULL,
  ALTER COLUMN correlation_id SET NOT NULL,
  ALTER COLUMN envelope_hash SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS sms_internal_events_event_id_uq
  ON sms_internal_events(event_id);
CREATE INDEX IF NOT EXISTS sms_internal_events_delivery_due_idx
  ON sms_internal_events(delivery_state, next_retry_at, created_at);

ALTER TABLE sms_internal_events DROP CONSTRAINT IF EXISTS sms_internal_events_delivery_state_check;
ALTER TABLE sms_internal_events ADD CONSTRAINT sms_internal_events_delivery_state_check
  CHECK (delivery_state IN ('pending','processing','delivered','failed','dead_letter'));
ALTER TABLE sms_internal_events DROP CONSTRAINT IF EXISTS sms_internal_events_attempt_count_check;
ALTER TABLE sms_internal_events ADD CONSTRAINT sms_internal_events_attempt_count_check
  CHECK (attempt_count BETWEEN 0 AND 5);

COMMIT;
