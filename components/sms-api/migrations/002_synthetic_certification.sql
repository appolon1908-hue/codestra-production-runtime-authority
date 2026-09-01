BEGIN;
INSERT INTO sms_routes(name,destination_prefix,provider,restricted_endpoint,unit_price,currency,enabled,synthetic_only)
VALUES ('telnexa-do-synthetic','+1809','telnexa','http://10.40.0.4:8443/v1/messages',0.010000,'USD',true,true)
ON CONFLICT(name) DO NOTHING;
INSERT INTO sms_accounts(kong_consumer_id,customer_code,status,sms_entitled,balance)
VALUES
 ('2a9add4c-70fa-4e12-9b62-ed3d1090349a','SYNTHETIC-A','active',true,10.000000),
 ('11111111-1111-4111-8111-111111111111','SYNTHETIC-DISABLED','disabled',true,10.000000),
 ('22222222-2222-4222-8222-222222222222','SYNTHETIC-B','active',true,10.000000),
 ('33333333-3333-4333-8333-333333333333','SYNTHETIC-NOFUNDS','active',true,0.000000)
ON CONFLICT(kong_consumer_id) DO NOTHING;
INSERT INTO sms_account_limits(account_id,messages_per_minute,max_segments,duplicate_window_seconds)
SELECT id,2,6,300 FROM sms_accounts WHERE customer_code LIKE 'SYNTHETIC-%' ON CONFLICT(account_id) DO NOTHING;
INSERT INTO sms_sender_profiles(account_id,sender,sender_type,country_codes)
SELECT id,'CODESTRA','alphanumeric',ARRAY['+1809'] FROM sms_accounts WHERE customer_code IN ('SYNTHETIC-A','SYNTHETIC-B','SYNTHETIC-NOFUNDS')
ON CONFLICT(account_id,sender) DO NOTHING;
COMMIT;

