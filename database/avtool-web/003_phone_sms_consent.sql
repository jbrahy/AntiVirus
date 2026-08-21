-- database/avtool-web/003_phone_sms_consent.sql
--
-- Phone number and SMS consent capture, for carrier route approval.
--
-- The two consent flags are deliberately separate columns rather than one
-- "sms_opt_in": the carrier standard requires transactional/service texts and
-- marketing texts to be consented to independently, and we have to be able to
-- prove which one a given user agreed to. The _at timestamps and the IP are
-- the audit trail if a consent is ever challenged.
ALTER TABLE users
  ADD COLUMN phone VARCHAR(20) NULL AFTER email,
  ADD COLUMN sms_service_consent TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN sms_service_consent_at DATETIME NULL,
  ADD COLUMN sms_marketing_consent TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN sms_marketing_consent_at DATETIME NULL,
  ADD COLUMN consent_ip VARCHAR(45) NULL,
  ADD COLUMN consent_user_agent VARCHAR(255) NULL;
