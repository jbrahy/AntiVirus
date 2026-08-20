-- database/avtool-web/002_index_stripe_customer_id.sql
-- The Stripe webhook looks up a user by stripe_customer_id on every
-- delivery (see internal/web/billing/webhook.go's upsertSubscription).
-- Without an index this is a full table scan. Not UNIQUE: Stripe customer
-- IDs are globally unique by construction, and the only writer of this
-- column is the checkout flow using an ID Stripe itself generated, so a
-- UNIQUE constraint isn't necessary here — a plain index is what lookup
-- performance actually needs.
CREATE INDEX idx_users_stripe_customer_id ON users (stripe_customer_id);
