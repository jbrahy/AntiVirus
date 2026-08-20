// internal/web/billing/webhook.go
package billing

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/jbrahy/AntiVirus/internal/web/license"
	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/webhook"
)

// maxWebhookBodyBytes bounds how much of the request body HandleWebhook will
// read. This route is publicly reachable and unauthenticated until the
// Stripe-Signature check passes, so an unbounded io.ReadAll would let an
// attacker exhaust memory by streaming an arbitrarily large body. 1MB is
// generous for a Stripe webhook payload.
const maxWebhookBodyBytes = 1 << 20

// errUnknownStripeCustomer indicates a webhook event about a Stripe customer
// with no local user mapping. This Stripe account is shared with other,
// unrelated products (AudioPanels, wearz.com) — every one of their
// subscription events also hits this endpoint, and none of them will ever
// resolve to a row in our users table. That is not a failure: it must not
// cause a 500, or Stripe will retry it for up to 3 days and eventually
// disable this endpoint, silently breaking license issuance for real avtool
// customers too.
var errUnknownStripeCustomer = errors.New("no local user for stripe customer")

func HandleWebhook(db *sql.DB, webhookSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxWebhookBodyBytes)
		payload, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "reading request body", http.StatusBadRequest)
			return
		}

		event, err := webhook.ConstructEvent(payload, r.Header.Get("Stripe-Signature"), webhookSecret)
		if err != nil {
			http.Error(w, "invalid signature", http.StatusBadRequest)
			return
		}

		switch event.Type {
		case "customer.subscription.created", "customer.subscription.updated":
			var sub stripe.Subscription
			if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
				http.Error(w, "parsing subscription payload", http.StatusBadRequest)
				return
			}
			if err := upsertSubscription(db, &sub); err != nil && !errors.Is(err, errUnknownStripeCustomer) {
				http.Error(w, fmt.Sprintf("processing subscription: %v", err), http.StatusInternalServerError)
				return
			}
		case "customer.subscription.deleted":
			var sub stripe.Subscription
			if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
				http.Error(w, "parsing subscription payload", http.StatusBadRequest)
				return
			}
			if err := cancelSubscription(db, sub.ID); err != nil {
				http.Error(w, fmt.Sprintf("canceling subscription: %v", err), http.StatusInternalServerError)
				return
			}
		}

		w.WriteHeader(http.StatusOK)
	}
}

func upsertSubscription(db *sql.DB, sub *stripe.Subscription) error {
	// users.stripe_customer_id is populated synchronously by the /checkout
	// handler (Task 9) at the moment the Stripe Customer is created, before
	// the user ever reaches Stripe's page — so by the time this webhook
	// fires, the mapping already exists and this lookup is never racing
	// against it.
	var userID uint64
	err := db.QueryRow(`SELECT id FROM users WHERE stripe_customer_id = ?`, sub.Customer.ID).Scan(&userID)
	if err == sql.ErrNoRows {
		fmt.Fprintf(os.Stderr, "webhook: ignoring event for stripe customer %s: no local user mapping (likely an unrelated product sharing this Stripe account)\n", sub.Customer.ID)
		return errUnknownStripeCustomer
	}
	if err != nil {
		return fmt.Errorf("looking up user for stripe customer %s: %w", sub.Customer.ID, err)
	}

	// In the resolved SDK (stripe-go v82), stripe.Subscription has no
	// CurrentPeriodEnd field — Stripe moved current_period_end onto each
	// SubscriptionItem in newer API versions (confirmed via
	// `go doc github.com/stripe/stripe-go/v82.Subscription` and
	// `.../v82.SubscriptionItem`). Read it off the first item instead.
	if sub.Items == nil || len(sub.Items.Data) == 0 {
		return fmt.Errorf("subscription %s has no items to read current_period_end from", sub.ID)
	}
	currentPeriodEnd := sub.Items.Data[0].CurrentPeriodEnd

	_, err = db.Exec(`
		INSERT INTO subscriptions (user_id, stripe_customer_id, stripe_subscription_id, tier, status, current_period_end)
		VALUES (?, ?, ?, ?, ?, FROM_UNIXTIME(?))
		ON DUPLICATE KEY UPDATE status = VALUES(status), current_period_end = VALUES(current_period_end)`,
		userID, sub.Customer.ID, sub.ID, "standard", string(sub.Status), currentPeriodEnd)
	if err != nil {
		return fmt.Errorf("upserting subscription: %w", err)
	}

	if string(sub.Status) == "active" {
		var existing int
		if err := db.QueryRow(`SELECT COUNT(*) FROM licenses WHERE user_id = ? AND revoked_at IS NULL`, userID).Scan(&existing); err != nil {
			return fmt.Errorf("checking existing licenses: %w", err)
		}
		if existing == 0 {
			if _, err := license.Generate(db, userID); err != nil {
				return fmt.Errorf("generating license: %w", err)
			}
		}
	}
	return nil
}

func cancelSubscription(db *sql.DB, stripeSubscriptionID string) error {
	_, err := db.Exec(`UPDATE subscriptions SET status = 'canceled' WHERE stripe_subscription_id = ?`, stripeSubscriptionID)
	if err != nil {
		return fmt.Errorf("canceling subscription: %w", err)
	}
	return nil
}
