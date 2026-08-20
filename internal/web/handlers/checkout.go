// internal/web/handlers/checkout.go
package handlers

import (
	"database/sql"
	"net/http"

	"github.com/jbrahy/AntiVirus/internal/web/auth"
	"github.com/jbrahy/AntiVirus/internal/web/billing"
)

func CheckoutRedirect(db *sql.DB, stripeSecretKey, priceID, successURL, cancelURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := auth.UserFromContext(r.Context())
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// A user who already has an active subscription doesn't need another
		// checkout session — send them straight to the dashboard instead of
		// minting a redundant one.
		var activeCount int
		if err := db.QueryRow(`SELECT COUNT(*) FROM subscriptions WHERE user_id = ? AND status = 'active'`, u.ID).Scan(&activeCount); err != nil {
			http.Error(w, "could not check subscription state", http.StatusInternalServerError)
			return
		}
		if activeCount > 0 {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}

		var existingCustomerID sql.NullString
		if err := db.QueryRow(`SELECT stripe_customer_id FROM users WHERE id = ?`, u.ID).Scan(&existingCustomerID); err != nil {
			http.Error(w, "could not load checkout state", http.StatusInternalServerError)
			return
		}

		checkoutURL, stripeCustomerID, err := billing.CreateCheckoutSession(stripeSecretKey, priceID, successURL, cancelURL, u.Email, existingCustomerID.String)
		if err != nil {
			http.Error(w, "could not start checkout", http.StatusInternalServerError)
			return
		}

		if stripeCustomerID != existingCustomerID.String {
			if _, err := db.Exec(`UPDATE users SET stripe_customer_id = ? WHERE id = ?`, stripeCustomerID, u.ID); err != nil {
				http.Error(w, "could not save checkout state", http.StatusInternalServerError)
				return
			}
		}

		http.Redirect(w, r, checkoutURL, http.StatusFound)
	}
}
