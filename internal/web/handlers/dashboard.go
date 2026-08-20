// internal/web/handlers/dashboard.go
package handlers

import (
	"database/sql"
	"html/template"
	"net/http"

	"github.com/jbrahy/AntiVirus/internal/web/auth"
)

type dashboardData struct {
	Email              string
	HasSubscription    bool
	SubscriptionStatus string
	LicenseKey         string
}

func Dashboard(db *sql.DB, tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := auth.UserFromContext(r.Context())
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		data := dashboardData{Email: u.Email}

		var status string
		err := db.QueryRow(`SELECT status FROM subscriptions WHERE user_id = ? ORDER BY id DESC LIMIT 1`, u.ID).Scan(&status)
		if err == nil {
			data.HasSubscription = true
			data.SubscriptionStatus = status
		}

		// Known gap, not silently fixed: only key_hash is ever stored (raw
		// license keys are never persisted, per this plan's global
		// constraints), so there is nothing valid to query here and
		// LicenseKey is left empty. A real implementation needs either a
		// one-time flash-message reveal at generation time, or an explicit
		// "regenerate license key" action, since a hashed key is
		// cryptographically not recoverable for redisplay.

		w.WriteHeader(http.StatusOK)
		tmpl.ExecuteTemplate(w, "dashboard.html", data)
	}
}
