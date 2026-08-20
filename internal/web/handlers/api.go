// internal/web/handlers/api.go
package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/jbrahy/AntiVirus/internal/web/license"
)

func ValidateLicenseAPI(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		if key == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"valid": false, "error": "missing X-API-Key header"})
			return
		}

		userID, valid, err := license.Validate(db, key)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]any{"valid": false, "error": "internal error"})
			return
		}
		if !valid {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"valid": false, "error": "invalid or unknown license key"})
			return
		}

		// A license implies an active subscription (license issuance is tied
		// to a subscription becoming active), but tolerate the row being
		// missing rather than erroring: omit tier instead of failing a
		// request we already know is a valid license.
		var tier string
		err = db.QueryRow(`SELECT tier FROM subscriptions WHERE user_id = ? AND status = 'active' ORDER BY id DESC LIMIT 1`, userID).Scan(&tier)
		if err != nil && err != sql.ErrNoRows {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]any{"valid": false, "error": "internal error"})
			return
		}

		resp := map[string]any{"valid": true}
		if tier != "" {
			resp["tier"] = tier
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}
}
