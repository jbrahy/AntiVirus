// internal/web/handlers/signup.go
package handlers

import (
	"database/sql"
	"html/template"
	"net/http"
	"time"

	"github.com/jbrahy/AntiVirus/internal/web/auth"
	"github.com/jbrahy/AntiVirus/internal/web/config"
)

// signupView is what signup.html renders against. It carries the business
// identity because the SMS consent copy must name the brand, and the carrier
// standard requires that name to match the rest of the site exactly.
type signupView struct {
	Site  config.SiteInfo
	Error string
}

const sessionTTL = 30 * 24 * time.Hour

func SignupPage(db *sql.DB, tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			tmpl.ExecuteTemplate(w, "signup.html", signupView{Site: config.Site})
			return
		}

		email := r.FormValue("email")
		password := r.FormValue("password")
		phone := normalizePhone(r.FormValue("phone"))

		consent := auth.Consent{
			SMSService:   checked(r, "sms_service_consent"),
			SMSMarketing: checked(r, "sms_marketing_consent"),
			IP:           clientIP(r),
			UserAgent:    r.UserAgent(),
		}
		// Consent without a number to send to is meaningless, and recording it
		// would overstate what the user actually agreed to.
		if phone == "" {
			consent.SMSService = false
			consent.SMSMarketing = false
		}

		u, err := auth.CreateUserWithConsent(db, email, phone, password, consent)
		if err != nil {
			w.WriteHeader(http.StatusOK)
			tmpl.ExecuteTemplate(w, "signup.html", signupView{
				Site:  config.Site,
				Error: "Could not create account. That email may already be in use.",
			})
			return
		}

		token, err := auth.CreateSession(db, u.ID, sessionTTL)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     auth.SessionCookieName,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			Expires:  time.Now().Add(sessionTTL),
		})
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	}
}
