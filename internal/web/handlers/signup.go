// internal/web/handlers/signup.go
package handlers

import (
	"database/sql"
	"html/template"
	"net/http"
	"time"

	"github.com/jbrahy/AntiVirus/internal/web/auth"
)

const sessionTTL = 30 * 24 * time.Hour

func SignupPage(db *sql.DB, tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			tmpl.ExecuteTemplate(w, "signup.html", nil)
			return
		}

		email := r.FormValue("email")
		password := r.FormValue("password")

		u, err := auth.CreateUser(db, email, password)
		if err != nil {
			w.WriteHeader(http.StatusOK)
			tmpl.ExecuteTemplate(w, "signup.html", map[string]string{"Error": "Could not create account. That email may already be in use."})
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
