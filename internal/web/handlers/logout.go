// internal/web/handlers/logout.go
package handlers

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/jbrahy/AntiVirus/internal/web/auth"
)

// LogoutHandler deletes the caller's session row (if any) and clears the
// session cookie. It sits behind auth.RequireAuth in main.go, so only a
// logged-in user can reach it.
func LogoutHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie(auth.SessionCookieName); err == nil {
			if err := auth.DeleteSession(db, cookie.Value); err != nil {
				log.Printf("logout: failed to delete session: %v", err)
			}
		}

		http.SetCookie(w, &http.Cookie{
			Name:     auth.SessionCookieName,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
			Expires:  time.Unix(0, 0),
		})
		http.Redirect(w, r, "/", http.StatusFound)
	}
}
