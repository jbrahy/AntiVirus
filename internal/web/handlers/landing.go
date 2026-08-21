// internal/web/handlers/landing.go
package handlers

import (
	"database/sql"
	"html/template"
	"net/http"

	"github.com/jbrahy/AntiVirus/internal/web/auth"
	"github.com/jbrahy/AntiVirus/internal/web/config"
)

// landingView carries the business identity the shared footer renders from.
type landingView struct {
	Site config.SiteInfo
}

// Landing renders the marketing landing page for anonymous visitors. A
// visitor who already has a valid session (see auth.OptionalAuth, which
// this route is wired behind) is redirected straight to the dashboard
// instead of being shown "Sign up | Log in" again.
func Landing(db *sql.DB, tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.UserFromContext(r.Context()); ok {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		tmpl.ExecuteTemplate(w, "landing.html", landingView{Site: config.Site})
	}
}
