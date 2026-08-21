// internal/web/handlers/pages.go
package handlers

import (
	"html/template"
	"net/http"

	"github.com/jbrahy/AntiVirus/internal/web/config"
)

// StaticPage renders one of the informational/legal templates. They all take
// the same data (the business identity), so one handler covers all of them.
func StaticPage(tmpl *template.Template, name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := tmpl.ExecuteTemplate(w, name, config.Site); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	}
}
