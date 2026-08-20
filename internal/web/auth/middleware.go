// internal/web/auth/middleware.go
package auth

import (
	"context"
	"database/sql"
	"net/http"
)

type contextKey struct{}

func UserFromContext(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(contextKey{}).(*User)
	return u, ok
}

func ContextWithUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, contextKey{}, u)
}

func RequireAuth(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(SessionCookieName)
			if err != nil {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			u, err := ValidateSession(db, cookie.Value)
			if err != nil {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			ctx := context.WithValue(r.Context(), contextKey{}, u)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func OptionalAuth(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(SessionCookieName)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			u, err := ValidateSession(db, cookie.Value)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			ctx := context.WithValue(r.Context(), contextKey{}, u)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
