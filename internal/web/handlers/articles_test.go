// internal/web/handlers/articles_test.go
package handlers

import (
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestArticlesIndexListsEveryArticle(t *testing.T) {
	tmpl := testTemplates(t)
	req := httptest.NewRequest(http.MethodGet, "/articles", nil)
	rec := httptest.NewRecorder()

	ArticlesIndex(tmpl)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if len(Articles) != 10 {
		t.Fatalf("Articles has %d entries, want 10", len(Articles))
	}
	for _, a := range Articles {
		if !strings.Contains(body, html.EscapeString(a.Title)) {
			t.Errorf("index missing title %q", a.Title)
		}
		if !strings.Contains(body, "/articles/"+a.Slug) {
			t.Errorf("index missing link to slug %q", a.Slug)
		}
	}
}

func TestArticleShowRendersKnownSlug(t *testing.T) {
	tmpl := testTemplates(t)
	r := chi.NewRouter()
	r.Get("/articles/{slug}", ArticleShow(tmpl))

	want := Articles[0]
	req := httptest.NewRequest(http.MethodGet, "/articles/"+want.Slug, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, html.EscapeString(want.Title)) {
		t.Errorf("body missing title %q", want.Title)
	}
	for _, p := range want.Body {
		if !strings.Contains(body, html.EscapeString(p)) {
			t.Errorf("body missing paragraph starting %q", p[:min(40, len(p))])
			break
		}
	}
}

func TestArticleShowReturns404ForUnknownSlug(t *testing.T) {
	tmpl := testTemplates(t)
	r := chi.NewRouter()
	r.Get("/articles/{slug}", ArticleShow(tmpl))

	req := httptest.NewRequest(http.MethodGet, "/articles/does-not-exist", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestEveryArticleSlugIsUnique(t *testing.T) {
	seen := make(map[string]bool, len(Articles))
	for _, a := range Articles {
		if seen[a.Slug] {
			t.Errorf("duplicate slug %q", a.Slug)
		}
		seen[a.Slug] = true
	}
}
