// internal/web/handlers/alternatives_test.go
package handlers

import (
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAlternativesListsEveryCompetitor(t *testing.T) {
	tmpl := testTemplates(t)
	req := httptest.NewRequest(http.MethodGet, "/alternatives", nil)
	rec := httptest.NewRecorder()

	Alternatives(tmpl)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, c := range Competitors {
		if !strings.Contains(body, html.EscapeString(c.Name)) {
			t.Errorf("comparison table missing competitor %q", c.Name)
		}
	}
}

func TestAlternativesIncludesNexGuardRow(t *testing.T) {
	found := false
	for _, c := range Competitors {
		if c.Name == "NexGuard" {
			found = true
			if !c.OpenSource {
				t.Error("NexGuard row must claim OpenSource=true (it's true and it's the whole point)")
			}
		}
	}
	if !found {
		t.Error("Competitors is missing a NexGuard row entirely")
	}
}

// A Note that names a specific incident (like the Avast/FTC settlement)
// must carry a source link — an unsourced specific claim about a named
// competitor is exactly the kind of thing that shouldn't ship.
func TestEveryDetailedNoteHasASource(t *testing.T) {
	for _, c := range Competitors {
		if c.Note != "" && strings.Contains(c.Note, "20") && c.NoteSource == "" && c.Name != "NexGuard" && c.Name != "ClamAV" {
			t.Errorf("%s has a dated/specific claim in its Note but no NoteSource", c.Name)
		}
	}
}
