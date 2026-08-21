// internal/web/handlers/compliance_test.go
package handlers

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/jbrahy/AntiVirus/internal/web/config"
)

// These assert the mechanical rules from the carrier route checklist against
// the RENDERED page, not the template source. A grep over source missed a
// disqualifying line on a sibling brand and it reached the reviewer; rendering
// first is the only way to be sure of what is actually served.

func renderPage(t *testing.T, name string, data any) string {
	t.Helper()
	tmpl, err := template.ParseGlob("../../../web/templates/*.html")
	if err != nil {
		t.Fatalf("parsing templates: %v", err)
	}
	w := httptest.NewRecorder()
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		t.Fatalf("rendering %s: %v", name, err)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("%s status = %d", name, w.Code)
	}
	return w.Body.String()
}

// §1.2 SMS consent must never be required to submit. This checks the input tag
// itself, because a label can say "optional" while the input carries `required`.
func TestConsentCheckboxesAreNotRequired(t *testing.T) {
	body := renderPage(t, "signup.html", signupView{Site: config.Site})
	inputRe := regexp.MustCompile(`(?s)<input[^>]*name="sms_[a-z_]*consent"[^>]*>`)
	found := inputRe.FindAllString(body, -1)
	if len(found) != 2 {
		t.Fatalf("found %d SMS consent inputs, want 2", len(found))
	}
	for _, tag := range found {
		if strings.Contains(tag, "required") {
			t.Errorf("SMS consent input carries required, which is forced consent: %s", tag)
		}
		if strings.Contains(tag, "checked") {
			t.Errorf("SMS consent input is pre-checked: %s", tag)
		}
	}
}

// §1.1 No autodialer or Do Not Call wording inside an SMS consent box. That
// language describes phone calls; carriers reject it in an SMS opt-in.
func TestNoAutodialerLanguageInConsentBoxes(t *testing.T) {
	body := renderPage(t, "signup.html", signupView{Site: config.Site})
	banned := []string{
		"autodialer", "auto-dialer", "automatic telephone dialing",
		"pre-recorded", "prerecorded", "do not call", "artificial voice",
	}
	lower := strings.ToLower(body)
	for _, b := range banned {
		if strings.Contains(lower, b) {
			t.Errorf("signup page contains banned call-consent phrase %q", b)
		}
	}
}

// §1.6 Each box must carry its own complete disclosure; none may lean on the
// other or on a parent checkbox.
func TestEachConsentBoxCarriesFullDisclosure(t *testing.T) {
	body := renderPage(t, "signup.html", signupView{Site: config.Site})
	required := []string{
		config.Site.Brand,
		"Message and data rates may apply",
		"Msg frequency varies",
		"STOP",
		"HELP",
		"Consent is not required for purchasing products or services",
		"not be shared with third parties or affiliates",
	}
	// The template wraps this copy across source lines, so collapse whitespace
	// before matching: the reader sees one sentence regardless of where the
	// HTML happens to break.
	normalized := strings.Join(strings.Fields(body), " ")

	// Split at the marketing box so each half can be checked independently.
	idx := strings.Index(normalized, `name="sms_marketing_consent"`)
	if idx < 0 {
		t.Fatal("marketing consent box not found")
	}
	svcHalf, mktHalf := normalized[:idx], normalized[idx:]
	for _, phrase := range required {
		if !strings.Contains(svcHalf, phrase) {
			t.Errorf("service consent box missing %q", phrase)
		}
		if !strings.Contains(mktHalf, phrase) {
			t.Errorf("marketing consent box missing %q", phrase)
		}
	}
}

// §3 The privacy policy must carry the reviewer's clause verbatim, under the
// heading they ask for it under.
func TestPrivacyPolicyCarriesRequiredClauseVerbatim(t *testing.T) {
	body := renderPage(t, "privacy.html", config.Site)
	const clause = "No mobile information will be shared with third parties or affiliates " +
		"for marketing or promotional purposes. All categories above exclude text messaging " +
		"originator opt-in data and consent; this information will not be shared with " +
		"any third parties."
	normalized := strings.Join(strings.Fields(body), " ")
	if !strings.Contains(normalized, clause) {
		t.Error("privacy policy is missing the required mobile-information clause verbatim")
	}
	heading := strings.Index(normalized, "How We Use Information Collected.")
	if heading < 0 {
		t.Fatal(`privacy policy lacks the "How We Use Information Collected." heading`)
	}
	if strings.Index(normalized, clause) < heading {
		t.Error("required clause appears before its required heading")
	}
}

// §6 Mobile Terms must state the program, frequency, cost, opt-out, help, and
// the carrier liability disclaimer.
func TestTermsCarryMobileTermsSection(t *testing.T) {
	body := renderPage(t, "terms.html", config.Site)
	normalized := strings.Join(strings.Fields(body), " ")
	for _, phrase := range []string{
		"Mobile Terms of Service",
		"Message frequency varies",
		"Message and data rates may apply",
		"Reply STOP",
		"Reply HELP",
		"Carriers are not liable for delayed or undelivered messages",
		"not be shared with third parties or affiliates",
	} {
		if !strings.Contains(normalized, phrase) {
			t.Errorf("terms missing %q", phrase)
		}
	}
}

// §2 Copy that implies the site routes user data to third parties sinks the
// brand even when the consent language is perfect.
func TestNoLeadGenLanguageOnPublicPages(t *testing.T) {
	banned := []string{
		"get matched", "matched with", "we'll match you", "connect you with",
		"vetted pros", "vetted partners", "someone will reach out",
		"quote request", "one request",
	}
	pages := map[string]any{
		"landing.html": landingView{Site: config.Site},
		"signup.html":  signupView{Site: config.Site},
		"about.html":   config.Site,
		"contact.html": config.Site,
		"privacy.html": config.Site,
		"terms.html":   config.Site,
	}
	for name, data := range pages {
		lower := strings.ToLower(renderPage(t, name, data))
		for _, b := range banned {
			if strings.Contains(lower, b) {
				t.Errorf("%s contains lead-gen phrase %q", name, b)
			}
		}
	}
}

// §4 Every public page must show the operating entity, a real address, phone,
// and an email, and they must agree with each other.
func TestBusinessIdentityAppearsOnEveryPublicPage(t *testing.T) {
	pages := map[string]any{
		"landing.html": landingView{Site: config.Site},
		"about.html":   config.Site,
		"contact.html": config.Site,
		"privacy.html": config.Site,
		"terms.html":   config.Site,
	}
	for name, data := range pages {
		normalized := strings.Join(strings.Fields(renderPage(t, name, data)), " ")
		for _, want := range []string{
			config.Site.LegalEntity,
			config.Site.AddressLine,
			config.Site.AddressCity,
			config.Site.Phone,
			config.Site.SupportMail,
		} {
			if !strings.Contains(normalized, want) {
				t.Errorf("%s missing business identity field %q", name, want)
			}
		}
	}
}
