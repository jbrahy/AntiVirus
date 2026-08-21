// internal/web/handlers/alternatives.go
package handlers

import (
	"html/template"
	"net/http"

	"github.com/jbrahy/AntiVirus/internal/web/config"
)

// Competitor is one row on the /alternatives comparison page. Every claim
// here is a structural, publicly verifiable fact (open source or not, what
// the free tier actually includes, pricing model) rather than a detection-
// rate or efficacy claim, which nobody outside a testing lab can verify —
// see docs/superpowers/ for the site's broader "don't claim what can't be
// checked" convention.
type Competitor struct {
	Name       string
	OpenSource bool
	FreeTier   string // what, if anything, the free tier actually includes
	Pricing    string
	Note       string
	NoteSource string // link backing the Note claim, when it names a specific incident
}

var Competitors = []Competitor{
	{
		Name:       "Norton (Gen Digital)",
		OpenSource: false,
		FreeTier:   "None for Mac",
		Pricing:    "Subscription only",
	},
	{
		Name:       "Avast / AVG (Gen Digital)",
		OpenSource: false,
		FreeTier:   "Limited free tier; full protection requires a paid plan",
		Pricing:    "Freemium, subscription for full protection",
		Note:       "In 2024 the FTC fined Avast $16.5 million and permanently banned it from selling browsing data for advertising, after finding it sold users' browsing history collected by its antivirus and browser tools, the same tools it marketed as blocking tracking.",
		NoteSource: "https://www.ftc.gov/news-events/news/press-releases/2024/02/ftc-order-will-ban-avast-selling-browsing-data-advertising-purposes-require-it-pay-165-million-over",
	},
	{
		Name:       "Malwarebytes",
		OpenSource: false,
		FreeTier:   "Manual scan and cleanup only; real-time protection requires Premium",
		Pricing:    "Freemium, subscription for real-time protection",
	},
	{
		Name:       "Bitdefender",
		OpenSource: false,
		FreeTier:   "None for Mac",
		Pricing:    "Subscription only",
	},
	{
		Name:       "Intego",
		OpenSource: false,
		FreeTier:   "30-day trial, not a permanent free tier",
		Pricing:    "Subscription only",
	},
	{
		Name:       "ClamAV",
		OpenSource: true,
		FreeTier:   "Everything, forever, same as NexGuard's free tier",
		Pricing:    "Free, no paid tier or company behind it",
		Note:       "A real, mature open-source engine, mainly built for mail-server scanning rather than a consumer desktop product: no GUI, no fleet dashboard, no support contract.",
	},
	{
		Name:       "NexGuard",
		OpenSource: true,
		FreeTier:   "The full scanner, real-time watching, and manual feed sync",
		Pricing:    "Free forever; $10/month for priority support and (soon) a premium feed",
		Note:       "The only row on this table you don't have to take our word for.",
	},
}

// Alternatives renders the /alternatives comparison page.
func Alternatives(tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		view := struct {
			Site        config.SiteInfo
			Competitors []Competitor
		}{Site: config.Site, Competitors: Competitors}
		if err := tmpl.ExecuteTemplate(w, "alternatives.html", view); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	}
}
