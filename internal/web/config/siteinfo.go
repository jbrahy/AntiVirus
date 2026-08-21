// internal/web/config/siteinfo.go
package config

// SiteInfo is the single source of truth for the business identity that the
// legal pages, footer, and SMS consent copy all render from.
//
// It is centralized deliberately: the carrier reviewer checks the entity name,
// address, and contact details for consistency across every page, and a
// mismatch between (say) the Mobile Terms and the footer is the kind of thing
// that gets a route rejected. Change it here, not in the templates.
type SiteInfo struct {
	Brand       string // brand name as it appears in SMS consent copy
	LegalEntity string // registered entity that operates the brand
	AddressLine string
	AddressCity string
	Phone       string
	SupportMail string
	Domain      string
}

// Site is the live NexGuard identity.
var Site = SiteInfo{
	Brand:       "NexGuard",
	LegalEntity: "Reach X, LLC",
	AddressLine: "3616 Far West Blvd., Suite 117-566",
	AddressCity: "Austin, Texas 78731",
	Phone:       "(877) 353-2374",
	SupportMail: "support@nexguardhq.com",
	Domain:      "nexguardhq.com",
}
