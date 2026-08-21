// internal/web/auth/consent_test.go
package auth

import (
	"database/sql"
	"testing"
)

// The carrier standard requires proving which of the two opt-ins a given user
// actually agreed to, so the two flags and their timestamps must move
// independently and an unticked box must leave a NULL timestamp rather than a
// zero time that would later read as a real consent.
func TestCreateUserWithConsentRecordsEachOptInSeparately(t *testing.T) {
	d := testDB(t)

	cases := []struct {
		name             string
		consent          Consent
		wantSvc, wantMkt bool
	}{
		{"neither", Consent{}, false, false},
		{"service only", Consent{SMSService: true}, true, false},
		{"marketing only", Consent{SMSMarketing: true}, false, true},
		{"both", Consent{SMSService: true, SMSMarketing: true}, true, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			email := uniqueEmail(t, "consent")
			c.consent.IP = "203.0.113.7"
			c.consent.UserAgent = "Mozilla/5.0 (test)"

			u, err := CreateUserWithConsent(d, email, "+15125550134", "correct horse battery staple", c.consent)
			if err != nil {
				t.Fatalf("CreateUserWithConsent: %v", err)
			}
			if u.Phone != "+15125550134" {
				t.Fatalf("Phone = %q", u.Phone)
			}

			var svc, mkt bool
			var svcAt, mktAt sql.NullTime
			var ip, ua sql.NullString
			err = d.QueryRow(`SELECT sms_service_consent, sms_service_consent_at,
				sms_marketing_consent, sms_marketing_consent_at, consent_ip, consent_user_agent
				FROM users WHERE id = ?`, u.ID).Scan(&svc, &svcAt, &mkt, &mktAt, &ip, &ua)
			if err != nil {
				t.Fatalf("reading back consent: %v", err)
			}

			if svc != c.wantSvc || mkt != c.wantMkt {
				t.Errorf("consent flags = (svc %v, mkt %v), want (%v, %v)", svc, mkt, c.wantSvc, c.wantMkt)
			}
			if svcAt.Valid != c.wantSvc {
				t.Errorf("service timestamp present = %v, want %v", svcAt.Valid, c.wantSvc)
			}
			if mktAt.Valid != c.wantMkt {
				t.Errorf("marketing timestamp present = %v, want %v", mktAt.Valid, c.wantMkt)
			}
			if ip.String != "203.0.113.7" || ua.String != "Mozilla/5.0 (test)" {
				t.Errorf("audit trail = (%q, %q)", ip.String, ua.String)
			}
		})
	}
}

// Phone is optional, so an account created without one must still work and
// must leave phone NULL rather than an empty string.
func TestCreateUserWithoutPhoneLeavesPhoneNull(t *testing.T) {
	d := testDB(t)
	u, err := CreateUser(d, uniqueEmail(t, "nophone"), "correct horse battery staple")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	var phone sql.NullString
	if err := d.QueryRow(`SELECT phone FROM users WHERE id = ?`, u.ID).Scan(&phone); err != nil {
		t.Fatalf("reading back phone: %v", err)
	}
	if phone.Valid {
		t.Errorf("phone = %q, want NULL", phone.String)
	}
}
