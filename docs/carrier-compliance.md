# Carrier / SMS route compliance

NexGuard is built to the tells.co carrier standard (reviewer Brandon McLevis,
July 2026), as distilled in `web-system-sites/docs/_shared/sms-route-approval-checklist.md`.

Note there are two conflicting standards in circulation. The other one, used for
TrueRoofHQ, **requires** autodialer and Do Not Call wording inside the SMS
checkbox. This one **forbids** it. Do not mix them: copy that satisfies one
fails the other.

## What is implemented

| Requirement | Where |
|---|---|
| Two separate SMS opt-ins (service, marketing) | `web/templates/signup.html` |
| Neither opt-in required, neither pre-checked | asserted by `TestConsentCheckboxesAreNotRequired` |
| No autodialer / DNC wording in an SMS box | asserted by `TestNoAutodialerLanguageInConsentBoxes` |
| Each box carries its own full disclosure | asserted by `TestEachConsentBoxCarriesFullDisclosure` |
| Phone optional; consent discarded if no number given | `internal/web/handlers/signup.go` |
| Consent audit trail (flags, timestamps, IP, user agent) | `database/avtool-web/003_phone_sms_consent.sql` |
| Privacy clause verbatim under its required heading | asserted by `TestPrivacyPolicyCarriesRequiredClauseVerbatim` |
| Mobile Terms section | asserted by `TestTermsCarryMobileTermsSection` |
| No lead-gen / matching language | asserted by `TestNoLeadGenLanguageOnPublicPages` |
| Entity, address, phone, email on every public page | asserted by `TestBusinessIdentityAppearsOnEveryPublicPage` |

Business identity lives in exactly one place, `internal/web/config/siteinfo.go`.
Change it there; the templates and the tests both read from it.

The compliance rules are enforced as tests against the **rendered** page rather
than the template source. A source grep on a sibling brand came back clean while
a disqualifying line was still on the page, and the reviewer found it.

## Resolved blockers

**1. `nexguardhq.com` couldn't receive email.** Fixed 2026-08-21: added MX
(`10 mx.emailredirectzone.com`), SPF, DMARC, and DKIM records to the
`nexguardhq.com` Route53 zone, matching the pattern the other brands already
use. Verified authoritatively (`aa` flag, queried from the server, not a
laptop resolver — a cached negative answer looks identical to a real one).
`SupportMail` is now `support@nexguardhq.com`.

Still outstanding: DNS resolving is not the same as mail actually landing
somewhere a human reads it. `mx.emailredirectzone.com` is a third-party
forwarding service — confirm with whoever administers it that
`support@nexguardhq.com` is configured to forward to a real inbox, then send
a test message end to end, before submitting for review.

**2. The operating entity sells leads.** Reach X, LLC describes itself
publicly as generating and selling leads and inbound calls. The consent copy
promises "My number will not be shared with third parties or affiliates",
and Reach-X's other brands are affiliates, so that promise covers them.

Decision (2026-08-21, John): **firewall NexGuard from the lead system.**
NexGuard signups are never piped into Reach X's lead business, full stop —
not "not yet," a standing policy. This is also already how the code
behaves: nothing in this codebase sends a NexGuard user's phone number
anywhere, and it should stay that way. Any future integration between
NexGuard's user data and a lead/CRM system is a policy violation, not just
a compliance risk — flag it rather than build it.

This also keeps the SMS copy consistent with the site's own pitch
("Protected, not monitored" — see the landing page's open-source section),
which would otherwise directly contradict a data-sharing arrangement with
an affiliate.

## Verifying

```bash
go test ./internal/web/...      # includes every compliance assertion above
```
