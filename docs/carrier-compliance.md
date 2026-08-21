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

## Open blockers before submitting for a route

**1. `nexguardhq.com` cannot receive email.** The domain has no MX record and no
SPF record, verified from a clean resolver. Any address at that domain bounces.
`SupportMail` therefore points at `sales@reach-x.com`, which does resolve, but
the checklist wants the contact address to match the brand. Fix by adding MX for
`nexguardhq.com` (the other brands route through `mx.emailredirectzone.com`),
then set `SupportMail` to `support@nexguardhq.com` and verify the mailbox
actually receives before submitting.

**2. The operating entity sells leads.** Reach X, LLC describes itself publicly
as generating and selling leads and inbound calls. A reviewer who looks up the
entity will find that. The consent copy promises "My number will not be shared
with third parties or affiliates", and Reach-X's other brands are affiliates, so
that promise covers them.

That promise is currently true: nothing in this codebase sends a NexGuard user's
phone number anywhere. It stays true only if NexGuard signups are never piped
into the lead business. This is the exact contradiction that got Elite Home Saver
rejected, so it has to be settled as a business decision, not a copy decision.

## Verifying

```bash
go test ./internal/web/...      # includes every compliance assertion above
```
