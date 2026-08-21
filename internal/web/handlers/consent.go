// internal/web/handlers/consent.go
package handlers

import (
	"net"
	"net/http"
	"strings"
)

// normalizePhone reduces user-typed input to E.164 for a US number, or returns
// "" if the input is not a plausible US number. Returning "" rather than an
// error is deliberate: the phone field is optional, and a malformed number must
// never block account creation.
func normalizePhone(in string) string {
	var digits strings.Builder
	for _, r := range in {
		if r >= '0' && r <= '9' {
			digits.WriteRune(r)
		}
	}
	d := digits.String()
	switch {
	case len(d) == 10:
		return "+1" + d
	case len(d) == 11 && d[0] == '1':
		return "+" + d
	default:
		return ""
	}
}

// checked reports whether a checkbox was ticked. An unticked HTML checkbox is
// simply absent from the POST body, so presence is the signal.
func checked(r *http.Request, name string) bool {
	v := r.FormValue(name)
	return v == "on" || v == "1" || v == "true"
}

// clientIP returns the caller's address for the consent audit trail. The app
// sits behind an Apache reverse proxy, so X-Forwarded-For carries the real
// client and its leftmost entry is the one to record.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if first, _, ok := strings.Cut(xff, ","); ok {
			return strings.TrimSpace(first)
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
