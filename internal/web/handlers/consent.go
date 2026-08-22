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

// clientIP returns the caller's address for the consent audit trail. The
// app sits behind exactly one Apache reverse proxy hop (no CDN or load
// balancer in front of it — confirmed against the live vhost config), and
// Apache's mod_proxy appends its own observed connection IP to
// X-Forwarded-For rather than replacing it. That means the RIGHTMOST entry
// is the one Apache itself set and is trustworthy; every entry before it
// came from the client and is trivially spoofable by sending a crafted
// X-Forwarded-For header — trusting the leftmost entry, as this function
// used to, let a caller claim any IP it wanted.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
