package transport

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

// validateConfiguration is shared by environment loading and the live send
// boundary. Callers can instantiate Relay directly; environment-only checks
// cannot protect those callers from accidental cleartext authentication.
func (r *Relay) validateConfiguration() error {
	if r == nil {
		return errors.New("SMTP relay is not configured")
	}
	host, port, err := net.SplitHostPort(r.Address)
	if err != nil || host == "" || port == "" {
		return errors.New("SMTP relay address must be host:port")
	}
	if strings.ContainsAny(host, "\x00\r\n\t /\\") {
		return errors.New("SMTP relay hostname contains invalid characters")
	}
	// Numeric ports avoid environment-dependent service-name resolution and
	// prevent a typo from silently selecting a different relay endpoint.
	for _, c := range port {
		if c < '0' || c > '9' {
			return errors.New("SMTP relay port must be numeric")
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("SMTP relay port must be between 1 and 65535")
	}
	switch r.TLSMode {
	case "required", "implicit", "none":
	default:
		return errors.New("SMTP relay TLS mode must be required, implicit or none")
	}
	// PLAIN credentials use NUL delimiters. A NUL in either component could
	// change the username/password interpreted by the remote SMTP server.
	if strings.ContainsAny(r.Username, "\x00\r\n") || strings.ContainsAny(r.Password, "\x00\r\n") {
		return errors.New("SMTP relay credentials contain forbidden control characters")
	}
	if (r.Username == "") != (r.Password == "") {
		return errors.New("SMTP relay username and password must be configured together")
	}
	if r.Username != "" && r.TLSMode == "none" {
		return errors.New("SMTP relay authentication requires TLS")
	}
	return nil
}
