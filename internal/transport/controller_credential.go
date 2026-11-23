package transport

import (
	"net/http"
	"strings"
)

// controllerCredential accepts exactly one credential transport. Ambiguous
// headers are refused rather than choosing one attacker-controlled value.
// Conventional Rspamd Password and HTTP Bearer are supported independently.
func controllerCredential(h http.Header) (string, bool) {
	auth, hasAuth := h["Authorization"]
	password, hasPassword := h["Password"]
	if hasAuth == hasPassword {
		return "", false
	}
	if hasAuth {
		if len(auth) != 1 || !strings.HasPrefix(auth[0], "Bearer ") {
			return "", false
		}
		token := strings.TrimPrefix(auth[0], "Bearer ")
		return token, validControllerToken(token)
	}
	if len(password) != 1 {
		return "", false
	}
	return password[0], validControllerToken(password[0])
}

func validControllerToken(token string) bool {
	if token == "" || strings.TrimSpace(token) != token {
		return false
	}
	for i := 0; i < len(token); i++ {
		if token[i] < 0x21 || token[i] > 0x7e {
			return false
		}
	}
	return true
}
