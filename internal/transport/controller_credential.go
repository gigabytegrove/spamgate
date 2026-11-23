package transport

import (
    "net/http"
    "strings"
)

// controllerCredential accepts one unambiguous credential transport. HTTP
// header names are case-insensitive even when callers construct a Header map
// directly instead of using Header.Set or Header.Add. Never use Header.Get:
// it silently selects one of several potentially conflicting credentials.
func controllerCredential(h http.Header) (string, bool) {
    var auth, password []string
    authPresent, passwordPresent := false, false
    for name, values := range h {
        switch {
        case strings.EqualFold(name, "Authorization"):
            if authPresent { return "", false }
            authPresent = true
            auth = values
        case strings.EqualFold(name, "Password"):
            if passwordPresent { return "", false }
            passwordPresent = true
            password = values
        }
    }
    if authPresent == passwordPresent { return "", false }
    if authPresent {
        if len(auth) != 1 || !strings.HasPrefix(auth[0], "Bearer ") {
            return "", false
        }
        token := strings.TrimPrefix(auth[0], "Bearer ")
        return token, validControllerToken(token)
    }
    if len(password) != 1 { return "", false }
    return password[0], validControllerToken(password[0])
}

func validControllerToken(token string) bool {
    if token == "" || strings.TrimSpace(token) != token { return false }
    for i := 0; i < len(token); i++ {
        if token[i] < 0x21 || token[i] > 0x7e { return false }
    }
    return true
}
