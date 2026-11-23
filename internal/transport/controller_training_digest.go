package transport

import (
    "crypto/sha256"
    "crypto/subtle"
    "encoding/base64"
    "net/http"
    "strings"
)

// controllerTrainingDigest parses the supported RFC 9530 structured-field
// dictionary member before any upload bytes are consumed. Deliberately accept
// only one sha-256 member; do not silently ignore unsupported algorithms.
func controllerTrainingDigest(r *http.Request) ([]byte, int) {
    if r == nil {
        return nil, http.StatusBadRequest
    }
    values := controllerHeaderValues(r.Header, "Content-Digest")
    if len(values) == 0 {
        return nil, http.StatusOK
    }
    if len(values) != 1 {
        return nil, http.StatusBadRequest
    }
    value := strings.TrimSpace(values[0])
    if !strings.HasPrefix(value, "sha-256=:") || !strings.HasSuffix(value, ":") {
        return nil, http.StatusBadRequest
    }
    encoded := strings.TrimSuffix(strings.TrimPrefix(value, "sha-256=:"), ":")
    if encoded == "" || strings.ContainsAny(encoded, " \t\r\n,;") {
        return nil, http.StatusBadRequest
    }
    digest, err := base64.StdEncoding.Strict().DecodeString(encoded)
    if err != nil || len(digest) != sha256.Size {
        return nil, http.StatusBadRequest
    }
    return digest, http.StatusOK
}

// validateControllerTrainingDigest preserves the existing entry point for
// direct callers while sharing strict header parsing with the upload reader.
func validateControllerTrainingDigest(r *http.Request, body []byte) int {
    expected, status := controllerTrainingDigest(r)
    if status != http.StatusOK {
        return status
    }
    return verifyControllerTrainingDigest(expected, body)
}

func verifyControllerTrainingDigest(expected, body []byte) int {
    if expected == nil {
        return http.StatusOK
    }
    actual := sha256.Sum256(body)
    if subtle.ConstantTimeCompare(expected, actual[:]) != 1 {
        return http.StatusBadRequest
    }
    return http.StatusOK
}
