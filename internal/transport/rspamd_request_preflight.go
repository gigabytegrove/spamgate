package transport

import (
    "errors"
    "fmt"
    "strings"
)

var (
    errRspamdUnsupportedEncoding = errors.New("unsupported request encoding")
    errRspamdInvalidHelo = errors.New("invalid Helo header")
)

// rspamdValidateRequestPreflight returns typed errors so HTTP status selection
// never depends on the wording of an error message.
func rspamdValidateRequestPreflight(m rspamdRequestMetadata) (string, error) {
    if m.Compression != "" {
        return "", fmt.Errorf("%w: Compression header", errRspamdUnsupportedEncoding)
    }
    encoding := strings.TrimSpace(m.ContentEncoding)
    if encoding != "" && !strings.EqualFold(encoding, "identity") {
        return "", fmt.Errorf("%w: Content-Encoding header", errRspamdUnsupportedEncoding)
    }
    if m.Helo == "" {
        return "", nil
    }
    helo, valid := parseSMTPXForwardHelo(m.Helo)
    if !valid {
        return "", errRspamdInvalidHelo
    }
    return helo, nil
}

func rspamdPreflightHTTPStatus(err error) int {
    switch {
    case errors.Is(err, errRspamdInvalidHelo):
        return 400
    case errors.Is(err, errRspamdUnsupportedEncoding):
        return 415
    default:
        return 400
    }
}
