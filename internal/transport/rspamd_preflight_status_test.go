package transport

import (
    "errors"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
)

func TestRspamdPreflightTypedStatus(t *testing.T) {
    cases := []struct {
        name string
        metadata rspamdRequestMetadata
        wantStatus int
        wantCause error
    }{
        {"gzip", rspamdRequestMetadata{ContentEncoding: "gzip"}, http.StatusUnsupportedMediaType, errRspamdUnsupportedEncoding},
        {"brotli", rspamdRequestMetadata{ContentEncoding: "br"}, http.StatusUnsupportedMediaType, errRspamdUnsupportedEncoding},
        {"chained", rspamdRequestMetadata{ContentEncoding: "identity,gzip"}, http.StatusUnsupportedMediaType, errRspamdUnsupportedEncoding},
        {"compressed", rspamdRequestMetadata{Compression: "zstd"}, http.StatusUnsupportedMediaType, errRspamdUnsupportedEncoding},
        {"invalid helo", rspamdRequestMetadata{Helo: "bad..example.test"}, http.StatusBadRequest, errRspamdInvalidHelo},
        {"invalid bracket", rspamdRequestMetadata{Helo: "[192.0.2.1"}, http.StatusBadRequest, errRspamdInvalidHelo},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            _, err := rspamdValidateRequestPreflight(tc.metadata)
            if !errors.Is(err, tc.wantCause) {
                t.Fatalf("error %v does not wrap %v", err, tc.wantCause)
            }
            if got := rspamdPreflightHTTPStatus(err); got != tc.wantStatus {
                t.Fatalf("HTTP status %d, want %d", got, tc.wantStatus)
            }
        })
    }
    if got := rspamdPreflightHTTPStatus(errors.New("unexpected preflight failure")); got != http.StatusBadRequest {
        t.Fatalf("unknown preflight error must fail closed with 400, got %d", got)
    }
}

func TestRspamdPreflightHandlerStatusAndNoBodyRead(t *testing.T) {
    cases := []struct {
        name string
        header string
        value string
        want int
    }{
        {"compressed request", "Compression", "zstd", http.StatusUnsupportedMediaType},
        {"encoded request", "Content-Encoding", "gzip", http.StatusUnsupportedMediaType},
        {"malformed greeting", "Helo", "bad..example.test", http.StatusBadRequest},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            body := &failingRspamdBody{}
            req := httptest.NewRequest(http.MethodPost, "/checkv2", nil)
            req.Body = body
            req.Header.Set("From", "sender@example.test")
            req.Header.Set("IP", "192.0.2.1")
            req.Header.Set(tc.header, tc.value)
            recorder := httptest.NewRecorder()
            (&RspamdWorker{}).check(recorder, req)
            if recorder.Code != tc.want {
                t.Fatalf("status=%d want=%d body=%s", recorder.Code, tc.want, recorder.Body.String())
            }
            if body.reads != 0 {
                t.Fatalf("preflight failure consumed request body %d times", body.reads)
            }
            if strings.Contains(recorder.Body.String(), "message body could not be read") {
                t.Fatalf("body read failure concealed preflight error")
            }
        })
    }
}
