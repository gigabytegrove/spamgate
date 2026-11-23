package transport

import (
    "crypto/sha256"
    "encoding/base64"
    "errors"
    "io"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
)

type trackingTrainingBody struct {
    reads int
    closed bool
}

func (b *trackingTrainingBody) Read(_ []byte) (int, error) {
    b.reads++
    return 0, errors.New("body should not be read")
}

func (b *trackingTrainingBody) Close() error {
    b.closed = true
    return nil
}

func TestControllerTrainingDigestPreflightRejectsWithoutReading(t *testing.T) {
    cases := []struct {
        name string
        headers http.Header
    }{
        {"invalid-base64", http.Header{"Content-Digest": {"sha-256=:!:"}}},
        {"duplicate", http.Header{"Content-Digest": {"sha-256=:YWJj:", "sha-256=:YWJj:"}}},
        {"unsupported", http.Header{"Content-Digest": {"sha-512=:YWJj:"}}},
        {"ambiguous-aliases", http.Header{"Content-Digest": {"sha-256=:YWJj:"}, "content-digest": {"sha-256=:YWJj:"}}},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            r := httptest.NewRequest(http.MethodPost, "/learnspam", nil)
            b := &trackingTrainingBody{}
            r.Body = b
            r.ContentLength = -1
            r.Header = tc.headers
            got, status := readControllerTrainingSample(httptest.NewRecorder(), r)
            if status != http.StatusBadRequest || got != nil {
                t.Fatalf("status=%d sample=%v", status, got)
            }
            if b.reads != 0 || !b.closed {
                t.Fatalf("reads=%d closed=%t", b.reads, b.closed)
            }
        })
    }
}

func TestControllerTrainingDigestPreflightValidBody(t *testing.T) {
    sample := "From: sender@example.org\r\nSubject: example\r\n\r\nbody"
    sum := sha256.Sum256([]byte(sample))
    digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
    for _, tc := range []struct {
        name string
        body string
        want int
    }{
        {"matching", sample, http.StatusOK},
        {"mismatching", sample + "!", http.StatusBadRequest},
    } {
        t.Run(tc.name, func(t *testing.T) {
            r := httptest.NewRequest(http.MethodPost, "/learnspam", strings.NewReader(tc.body))
            r.Header.Set("Content-Digest", digest)
            got, status := readControllerTrainingSample(httptest.NewRecorder(), r)
            if status != tc.want {
                t.Fatalf("status=%d want=%d", status, tc.want)
            }
            if status == http.StatusOK && string(got) != tc.body {
                t.Fatal("accepted body changed")
            }
            if status != http.StatusOK && got != nil {
                t.Fatal("rejected body returned")
            }
        })
    }
}

func TestControllerTrainingDigestPreflightReadFailure(t *testing.T) {
    r := httptest.NewRequest(http.MethodPost, "/learnspam", nil)
    r.Body = io.NopCloser(&failingTrainingReader{})
    r.ContentLength = -1
    sum := sha256.Sum256([]byte("sample"))
    r.Header.Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(sum[:])+":")
    got, status := readControllerTrainingSample(httptest.NewRecorder(), r)
    if status != http.StatusBadRequest || got != nil {
        t.Fatalf("status=%d sample=%v", status, got)
    }
}

type failingTrainingReader struct{}
func (*failingTrainingReader) Read([]byte) (int, error) {
    return 0, errors.New("interrupted upload")
}
