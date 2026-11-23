package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type failingTrainingBody struct{}
func (failingTrainingBody) Read([]byte) (int, error) { return 0, errors.New("client upload disconnected") }
func (failingTrainingBody) Close() error { return nil }

func TestControllerTrainingSampleBoundary(t *testing.T) {
	for _, tc := range []struct {
		name string
		body []byte
		length int64
		want int
	}{
		{"empty", nil, 0, http.StatusBadRequest},
		{"normal", []byte("From: a@example.test\r\n\r\nbody"), -1, http.StatusOK},
		{"exact-limit", bytes.Repeat([]byte("x"), int(controllerMaxTrainingSampleBytes)), -1, http.StatusOK},
		{"over-limit-stream", bytes.Repeat([]byte("x"), int(controllerMaxTrainingSampleBytes)+1), -1, http.StatusRequestEntityTooLarge},
		{"over-limit-declared", []byte("small"), controllerMaxTrainingSampleBytes+1, http.StatusRequestEntityTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/learnspam", bytes.NewReader(tc.body))
			r.ContentLength = tc.length
			got, status := readControllerTrainingSample(httptest.NewRecorder(), r)
			if status != tc.want { t.Fatalf("status %d, want %d", status, tc.want) }
			if status == http.StatusOK && !bytes.Equal(got, tc.body) { t.Fatal("sample was modified") }
			if status != http.StatusOK && got != nil { t.Fatal("failure returned sample bytes") }
		})
	}
}

func TestControllerTrainingSampleTransportErrors(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/learnham", nil)
	r.Body = failingTrainingBody{}
	if _, status := readControllerTrainingSample(httptest.NewRecorder(), r); status != http.StatusBadRequest {
		t.Fatalf("broken upload status %d", status)
	}
	r = httptest.NewRequest(http.MethodPost, "/learnham", strings.NewReader("message"))
	ctx, cancel := context.WithCancel(r.Context())
	cancel()
	r = r.WithContext(ctx)
	if _, status := readControllerTrainingSample(httptest.NewRecorder(), r); status != http.StatusRequestTimeout {
		t.Fatalf("cancelled upload status %d", status)
	}
	r = httptest.NewRequest(http.MethodPost, "/learnham", nil)
	r.Body = nil
	if _, status := readControllerTrainingSample(httptest.NewRecorder(), r); status != http.StatusBadRequest {
		t.Fatalf("missing body status %d", status)
	}
}

type closingTrainingBody struct { io.Reader; closed bool }
func (b *closingTrainingBody) Close() error { b.closed = true; return nil }

func TestControllerTrainingSampleClosesBody(t *testing.T) {
	body := &closingTrainingBody{Reader: strings.NewReader("training")}
	r := httptest.NewRequest(http.MethodPost, "/learnspam", nil)
	r.Body = body
	if _, status := readControllerTrainingSample(httptest.NewRecorder(), r); status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if !body.closed { t.Fatal("training request body left open") }
}
