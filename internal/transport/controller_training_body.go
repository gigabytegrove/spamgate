package transport

import (
	"context"
	"errors"
	"io"
	"net/http"
)

// Training is deliberately bounded before it reaches the classifier. A broken
// upload is not a too-large upload: preserve the distinction for operators
// without returning internal filesystem or classifier details to clients.
const controllerMaxTrainingSampleBytes int64 = 10 << 20

func readControllerTrainingSample(w http.ResponseWriter, r *http.Request) ([]byte, int) {
	if r == nil || r.Body == nil {
		return nil, http.StatusBadRequest
	}
	defer r.Body.Close()
	if status := validateControllerTrainingFraming(r); status != http.StatusOK {
		return nil, status
	}
	if status := validateControllerTrainingRepresentation(r); status != http.StatusOK {
		return nil, status
	}
	if err := r.Context().Err(); err != nil {
		return nil, http.StatusRequestTimeout
	}
	if r.ContentLength > controllerMaxTrainingSampleBytes {
		return nil, http.StatusRequestEntityTooLarge
	}
	limited := http.MaxBytesReader(w, r.Body, controllerMaxTrainingSampleBytes)
	defer limited.Close()
	raw, err := io.ReadAll(limited)
	if err != nil {
		var tooLarge *http.MaxBytesError
		switch {
		case errors.As(err, &tooLarge):
			return nil, http.StatusRequestEntityTooLarge
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return nil, http.StatusRequestTimeout
		default:
			return nil, http.StatusBadRequest
		}
	}
	if r.Context().Err() != nil {
		return nil, http.StatusRequestTimeout
	}
	if len(raw) == 0 {
		return nil, http.StatusBadRequest
	}
	return raw, http.StatusOK
}
