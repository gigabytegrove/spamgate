package transport

import (
	"errors"
	"net/textproto"
)

// relayStageError retains the SMTP transaction stage without parsing
// free-form server text. Only a documented 5xx response from MAIL, RCPT,
// or DATA is a permanent message-level delivery failure. Authentication,
// greeting, TLS and network errors must not silently discard queued mail.
type relayStageError struct {
	stage string
	err   error
}

func (e *relayStageError) Error() string { return "relay " + e.stage + ": " + e.err.Error() }
func (e *relayStageError) Unwrap() error { return e.err }

func wrapRelayStage(stage string, err error) error {
	if err == nil {
		return nil
	}
	return &relayStageError{stage: stage, err: err}
}

// isPermanentRelayFailure is deliberately conservative. A 5xx returned
// during authentication can be fixed by an administrator, and a transport
// failure after DATA may have an ambiguous delivery outcome.
func isPermanentRelayFailure(err error) bool {
	var stage *relayStageError
	if !errors.As(err, &stage) {
		return false
	}
	switch stage.stage {
	case "MAIL", "RCPT", "DATA":
	default:
		return false
	}
	var response *textproto.Error
	return errors.As(err, &response) && response.Code >= 500 && response.Code <= 599
}
