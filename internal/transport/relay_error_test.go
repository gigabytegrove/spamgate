package transport

import (
	"errors"
	"fmt"
	"net/textproto"
	"testing"
)

func TestPermanentRelayFailureRequiresMessageStageAndSMTP5xx(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"mail 550", wrapRelayStage("MAIL", &textproto.Error{Code: 550, Msg: "sender rejected"}), true},
		{"rcpt 550 wrapped", fmt.Errorf("delivery: %w", wrapRelayStage("RCPT", &textproto.Error{Code: 550, Msg: "recipient unknown"})), true},
		{"data 554", wrapRelayStage("DATA", &textproto.Error{Code: 554, Msg: "content rejected"}), true},
		{"mail 451", wrapRelayStage("MAIL", &textproto.Error{Code: 451, Msg: "try later"}), false},
		{"data 421", wrapRelayStage("DATA", &textproto.Error{Code: 421, Msg: "temporarily unavailable"}), false},
		{"network error", wrapRelayStage("DATA", errors.New("broken pipe")), false},
		{"bare authentication 535", &textproto.Error{Code: 535, Msg: "credentials rejected"}, false},
		{"auth stage 535", wrapRelayStage("AUTH", &textproto.Error{Code: 535, Msg: "credentials rejected"}), false},
		{"greeting 554", wrapRelayStage("GREETING", &textproto.Error{Code: 554, Msg: "unavailable"}), false},
		{"untyped text", errors.New("550 recipient rejected"), false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPermanentRelayFailure(tt.err); got != tt.want {
				t.Fatalf("isPermanentRelayFailure(%v) = %t, want %t", tt.err, got, tt.want)
			}
		})
	}
	if wrapRelayStage("DATA", nil) != nil {
		t.Fatal("nil stage error must remain nil")
	}
}
