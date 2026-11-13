package smtpprobe

import (
 "reflect"
 "testing"
)

// Regression: AUTH-specific duplicate warnings must be stable, independently
// observable, and must not be emitted for duplicate unrelated extensions.
func TestCapabilityWarningsAUTHDuplicateMatrix(t *testing.T) {
 tests := []struct {
  name string
  lines []string
  want []string
 }{
  {"repeated AUTH", []string{"mx.example", "AUTH PLAIN", "AUTH LOGIN"}, []string{"DUPLICATE_EXTENSION", "DUPLICATE_AUTH_EXTENSION"}},
  {"legacy and standard AUTH", []string{"mx.example", "AUTH=PLAIN", "AUTH LOGIN"}, []string{"DUPLICATE_EXTENSION", "DUPLICATE_AUTH_EXTENSION"}},
  {"case insensitive AUTH", []string{"mx.example", "auth plain", "AuTh login"}, []string{"DUPLICATE_EXTENSION", "DUPLICATE_AUTH_EXTENSION"}},
  {"repeated mechanism", []string{"mx.example", "AUTH PLAIN plain"}, []string{"DUPLICATE_AUTH_MECHANISM"}},
  {"repeated unrelated extension", []string{"mx.example", "PIPELINING", "PIPELINING"}, []string{"DUPLICATE_EXTENSION"}},
  {"repeated SIZE", []string{"mx.example", "SIZE 1024", "SIZE 2048"}, []string{"DUPLICATE_EXTENSION"}},
  {"empty AUTH repeated", []string{"mx.example", "AUTH", "AUTH"}, []string{"EMPTY_AUTH_ADVERTISEMENT", "DUPLICATE_EXTENSION", "DUPLICATE_AUTH_EXTENSION"}},
  {"identity is not extension", []string{"AUTH PLAIN", "AUTH LOGIN"}, nil},
 }
 for _, tc := range tests {
  t.Run(tc.name, func(t *testing.T) {
   got := capabilityWarnings(tc.lines)
   if len(got)==0 {got=nil}
   if !reflect.DeepEqual(got,tc.want) {t.Fatalf("warnings = %q, want %q",got,tc.want)}
  })
 }
}
