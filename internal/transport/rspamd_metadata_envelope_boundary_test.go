package transport

import (
 "net/http"
 "testing"
)

func TestRspamdMetadataPreservesQuotedRecipientAndRejectsWhitespace(t *testing.T) {
 cases := []struct{name string; headers http.Header; valid bool; recipient string}{
  {"quoted comma recipient", http.Header{"Rcpt": {`"last,first"@example.test`}}, true, `"last,first"@example.test`},
  {"wrapped quoted comma recipient", http.Header{"Rcpt": {`<"last,first"@example.test>`}}, true, `"last,first"@example.test`},
  {"unquoted comma recipient", http.Header{"Rcpt": {"last,first@example.test"}}, false, ""},
  {"recipient leading space", http.Header{"Rcpt": {" alice@example.test"}}, false, ""},
  {"recipient trailing space", http.Header{"Rcpt": {"alice@example.test "}}, false, ""},
  {"sender leading space", http.Header{"From": {" alice@example.test"}, "Rcpt": {"bob@example.test"}}, false, ""},
  {"null sender", http.Header{"From": {"<>"}, "Rcpt": {"bob@example.test"}}, true, "bob@example.test"},
 }
 for _, tc := range cases { t.Run(tc.name,func(t *testing.T) {
  got, err := rspamdReadRequestMetadata(tc.headers)
  if (err == nil) != tc.valid { t.Fatalf("valid=%v err=%v",tc.valid,err) }
  if err == nil && (len(got.Recipients)!=1 || got.Recipients[0]!=tc.recipient) { t.Fatalf("recipients=%q want=%q",got.Recipients,tc.recipient) }
 }) }
}
