package transport

import (
 "net/http"
 "testing"
)

func TestRspamdMailboxIdentity(t *testing.T) {
 cases := []struct {name, value string; allowNull bool; want string; bad bool}{
  {"bracketed", "<user@example.test>", false, "user@example.test", false},
  {"bare", "user@example.test", false, "user@example.test", false},
  {"null sender", "<>", true, "", false},
  {"empty sender", "", true, "", false},
  {"empty recipient", "", false, "", true},
  {"null recipient", "<>", false, "", true},
  {"double open", "<<user@example.test>", false, "", true},
  {"double close", "<user@example.test>>", false, "", true},
  {"unmatched open", "<user@example.test", false, "", true},
  {"unmatched close", "user@example.test>", false, "", true},
  {"embedded angle", "us<er@example.test", false, "", true},
  {"multiple addresses", "a@example.test,b@example.test", false, "", true},
  {"space inside wrapper", "< user@example.test>", false, "", true},
  {"quoted local part", "<\"first last\"@example.test>", false, "\"first last\"@example.test", false},
 }
 for _, tc := range cases { t.Run(tc.name, func(t *testing.T) {
  got, err := rspamdMailboxIdentity(tc.value, tc.allowNull)
  if (err != nil) != tc.bad || (!tc.bad && got != tc.want) { t.Fatalf("got=%q err=%v want=%q bad=%v", got, err, tc.want, tc.bad) }
 }) }
}
func TestRspamdMetadataRejectsMalformedRecipientPaths(t *testing.T) {
 for _, header := range []string{"Rcpt", "Deliver-To", "From"} {
  t.Run(header, func(t *testing.T) {
   h := make(http.Header)
   h.Set(header, "<<a@example.test>>")
   if _, err := rspamdReadRequestMetadata(h); err == nil { t.Fatal("accepted malformed SMTP path") }
  })
 }
}
func TestRspamdMetadataRecipientBudgetIncludesDeliverTo(t *testing.T) {
 h := make(http.Header)
 for i:=0; i<100; i++ { h.Add("Rcpt", "user@example.test") }
 h.Set("Deliver-To", "extra@example.test")
 if _, err := rspamdReadRequestMetadata(h); err == nil { t.Fatal("accepted 101 total recipients") }
}
