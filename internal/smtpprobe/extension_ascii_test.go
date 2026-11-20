package smtpprobe

import "testing"

func TestSMTPKeywordASCIIValidation(t *testing.T) {
 cases := []struct{ token string; valid bool }{
  {"PIPELINING", true},
  {"8BITMIME", true},
  {"ENHANCEDSTATUSCODES", true},
  {"REQUIRETLS", true},
  {"X-CUSTOM", true},
  {"", false},
  {"PIPELINING\r", false},
  {"PIPELINING\n", false},
  {"PIPELINING\x00", false},
  {"PIPELINING\t", false},
  {"PIPELINING ", false},
  {"PIPELINING\u200b", false},
  {"PIPELINING\u00a0", false},
 }
 for _, tc := range cases {
  t.Run(tc.token,func(t *testing.T) {
   if got := smtpExtensionASCIIKeyword(tc.token); got != tc.valid {
    t.Fatalf("token %q valid=%v want %v",tc.token,got,tc.valid)
   }
  })
 }
}

func TestSMTPMalformedExtensionCannotBecomeTrusted(t *testing.T) {
 for _, line := range []string{
  "PIPELINING\r", "PIPELINING\x00", "PIPELINING\t", "PIPELINING ",
 } {
  got := inspectExtensions([]string{"mx.example",line})
  if got.PIPELINING { t.Fatalf("malformed %q became trusted",line) }
  if !extensionWarning(got.Warnings,"PIPELINING") {
   t.Fatalf("malformed %q lacked warning: %v",line,got.Warnings)
  }
 }
}
