package transport

import "testing"

func TestRspamdDisposition(t *testing.T) {
 cases := []struct { input, want string; valid bool }{
  {"accept", "no action", true},
  {"no action", "no action", true},
  {"tag", "add header", true},
  {"reject", "reject", true},
  {"quarantine", "quarantine", true},
  {"", "", false},
  {"defer", "", false},
  {"discard", "", false},
  {"soft reject", "", false},
  {"ALLOW", "", false},
  {"unknown", "", false},
 }
 for _, tc := range cases {
  t.Run(tc.input, func(t *testing.T) {
   got, err := rspamdDisposition(tc.input)
   if (err == nil) != tc.valid { t.Fatalf("error=%v, valid=%v", err, tc.valid) }
   if got != tc.want { t.Fatalf("got %q, want %q", got, tc.want) }
  })
 }
}
