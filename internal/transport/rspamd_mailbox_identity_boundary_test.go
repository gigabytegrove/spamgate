package transport

import "testing"

func TestRspamdMailboxIdentityBoundary(t *testing.T) {
 cases := []struct{name, input string; nullOK, valid bool; want string}{
  {"bare sender", "alice@example.test", false, true, "alice@example.test"},
  {"wrapped sender", "<alice@example.test>", false, true, "alice@example.test"},
  {"null reverse path", "<>", true, true, ""},
  {"empty null reverse path", "", true, true, ""},
  {"null recipient forbidden", "<>", false, false, ""},
  {"empty recipient forbidden", "", false, false, ""},
  {"leading space", " alice@example.test", false, false, ""},
  {"trailing space", "alice@example.test ", false, false, ""},
  {"wrapped outer space", " <alice@example.test>", false, false, ""},
  {"wrapped trailing space", "<alice@example.test> ", false, false, ""},
  {"wrapped inner space", "< alice@example.test>", false, false, ""},
  {"quoted comma", "\"last,first\"@example.test", false, true, "\"last,first\"@example.test"},
  {"wrapped quoted comma", "<\"last,first\"@example.test>", false, true, "\"last,first\"@example.test"},
  {"unquoted comma", "last,first@example.test", false, false, ""},
  {"nested wrapper", "<<alice@example.test>>", false, false, ""},
  {"newline", "alice@example.test\n", false, false, ""},
  {"quoted escaped comma", "\"a\\,b\"@example.test", false, true, "\"a\\,b\"@example.test"},
 }
 for _, tc := range cases { t.Run(tc.name, func(t *testing.T) {
  got, err := rspamdMailboxIdentity(tc.input, tc.nullOK)
  if (err == nil) != tc.valid || (err == nil && got != tc.want) { t.Fatalf("input=%q got=%q err=%v valid=%v want=%q", tc.input,got,err,tc.valid,tc.want) }
 }) }
}
