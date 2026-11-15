package transport

import "testing"

func TestRspamdMailboxStructuralBoundaries(t *testing.T) {
 cases := []struct{name, mailbox string; invalid bool}{
  {"ordinary", "user@example.test", false},
  {"quoted whitespace", "\"first last\"@example.test", false},
  {"quoted at sign", "\"first@last\"@example.test", false},
  {"escaped quote", "\"first\\\"last\"@example.test", false},
  {"domain literal", "user@[127.0.0.1]", false},
  {"two separators", "a@b@example.test", true},
  {"quoted local not closed", "\"first@example.test", true},
  {"space in unquoted local", "first last@example.test", true},
  {"space in domain", "first@example .test", true},
  {"tab in domain", "first@example\t.test", true},
  {"consecutive dots", "first@example..test", true},
  {"leading dot", "first@.example.test", true},
  {"trailing dot", "first@example.test.", true},
  {"invalid domain character", "first@example!.test", true},
  {"hyphen prefix", "first@-example.test", true},
  {"hyphen suffix", "first@example-.test", true},
  {"empty domain literal", "first@[]", true},
  {"unclosed domain literal", "first@[127.0.0.1", true},
  {"invalid UTF8", "first@exam\xffple.test", true},
  {"control character", "first@exa\x01mple.test", true},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   _, err := rspamdMailboxIdentity(tc.mailbox, false)
   if (err != nil) != tc.invalid { t.Fatalf("mailbox=%q err=%v invalid=%v", tc.mailbox, err, tc.invalid) }
  })
 }
}
