package transport

import (
 "strings"
 "testing"
)

func TestRspamdMailboxAdversarialStructure(t *testing.T) {
 cases := []struct{name, mailbox string; valid bool}{
  {"simple", "alice@example.test", true},
  {"quoted whitespace", "\"first last\"@example.test", true},
  {"escaped quote", "\"first\\\"last\"@example.test", true},
  {"quoted at", "\"first@last\"@example.test", true},
  {"ipv4 literal", "user@[192.0.2.1]", true},
  {"ipv6 literal", "user@[IPv6:2001:db8::1]", true},
  {"unicode local", "josé@example.test", true},
  {"embedded quote", "a\"b\"c@example.test", false},
  {"unescaped quote", "\"a\"b\"@example.test", false},
  {"local leading dot", ".a@example.test", false},
  {"local trailing dot", "a.@example.test", false},
  {"local consecutive dots", "a..b@example.test", false},
  {"invalid literal", "a@[not-an-ip]", false},
  {"invalid ipv4", "a@[999.999.999.999]", false},
  {"invalid ipv6", "a@[IPv6:bad]", false},
  {"ipv6 missing tag", "a@[2001:db8::1]", false},
  {"nested domain bracket", "a@[[127.0.0.1]]", false},
  {"c1 control", "a\u0085@example.test", false},
  {"local overlong", strings.Repeat("a",65)+"@example.test", false},
  {"local boundary", strings.Repeat("a",64)+"@example.test", true},
  {"domain label overlong", "a@"+strings.Repeat("a",64)+".test", false},
  {"domain label boundary", "a@"+strings.Repeat("a",63)+".test", true},
  {"quoted escape trailing", "\"abc\\\"@example.test", false},
 }
 for _, tc := range cases { t.Run(tc.name,func(t *testing.T) {
  _, err := rspamdMailboxIdentity(tc.mailbox,false)
  if (err==nil)!=tc.valid { t.Fatalf("mailbox=%q valid=%v err=%v",tc.mailbox,tc.valid,err) }
 }) }
}
