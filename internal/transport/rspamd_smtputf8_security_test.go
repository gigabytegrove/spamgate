package transport

import "testing"

func TestRspamdSMTPUTF8MailboxSecurity(t *testing.T) {
 cases := []struct{name, mailbox string; valid bool}{
  {"ascii atext", "a!#$%&'*+-/=?^_`{|}~b@example.test", true},
  {"unicode local", "josé@example.test", true},
  {"quoted ascii space", "\"first last\"@example.test", true},
  {"unicode nonbreaking space", "first\u00a0last@example.test", false},
  {"unicode em space", "first\u2003last@example.test", false},
  {"unicode line separator", "first\u2028last@example.test", false},
  {"unicode bidi override", "first\u202elast@example.test", false},
  {"unicode zero width joiner", "first\u200dlast@example.test", false},
  {"unicode tab", "first\tlast@example.test", false},
  {"quoted unicode format", "\"first\u200dlast\"@example.test", false},
  {"quoted unicode separator", "\"first\u00a0last\"@example.test", false},
  {"unquoted comma", "first,last@example.test", false},
  {"unquoted colon", "first:last@example.test", false},
  {"unquoted quote", "first\"last@example.test", false},
  {"unquoted backslash", "first\\last@example.test", false},
  {"quoted escape", "\"first\\\"last\"@example.test", true},
 }
 for _, tc := range cases { t.Run(tc.name,func(t *testing.T) {
  err := rspamdValidateMailboxStructure(tc.mailbox)
  if (err == nil) != tc.valid { t.Fatalf("mailbox=%q valid=%v err=%v",tc.mailbox,tc.valid,err) }
 }) }
}
