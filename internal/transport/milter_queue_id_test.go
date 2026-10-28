package transport

import "testing"

func TestMilterQueueIDMacroStrict(t *testing.T) {
	for _, tc := range []struct {
		data string
		want string
	}{
		{"Ei\x00A19BD38C\x00", "A19BD38C"},
		{"E{j}\x00unused\x00{i}\x00ABC123\x00", "ABC123"},
		{"Ei\x00bad/path\x00", ""},
		{"Ei\x00bad\r\nvalue\x00", ""},
		{"Ei\x00\x00", ""},
	} {
		if got := milterQueueID([]byte(tc.data)); got != tc.want {
			t.Errorf("queue ID %q -> %q; expected %q", tc.data, got, tc.want)
		}
	}
}
