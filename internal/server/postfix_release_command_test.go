package server

import (
	"reflect"
	"strings"
	"testing"
)

func TestPostfixReleaseCommandNarrowPrivilegeBoundary(t *testing.T) {
	for _, tc := range []struct {
		uid  int
		name string
		args []string
	}{
		{0, "/usr/sbin/postsuper", []string{"-H", "AB1234"}},
		{1001, "/usr/bin/sudo", []string{"-n", "--", "/usr/local/libexec/spamgate/postfix-hold-release", "AB1234"}},
	} {
		name, args, err := postfixReleaseCommand(tc.uid, "AB1234")
		if err != nil || name != tc.name || !reflect.DeepEqual(args, tc.args) {
			t.Fatalf("uid=%d: got %q %q %v", tc.uid, name, args, err)
		}
	}
}

func TestPostfixReleaseCommandRejectsReservedOrInjectedIDs(t *testing.T) {
	for _, id := range []string{"", "ALL", "all", "-H", "AB;id", "AB CD", "AB\nCD", "AB/CD", strings.Repeat("A", 33)} {
		for _, uid := range []int{0, 1001} {
			name, args, err := postfixReleaseCommand(uid, id)
			if err == nil || name != "" || len(args) != 0 {
				t.Fatalf("uid=%d accepted %q: %q %q %v", uid, id, name, args, err)
			}
		}
	}
}
