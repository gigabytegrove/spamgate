package transport

import (
 "strings"
 "testing"
)

func TestUniqueDurableJSON(t *testing.T) {
 cases := []struct { name, document string; valid bool }{
  {"valid nested", `{"id":"a","scan":{"symbols":[{"name":"SPF","score":1},{"name":"DKIM","score":2}]}}`, true},
  {"duplicate top level", `{"id":"a","id":"b"}`, false},
  {"duplicate nested", `{"scan":{"verdict":"allow","verdict":"reject"}}`, false},
  {"duplicate array object", `{"scan":[{"score":1,"score":99}]}`, false},
  {"escaped alias", `{"sender":"a","\u0073ender":"b"}`, false},
  {"different nested objects", `{"scan":[{"score":1},{"score":2}]}`, true},
  {"trailing object", `{} {}`, false},
  {"trailing primitive", `{} true`, false},
  {"truncated", `{"scan":{"verdict":"allow"}`, false},
  {"malformed", `{"scan":]}`, false},
  {"max depth", strings.Repeat("[", maxDurableJSONDepth) + "0" + strings.Repeat("]", maxDurableJSONDepth), true},
  {"excessive depth", strings.Repeat("[", maxDurableJSONDepth+1) + "0" + strings.Repeat("]", maxDurableJSONDepth+1), false},
 }
 for _, tc := range cases { t.Run(tc.name, func(t *testing.T) {
  err := validateUniqueDurableJSON([]byte(tc.document))
  if (err == nil) != tc.valid { t.Fatalf("valid=%v, error=%v", tc.valid, err) }
 }) }
}
