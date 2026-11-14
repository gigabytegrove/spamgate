package transport

import "testing"

func TestRspamdParseFlags(t *testing.T) {
 cases := []struct{name, input string; ok bool; count int}{
  {"absent", "", true, 0},
  {"no log", "no_log", true, 1},
  {"milter", "milter", true, 1},
  {"combined", "no_log, milter", true, 2},
  {"case folded", "NO_LOG,MiLtEr", true, 2},
  {"pass all ignored before", "pass_all", false, 0},
  {"groups ignored before", "groups", false, 0},
  {"unknown", "foobar", false, 0},
  {"empty element", "no_log,", false, 0},
  {"leading empty", ",milter", false, 0},
  {"duplicate", "milter,MILTER", false, 0},
  {"whitespace only", "  ", false, 0},
 }
 for _, tc := range cases { t.Run(tc.name,func(t *testing.T){
  got,err:=rspamdParseFlags(tc.input)
  if (err==nil)!=tc.ok {t.Fatalf("flags=%v err=%v",got,err)}
  if tc.ok && len(got)!=tc.count {t.Fatalf("count=%d want=%d",len(got),tc.count)}
 }) }
}
