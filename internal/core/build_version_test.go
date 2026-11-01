package core

import "testing"

func TestBuildVersionValidation(t *testing.T) {
 valid := []string{"20261101-00", "20261101-01", "20261101-23", "20261101-01a", "20261231-23z", "20260228-12"}
 for _, id := range valid {
  if !ValidBuildVersion(id) { t.Errorf("valid build ID rejected: %q", id) }
 }
 invalid := []string{"", "unversioned", "20261101-24", "20261101-1", "20261101-001", "20261101-01aa", "20261101-01A", "20260230-12", "20261301-01", "20261031-23+", "20261101-01/../../", "20261101-01_"}
 for _, id := range invalid {
  if ValidBuildVersion(id) { t.Errorf("invalid build ID accepted: %q", id) }
 }
}

func TestBuildVersionComparison(t *testing.T) {
 cases := []struct{ a, b string; expected int }{
 {"unversioned","20261101-00",-1},
 {"20261101-00","unversioned",1},
 {"20261101-01","20261101-01",0},
 {"20261101-01","20261101-01a",-1},
 {"20261101-01a","20261101-01b",-1},
 {"20261101-01z","20261101-02",-1},
 {"20261101-23","20261102-00",-1},
 {"20261231-23z","20270101-00",-1},
 }
 for _, test := range cases {
  got, err := CompareBuildVersions(test.a, test.b)
  if err != nil { t.Fatal(err) }
  if (got < 0 && test.expected >= 0) || (got > 0 && test.expected <= 0) || (got == 0 && test.expected != 0) {
   t.Errorf("CompareBuildVersions(%q,%q)=%d, expected sign %d",test.a,test.b,got,test.expected)
  }
 }
 for _, input := range []string{"INVALID","20261101-24","20260230-01"} {
  if _, err := CompareBuildVersions(input,"20261101-00"); err == nil { t.Errorf("accepted invalid build ID %q",input) }
 }
}
