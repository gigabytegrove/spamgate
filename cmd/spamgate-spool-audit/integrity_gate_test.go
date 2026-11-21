package main

import (
 "reflect"
 "testing"

 "github.com/gigabytegrove/spamgate/internal/spoolaudit"
)

func TestIntegrityGateFailures(t *testing.T) {
 tests := []struct {
  name string
  report spoolaudit.Report
  want []string
 }{
  {"clean", spoolaudit.Report{}, []string{}},
  {"sorted", spoolaudit.Report{FindingCounts:map[string]int{"z":2,"a":1,"zero":0}}, []string{"integrity:a=1","integrity:z=2"}},
  {"truncated", spoolaudit.Report{FindingCounts:map[string]int{"unreadable_record":4},Truncated:true}, []string{"integrity:unreadable_record=4","integrity:findings_truncated"}},
  {"inconsistent", spoolaudit.Report{Findings:[]spoolaudit.Finding{{Code:"test"}}}, []string{"integrity:unclassified_findings"}},
 }
 for _, tt := range tests {
  t.Run(tt.name,func(t *testing.T) {
   got := integrityGateFailures(tt.report)
   if !reflect.DeepEqual(got,tt.want) {
    t.Fatalf("got %v, want %v",got,tt.want)
   }
  })
 }
}
