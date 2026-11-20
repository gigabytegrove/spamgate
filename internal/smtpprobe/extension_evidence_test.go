package smtpprobe

import (
 "reflect"
 "testing"
)

func TestExtensionEvidenceBoundaries(t *testing.T) {
 cases := []struct{
  name string
  lines []string
  want ExtensionEvidence
 }{
  {"identity only",[]string{"PIPELINING"},ExtensionEvidence{Warnings:[]string{}}},
  {"valid all",[]string{"server","PIPELINING","8BITMIME","SMTPUTF8","CHUNKING","DSN","REQUIRETLS"},ExtensionEvidence{true,true,true,true,true,true,[]string{}}},
  {"case insensitive",[]string{"server","pipelining","smtpUtf8"},ExtensionEvidence{PIPELINING:true,SMTPUTF8:true,Warnings:[]string{}}},
  {"duplicate",[]string{"server","PIPELINING","pipelining"},ExtensionEvidence{Warnings:[]string{"DUPLICATE_PIPELINING_EXTENSION"}}},
  {"parameters",[]string{"server","SMTPUTF8 EXTRA"},ExtensionEvidence{Warnings:[]string{"MALFORMED_SMTPUTF8_EXTENSION"}}},
  {"trailing space",[]string{"server","DSN "},ExtensionEvidence{Warnings:[]string{"MALFORMED_DSN_EXTENSION"}}},
  {"unknown extension",[]string{"server","BINARYMIME"},ExtensionEvidence{Warnings:[]string{}}},
 }
 for _, tc := range cases { t.Run(tc.name,func(t *testing.T){
  got := inspectExtensions(tc.lines)
  if !reflect.DeepEqual(got,tc.want) { t.Fatalf("got %+v want %+v",got,tc.want) }
 }) }
}

func TestExtensionEvidenceAssessment(t *testing.T) {
 before := inspectExtensions([]string{"server","PIPELINING","8BITMIME"})
 after := inspectExtensions([]string{"server","PIPELINING","SMTPUTF8"})
 findings := extensionEvidenceFindings(before,after,true)
 if len(findings)!=2 { t.Fatalf("unexpected findings: %+v",findings) }
 if findings[0].Code!="8BITMIME_ADVERTISEMENT_CHANGED_AFTER_TLS" || findings[1].Code!="SMTPUTF8_ADVERTISEMENT_CHANGED_AFTER_TLS" {
  t.Fatalf("unexpected change codes: %+v",findings)
 }
 if len(extensionEvidenceFindings(before,after,false))!=0 { t.Fatal("reported TLS drift without TLS") }
}

func TestAmbiguousExtensionDoesNotProduceFalseDrift(t *testing.T) {
 before := inspectExtensions([]string{"server","CHUNKING","CHUNKING"})
 after := inspectExtensions([]string{"server","CHUNKING"})
 for _, f := range extensionEvidenceFindings(before,after,true) {
  if f.Code=="CHUNKING_ADVERTISEMENT_CHANGED_AFTER_TLS" { t.Fatal("ambiguous baseline produced drift") }
 }
}

func TestExtensionEvidenceIsReadOnlyObservation(t *testing.T) {
 r := Result{BannerCode:220,EHLOCode:250,Extensions:inspectExtensions([]string{"server","PIPELINING"})}
 for _, f := range Assess(r) {
  if f.Code=="PIPELINING_ADVERTISEMENT_CHANGED_AFTER_TLS" { t.Fatal("drift before TLS") }
 }
}
