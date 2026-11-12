package server

import (
 "sort"
 "strings"
)

// relayCapabilityWarnings reports contradictory or malformed EHLO extension
// advertisements. These are observations only; they do not prove compliance.
func relayCapabilityWarnings(message string) []string {
 lines := strings.Split(message, "\n")
 counts := make(map[string]int)
 warnings := make(map[string]bool)
 noParameters := map[string]bool{
  "8BITMIME":true, "SMTPUTF8":true, "PIPELINING":true,
  "DSN":true, "CHUNKING":true, "BINARYMIME":true,
  "REQUIRETLS":true, "ENHANCEDSTATUSCODES":true, "STARTTLS":true,
 }
 for _, line := range lines[1:] {
  fields := strings.Fields(line)
  if len(fields)==0 { continue }
  keyword := strings.ToUpper(fields[0])
  if !validRelayExtension(fields[0]) { warnings["malformed_extension_keyword"]=true; continue }
  counts[keyword]++
  if noParameters[keyword] && len(fields)>1 {
   warnings["unexpected_parameters_"+strings.ToLower(keyword)]=true
  }
 }
 for keyword,count := range counts {
  if count>1 { warnings["duplicate_extension_"+strings.ToLower(keyword)]=true }
 }
 if counts["BINARYMIME"]>0 && counts["CHUNKING"]==0 {
  warnings["binarymime_without_chunking"]=true
 }
 result := make([]string,0,len(warnings))
 for warning := range warnings { result=append(result,warning) }
 sort.Strings(result)
 return result
}
