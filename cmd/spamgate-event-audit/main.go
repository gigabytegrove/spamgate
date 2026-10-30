package main

import (
 "bufio"
 "encoding/json"
 "flag"
 "fmt"
 "io"
 "os"
 "sort"
 "strings"
)

type event struct {
 Action string `json:"action"`
 Connector string `json:"connector"`
 Score *float64 `json:"score"`
 Findings json.RawMessage `json:"findings"`
 MTAAction string `json:"mta_action"`
 MTAState string `json:"mta_action_state"`
 MTANote string `json:"mta_action_note"`
}
type report struct {
 Total int `json:"total"`
 Malformed int `json:"malformed"`
 Actions map[string]int `json:"actions"`
 MTAStates map[string]int `json:"mta_states"`
 ZeroScore int `json:"zero_score"`
 ZeroScoreAccepted int `json:"zero_score_accepted"`
 MissingScore int `json:"missing_score"`
 WithFindings int `json:"with_findings"`
 UnconfirmedQuarantine int `json:"unconfirmed_quarantine"`
}
func analyze(r io.Reader) (report,error) {
 out:=report{Actions:map[string]int{},MTAStates:map[string]int{}}
 scan:=bufio.NewScanner(r)
 scan.Buffer(make([]byte,64*1024),2<<20)
 for scan.Scan() {
  line:=strings.TrimSpace(scan.Text()); if line=="" {continue}
  var e event
  if err:=json.Unmarshal([]byte(line),&e); err!=nil {out.Malformed++;continue}
  if e.Connector!="milter" {continue}
  out.Total++
  action:=strings.ToLower(strings.TrimSpace(e.Action))
  if action=="" {action="unknown"}
  out.Actions[action]++
  state:=strings.ToLower(strings.TrimSpace(e.MTAState))
  if state=="" {state="unknown"}
  out.MTAStates[state]++
  if e.Score==nil {out.MissingScore++} else if *e.Score==0 {
   out.ZeroScore++
   if action=="accept" {out.ZeroScoreAccepted++}
  }
  var findings []json.RawMessage
  if len(e.Findings)>0 && json.Unmarshal(e.Findings,&findings)==nil && len(findings)>0 {out.WithFindings++}
  // The Milter worker reports its requested action, not independent proof
  // that Postfix held or rejected the message. Never infer confirmation
  // from a self-reported mta_action_state value.
  if action=="quarantine" {out.UnconfirmedQuarantine++}
 }
 if err:=scan.Err();err!=nil{return out,fmt.Errorf("read events: %w",err)}
 return out,nil
}
func main(){
 path:=flag.String("events","/opt/spamgate/data/events.jsonl","read-only event history path")
 jsonOutput:=flag.Bool("json",false,"print JSON report")
 flag.Parse()
 f,err:=os.Open(*path);if err!=nil {fmt.Fprintln(os.Stderr,err);os.Exit(2)}
 defer f.Close()
 result,err:=analyze(f);if err!=nil {fmt.Fprintln(os.Stderr,err);os.Exit(2)}
 if *jsonOutput {enc:=json.NewEncoder(os.Stdout);enc.SetIndent("","  ");_ =enc.Encode(result);return}
 fmt.Printf("Milter events: %d; malformed lines: %d; zero scores: %d; zero-score accepts: %d; missing scores: %d; scans with findings: %d; quarantines requiring Postfix verification: %d\n",result.Total,result.Malformed,result.ZeroScore,result.ZeroScoreAccepted,result.MissingScore,result.WithFindings,result.UnconfirmedQuarantine)
 keys:=make([]string,0,len(result.Actions));for k:=range result.Actions {keys=append(keys,k)};sort.Strings(keys)
 for _,k:=range keys {fmt.Printf("action %s: %d\n",k,result.Actions[k])}
 keys=keys[:0];for k:=range result.MTAStates {keys=append(keys,k)};sort.Strings(keys)
 for _,k:=range keys {fmt.Printf("mta state %s: %d\n",k,result.MTAStates[k])}
 if result.UnconfirmedQuarantine>0 {fmt.Fprintln(os.Stderr,"WARNING: quarantine decisions are not independent evidence of Postfix hold; correlate queue IDs with Postfix logs and queue state")}
}
