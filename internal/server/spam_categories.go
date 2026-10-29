package server

// Admin-only category catalog, bounded history lists, harmless .eml generation,
// and in-memory synthetic scan. No test endpoint sends mail or saves a message.
import (
 "fmt"
 "net/http"
 "os"
 "strconv"
 "strings"
 "github.com/gigabytegrove/spamgate/internal/core"
)
func (s *Server) spamCategoryCatalog(w http.ResponseWriter,r *http.Request){
 if _,ok:=s.authorized(w,r,true,false);!ok{return}
 recent:=s.Store.List(1000,"")
 counts:=map[string]int{}
 tests:=map[string]int{}
 for _,m:=range recent{
  if m.Category==""{counts["unclassified_legacy"]++}else{counts[m.Category]++}
  if m.TestCase!=""{tests[m.Category]++}
 }
 enabled:=false
 for _,entry:=range strings.Split(os.Getenv("SPAMGATE_TEST_RECIPIENTS"),","){if strings.Contains(strings.TrimSpace(entry),"@"){enabled=true}}
 jsonReply(w,200,map[string]any{"categories":core.CategoryCatalog(),"recent_counts":counts,"synthetic_test_counts":tests,"sampled_history":len(recent),"sample_limit":1000,"live_test_enabled":enabled,"note":"Counts cover at most 1000 recent retained scans, not all-time mail. Synthetic category matching does not prove real-world detection."})
}
func (s *Server) spamCategoryMessages(w http.ResponseWriter,r *http.Request){
 if _,ok:=s.authorized(w,r,true,false);!ok{return}
 id:=r.PathValue("id")
 if _,ok:=core.GetSpamCategory(id);!ok{fail(w,404,"Unknown spam category");return}
 limit:=50
 if raw:=r.URL.Query().Get("limit");raw!=""{
  n,err:=strconv.Atoi(raw);if err!=nil||n<1||n>200{fail(w,400,"limit must be between 1 and 200");return};limit=n
 }
 recent:=s.Store.List(1000,"")
 records:=make([]core.Message,0,limit);total:=0
 for _,m:=range recent{if m.Category==id{total++;if len(records)<limit{records=append(records,m)}}}
 jsonReply(w,200,map[string]any{"category":id,"messages":records,"matched_in_recent":total,"sampled_history":len(recent),"sample_limit":1000,"limit":limit})
}
func (s *Server) spamCategorySample(w http.ResponseWriter,r *http.Request){
 if _,ok:=s.authorized(w,r,true,false);!ok{return}
 id:=r.PathValue("id")
 raw,err:=core.CategoryTestMessage(id,r.URL.Query().Get("recipient"))
 if err!=nil{fail(w,400,"Invalid category or recipient address");return}
 w.Header().Set("Content-Type","message/rfc822; charset=utf-8")
 w.Header().Set("Content-Disposition",fmt.Sprintf("attachment; filename=spamgate-test-%s.eml",id))
 w.Header().Set("Cache-Control","no-store")
 _,_=w.Write(raw)
}
func (s *Server) spamCategorySimulate(w http.ResponseWriter,r *http.Request){
 if _,ok:=s.authorized(w,r,true,true);!ok{return}
 id:=r.PathValue("id")
 raw,err:=core.CategoryTestMessage(id,"sgtube@example.invalid")
 if err!=nil{fail(w,404,"Unknown spam category");return}
 msg,err:=s.Scanner.Scan(r.Context(),core.Input{Raw:raw,Sender:"sgtube@example.invalid",Recipients:[]string{"sgtube@example.invalid"},Connector:"test-lab"})
 if err!=nil{fail(w,503,"Synthetic category scan failed: "+err.Error());return}
 jsonReply(w,200,map[string]any{"simulation":true,"persisted":false,"delivered":false,"mta_verified":false,"category":id,"message":msg,"warning":"Synthetic signature validates the test-marker/scan path only. Use independently labeled spam samples for detection accuracy; send from outside to an allowlisted test mailbox for a real Postfix disposition test."})
}
