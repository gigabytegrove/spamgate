package server

import (
 "context"
 "net/http"
 "time"
)

// Authenticated disk-vs-memory audit. The endpoint never returns mail content
// or messages and never modifies the on-disk scan journal.
func (s *Server) historyIntegrity(w http.ResponseWriter, r *http.Request) {
 if _,ok:=s.authorized(w,r,true,false);!ok{return}
 ctx,cancel:=context.WithTimeout(r.Context(),15*time.Second)
 defer cancel()
 result,err:=s.Store.AuditHistory(ctx)
 if err!=nil{
  s.log.Error("history integrity audit failed","error",err)
  fail(w,http.StatusServiceUnavailable,"Unable to complete history integrity audit")
  return
 }
 jsonReply(w,http.StatusOK,result)
}
