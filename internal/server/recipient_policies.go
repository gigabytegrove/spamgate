package server

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "net/http"
 "sort"
 "strings"
 "github.com/gigabytegrove/spamgate/internal/core"
)

// Order-independent revision for a complete recipient-policy set. This is not
// an authentication token. A missing legacy array is equivalent to [].
func recipientPoliciesRevision(p []core.RecipientPolicy) string {
 ordered:=append([]core.RecipientPolicy{},p...)
 sort.Slice(ordered,func(i,j int)bool{return strings.ToLower(ordered[i].Mailbox)<strings.ToLower(ordered[j].Mailbox)})
 b,_:=json.Marshal(ordered)
 sum:=sha256.Sum256(b)
 return hex.EncodeToString(sum[:])
}
var errRecipientPoliciesChanged=errors.New("recipient policies changed since they were loaded; refresh before saving")

// Full-set replacement requires a revision. The compare happens inside the
// Store configuration lock to prevent concurrent administrator lost updates.
func (s *Server) updateRecipientPolicies(w http.ResponseWriter,r *http.Request){
 if _,ok:=s.authorized(w,r,true,true);!ok{return}
 var in struct{
  Policies []core.RecipientPolicy `json:"policies"`
  ExpectedRevision string `json:"expected_revision"`
 }
 if err:=decode(r,&in);err!=nil{fail(w,400,"Expected policies array and expected_revision");return}
 if len(in.ExpectedRevision)!=64{fail(w,400,"Policy revision required; refresh policies before saving");return}
 err:=s.Store.UpdateConfig(func(c *core.Config)error{
  if recipientPoliciesRevision(c.RecipientPolicies)!=in.ExpectedRevision{return errRecipientPoliciesChanged}
  c.RecipientPolicies=in.Policies
  return nil
 })
 if errors.Is(err,errRecipientPoliciesChanged){fail(w,http.StatusConflict,err.Error());return}
 if err!=nil{fail(w,400,err.Error());return}
 policies:=s.Store.Config().RecipientPolicies
 jsonReply(w,200,map[string]any{"policies":policies,"revision":recipientPoliciesRevision(policies)})
}
