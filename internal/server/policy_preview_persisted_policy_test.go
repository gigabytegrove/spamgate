package server

import (
 "testing"

 "github.com/gigabytegrove/spamgate/internal/core"
)

// Stored tenant policies must satisfy the same safety contract as proposed
// policies. A broken persisted configuration must not yield credible replay.
func TestValidateEffectivePreviewPolicies(t *testing.T) {
 valid := core.RecipientPolicy{Mailbox:"alice@example.org",TagThreshold:1,QuarantineThreshold:2,RejectThreshold:3}
 cases := []struct{name string; policies []core.RecipientPolicy; valid bool}{
  {"empty",nil,true},
  {"single",[]core.RecipientPolicy{valid},true},
  {"duplicate_case_insensitive",[]core.RecipientPolicy{valid,{Mailbox:"ALICE@example.org",TagThreshold:1,QuarantineThreshold:2,RejectThreshold:3}},false},
  {"missing_mailbox",[]core.RecipientPolicy{{Mailbox:"",TagThreshold:1,QuarantineThreshold:2,RejectThreshold:3}},false},
  {"non_ascending",[]core.RecipientPolicy{{Mailbox:"alice@example.org",TagThreshold:2,QuarantineThreshold:2,RejectThreshold:3}},false},
  {"out_of_range",[]core.RecipientPolicy{{Mailbox:"alice@example.org",TagThreshold:1,QuarantineThreshold:2,RejectThreshold:1001}},false},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   err:=validateEffectivePreviewPolicies(tc.policies)
   if (err==nil)!=tc.valid {t.Fatalf("valid=%v err=%v",tc.valid,err)}
  })
 }
 many:=make([]core.RecipientPolicy,201)
 for i:=range many {many[i]=valid}
 if err:=validateEffectivePreviewPolicies(many);err==nil {t.Fatal("oversized persisted tenant policy set accepted")}
}
