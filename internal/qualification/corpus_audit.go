package qualification

import (
 "fmt"
 "sort"
)

// CorpusAudit exposes dataset composition before a classifier acceptance decision.
// It does not establish that labels are independent or representative.
type CorpusAudit struct {
 Total int `json:"total"`
 Spam int `json:"spam"`
 Clean int `json:"clean"`
 Tenants []TenantCorpusAudit `json:"tenants"`
}
type TenantCorpusAudit struct {
 Tenant string `json:"tenant"`
 Total int `json:"total"`
 Spam int `json:"spam"`
 Clean int `json:"clean"`
 SpamPrevalence float64 `json:"spam_prevalence"`
}
func AuditCorpus(samples []Sample) (CorpusAudit,error) {
 if err:=Validate(samples,0);err!=nil{return CorpusAudit{},err}
 counts:=map[string]TenantCorpusAudit{}
 result:=CorpusAudit{Total:len(samples)}
 for _,s:=range samples {
  t:=counts[s.Tenant];t.Tenant=s.Tenant;t.Total++
  if s.Spam {t.Spam++;result.Spam++} else {t.Clean++;result.Clean++}
  counts[s.Tenant]=t
 }
 keys:=make([]string,0,len(counts))
 for k:=range counts {keys=append(keys,k)}
 sort.Strings(keys)
 for _,k:=range keys {
  t:=counts[k]
  t.SpamPrevalence=float64(t.Spam)/float64(t.Total)
  result.Tenants=append(result.Tenants,t)
 }
 if result.Spam+result.Clean!=result.Total {return CorpusAudit{},fmt.Errorf("inconsistent corpus totals")}
 return result,nil
}
