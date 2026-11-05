package spoolaudit

import (
 "strings"
 "testing"
)

func TestValidateDurableState(t *testing.T) {
 base:=`{"state":"queued","size":1,"attempts":0}`
 cases:=[]struct{name,body string;valid bool}{
  {"valid queued",base,true},
  {"valid delivering",strings.Replace(base,"queued","delivering",1),true},
  {"valid dead",strings.Replace(base,"queued","dead",1),true},
  {"valid delivered",strings.Replace(base,"queued","delivered",1),true},
  {"valid discard pending",strings.Replace(base,"queued","discard_pending",1),true},
  {"missing state",`{"size":1,"attempts":0}`,false},
  {"null state",strings.Replace(base,`"queued"`,"null",1),false},
  {"numeric state",strings.Replace(base,`"queued"`,"42",1),false},
  {"unknown state",strings.Replace(base,"queued","unknown",1),false},
  {"missing size",`{"state":"queued","attempts":0}`,false},
  {"null size",strings.Replace(base,`"size":1`,`"size":null`,1),false},
  {"float size",strings.Replace(base,`"size":1`,`"size":1.0`,1),false},
  {"string size",strings.Replace(base,`"size":1`,`"size":"1"`,1),false},
  {"zero size",strings.Replace(base,`"size":1`,`"size":0`,1),false},
  {"oversized",strings.Replace(base,`"size":1`,`"size":10485761`,1),false},
  {"missing attempts",`{"state":"queued","size":1}`,false},
  {"null attempts",strings.Replace(base,`"attempts":0`,`"attempts":null`,1),false},
  {"fraction attempts",strings.Replace(base,`"attempts":0`,`"attempts":0.5`,1),false},
  {"negative attempts",strings.Replace(base,`"attempts":0`,`"attempts":-1`,1),false},
  {"boolean attempts",strings.Replace(base,`"attempts":0`,`"attempts":true`,1),false},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   err:=validateDurableState([]byte(tc.body))
   if (err==nil)!=tc.valid {t.Fatalf("valid=%t err=%v",tc.valid,err)}
  })
 }
}
