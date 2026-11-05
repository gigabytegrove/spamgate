package spoolaudit

import (
 "fmt"
 "strings"
 "testing"
)

const durableIdentityFixture = `{"id":"0123456789abcdef0123456789abcdef","sender":"","recipients":["a@example.test"],"raw":"YQ=="}`

func TestValidateDurableIdentity(t *testing.T) {
 cases:=[]struct{name,body string;reject bool}{
  {"empty bounce sender valid",durableIdentityFixture,false},
  {"normal sender",strings.Replace(durableIdentityFixture,`"sender":""`,`"sender":"mail@example.test"`,1),false},
  {"missing sender",strings.Replace(durableIdentityFixture,`"sender":"",`,"",1),true},
  {"null sender",strings.Replace(durableIdentityFixture,`"sender":""`,`"sender":null`,1),true},
  {"numeric sender",strings.Replace(durableIdentityFixture,`"sender":""`,`"sender":7`,1),true},
  {"missing id",strings.Replace(durableIdentityFixture,`"id":"0123456789abcdef0123456789abcdef",`,"",1),true},
  {"null id",strings.Replace(durableIdentityFixture,`"id":"0123456789abcdef0123456789abcdef"`,`"id":null`,1),true},
  {"uppercase id",strings.Replace(durableIdentityFixture,"0123456789abcdef0123456789abcdef","0123456789ABCDEF0123456789abcdef",1),true},
  {"missing raw",strings.Replace(durableIdentityFixture,`,"raw":"YQ=="`,"",1),true},
  {"null raw",strings.Replace(durableIdentityFixture,`"raw":"YQ=="`,`"raw":null`,1),true},
  {"numeric raw",strings.Replace(durableIdentityFixture,`"raw":"YQ=="`,`"raw":123`,1),true},
  {"null recipient",strings.Replace(durableIdentityFixture,`"a@example.test"`,"null",1),true},
  {"missing recipients",strings.Replace(durableIdentityFixture,`"recipients":["a@example.test"],`,"",1),true},
  {"nonobject",`[]`,true},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   err:=validateDurableIdentity([]byte(tc.body))
   if (err!=nil)!=tc.reject {t.Fatal(fmt.Sprintf("reject=%t err=%v",tc.reject,err))}
  })
 }
}
