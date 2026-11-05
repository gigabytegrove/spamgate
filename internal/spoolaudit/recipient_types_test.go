package spoolaudit

import "testing"

func TestValidateDurableRecipients(t *testing.T) {
 cases:=[]struct{name,body string; reject bool}{
  {"single",`{"recipients":["user@example.test"]}`,false},
  {"multiple",`{"recipients":["a@example.test","b@example.test"]}`,false},
  {"null element",`{"recipients":[null]}`,true},
  {"mixed null",`{"recipients":["a@example.test",null]}`,true},
  {"empty element",`{"recipients":[""]}`,true},
  {"number",`{"recipients":[42]}`,true},
  {"boolean",`{"recipients":[true]}`,true},
  {"object",`{"recipients":[{}]}`,true},
  {"nested array",`{"recipients":[[]]}`,true},
  {"null array",`{"recipients":null}`,true},
  {"missing",`{"sender":""}`,true},
  {"empty array",`{"recipients":[]}`,true},
  {"wrong type",`{"recipients":"user@example.test"}`,true},
  {"invalid JSON",`{"recipients":[}`,true},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   err:=validateDurableRecipients([]byte(tc.body))
   if (err!=nil)!=tc.reject {t.Fatalf("reject=%t, got %v",tc.reject,err)}
  })
 }
}
