package main

import (
 "strings"
 "testing"
)

func TestExplicitExpectedTenantInventoryFailsClosed(t *testing.T) {
 corpus:=`[{"id":"clean-a","tenant":"alpha","spam":false,"score":0},{"id":"spam-a","tenant":"alpha","spam":true,"score":10}]`
 cases:=[]struct{name string;args []string;want string}{
  {"empty",[]string{"-expected-tenants="},"expected-tenants must not be empty"},
  {"spaces",[]string{"-expected-tenants=   "},"expected-tenants must not be empty"},
  {"trailing comma",[]string{"-expected-tenants=alpha,"},"expected-tenants contains an empty tenant"},
  {"leading comma",[]string{"-expected-tenants=,alpha"},"expected-tenants contains an empty tenant"},
  {"surrounding whitespace",[]string{"-expected-tenants= alpha"},"surrounding whitespace"},
  {"missing tenant",[]string{"-expected-tenants=beta"},"tenant coverage mismatch"},
  {"valid inventory",[]string{"-expected-tenants=alpha"},""},
  {"omitted inventory",nil,""},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   var out strings.Builder
   err:=run(tc.args,strings.NewReader(corpus),&out)
   if tc.want=="" {if err!=nil{t.Fatalf("unexpected error: %v",err)};if out.Len()==0{t.Fatal("missing report")};return}
   if err==nil||!strings.Contains(err.Error(),tc.want){t.Fatalf("wanted %q, got %v",tc.want,err)}
   if out.Len()!=0{t.Fatalf("report emitted for invalid inventory: %q",out.String())}
  })
 }
}
