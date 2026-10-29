package core

import(
 "bytes"
 "context"
 "fmt"
 "strings"
 "testing"
)
func TestCategoryCatalogUniqueMarkers(t *testing.T){
 ids:=map[string]bool{};markers:=map[string]bool{}
 for _,c:=range CategoryCatalog(){
  if ids[c.ID]||markers[c.TestMarker]||c.Group==""{t.Fatalf("duplicate category: %+v",c)}
  ids[c.ID]=true;markers[c.TestMarker]=true
  b,e:=CategoryTestMessage(c.ID,"sgtest@example.org");if e!=nil{t.Fatal(e)}
  if !bytes.Contains(b,[]byte(c.TestMarker))||DetectCategoryTest(string(b))!=c.ID{t.Fatal(c.ID)}
 }
 if len(ids)!=16{t.Fatalf("unexpected taxonomy size: %d",len(ids))}
 if _,e:=CategoryTestMessage("missing","sgtest@example.org");e==nil{t.Fatal("unknown ID accepted")}
 if _,e:=CategoryTestMessage("phishing","a@example.org\r\nBcc:evil@example.org");e==nil{t.Fatal("header injection")}
}
func TestSGTUBEMailboxIsolationAndVerdict(t *testing.T){
 c,_:=GetSpamCategory("phishing")
 scan:=func(recipients []string,connector string) Message {
  store,e:=Open(t.TempDir());if e!=nil{t.Fatal(e)}
  raw:=fmt.Sprintf("From: sender@example.org\r\nTo: demo@example.org\r\nDate: Wed, 28 Oct 2026 10:00:00 +0000\r\nMessage-ID: <test@example.org>\r\n\r\nHarmless category test %s\r\n",c.TestMarker)
  m,e:=(&Scanner{Store:store}).Scan(context.Background(),Input{Raw:[]byte(raw),Recipients:recipients,Connector:connector});if e!=nil{t.Fatal(e)}
  return m
 }
 t.Setenv("SPAMGATE_TEST_RECIPIENTS","")
 m:=scan([]string{"sgtest@example.org"},"milter");if m.TestCase!=""{t.Fatal("test forced while disabled")}
 t.Setenv("SPAMGATE_TEST_RECIPIENTS","sgtest@example.org")
 m=scan([]string{"unrelated@example.org"},"milter");if m.TestCase!=""{t.Fatal("unrelated mailbox forced")}
 m=scan([]string{"sgtest@example.org","unrelated@example.org"},"milter");if m.TestCase!=""{t.Fatal("multi-recipient test activated")}
 m=scan([]string{"sgtest@example.org"},"milter")
 if m.TestCase!="phishing"||m.Category!="phishing"||m.Action!="reject"||len(m.Categories)!=1||m.Categories[0].Confidence!="synthetic"{t.Fatalf("bad test verdict %+v",m)}
}
func TestCategoryClassificationConservative(t *testing.T){
 if DetectCategoryTest(StandardGTUBE)!="generic_spam"{t.Fatal("canonical GTUBE unrecognized")}
 c,_:=GetSpamCategory("malware")
 if DetectCategoryTest(strings.ToLower(c.TestMarker))!=""{t.Fatal("case-folded marker accepted")}
 id,hits:=ClassifyCategories([]Finding{{Symbol:"PHISHING_VISIBLE_LINK",Score:3},{Symbol:"RISKY_ATTACHMENT",Score:5}},"tag","")
 if id!="phishing"||len(hits)!=2||hits[0].Confidence!="indicative"{t.Fatalf("unexpected evidence: %q %+v",id,hits)}
 id,hits=ClassifyCategories(nil,"accept","");if id!="uncategorized"||len(hits)!=0{t.Fatal("clean message labeled spam")}
}
