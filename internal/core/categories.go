package core

// Built-in, stable spam category taxonomy. Synthetic tokens do not prove real detection.
// Live test tokens activate only for an explicitly allowlisted, single SMTP recipient.
import (
 "fmt"
 "net/mail"
 "os"
 "strings"
)

type SpamCategory struct {
 ID string `json:"id"`
 Name string `json:"name"`
 Group string `json:"group"`
 Description string `json:"description"`
 TestMarker string `json:"test_marker"`
 TestSubject string `json:"test_subject"`
}
type CategoryHit struct {
 ID string `json:"id"`
 Name string `json:"name"`
 Confidence string `json:"confidence"`
 Evidence []string `json:"evidence,omitempty"`
}

var spamCategories = []SpamCategory{
 {ID:"generic_spam",Name:"Generic spam",Group:"General",Description:"High-scoring mail without narrower supported evidence"},
 {ID:"bulk_marketing",Name:"Unsolicited bulk marketing",Group:"Bulk",Description:"Unrequested promotional mail"},
 {ID:"newsletter_spam",Name:"Unwanted newsletters",Group:"Bulk",Description:"Unsolicited subscriptions and bulk lists"},
 {ID:"phishing",Name:"Phishing",Group:"Fraud",Description:"Deceptive links and account verification"},
 {ID:"credential_theft",Name:"Credential theft",Group:"Fraud",Description:"Login and password harvesting"},
 {ID:"identity_spoofing",Name:"Identity spoofing",Group:"Authentication",Description:"Sender/domain authentication abuse indicators"},
 {ID:"payment_fraud",Name:"Invoice and payment fraud",Group:"Fraud",Description:"Payment redirection, gift card and invoice scams"},
 {ID:"crypto_fraud",Name:"Cryptocurrency scams",Group:"Fraud",Description:"Crypto investment and wallet lures"},
 {ID:"malware",Name:"Malware",Group:"Threats",Description:"Malware detected by qualified antivirus"},
 {ID:"ransomware",Name:"Ransomware lures",Group:"Threats",Description:"Ransomware-themed messages and payload lures"},
 {ID:"suspicious_attachments",Name:"Suspicious attachments",Group:"Threats",Description:"Risky attachment types and filenames"},
 {ID:"extortion",Name:"Extortion and blackmail",Group:"Fraud",Description:"Threats and coercive payment requests"},
 {ID:"adult_spam",Name:"Adult content spam",Group:"Content",Description:"Unsolicited adult advertisements"},
 {ID:"gambling_spam",Name:"Gambling spam",Group:"Content",Description:"Unsolicited gambling and betting offers"},
 {ID:"counterfeit",Name:"Counterfeit goods",Group:"Commerce",Description:"Counterfeit and misrepresented goods"},
 {ID:"reputation_abuse",Name:"Reputation-based spam",Group:"Signals",Description:"Spam reputation and learning indicators"},
}
const StandardGTUBE = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"
const categoryMarkerSuffix = "-SAFE-CATEGORY-TEST-ONLY-7F60C1D2"

func CategoryCatalog() []SpamCategory {
 items:=make([]SpamCategory,0,len(spamCategories))
 for _,c:=range spamCategories {
  c.TestMarker="SGTUBE-V1-"+strings.ToUpper(strings.ReplaceAll(c.ID,"_","-"))+categoryMarkerSuffix
  c.TestSubject="[SpamGate TEST] "+c.Name
  items=append(items,c)
 }
 return items
}
func GetSpamCategory(id string)(SpamCategory,bool){
 for _,c:=range CategoryCatalog(){if c.ID==id{return c,true}}
 return SpamCategory{},false
}
func CategoryTestMessage(id,recipient string)([]byte,error){
 c,ok:=GetSpamCategory(id)
 if !ok{return nil,fmt.Errorf("unknown category %q",id)}
 if strings.TrimSpace(recipient)!=recipient || strings.ContainsAny(recipient,"\r\n<> "){return nil,fmt.Errorf("valid test recipient required")}
 addr,err:=mail.ParseAddress(recipient)
 if err!=nil||addr.Address!=recipient||strings.Count(recipient,"@")!=1{return nil,fmt.Errorf("valid test recipient required")}
 raw:=fmt.Sprintf("From: SpamGate Test <sgtube@example.invalid>\r\nTo: <%s>\r\nSubject: %s\r\nDate: Thu, 29 Oct 2026 12:00:00 +0000\r\nMessage-ID: <sgtube-%s@example.invalid>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nThis is a harmless synthetic SpamGate category test, not real malware or spam.\r\nCategory: %s\r\n%s\r\n",recipient,c.TestSubject,c.ID,c.ID,c.TestMarker)
 return []byte(raw),nil
}
func TestRecipientAllowed(recipients []string) bool {
 if len(recipients)!=1{return false}
 want:=strings.TrimSpace(recipients[0]);if want==""{return false}
 for _,part:=range strings.Split(os.Getenv("SPAMGATE_TEST_RECIPIENTS"),","){
  allowed:=strings.TrimSpace(part)
  if strings.Contains(allowed,"@") && strings.EqualFold(want,allowed) {return true}
 }
 return false
}
func DetectCategoryTest(text string) string {
 if strings.Contains(text,StandardGTUBE){return "generic_spam"}
 for _,c:=range CategoryCatalog(){if strings.Contains(text,c.TestMarker){return c.ID}}
 return ""
}
func ClassifyCategories(findings []Finding,action,testID string)(string,[]CategoryHit){
 if testID!=""{
  if c,ok:=GetSpamCategory(testID);ok{return testID,[]CategoryHit{{ID:c.ID,Name:c.Name,Confidence:"synthetic",Evidence:[]string{"SGTUBE_"+strings.ToUpper(c.ID)}}}}
 }
 evidence:=map[string][]string{}
 add:=func(id,sym string){for _,v:=range evidence[id]{if v==sym{return}};evidence[id]=append(evidence[id],sym)}
 for _,f:=range findings{
  if f.Score<=0{continue}
  switch f.Symbol {
  case "PHISHING_VISIBLE_LINK","CONTENT_VERIFY_YOUR_ACCOUNT","CONTENT_CLICK_HERE_TO_AVOID":add("phishing",f.Symbol)
  case "CONTENT_CONFIRM_YOUR_PASSWORD","CONTENT_ACCOUNT_SUSPENDED":add("credential_theft",f.Symbol)
  case "R_SPF_FAIL","DMARC_FAIL","R_DKIM_REJECT":add("identity_spoofing",f.Symbol)
  case "CONTENT_WIRE_TRANSFER","CONTENT_GIFT_CARD":add("payment_fraud",f.Symbol)
  case "CONTENT_CRYPTO_WALLET":add("crypto_fraud",f.Symbol)
  case "CLAMAV_MALWARE":add("malware",f.Symbol)
  case "RISKY_ATTACHMENT","DOUBLE_EXTENSION":add("suspicious_attachments",f.Symbol)
  case "BAYES_SPAM","FUZZY_SPAM","REMOTE_FUZZY_SPAM","NEURAL_SPAM","REVIEWED_DOMAIN_REPUTATION":add("reputation_abuse",f.Symbol)
  }
  if strings.HasPrefix(f.Symbol,"DNSBL_"){add("reputation_abuse",f.Symbol)}
 }
 hits:=[]CategoryHit{}
 for _,id:=range []string{"malware","credential_theft","phishing","payment_fraud","crypto_fraud","identity_spoofing","suspicious_attachments","reputation_abuse"}{
  if syms:=evidence[id];len(syms)>0{c,_:=GetSpamCategory(id);hits=append(hits,CategoryHit{ID:id,Name:c.Name,Confidence:"indicative",Evidence:syms})}
 }
 if len(hits)==0 && (action=="tag"||action=="quarantine"||action=="reject"){
  c,_:=GetSpamCategory("generic_spam");hits=append(hits,CategoryHit{ID:c.ID,Name:c.Name,Confidence:"indicative",Evidence:[]string{"score/action"}})
 }
 if len(hits)==0{return "uncategorized",nil}
 return hits[0].ID,hits
}
