package core

import (
 "context"
 "fmt"
 "testing"
)

// These are deterministic benign regression fixtures, NOT a representative
// independent real-world corpus or evidence of production false-positive rates.
// Preserve them as guardrails when adding new classification heuristics.
func TestBetaBenignMessagesAreNotHeldOrRejected(t *testing.T) {
 scenarios:=[]struct{name,subject,body string}{
  {"family","Family dinner plans","Dinner is at seven. Let us know if you're coming."},
  {"billing","Invoice paid receipt","Your invoice has been paid. Thank you for the payment."},
  {"vendor-payment","Wire transfer documentation","Please attach the wire transfer receipt to the accounting record."},
  {"password-reset","Account password reset information","You requested a password reset yesterday. If you did not request it, contact support."},
  {"gift-cards","Gift card accounting","We reconciled the gift card inventory for the employee appreciation program."},
  {"security-update","Security alert","There was an unusual sign-in; please contact the security desk."},
  {"account-notice","Account suspended information","The archived account suspended last quarter is listed in the audit report."},
  {"tax","Tax filing notice","Your tax receipt is available for download in the normal portal."},
  {"calendar","Appointment reminder","Your appointment is on Wednesday at 11 AM."},
  {"meeting","Project kickoff","The engineering team will review the project milestones."},
  {"newsletter","Subscribed newsletter","Here is the newsletter you signed up for, with links to previous issues."},
  {"crypto-report","Crypto wallet accounting","The crypto wallet transaction report was reviewed by the finance team."},
  {"device","Network maintenance","The office switch will reboot during tonight's maintenance window."},
  {"support","Help desk ticket closed","Your support ticket was completed; reply to reopen it."},
  {"travel","Travel itinerary","Your flight itinerary and hotel reservation are attached."},
  {"candidate","Interview invitation","Please confirm your interview appointment for next Tuesday."},
  {"postfix","Mail delivery status","The local Postfix queue has no outstanding deferred messages."},
  {"auth","Authentication report","SPF, DKIM and DMARC passed the expected checks in the report."},
  {"order","Order confirmation","The product shipment is scheduled for next week."},
  {"bank-statement","Monthly statement","Your monthly statement is now available at the bank's regular website."},
 }
 st,err:=Open(t.TempDir());if err!=nil{t.Fatal(err)}
 scanner:=&Scanner{Store:st,Resolver:stubDNS{}}
 for i,tc:=range scenarios {
  t.Run(tc.name,func(t *testing.T){
   raw:=fmt.Sprintf("From: accounts@example.org\r\nTo: employee@example.net\r\nDate: Thu, 29 Oct 2026 10:00:00 +0000\r\nMessage-ID: <benign-%d@example.org>\r\nSubject: %s\r\n\r\n%s\r\n",i,tc.subject,tc.body)
   m,e:=scanner.Scan(context.Background(),Input{Raw:[]byte(raw),Sender:"accounts@example.org",Recipients:[]string{"employee@example.net"},Connector:"milter"})
   if e!=nil{t.Fatal(e)}
   if m.Action=="reject"||m.Action=="quarantine" {
    t.Fatalf("benign beta fixture would block ordinary mail: score=%.2f action=%s findings=%+v",m.Score,m.Action,m.Findings)
   }
  })
 }
}
