package smtpprobe

import (
 "errors"
 "net"
 "strings"
)

// validateEHLOName accepts a DNS hostname or an SMTP address literal.
// Reject ambiguous labels and protocol metacharacters before any network I/O.
func validateEHLOName(name string) error {
 if len(name)==0 || len(name)>253 || invalidHostname(name) { return errors.New("invalid EHLO hostname") }
 if strings.HasPrefix(name,"[") && strings.HasSuffix(name,"]") {
  inner:=name[1:len(name)-1]
  if strings.HasPrefix(strings.ToUpper(inner),"IPV6:") {
   if ip:=net.ParseIP(inner[5:]); ip!=nil && strings.Contains(inner[5:],":") { return nil }
  } else if ip:=net.ParseIP(inner); ip!=nil && ip.To4()!=nil { return nil }
  return errors.New("invalid EHLO address literal")
 }
 if strings.HasSuffix(name,".") { name=name[:len(name)-1] }
 if len(name)==0 { return errors.New("invalid EHLO hostname") }
 for _,label:=range strings.Split(name,".") {
  if len(label)==0 || len(label)>63 || label[0]=='-' || label[len(label)-1]=='-' { return errors.New("invalid EHLO DNS label") }
  for i:=0;i<len(label);i++ {
   c:=label[i]
   if !((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-') { return errors.New("invalid EHLO DNS label") }
  }
 }
 return nil
}

// validateTLSName prevents accidental certificate validation against malformed
// names. net/http's URL parser is deliberately not used for an SMTP hostname.
func validateTLSName(name string) error {
 if len(name)==0 || len(name)>253 || invalidHostname(name) { return errors.New("invalid TLS server name") }
 if strings.ContainsAny(name,"/@\\[]") { return errors.New("invalid TLS server name") }
 if ip:=net.ParseIP(name); ip!=nil { return nil }
 return validateEHLOName(name)
}
