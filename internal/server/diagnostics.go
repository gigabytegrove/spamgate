package server

import (
 "context"
 "crypto/tls"
 "fmt"
 "net"
 "net/http"
 "net/textproto"
 "os"
 "strings"
 "strconv"
 "time"
)

type RelayDiagnostic struct {
 Configured bool `json:"configured"`
 Address string `json:"address,omitempty"`
 TLSMode string `json:"tls_mode,omitempty"`
 TCPReachable bool `json:"tcp_reachable"`
 SMTPReady bool `json:"smtp_ready"`
 STARTTLSAdvertised bool `json:"starttls_advertised"`
 TLSVerified bool `json:"tls_verified"`
 AUTHAdvertised bool `json:"auth_advertised"`
 AUTHMechanisms []string `json:"auth_mechanisms,omitempty"`
 AUTHMechanismsKnown bool `json:"auth_mechanisms_known"`
 SMTPUTF8Advertised bool `json:"smtputf8_advertised"`
 EightBitMIMEAdvertised bool `json:"eight_bit_mime_advertised"`
 PIPELININGAdvertised bool `json:"pipelining_advertised"`
 DSNAdvertised bool `json:"dsn_advertised"`
 CHUNKINGAdvertised bool `json:"chunking_advertised"`
 BINARYMIMEAdvertised bool `json:"binary_mime_advertised"`
 REQUIRETLSAdvertised bool `json:"requiretls_advertised"`
 EnhancedStatusCodesAdvertised bool `json:"enhanced_status_codes_advertised"`
 SIZEAdvertised bool `json:"size_advertised"`
 SIZELimitBytes *uint64 `json:"size_limit_bytes,omitempty"`
 SIZELimitKnown bool `json:"size_limit_known"`
 SIZEParameterMalformed bool `json:"size_parameter_malformed"`
 CapabilityWarnings []string `json:"capability_warnings"`
 CredentialsConfigured bool `json:"credentials_configured"`
 Detail string `json:"detail"`
 CheckedAt time.Time `json:"checked_at"`
}

// The first EHLO line is the server identity; extensions are advertised on
// subsequent lines. Never infer AUTH support from a plaintext pre-TLS banner.
func relayExtensions(message string) map[string]bool {
 out:=map[string]bool{}
 lines:=strings.Split(message,"\n")
 for _,line:=range lines[1:]{
  fields:=strings.Fields(line)
  if len(fields)>0 && validRelayExtension(fields[0]) {out[strings.ToUpper(fields[0])]=true}
 }
 return out
}

// validRelayExtension rejects malformed or control-bearing extension keywords.
// Only ASCII letters, digits and hyphens are legal in the diagnostic key.
func validRelayExtension(value string) bool {
 if len(value)==0 || len(value)>64 {return false}
 for _,r:=range value {if !(r>='A'&&r<='Z'||r>='a'&&r<='z'||r>='0'&&r<='9'||r=='-'){return false}}
 return true
}

// relayAuthMechanisms returns only mechanism tokens advertised in a successful
// EHLO response. The server's identity line is not a capability. The AUTH
// extension may be present with no mechanisms, which is not actionable.
func relayAuthMechanisms(message string) []string {
 lines:=strings.Split(message,"\n")
 seen:=map[string]bool{}
 var mechanisms []string
 for _,line:=range lines[1:] {
  fields:=strings.Fields(line)
  if len(fields)<2 || !strings.EqualFold(fields[0],"AUTH") { continue }
  for _,token:=range fields[1:] {
   valid:=len(token)<=40 && len(token)>0
   for _,r:=range token {
    if !(r>='A'&&r<='Z'||r>='a'&&r<='z'||r>='0'&&r<='9'||r=='-'||r=='_') {valid=false;break}
   }
   if !valid {continue}
   name:=strings.ToUpper(token)
   if !seen[name] {seen[name]=true;mechanisms=append(mechanisms,name)}
  }
 }
 return mechanisms
}

// relaySizeLimit distinguishes SIZE with no advertised maximum from a numeric
// maximum. Malformed, duplicated or conflicting SIZE declarations never yield
// a trusted limit. A zero limit is valid per RFC 1870 (no fixed maximum).
func relaySizeLimit(message string) (*uint64, bool) {
 lines := strings.Split(message, "\n")
 var found bool
 var limit *uint64
 for _, line := range lines[1:] {
  fields := strings.Fields(line)
  if len(fields)==0 || !strings.EqualFold(fields[0], "SIZE") {continue}
  if found {return nil,true}
  found=true
  if len(fields)==1 {continue}
  if len(fields)!=2 {return nil,true}
  for _, c := range fields[1] {if c<'0'||c>'9' {return nil,true}}
  n,err:=strconv.ParseUint(fields[1],10,64)
  if err!=nil {return nil,true}
  limit=&n
 }
 return limit,false
}

func relayEHLODetails(proto *textproto.Conn)(map[string]bool,[]string,*uint64,bool,[]string,error){
 if err:=proto.PrintfLine("EHLO spamgate.local");err!=nil{return nil,nil,nil,false,nil,err}
 _,message,err:=proto.ReadResponse(250)
 if err!=nil{return nil,nil,nil,false,err}
 limit,malformed:=relaySizeLimit(message)
 return relayExtensions(message),relayAuthMechanisms(message),limit,malformed,relayCapabilityWarnings(message),nil
}

func relayEHLO(proto *textproto.Conn)(map[string]bool,error){
 if err:=proto.PrintfLine("EHLO spamgate.local");err!=nil{return nil,err}
 _,message,err:=proto.ReadResponse(250)
 if err!=nil{return nil,err}
 return relayExtensions(message),nil
}

// probeRelay verifies a real SMTP 220 greeting and a successful EHLO. Unlike
// net/smtp.Client.Hello it must NOT fall back to HELO and call it EHLO-ready.
// STARTTLS is verified with the platform trust store and EHLO is repeated
// after the upgrade. No AUTH, MAIL FROM, RCPT TO or DATA is ever sent.
func probeRelay(ctx context.Context,addr,tlsMode string,credentialsConfigured bool)RelayDiagnostic{
 result:=RelayDiagnostic{Configured:addr!="",Address:addr,TLSMode:tlsMode,CredentialsConfigured:credentialsConfigured,CheckedAt:time.Now().UTC(),Detail:"No relay configured"}
 if addr==""{return result}
 host,_,err:=net.SplitHostPort(addr)
 if err!=nil||host==""{result.Detail="Invalid relay host:port";return result}
 if tlsMode==""{tlsMode="required";result.TLSMode=tlsMode}
 if tlsMode!="required"&&tlsMode!="implicit"&&tlsMode!="none"{result.Detail="Invalid TLS mode: configure required, implicit or none";return result}
 ctx,cancel:=context.WithTimeout(ctx,5*time.Second);defer cancel()
 dialer:=net.Dialer{Timeout:4*time.Second}
 conn,err:=dialer.DialContext(ctx,"tcp",addr)
 if err!=nil{result.Detail="TCP connection failed: "+err.Error();return result}
 defer conn.Close()
 result.TCPReachable=true
 deadline:=time.Now().Add(5*time.Second)
 if d,ok:=ctx.Deadline();ok&&d.Before(deadline){deadline=d}
 _=conn.SetDeadline(deadline)
 if tlsMode=="implicit"{
  secure:=tls.Client(conn,&tls.Config{ServerName:host,MinVersion:tls.VersionTLS12})
  if err:=secure.HandshakeContext(ctx);err!=nil{result.Detail="Implicit TLS handshake/certificate verification failed: "+err.Error();return result}
  result.TLSVerified=true
  conn=secure
 }
 proto:=textproto.NewConn(conn)
 if _,_,err:=proto.ReadResponse(220);err!=nil{result.Detail="SMTP banner rejected: "+err.Error();return result}
 extensions,mechanisms,sizeLimit,sizeMalformed,warnings,err:=relayEHLODetails(proto)
 if err!=nil{result.Detail="SMTP EHLO failed (HELO fallback is not accepted): "+err.Error();return result}
 result.SMTPReady=true
 result.STARTTLSAdvertised=extensions["STARTTLS"]
 if tlsMode=="required"{
  if !result.STARTTLSAdvertised{
   result.SMTPReady=false
   result.Detail="SMTP server does not advertise required STARTTLS"
   return result
  }
  if err:=proto.PrintfLine("STARTTLS");err!=nil{result.SMTPReady=false;result.Detail="STARTTLS command failed: "+err.Error();return result}
  if _,_,err:=proto.ReadResponse(220);err!=nil{result.SMTPReady=false;result.Detail="STARTTLS rejected: "+err.Error();return result}
  secure:=tls.Client(conn,&tls.Config{ServerName:host,MinVersion:tls.VersionTLS12})
  if err:=secure.HandshakeContext(ctx);err!=nil{result.SMTPReady=false;result.Detail="STARTTLS handshake/certificate verification failed: "+err.Error();return result}
  result.TLSVerified=true
  conn=secure
  proto=textproto.NewConn(conn)
  extensions,mechanisms,sizeLimit,sizeMalformed,warnings,err=relayEHLODetails(proto)
  if err!=nil{result.SMTPReady=false;result.Detail="Post-STARTTLS EHLO failed: "+err.Error();return result}
 }
 result.SMTPUTF8Advertised=extensions["SMTPUTF8"]
 result.EightBitMIMEAdvertised=extensions["8BITMIME"]
 result.PIPELININGAdvertised=extensions["PIPELINING"]
 result.DSNAdvertised=extensions["DSN"]
 result.CHUNKINGAdvertised=extensions["CHUNKING"]
 result.BINARYMIMEAdvertised=extensions["BINARYMIME"]
 result.REQUIRETLSAdvertised=extensions["REQUIRETLS"]
 result.EnhancedStatusCodesAdvertised=extensions["ENHANCEDSTATUSCODES"]
 result.SIZEAdvertised=extensions["SIZE"]
 result.SIZELimitBytes=sizeLimit
 result.SIZELimitKnown=sizeLimit!=nil
 result.SIZEParameterMalformed=sizeMalformed
 result.CapabilityWarnings=warnings
 result.AUTHAdvertised=extensions["AUTH"]
 result.AUTHMechanisms=mechanisms
 result.AUTHMechanismsKnown=len(mechanisms)>0
 switch {
 case credentialsConfigured&&tlsMode=="none":
  result.Detail="SMTP EHLO succeeded but credentials are configured with plaintext TLS mode none; no authentication was attempted"
 case credentialsConfigured&&!result.AUTHMechanismsKnown:
  result.Detail="SMTP EHLO succeeded but the server does not advertise usable AUTH mechanisms after TLS negotiation; no credentials were sent"
 default:
  result.Detail=fmt.Sprintf("SMTP banner and EHLO succeeded; TLS mode %s; encrypted channel verified=%t; AUTH advertised=%t. No authentication or delivery was attempted",tlsMode,result.TLSVerified,result.AUTHAdvertised)
 }
 _=proto.PrintfLine("QUIT")
 return result
}

func (s *Server) integrationDiagnostics(w http.ResponseWriter,r *http.Request){
 if _,ok:=s.authorized(w,r,true,false);!ok{return}
 addr:=strings.TrimSpace(os.Getenv("SPAMGATE_RELAY_ADDRESS"))
 result:=probeRelay(r.Context(),addr,os.Getenv("SPAMGATE_RELAY_TLS"),os.Getenv("SPAMGATE_RELAY_USERNAME")!="")
 jsonReply(w,http.StatusOK,map[string]any{"relay":result,"services":s.Runtime.Services,"note":"SMTP checks do not authenticate, send a message, or verify mail-server disposition. Listener settings are configuration, not proof of MTA interoperability."})
}
