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
  if len(fields)>0{out[strings.ToUpper(fields[0])]=true}
 }
 return out
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
 extensions,err:=relayEHLO(proto)
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
  extensions,err=relayEHLO(proto)
  if err!=nil{result.SMTPReady=false;result.Detail="Post-STARTTLS EHLO failed: "+err.Error();return result}
 }
 result.AUTHAdvertised=extensions["AUTH"]
 switch {
 case credentialsConfigured&&tlsMode=="none":
  result.Detail="SMTP EHLO succeeded but credentials are configured with plaintext TLS mode none; no authentication was attempted"
 case credentialsConfigured&&!result.AUTHAdvertised:
  result.Detail="SMTP EHLO succeeded but the server does not advertise AUTH after TLS negotiation; no credentials were sent"
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
