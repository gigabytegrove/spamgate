package smtpprobe

import (
 "bufio"
 "context"
 "crypto/tls"
 "errors"
 "fmt"
 "net"
 "strconv"
 "strings"
 "time"
)
const maxLine=2048
const maxLines=64
type Result struct {
 BannerCode int `json:"banner_code"`
 EHLOCode int `json:"ehlo_code"`
 StartTLSAdvertised bool `json:"starttls_advertised"`
 StartTLSVerified bool `json:"starttls_verified"`
 TLSVersion string `json:"tls_version,omitempty"`
 AuthMechanisms []string `json:"auth_mechanisms"`
 PostTLSEHLOCode int `json:"post_tls_ehlo_code,omitempty"`
 PostTLSAuthMechanisms []string `json:"post_tls_auth_mechanisms"`
}
type Options struct { Address,ServerName,HelloName string; Timeout time.Duration; RequireTLS bool }
func readReply(r *bufio.Reader)(int,[]string,error){
 var code int;var lines []string
 for i:=0;i<maxLines;i++{
  // ReadSlice bounds memory even when a hostile peer never sends a newline.
  // Discarding an oversized line is unsafe: fail the entire probe instead.
  line,err:=r.ReadSlice('\n')
  if errors.Is(err,bufio.ErrBufferFull){return 0,nil,errors.New("SMTP reply line exceeds limit")}
  if err!=nil{return 0,nil,fmt.Errorf("SMTP reply interrupted: %w",err)}
  if len(line)>maxLine{return 0,nil,errors.New("SMTP reply line exceeds limit")}
  if len(line)<2 || line[len(line)-2]!='\r' {return 0,nil,errors.New("SMTP reply must end with CRLF")}
  line=line[:len(line)-2]
  for _, b := range line { if b < 32 || b == 127 { return 0,nil,errors.New("SMTP reply contains control byte") } }
  if len(line)<4||(line[3]!='-'&&line[3]!=' '){return 0,nil,errors.New("malformed SMTP reply framing")}
  if line[0]<'0'||line[0]>'9'||line[1]<'0'||line[1]>'9'||line[2]<'0'||line[2]>'9'{return 0,nil,errors.New("invalid SMTP reply code")}
  n,err:=strconv.Atoi(string(line[:3]));if err!=nil||n<200||n>599{return 0,nil,errors.New("invalid SMTP reply code")}
  if i==0{code=n}else if n!=code{return 0,nil,errors.New("mixed SMTP reply codes")}
  lines=append(lines,string(line[4:]));if line[3]==' '{return code,lines,nil}
 }
 return 0,nil,errors.New("SMTP reply exceeds line limit")
}
func send(w *bufio.Writer,command string)error{
 if _,err:=w.WriteString(command+"\r\n");err!=nil{return err};return w.Flush()
}
func capabilities(lines []string)(bool,[]string){
 startTLS:=false;auth:=[]string{}
 for _,line:=range lines{
  fields:=strings.Fields(strings.ToUpper(line));if len(fields)==0{continue}
  if fields[0]=="STARTTLS"{startTLS=true}
  if fields[0]=="AUTH"{auth=append(auth,fields[1:]...)}
  if strings.HasPrefix(fields[0],"AUTH="){auth=append(auth,strings.TrimPrefix(fields[0],"AUTH="));auth=append(auth,fields[1:]...)}
 }
 return startTLS,auth
}
func invalidHostname(name string) bool {
 for i := 0; i < len(name); i++ {
  b := name[i]
  if b <= 32 || b == 127 { return true }
 }
 return false
}
func Probe(ctx context.Context,opt Options)(Result,error){
 result:=Result{AuthMechanisms:[]string{},PostTLSAuthMechanisms:[]string{}}
 if opt.Timeout<=0||opt.Timeout>60*time.Second{return result,errors.New("timeout must be between 1ns and 60s")}
 if ctx==nil{return result,errors.New("nil context")}
 if err:=ctx.Err();err!=nil{return result,err}
 if opt.HelloName==""{opt.HelloName="localhost"}
 if invalidHostname(opt.HelloName)||len(opt.HelloName)>253{return result,errors.New("invalid EHLO hostname")}
 host,_,err:=net.SplitHostPort(opt.Address);if err!=nil{return result,fmt.Errorf("invalid address: %w",err)}
 if opt.ServerName==""{opt.ServerName=host}
 if opt.ServerName==""||len(opt.ServerName)>253||invalidHostname(opt.ServerName){return result,errors.New("invalid TLS server name")}
 probeCtx,cancel:=context.WithTimeout(ctx,opt.Timeout);defer cancel()
 dialer:=net.Dialer{}
 conn,err:=dialer.DialContext(probeCtx,"tcp",opt.Address);if err!=nil{return result,err};defer conn.Close()
 // A canceled context without a deadline must also interrupt stalled reads.
 stop:=context.AfterFunc(probeCtx,func(){_ = conn.Close()})
 defer stop()
 deadline,_:=probeCtx.Deadline()
 if err:=conn.SetDeadline(deadline);err!=nil{return result,err}
 reader:=bufio.NewReader(conn);writer:=bufio.NewWriter(conn)
 code,_,err:=readReply(reader);if err!=nil{return result,err};result.BannerCode=code
 if code!=220{return result,fmt.Errorf("SMTP banner returned %d, expected 220",code)}
 if err:=send(writer,"EHLO "+opt.HelloName);err!=nil{return result,err}
 code,lines,err:=readReply(reader);if err!=nil{return result,err};result.EHLOCode=code
 if code!=250{return result,fmt.Errorf("EHLO returned %d, expected 250",code)}
 result.StartTLSAdvertised,result.AuthMechanisms=capabilities(lines)
 if !result.StartTLSAdvertised{
  if opt.RequireTLS{return result,errors.New("STARTTLS not advertised; refusing downgrade")}
  return result,nil
 }
 if err:=send(writer,"STARTTLS");err!=nil{return result,err}
 code,_,err=readReply(reader);if err!=nil{return result,err}
 if code!=220{return result,fmt.Errorf("STARTTLS returned %d, expected 220",code)}
 tlsConn:=tls.Client(conn,&tls.Config{ServerName:opt.ServerName,MinVersion:tls.VersionTLS12})
 if err:=tlsConn.HandshakeContext(probeCtx);err!=nil{return result,fmt.Errorf("TLS verification failed: %w",err)}
 state:=tlsConn.ConnectionState();result.StartTLSVerified=true;result.TLSVersion=tls.VersionName(state.Version)
 reader=bufio.NewReader(tlsConn);writer=bufio.NewWriter(tlsConn)
 if err:=send(writer,"EHLO "+opt.HelloName);err!=nil{return result,err}
 code,lines,err=readReply(reader);if err!=nil{return result,err}
 result.PostTLSEHLOCode=code
 if code!=250{return result,fmt.Errorf("post-TLS EHLO returned %d, expected 250",code)}
 _,result.PostTLSAuthMechanisms=capabilities(lines)
 return result,nil
}
