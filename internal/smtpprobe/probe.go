package smtpprobe

import (
 "bufio"
 "context"
 "crypto/tls"
 "crypto/x509"
 "errors"
 "fmt"
 "net"
 "strconv"
 "time"
)
const maxLine=2048
const maxLines=64
type Result struct {
 ProbeDurationMillis int64 `json:"probe_duration_ms"`
 GreetingDurationMillis int64 `json:"greeting_duration_ms,omitempty"`
 EHLORoundTripMillis int64 `json:"ehlo_round_trip_ms,omitempty"`
 StartTLSRoundTripMillis int64 `json:"starttls_round_trip_ms,omitempty"`
 PostTLSEHLORoundTripMillis int64 `json:"post_tls_ehlo_round_trip_ms,omitempty"`
 TLSHandshakeMillis int64 `json:"tls_handshake_ms,omitempty"`
 BannerCode int `json:"banner_code"`
 EHLOCode int `json:"ehlo_code"`
 StartTLSAdvertised bool `json:"starttls_advertised"`
 SizeAdvertised bool `json:"size_advertised"`
 SizeLimitKnown bool `json:"size_limit_known"`
 SizeLimitBytes uint64 `json:"size_limit_bytes"`
 SizeWarning string `json:"size_warning,omitempty"`
 PostTLSSizeAdvertised bool `json:"post_tls_size_advertised"`
 PostTLSSizeLimitKnown bool `json:"post_tls_size_limit_known"`
 PostTLSSizeLimitBytes uint64 `json:"post_tls_size_limit_bytes"`
 PostTLSSizeWarning string `json:"post_tls_size_warning,omitempty"`
 StartTLSReplyCode int `json:"starttls_reply_code,omitempty"`
 StartTLSVerified bool `json:"starttls_verified"`
 PostTLSStartTLSAdvertised bool `json:"post_tls_starttls_advertised"`
 TLSVersion string `json:"tls_version,omitempty"`
 TLSCertificate *CertificateInfo `json:"tls_certificate,omitempty"`
 Findings []Finding `json:"findings"`
 FailureStage string `json:"failure_stage,omitempty"`
 FailureKind string `json:"failure_kind,omitempty"`
 EHLOWarnings []string `json:"ehlo_warnings"`
 PostTLSEHLOWarnings []string `json:"post_tls_ehlo_warnings"`
 AuthMechanisms []string `json:"auth_mechanisms"`
 PostTLSEHLOCode int `json:"post_tls_ehlo_code,omitempty"`
 PostTLSAuthMechanisms []string `json:"post_tls_auth_mechanisms"`
}
// CertificateInfo reports the verified peer leaf certificate without exposing its raw DER.
type CertificateInfo struct {
 Subject string `json:"subject"`
 Issuer string `json:"issuer"`
 DNSNames []string `json:"dns_names"`
 NotBefore time.Time `json:"not_before"`
 NotAfter time.Time `json:"not_after"`
 DaysUntilExpiry int `json:"days_until_expiry"`
}
func certificateInfo(cert *x509.Certificate, now time.Time) *CertificateInfo {
 if cert == nil { return nil }
 remaining := cert.NotAfter.Sub(now)
 days := 0
 if remaining < 0 {
  days = -1
 } else if remaining > 0 {
  // Round up so a certificate with less than 24 hours remaining is not
  // reported as already at zero days, and avoid early expiry claims.
  days = int(remaining / (24*time.Hour))
  if remaining % (24*time.Hour) != 0 { days++ }
 }
 return &CertificateInfo{
  Subject: cert.Subject.String(), Issuer: cert.Issuer.String(),
  DNSNames: append([]string{},cert.DNSNames...),
  NotBefore: cert.NotBefore, NotAfter: cert.NotAfter,
  DaysUntilExpiry: days,
 }
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
func invalidHostname(name string) bool {
 for i := 0; i < len(name); i++ {
  b := name[i]
  if b <= 32 || b == 127 { return true }
 }
 return false
}
// elapsedMillis rounds a completed positive interval up to one millisecond.
// It intentionally does not expose the SMTP target or server reply text.
func elapsedMillis(start time.Time) int64 {
 elapsed := time.Since(start)
 ms := int64(elapsed / time.Millisecond)
 if elapsed % time.Millisecond != 0 { ms++ }
 return ms
}
func Probe(ctx context.Context,opt Options)(result Result,err error){
 result=Result{AuthMechanisms:[]string{},PostTLSAuthMechanisms:[]string{},Findings:[]Finding{},EHLOWarnings:[]string{},PostTLSEHLOWarnings:[]string{}}
 started := time.Now()
 stage := "configuration"
 var probeCtx context.Context
 var cancel context.CancelFunc
 defer func(){
  // A blocked socket read may return EOF or a closed-connection error after
  // context cancellation. Preserve the actual cancellation cause for callers.
  if err != nil && probeCtx != nil {
   // The connection deadline and context timer race at the same instant.
   // net.Conn may return a timeout before context.Err() becomes visible.
   // This socket deadline is exclusively derived from probeCtx.
   if cause := probeCtx.Err(); cause != nil {
    err = cause
   } else if deadline, ok := probeCtx.Deadline(); ok && !time.Now().Before(deadline) {
    var netErr net.Error
    if errors.As(err, &netErr) && netErr.Timeout() {
     err = context.DeadlineExceeded
    }
   }
  }
  // Use monotonic elapsed time and round upward so a completed sub-ms probe
  // is not misrepresented as zero latency. Never expose target identifiers.
  result.ProbeDurationMillis = elapsedMillis(started)
  if err != nil { result.FailureStage = stage; result.FailureKind = classifyProbeFailure(stage, err) }
  result.Findings=Assess(result)
  if err != nil { result.Findings=append(result.Findings, failureFinding(stage)); if detail := classifiedFailureFinding(result.FailureKind); detail != nil { result.Findings=append(result.Findings, *detail) } }
  // Cancel only after classifying the actual outcome; an earlier deferred
  // cancel would turn every SMTP rejection into a spurious CANCELED failure.
  if cancel != nil { cancel() }
 }()
 if opt.Timeout<=0||opt.Timeout>60*time.Second{return result,errors.New("timeout must be between 1ns and 60s")}
 if ctx==nil{return result,errors.New("nil context")}
 if err:=ctx.Err();err!=nil{return result,err}
 if opt.HelloName==""{opt.HelloName="localhost"}
 if err:=validateEHLOName(opt.HelloName);err!=nil{return result,err}
 host,_,err:=net.SplitHostPort(opt.Address);if err!=nil{return result,fmt.Errorf("invalid address: %w",err)}
 if opt.ServerName==""{opt.ServerName=host}
 if err:=validateTLSName(opt.ServerName);err!=nil{return result,err}
 stage = "connection"
 probeCtx,cancel=context.WithTimeout(ctx,opt.Timeout)
 dialer:=net.Dialer{}
 conn,err:=dialer.DialContext(probeCtx,"tcp",opt.Address);if err!=nil{return result,err};defer conn.Close()
 // A canceled context without a deadline must also interrupt stalled reads.
 stop:=context.AfterFunc(probeCtx,func(){_ = conn.Close()})
 defer stop()
 deadline,_:=probeCtx.Deadline()
 if err:=conn.SetDeadline(deadline);err!=nil{return result,err}
 reader:=bufio.NewReader(conn);writer:=bufio.NewWriter(conn)
 stage = "greeting"
 greetingStarted := time.Now()
 code,_,err:=readReply(reader);
 result.GreetingDurationMillis = elapsedMillis(greetingStarted)
 if err!=nil{return result,err}
 result.BannerCode=code
 if code!=220{return result,&SMTPReplyError{Stage:stage,Code:code}}
 stage = "ehlo"
 ehloStarted := time.Now()
 if err:=send(writer,"EHLO "+opt.HelloName);err!=nil{return result,err}
 code,lines,err:=readReply(reader);result.EHLORoundTripMillis=elapsedMillis(ehloStarted);if err!=nil{return result,err};result.EHLOCode=code
 if code!=250{return result,&SMTPReplyError{Stage:stage,Code:code}}
 result.EHLOWarnings=capabilityWarnings(lines)
 result.SizeAdvertised,result.SizeLimitKnown,result.SizeLimitBytes,result.SizeWarning=sizeEvidence(lines)
 result.StartTLSAdvertised,result.AuthMechanisms=capabilities(lines)
 if !result.StartTLSAdvertised{
  if opt.RequireTLS{stage = "tls_policy"; return result,errors.New("STARTTLS not advertised; refusing downgrade")}
  return result,nil
 }
 stage = "starttls"
 startTLSStarted := time.Now()
 if err:=send(writer,"STARTTLS");err!=nil{return result,err}
 code,_,err=readReply(reader);result.StartTLSRoundTripMillis=elapsedMillis(startTLSStarted);if err!=nil{return result,err}
 result.StartTLSReplyCode=code
 if code!=220{return result,&SMTPReplyError{Stage:stage,Code:code}}
 stage = "tls_handshake"
 tlsConn:=tls.Client(conn,&tls.Config{ServerName:opt.ServerName,MinVersion:tls.VersionTLS12})
 handshakeStarted := time.Now()
 handshakeErr := tlsConn.HandshakeContext(probeCtx)
 handshakeElapsed := time.Since(handshakeStarted)
 result.TLSHandshakeMillis = int64(handshakeElapsed / time.Millisecond)
 if handshakeElapsed % time.Millisecond != 0 { result.TLSHandshakeMillis++ }
 if handshakeErr!=nil{return result,fmt.Errorf("TLS verification failed: %w",handshakeErr)}
 state:=tlsConn.ConnectionState();result.StartTLSVerified=true;result.TLSVersion=tls.VersionName(state.Version)
 if len(state.PeerCertificates)>0 {result.TLSCertificate=certificateInfo(state.PeerCertificates[0],time.Now())}
 reader=bufio.NewReader(tlsConn);writer=bufio.NewWriter(tlsConn)
 stage = "post_tls_ehlo"
 postEHLOStarted := time.Now()
 if err:=send(writer,"EHLO "+opt.HelloName);err!=nil{return result,err}
 code,lines,err=readReply(reader);result.PostTLSEHLORoundTripMillis=elapsedMillis(postEHLOStarted);if err!=nil{return result,err}
 result.PostTLSEHLOCode=code
 if code!=250{return result,&SMTPReplyError{Stage:stage,Code:code}}
 result.PostTLSEHLOWarnings=capabilityWarnings(lines)
 result.PostTLSSizeAdvertised,result.PostTLSSizeLimitKnown,result.PostTLSSizeLimitBytes,result.PostTLSSizeWarning=sizeEvidence(lines)
 result.PostTLSStartTLSAdvertised,result.PostTLSAuthMechanisms=capabilities(lines)
 return result,nil
}
