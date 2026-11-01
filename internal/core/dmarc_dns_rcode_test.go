package core

import (
 "context"
 "encoding/binary"
 "io"
 "net"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

func testDMARCDNSReply(request []byte, rcode uint16, truncated bool, answers uint16) []byte {
 reply := append([]byte(nil), request...)
 flags := uint16(0x8180) | rcode
 if truncated { flags |= 0x0200 }
 binary.BigEndian.PutUint16(reply[2:4], flags)
 binary.BigEndian.PutUint16(reply[6:8], answers)
 return reply
}

func TestDMARCRCODEParserRejectsSpoofedAndAmbiguousReplies(t *testing.T) {
 q, err := dmarcDNSQuestion("sender.example.org")
 if err != nil { t.Fatal(err) }
 req := make([]byte, 12)
 binary.BigEndian.PutUint16(req[:2], 123)
 binary.BigEndian.PutUint16(req[4:6], 1)
 req = append(req, q...)
 for _, tc := range []struct{ name string; rcode uint16; truncated bool; answers uint16; invalid bool }{
  {"NXDOMAIN",3,false,0,false},
  {"NOERROR NODATA",0,false,0,false},
  {"SERVFAIL",2,false,0,false},
  {"truncated",0,true,0,false},
  {"CNAME target NXDOMAIN ambiguous",3,false,1,true},
 } {
  t.Run(tc.name,func(t *testing.T){
   resp := testDMARCDNSReply(req,tc.rcode,tc.truncated,tc.answers)
   code,truncated,err:=dmarcDNSRCODE(resp,123,"sender.example.org")
   if (err!=nil)!=tc.invalid || !tc.invalid && (code!=int(tc.rcode) && !tc.truncated || truncated!=tc.truncated) {
    t.Fatalf("code=%d truncated=%v err=%v",code,truncated,err)
   }
  })
 }
 for _, tc := range []struct{ name string; mutate func([]byte) }{
  {"transaction ID",func(b []byte){b[0]++}},
  {"question name",func(b []byte){b[13]='x'}},
  {"question type",func(b []byte){b[len(b)-4]=2}},
  {"question class",func(b []byte){b[len(b)-2]=2}},
  {"not response",func(b []byte){b[2]=0}},
  {"question count",func(b []byte){b[5]=2}},
  {"bad compression pointer",func(b []byte){b[12]=0xc0;b[13]=0xff}},
 } {
  t.Run(tc.name,func(t *testing.T){
   resp:=testDMARCDNSReply(req,3,false,0)
   tc.mutate(resp)
   if _,_,err:=dmarcDNSRCODE(resp,123,"sender.example.org");err==nil {t.Fatal("malformed reply accepted")}
  })
 }
}

func TestDMARCDNSQuestionValidation(t *testing.T) {
 for _, domain := range []string{"","bad name.example",strings.Repeat("x",64)+".example.org","foo..example.org","localhost"} {
  if _,err:=dmarcDNSQuestion(domain);err==nil {t.Errorf("accepted %q",domain)}
 }
}

func TestDMARCDNSLocalWireRCODE(t *testing.T) {
 for _, tc := range []struct{name string;rcode uint16;nx,fail bool}{
  {"NXDOMAIN",3,true,false},{"NODATA",0,false,false},
  {"SERVFAIL",2,false,true},{"REFUSED",5,false,true},
 } {
  t.Run(tc.name,func(t *testing.T){
   conn,err:=net.ListenPacket("udp","127.0.0.1:0")
   if err!=nil {t.Fatal(err)}
   defer conn.Close()
   done:=make(chan error,1)
   go func(){
    b:=make([]byte,512)
    n,addr,err:=conn.ReadFrom(b)
    if err!=nil {done<-err;return}
    _,err=conn.WriteTo(testDMARCDNSReply(b[:n],tc.rcode,false,0),addr)
    done<-err
   }()
   ctx,cancel:=context.WithTimeout(context.Background(),time.Second)
   defer cancel()
   nx,err:=(dmarcDNSClient{serversOverride:[]string{conn.LocalAddr().String()}}).nameNXDOMAIN(ctx,"sender.example.org")
   if nx!=tc.nx || (err!=nil)!=tc.fail {t.Fatalf("nx=%v err=%v",nx,err)}
   if err:=<-done;err!=nil {t.Fatal(err)}
  })
 }
}

func TestDMARCDNSTruncatedUDPUsesTCP(t *testing.T) {
 tcp,err:=net.Listen("tcp","127.0.0.1:0")
 if err!=nil {t.Fatal(err)}
 defer tcp.Close()
 udp,err:=net.ListenPacket("udp",tcp.Addr().String())
 if err!=nil {t.Fatal(err)}
 defer udp.Close()
 done:=make(chan error,2)
 go func(){
  b:=make([]byte,512)
  n,addr,err:=udp.ReadFrom(b)
  if err!=nil {done<-err;return}
  resp:=testDMARCDNSReply(b[:n],0,true,0)
  _,err=udp.WriteTo(resp[:12],addr) // truncated replies can omit the question
  done<-err
 }()
 go func(){
  conn,err:=tcp.Accept()
  if err!=nil {done<-err;return}
  defer conn.Close()
  var prefix [2]byte
  if _,err=io.ReadFull(conn,prefix[:]);err!=nil {done<-err;return}
  req:=make([]byte,int(binary.BigEndian.Uint16(prefix[:])))
  if _,err=io.ReadFull(conn,req);err!=nil {done<-err;return}
  resp:=testDMARCDNSReply(req,3,false,0)
  binary.BigEndian.PutUint16(prefix[:],uint16(len(resp)))
  _,err=conn.Write(append(prefix[:],resp...))
  done<-err
 }()
 ctx,cancel:=context.WithTimeout(context.Background(),2*time.Second)
 defer cancel()
 nx,err:=(dmarcDNSClient{serversOverride:[]string{tcp.Addr().String()}}).nameNXDOMAIN(ctx,"missing.example.org")
 if err!=nil || !nx {t.Fatalf("TCP fallback nx=%v err=%v",nx,err)}
 for i:=0;i<2;i++ {if err:=<-done;err!=nil {t.Fatal(err)}}
}

func TestDMARCDNSResolvConfValidation(t *testing.T) {
 for _,tc:=range []struct{input string;count int;fail bool}{
  {"nameserver 127.0.0.53\nnameserver 2001:db8::1\n",2,false},
  {"search example.org\nnameserver 192.0.2.1 # comment\n",1,false},
  {"nameserver dns.example.org\n",0,true},
  {"nameserver\n",0,true},
  {"search example.org\n",0,true},
 } {
  path:=filepath.Join(t.TempDir(),"resolv.conf")
  if err:=os.WriteFile(path,[]byte(tc.input),0600);err!=nil {t.Fatal(err)}
  servers,err:=(dmarcDNSClient{configPath:path}).servers()
  if (err!=nil)!=tc.fail || !tc.fail && len(servers)!=tc.count {t.Errorf("%q servers=%v err=%v",tc.input,servers,err)}
 }
}

func TestDMARCDNSCancellationAndOptIn(t *testing.T) {
 ctx,cancel:=context.WithCancel(context.Background())
 cancel()
 if _,err:=(dmarcDNSClient{configPath:"/missing"}).nameNXDOMAIN(ctx,"sender.example.org");err!=context.Canceled {
  t.Fatalf("cancellation not respected: %v",err)
 }
 t.Setenv("SPAMGATE_DMARC_NP_DNS","")
 for _,resolver:=range []SPFResolver{nil,net.DefaultResolver} {
  if _,ok:=dmarcPolicyResolver(resolver).(DMARCNameStatusResolver);ok {t.Fatal("backend enabled without opt-in")}
 }
 t.Setenv("SPAMGATE_DMARC_NP_DNS","system")
 for _,resolver:=range []SPFResolver{nil,net.DefaultResolver} {
  if _,ok:=dmarcPolicyResolver(resolver).(DMARCNameStatusResolver);!ok {t.Fatal("backend not enabled")}
 }
 custom:=&net.Resolver{PreferGo:true}
 if dmarcPolicyResolver(custom)!=custom {t.Fatal("custom resolver replaced")}
 t.Setenv("SPAMGATE_DMARC_NP_DNS","unknown")
 if _,ok:=dmarcPolicyResolver(nil).(DMARCNameStatusResolver);ok {t.Fatal("unknown opt-in enabled")}
}
