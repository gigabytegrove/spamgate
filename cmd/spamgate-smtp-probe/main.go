package main
import (
 "context"
 "encoding/json"
 "flag"
 "fmt"
 "os"
 "time"
 "github.com/gigabytegrove/spamgate/internal/smtpprobe"
)
func main(){
 address:=flag.String("address","127.0.0.1:25","SMTP host:port")
 serverName:=flag.String("tls-name","","certificate verification name (defaults to address host)")
 hello:=flag.String("ehlo","localhost","EHLO hostname")
 timeout:=flag.Duration("timeout",8*time.Second,"overall timeout, maximum 60s")
 requireTLS:=flag.Bool("require-tls",true,"fail when STARTTLS is not advertised")
 flag.Parse()
 if flag.NArg()!=0{fmt.Fprintln(os.Stderr,"unexpected positional arguments");os.Exit(2)}
 result,err:=smtpprobe.Probe(context.Background(),smtpprobe.Options{Address:*address,ServerName:*serverName,HelloName:*hello,Timeout:*timeout,RequireTLS:*requireTLS})
 if encErr:=json.NewEncoder(os.Stdout).Encode(result);encErr!=nil{fmt.Fprintln(os.Stderr,encErr);os.Exit(2)}
 if err!=nil{fmt.Fprintln(os.Stderr,"SMTP diagnostic failed:",err);os.Exit(1)}
}
