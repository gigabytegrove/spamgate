// spamgate-spool-trend compares two independently captured, read-only spool audit reports.
// It never reads, mutates, replays or acknowledges SMTP messages.
package main

import (
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "io"
 "os"

 "github.com/gigabytegrove/spamgate/internal/spooltrend"
)

func run(args []string, stdout, stderr io.Writer) int {
 fs := flag.NewFlagSet("spamgate-spool-trend", flag.ContinueOnError)
 fs.SetOutput(stderr)
 before := fs.String("before", "", "earlier spamgate-spool-audit -json report")
 after := fs.String("after", "", "later spamgate-spool-audit -json report")
 maxGrowth := fs.Int("max-queue-growth", -1, "maximum increase in queued messages; -1 disables")
 maxDeadGrowth := fs.Int("max-dead-growth", -1, "maximum increase in dead messages; -1 disables")
 if err := fs.Parse(args); err != nil { return 2 }
 if fs.NArg()!=0 || *before=="" || *after=="" || *before==*after || *maxGrowth < -1 || *maxDeadGrowth < -1 {
  fmt.Fprintln(stderr,"provide distinct -before and -after paths and limits >= -1")
  return 2
 }
 a,err:=spooltrend.Load(*before)
 if err!=nil { fmt.Fprintln(stderr,"earlier report:",err); return 2 }
 b,err:=spooltrend.Load(*after)
 if err!=nil { fmt.Fprintln(stderr,"later report:",err); return 2 }
 result,err:=spooltrend.Compare(a,b,*maxGrowth,*maxDeadGrowth)
 if err!=nil { fmt.Fprintln(stderr,"comparison:",err); return 2 }
 enc:=json.NewEncoder(stdout)
 enc.SetIndent("","  ")
 if err:=enc.Encode(result);err!=nil {
  fmt.Fprintln(stderr,"write trend:",err)
  return 2
 }
 if !result.GatePassed { return 1 }
 return 0
}
func main() { os.Exit(run(os.Args[1:],os.Stdout,os.Stderr)) }
var _ = errors.New
