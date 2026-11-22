// spamgate-spool-trend compares two independently captured, read-only spool audit reports.
// It never reads, mutates, replays or acknowledges SMTP messages.
package main

import (
 "encoding/json"
 "flag"
 "fmt"
 "io"
 "os"
 "time"

 "github.com/gigabytegrove/spamgate/internal/spooltrend"
)

func run(args []string, stdout, stderr io.Writer) int {
 fs := flag.NewFlagSet("spamgate-spool-trend", flag.ContinueOnError)
 fs.SetOutput(stderr)
 before := fs.String("before", "", "earlier spamgate-spool-audit -json report")
 after := fs.String("after", "", "later spamgate-spool-audit -json report")
 maxGrowth := fs.Int("max-queue-growth", -1, "maximum increase in queued messages; -1 disables")
 maxDeadGrowth := fs.Int("max-dead-growth", -1, "maximum increase in dead messages; -1 disables")
 maxDeliveringGrowth := fs.Int("max-delivering-growth", -1, "maximum increase in actively delivering messages; -1 disables")
 maxPendingGrowth := fs.Int("max-pending-growth", -1, "maximum increase in unpublished pending messages; -1 disables")
 maxDeadCount := fs.Int("max-dead-count", -1, "maximum absolute dead messages in later report; -1 disables")
 requireTimestamps := fs.Bool("require-timestamps", false, "reject legacy evidence without capture timestamps")
 maxSnapshotAge := fs.Duration("max-snapshot-age", 0, "maximum age of later report, e.g. 15m; 0 disables")
 maxSnapshotGap := fs.Duration("max-snapshot-gap", 0, "maximum elapsed time between captures, e.g. 1h; 0 disables")
 if err := fs.Parse(args); err != nil { return 2 }
 policy:=spooltrend.Policy{
  MaxQueuedGrowth:*maxGrowth,
  MaxDeadGrowth:*maxDeadGrowth,
  MaxDeliveringGrowth:*maxDeliveringGrowth,
  MaxPendingGrowth:*maxPendingGrowth,
  MaxDeadCount:*maxDeadCount,
 }
 freshness:=spooltrend.FreshnessPolicy{RequireTimestamps:*requireTimestamps,MaxSnapshotAge:*maxSnapshotAge,MaxSnapshotGap:*maxSnapshotGap}
 if err:=freshness.Validate();err!=nil{fmt.Fprintln(stderr,err);return 2}
 if fs.NArg()!=0 || *before=="" || *after=="" || *before==*after {
  fmt.Fprintln(stderr,"provide distinct -before and -after paths and no positional arguments")
  return 2
 }
 if err:=policy.Validate();err!=nil{fmt.Fprintln(stderr,err);return 2}
 a,err:=spooltrend.Load(*before)
 if err!=nil { fmt.Fprintln(stderr,"earlier report:",err); return 2 }
 b,err:=spooltrend.Load(*after)
 if err!=nil { fmt.Fprintln(stderr,"later report:",err); return 2 }
 if err:=spooltrend.CheckFreshness(a,b,freshness,time.Now().UTC());err!=nil{fmt.Fprintln(stderr,"freshness:",err);return 2}
 result,err:=spooltrend.CompareWithPolicy(a,b,policy)
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
