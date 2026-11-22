// spamgate-spool-history checks every interval in a chronological sequence of
// independently captured spool audits. It never modifies the live mail host.
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

type reports []string
func (r *reports) String() string {return fmt.Sprint([]string(*r))}
func (r *reports) Set(value string) error {
 if value=="" {return fmt.Errorf("empty report path")}
 if len(*r)>=1024 {return fmt.Errorf("too many reports")}
 *r=append(*r,value)
 return nil
}

func run(args []string,stdout,stderr io.Writer) int {
 fs:=flag.NewFlagSet("spamgate-spool-history",flag.ContinueOnError)
 fs.SetOutput(stderr)
 var paths reports
 fs.Var(&paths,"report","chronologically ordered spool-audit JSON report; repeat 2-1024 times")
 queued:=fs.Int("max-queue-growth",-1,"maximum per-interval queued growth")
 dead:=fs.Int("max-dead-growth",-1,"maximum per-interval dead growth")
 delivering:=fs.Int("max-delivering-growth",-1,"maximum per-interval delivering growth")
 pending:=fs.Int("max-pending-growth",-1,"maximum per-interval pending growth")
 deadCount:=fs.Int("max-dead-count",-1,"maximum absolute dead count")
 queuedCount:=fs.Int("max-queued-count",-1,"maximum absolute queued count across all observations")
 deliveringCount:=fs.Int("max-delivering-count",-1,"maximum absolute delivering count across all observations")
 pendingCount:=fs.Int("max-pending-count",-1,"maximum absolute pending count across all observations")
 sustainedQueued:=fs.Int("max-sustained-queued",-1,"maximum queued count for sustained pressure; -1 disables")
 sustainedDelivering:=fs.Int("max-sustained-delivering",-1,"maximum delivering count for sustained pressure; -1 disables")
 sustainedPending:=fs.Int("max-sustained-pending",-1,"maximum pending count for sustained pressure; -1 disables")
 sustainedSamples:=fs.Int("min-sustained-samples",2,"consecutive observations required to report sustained pressure")
 durationQueued:=fs.Duration("min-queued-pressure-duration",0,"minimum observed time above queued ceiling; zero disables")
 durationDelivering:=fs.Duration("min-delivering-pressure-duration",0,"minimum observed time above delivering ceiling; zero disables")
 durationPending:=fs.Duration("min-pending-pressure-duration",0,"minimum observed time above pending ceiling; zero disables")
 age:=fs.Duration("max-snapshot-age",0,"maximum age of latest report; zero disables")
 gap:=fs.Duration("max-snapshot-gap",0,"maximum interval between captures; zero disables")
 if err:=fs.Parse(args);err!=nil{return 2}
 if fs.NArg()!=0 || len(paths)<2 {fmt.Fprintln(stderr,"provide 2-1024 ordered -report paths without positional arguments");return 2}
 policy:=spooltrend.Policy{MaxQueuedGrowth:*queued,MaxDeadGrowth:*dead,MaxDeliveringGrowth:*delivering,MaxPendingGrowth:*pending,MaxDeadCount:*deadCount}
 freshness:=spooltrend.FreshnessPolicy{RequireTimestamps:true,MaxSnapshotAge:*age,MaxSnapshotGap:*gap}
 if err:=policy.Validate();err!=nil{fmt.Fprintln(stderr,err);return 2}
 if err:=freshness.Validate();err!=nil{fmt.Fprintln(stderr,err);return 2}
 ceilings:=spooltrend.SeriesCeilings{MaxQueued:*queuedCount,MaxDelivering:*deliveringCount,MaxPending:*pendingCount}
 if err:=ceilings.Validate();err!=nil{fmt.Fprintln(stderr,err);return 2}
 sustained:=spooltrend.SustainedPolicy{MaxQueued:*sustainedQueued,MaxDelivering:*sustainedDelivering,MaxPending:*sustainedPending,MinSamples:*sustainedSamples}
 if err:=sustained.Validate();err!=nil{fmt.Fprintln(stderr,err);return 2}
 durationPolicy:=spooltrend.DurationPressurePolicy{Queued:*durationQueued,Delivering:*durationDelivering,Pending:*durationPending}
 if err:=durationPolicy.Validate();err!=nil{fmt.Fprintln(stderr,err);return 2}
 seen:=map[string]os.FileInfo{}
 snapshots:=make([]spooltrend.Snapshot,0,len(paths))
 for i,path:=range paths {
  fi,err:=os.Lstat(path)
  if err!=nil{fmt.Fprintf(stderr,"report %d: %v\n",i,err);return 2}
  for prev,other:=range seen {
   if os.SameFile(fi,other){fmt.Fprintf(stderr,"report %d aliases %s\n",i,prev);return 2}
  }
  seen[path]=fi
  s,err:=spooltrend.Load(path)
  if err!=nil{fmt.Fprintf(stderr,"report %d: %v\n",i,err);return 2}
  snapshots=append(snapshots,s)
 }
 result,err:=spooltrend.AnalyzeSeries(snapshots,policy,freshness,time.Now().UTC())
 if err!=nil{fmt.Fprintln(stderr,err);return 2}
 result,err=spooltrend.ApplySeriesCeilings(result,ceilings)
 if err!=nil{fmt.Fprintln(stderr,err);return 2}
 result,err=spooltrend.ApplySustainedPolicy(result,sustained)
 if err!=nil{fmt.Fprintln(stderr,err);return 2}
 result,err=spooltrend.ApplyDurationPressure(result,ceilings,durationPolicy)
 if err!=nil{fmt.Fprintln(stderr,err);return 2}
 encoder:=json.NewEncoder(stdout)
 encoder.SetIndent("","  ")
 if err:=encoder.Encode(result);err!=nil{fmt.Fprintln(stderr,err);return 2}
 if !result.GatePassed{return 1}
 return 0
}
func main(){os.Exit(run(os.Args[1:],os.Stdout,os.Stderr))}
