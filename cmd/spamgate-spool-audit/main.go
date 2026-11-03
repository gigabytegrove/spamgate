package main

import (
 "encoding/json"
 "flag"
 "fmt"
 "io"
 "os"
 "sort"

 "github.com/gigabytegrove/spamgate/internal/spoolaudit"
)

// Exit 0 means a complete audit without findings; 1 means findings;
// 2 means invocation, input, or output failure. A failed report write
// must never be reported as a clean or merely suspicious spool.
func run(args []string, stdout, stderr io.Writer) int {
 flags := flag.NewFlagSet("spamgate-spool-audit", flag.ContinueOnError)
 flags.SetOutput(stderr)
 dir := flags.String("dir", "/opt/spamgate/data/delivery-queue", "native SMTP spool directory (read-only)")
 jsonOut := flags.Bool("json", false, "emit privacy-limited JSON")
 if err := flags.Parse(args); err != nil { return 2 }
 if flags.NArg() != 0 { fmt.Fprintln(stderr, "unexpected positional arguments"); return 2 }
 report, err := spoolaudit.Audit(*dir)
 if err != nil { fmt.Fprintln(stderr, "spool audit failed:", err); return 2 }
 if *jsonOut {
  enc := json.NewEncoder(stdout)
  enc.SetIndent("", "  ")
  if err := enc.Encode(report); err != nil {
   fmt.Fprintln(stderr, "write spool audit:", err)
   return 2
  }
 } else {
  if _, err := fmt.Fprintln(stdout, report.Explain()); err != nil {
   fmt.Fprintln(stderr, "write spool audit:", err)
   return 2
  }
  keys := make([]string, 0, len(report.States))
  for key := range report.States { keys = append(keys, key) }
  sort.Strings(keys)
  for _, key := range keys {
   if _, err := fmt.Fprintf(stdout, "state %s: %d\n", key, report.States[key]); err != nil {
    fmt.Fprintln(stderr, "write spool audit:", err)
    return 2
   }
  }
  for _, finding := range report.Findings {
   if _, err := fmt.Fprintf(stdout, "%s %s: %s\n", finding.Code, finding.Object, finding.Detail); err != nil {
    fmt.Fprintln(stderr, "write spool audit:", err)
    return 2
   }
  }
 }
 if report.HasFindings() { return 1 }
 return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
