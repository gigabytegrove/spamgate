package transport

import (
 "context"
 "net"
 "strings"
 "testing"
 "time"

 "github.com/gigabytegrove/spamgate/internal/core"
)

func TestControllerStartupRejectsUnusableSecrets(t *testing.T) {
 store, err := core.Open(t.TempDir())
 if err != nil { t.Fatal(err) }
 t.Setenv("SPAMGATE_CONTROLLER_LISTEN", "127.0.0.1:38474")
 t.Setenv("SPAMGATE_CONTROLLER_TRUSTED_CIDRS", "127.0.0.1/32")
 good := strings.Repeat("a", 24)
 for _, tc := range []struct{name, secret string; accepted bool}{
  {"valid-minimum", good, true},
  {"valid-long", good+"Z09!_~", true},
  {"too-short", good[:23], false},
  {"leading-space", " "+good, false},
  {"trailing-space", good+" ", false},
  {"embedded-space", good+" bad", false},
  {"newline", good+"\n", false},
  {"tab", good+"\t", false},
  {"nonascii", good+"é", false},
  {"control", good+"\x7f", false},
 } {
  t.Run(tc.name, func(t *testing.T) {
   t.Setenv("SPAMGATE_CONTROLLER_TOKEN", tc.secret)
   got, err := ControllerFromEnv(store)
   if tc.accepted && (err != nil || got == nil || got.Token != tc.secret) { t.Fatalf("valid secret refused: %v", err) }
   if !tc.accepted && err == nil { t.Fatal("invalid secret accepted") }
  })
 }
}

func TestControllerListenStopsOnCancellation(t *testing.T) {
 store, err := core.Open(t.TempDir())
 if err != nil { t.Fatal(err) }
 cidrs, err := parseTrustedCIDRs("127.0.0.1/32")
 if err != nil { t.Fatal(err) }
 probe, err := net.Listen("tcp", "127.0.0.1:0")
 if err != nil { t.Fatal(err) }
 addr := probe.Addr().String()
 if err := probe.Close(); err != nil { t.Fatal(err) }
 c := &RspamdController{ListenAddress: addr, Trusted: cidrs, Token: strings.Repeat("x", 32), Store: store}
 ctx, cancel := context.WithCancel(context.Background())
 done := make(chan error, 1)
 go func() { done <- c.Listen(ctx) }()
 defer cancel()
 deadline := time.Now().Add(2*time.Second)
 for {
  conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
  if err == nil { _ = conn.Close(); break }
  if time.Now().After(deadline) {
   cancel()
   <-done
   t.Fatalf("listener did not start: %v", err)
  }
  time.Sleep(10*time.Millisecond)
 }
 cancel()
 select {
 case err := <-done:
  if err != nil { t.Fatalf("shutdown failed: %v", err) }
 case <-time.After(7*time.Second):
  t.Fatal("listener did not shut down")
 }
}
