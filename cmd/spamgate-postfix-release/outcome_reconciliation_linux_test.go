//go:build linux

package main

import (
 "bytes"
 "context"
 "errors"
 "io"
 "strings"
 "testing"
)

type releaseSinkError struct{}
func (releaseSinkError) Write([]byte) (int,error) { return 0, errors.New("recipient=secret@example.invalid") }
type releaseShortSink struct{}
func (releaseShortSink) Write(p []byte) (int,error) { return len(p)-1,nil }

func TestReleaseOutcomeUnknownAfterAction(t *testing.T) {
 path := helperScript(t, "exit 0")
 for _, tc := range []struct{name string; sink io.Writer}{
  {"writer error", releaseSinkError{}},
  {"short write", releaseShortSink{}},
 } {
  t.Run(tc.name,func(t *testing.T){
   err:=runPostsuperCommand(context.Background(),path,[]string{"-H","A123"},tc.sink)
   if !errors.Is(err,errReleaseOutcomeUnknown) {t.Fatalf("post-action failure must be indeterminate: %v",err)}
   if strings.Contains(err.Error(),"secret@example.invalid") {t.Fatalf("sink detail leaked: %v",err)}
  })
 }
}

func TestReleaseOutcomeUnknownNotAppliedBeforeAction(t *testing.T) {
 path:=helperScript(t,"exit 7")
 var out bytes.Buffer
 err:=runPostsuperCommand(context.Background(),path,[]string{"-H","A123"},&out)
 if err==nil {t.Fatal("expected failure")}
 if !errors.Is(err,errReleaseOutcomeUnknown) {t.Fatalf("child may have changed queue state before failure: %v",err)}
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 err=runPostsuperCommand(ctx,path,[]string{"-H","A123"},&out)
 if !errors.Is(err,context.Canceled) || errors.Is(err,errReleaseOutcomeUnknown) {t.Fatalf("pre-execution cancellation misclassified: %v",err)}
 err=runPostsuperCommand(context.Background(),path,[]string{"-H","A123"},nil)
 if err==nil || errors.Is(err,errReleaseOutcomeUnknown) {t.Fatalf("missing sink misclassified: %v",err)}
}
