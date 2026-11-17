//go:build linux

package main

import (
 "bytes"
 "context"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

// The privileged helper must never forward child diagnostics on failure:
// Postfix can include addresses, queue identifiers and filesystem paths.
func TestPostsuperFailureDoesNotExposeChildOutput(t *testing.T) {
 dir:=t.TempDir()
 script:=filepath.Join(dir,"postsuper-failure")
 secret:="private-recipient@example.invalid /var/spool/postfix/private/secret"
 if err:=os.WriteFile(script,[]byte("#!/bin/sh\nprintf '%s\\n' '"+secret+"' >&2\nprintf '%s\\n' 'sensitive stdout'\nexit 42\n"),0700);err!=nil{t.Fatal(err)}
 var result bytes.Buffer
 err:=runPostsuperCommand(context.Background(),script,[]string{"-H","ABC123"},&result)
 if err==nil{t.Fatal("failed command was accepted")}
 if !strings.Contains(err.Error(),"exit status 42"){t.Fatalf("lost exit status: %v",err)}
 for _,s:=range []string{secret,"sensitive stdout","private-recipient","/var/spool"}{
  if strings.Contains(err.Error(),s)||strings.Contains(result.String(),s){
   t.Fatalf("child output escaped on failure: %q, result %q",err,result.String())
  }
 }
 if result.Len()!=0{t.Fatalf("failure wrote operator success output: %q",result.String())}
}

func TestPostsuperSuccessPreservesBoundedSanitizedReport(t *testing.T) {
 dir:=t.TempDir()
 script:=filepath.Join(dir,"postsuper-success")
 if err:=os.WriteFile(script,[]byte("#!/bin/sh\nprintf 'released\\n'\n"),0700);err!=nil{t.Fatal(err)}
 var result bytes.Buffer
 if err:=runPostsuperCommand(context.Background(),script,[]string{"-H","ABC123"},&result);err!=nil{t.Fatal(err)}
 if result.String()!="Postfix HOLD release command completed\n"{t.Fatalf("unexpected success report: %q",result.String())}
}

func TestPostsuperRejectsNilSinkBeforeExecution(t *testing.T) {
 dir:=t.TempDir()
 marker:=filepath.Join(dir,"executed")
 script:=filepath.Join(dir,"postsuper-marker")
 if err:=os.WriteFile(script,[]byte("#!/bin/sh\ntouch '"+marker+"'\n"),0700);err!=nil{t.Fatal(err)}
 err:=runPostsuperCommand(context.Background(),script,nil,nil)
 if err==nil{t.Fatal("nil result sink accepted")}
 if _,statErr:=os.Stat(marker);!errors.Is(statErr,os.ErrNotExist){t.Fatalf("command executed before sink validation: %v",statErr)}
}

func TestPostsuperSuccessRedactsSensitiveChildOutput(t *testing.T) {
 dir:=t.TempDir()
 script:=filepath.Join(dir,"postsuper-sensitive-success")
 secret:="recipient@example.invalid /var/spool/postfix/private ABC123"
 if err:=os.WriteFile(script,[]byte("#!/bin/sh\nprintf '%s\\n' '"+secret+"'\nprintf '%s\\n' '"+secret+"' >&2\n"),0700);err!=nil{t.Fatal(err)}
 var result bytes.Buffer
 if err:=runPostsuperCommand(context.Background(),script,[]string{"-H","ABC123"},&result);err!=nil{t.Fatal(err)}
 if strings.Contains(result.String(),secret)||strings.Contains(result.String(),"ABC123"){t.Fatalf("privileged child output leaked on success: %q",result.String())}
 if result.String()!="Postfix HOLD release command completed\n"{t.Fatalf("unexpected confirmation: %q",result.String())}
}
