package backupverify

import (
 "bytes"
 "context"
 "errors"
 "io"
 "os"
 "path/filepath"
 "testing"
)

type cancelOnRead struct {
 cancel context.CancelFunc
}
func (r cancelOnRead) Read(p []byte) (int,error) {
 r.cancel()
 return 0, io.EOF
}

func TestVerificationReaderCancellation(t *testing.T) {
 ctx,cancel:=context.WithCancel(context.Background())
 reader:=&verificationContextReader{ctx:ctx,reader:cancelOnRead{cancel:cancel}}
 buf:=make([]byte,8)
 if _,err:=reader.Read(buf);!errors.Is(err,context.Canceled) { t.Fatalf("expected cancellation, got %v",err) }
}

func TestVerifyCompleteContextCancellation(t *testing.T) {
 root:=t.TempDir()
 if err:=os.WriteFile(filepath.Join(root,"message"),[]byte("message"),0600);err!=nil { t.Fatal(err) }
 key:=bytes.Repeat([]byte{0x37},32)
 signed,err:=CreateSignedInventory(root,key)
 if err!=nil { t.Fatal(err) }
 ctx,cancel:=context.WithCancel(context.Background())
 cancel()
 if _,err:=VerifyCompleteContext(ctx,root,signed,key);!errors.Is(err,context.Canceled) { t.Fatalf("expected cancellation, got %v",err) }
 if _,err:=BuildInventoryContext(ctx,root);!errors.Is(err,context.Canceled) { t.Fatalf("inventory cancellation: %v",err) }
 if _,err:=VerifyContext(ctx,root,signed.Manifest);!errors.Is(err,context.Canceled) { t.Fatalf("file verification cancellation: %v",err) }
 if _,err:=VerifyCompleteContext(nil,root,signed,key);err==nil { t.Fatal("nil context accepted") }
 if _,err:=VerifyCompleteContext(context.Background(),root,signed,key);err!=nil { t.Fatalf("valid backup rejected: %v",err) }
}
