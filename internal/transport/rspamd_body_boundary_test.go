package transport

import (
 "errors"
 "io"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
)

type failingRspamdBody struct{ reads int }
func (b *failingRspamdBody) Read(_ []byte) (int,error) { b.reads++; return 0,errors.New("upstream connection interrupted") }
func (b *failingRspamdBody) Close() error { return nil }

func TestRspamdCheckRejectsBadPeerBeforeReadingBody(t *testing.T) {
 body:= &failingRspamdBody{}
 r:=httptest.NewRequest(http.MethodPost,"/checkv2",nil)
 r.Body=body
 r.Header.Set("From","sender@example.test")
 r.Header.Set("IP","::ffff:192.0.2.1")
 w:=httptest.NewRecorder()
 (&RspamdWorker{}).check(w,r)
 if w.Code!=http.StatusBadRequest { t.Fatalf("status=%d body=%s",w.Code,w.Body.String()) }
 if body.reads!=0 { t.Fatalf("untrusted request body read %d times",body.reads) }
}

func TestRspamdCheckRejectsDeclaredOversizeBeforeReadingBody(t *testing.T) {
 body:= &failingRspamdBody{}
 r:=httptest.NewRequest(http.MethodPost,"/checkv2",nil)
 r.Body=body
 r.ContentLength=10<<20+1
 r.Header.Set("From","sender@example.test")
 r.Header.Set("IP","192.0.2.1")
 w:=httptest.NewRecorder()
 (&RspamdWorker{}).check(w,r)
 if w.Code!=http.StatusRequestEntityTooLarge { t.Fatalf("status=%d body=%s",w.Code,w.Body.String()) }
 if body.reads!=0 { t.Fatalf("oversized request body read %d times",body.reads) }
}

func TestRspamdCheckDistinguishesInterruptedBodyFromOversize(t *testing.T) {
 r:=httptest.NewRequest(http.MethodPost,"/checkv2",nil)
 r.Body=&failingRspamdBody{}
 r.Header.Set("From","sender@example.test")
 r.Header.Set("IP","192.0.2.1")
 w:=httptest.NewRecorder()
 (&RspamdWorker{}).check(w,r)
 if w.Code!=http.StatusBadRequest { t.Fatalf("status=%d body=%s",w.Code,w.Body.String()) }
 if !strings.Contains(w.Body.String(),"could not be read") { t.Fatalf("unexpected response: %s",w.Body.String()) }
}

func TestRspamdCheckRejectsStreamingOversize(t *testing.T) {
 r:=httptest.NewRequest(http.MethodPost,"/checkv2",io.NopCloser(strings.NewReader(strings.Repeat("x",10<<20+1))))
 r.ContentLength=-1
 r.Header.Set("From","sender@example.test")
 r.Header.Set("IP","192.0.2.1")
 w:=httptest.NewRecorder()
 (&RspamdWorker{}).check(w,r)
 if w.Code!=http.StatusRequestEntityTooLarge { t.Fatalf("status=%d body=%s",w.Code,w.Body.String()) }
}
