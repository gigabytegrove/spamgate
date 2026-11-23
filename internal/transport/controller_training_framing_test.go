package transport

import (
 "io"
 "net/http"
 "net/http/httptest"
 "strings"
 "strconv"
 "testing"
)

type trackingTrainingBody struct {
 io.Reader
 closed bool
}
func (b *trackingTrainingBody) Close() error { b.closed = true; return nil }

func TestControllerTrainingFraming(t *testing.T) {
 cases := []struct {
  name string
  mutate func(*http.Request)
  want int
 }{
  {"ordinary", func(*http.Request){}, http.StatusOK},
  {"unknown-length", func(r *http.Request){r.ContentLength=-1}, http.StatusOK},
  {"negative-length", func(r *http.Request){r.ContentLength=-2}, http.StatusBadRequest},
  {"matching-length", func(r *http.Request){r.Header.Set("Content-Length","7")}, http.StatusOK},
  {"mismatch", func(r *http.Request){r.Header.Set("Content-Length","8")}, http.StatusBadRequest},
  {"duplicate", func(r *http.Request){r.Header["Content-Length"]=[]string{"7","7"}}, http.StatusBadRequest},
  {"mixed-case-duplicate", func(r *http.Request){r.Header=http.Header{"Content-Length":{"7"},"content-length":{"7"}}}, http.StatusBadRequest},
  {"signed-length", func(r *http.Request){r.Header.Set("Content-Length","+7")}, http.StatusBadRequest},
  {"spaced-length", func(r *http.Request){r.Header.Set("Content-Length"," 7")}, http.StatusBadRequest},
  {"overflow-length", func(r *http.Request){r.Header.Set("Content-Length","9999999999999999999999")}, http.StatusBadRequest},
  {"oversized-declared", func(r *http.Request){r.ContentLength=controllerMaxTrainingSampleBytes+1}, http.StatusRequestEntityTooLarge},
  {"oversized-header", func(r *http.Request){r.Header.Set("Content-Length","10485761");r.ContentLength=10485761}, http.StatusRequestEntityTooLarge},
  {"unsupported-transfer", func(r *http.Request){r.TransferEncoding=[]string{"gzip"};r.ContentLength=-1}, http.StatusBadRequest},
  {"multiple-transfer", func(r *http.Request){r.TransferEncoding=[]string{"gzip","chunked"};r.ContentLength=-1}, http.StatusBadRequest},
  {"chunked", func(r *http.Request){r.TransferEncoding=[]string{"chunked"};r.ContentLength=-1}, http.StatusOK},
  {"raw-transfer-encoding", func(r *http.Request){r.Header.Set("Transfer-Encoding","chunked");r.ContentLength=-1}, http.StatusBadRequest},
  {"raw-transfer-encoding-case", func(r *http.Request){r.Header=http.Header{"transfer-encoding":{"chunked"}};r.ContentLength=-1}, http.StatusBadRequest},
  {"raw-trailer", func(r *http.Request){r.Header.Set("Trailer","X-Checksum")}, http.StatusBadRequest},
  {"raw-trailer-case", func(r *http.Request){r.Header=http.Header{"trailer":{"X-Checksum"}}}, http.StatusBadRequest},
  {"populated-trailer", func(r *http.Request){r.Trailer=http.Header{"X-Checksum":{"bad"}}}, http.StatusBadRequest},
  {"chunked-with-trailer", func(r *http.Request){r.TransferEncoding=[]string{"chunked"};r.ContentLength=-1;r.Trailer=http.Header{"X-Checksum":nil}}, http.StatusBadRequest},
  {"chunked-with-length", func(r *http.Request){r.TransferEncoding=[]string{"chunked"}}, http.StatusBadRequest},
  {"chunked-with-header", func(r *http.Request){r.TransferEncoding=[]string{"chunked"};r.ContentLength=-1;r.Header.Set("Content-Length","7")}, http.StatusBadRequest},
 }
 for _, tc := range cases {
  t.Run(tc.name,func(t *testing.T){
   r:=httptest.NewRequest(http.MethodPost,"/learnspam",strings.NewReader("sample!"))
   body:=&trackingTrainingBody{Reader:r.Body}
   r.Body=body
   tc.mutate(r)
   if got:=validateControllerTrainingFraming(r);got!=tc.want {t.Fatalf("framing status %d want %d",got,tc.want)}
   data,got:=readControllerTrainingSample(httptest.NewRecorder(),r)
   if got!=tc.want {t.Fatalf("read status %d want %d",got,tc.want)}
   if !body.closed {t.Fatal("request body not closed")}
   if got!=http.StatusOK && data!=nil {t.Fatal("rejected bytes reached training")}
   if got==http.StatusOK && string(data)!="sample!" {t.Fatalf("unexpected accepted sample %q",data)}
  })
 }
}
func TestControllerTrainingFramingNil(t *testing.T) {
 if got:=validateControllerTrainingFraming(nil);got!=http.StatusBadRequest {t.Fatalf("nil request: %d",got)}
 r:=httptest.NewRequest(http.MethodPost,"/learnspam",nil)
 r.Body=nil
 if got:=validateControllerTrainingFraming(r);got!=http.StatusBadRequest {t.Fatalf("nil body: %d",got)}
}

func TestControllerTrainingDeclaredBodyIntegrity(t *testing.T) {
 for _, tc := range []struct{name string; declared int64; want int}{
  {"short-body",8,http.StatusBadRequest},
  {"excess-body",6,http.StatusBadRequest},
  {"exact-body",7,http.StatusOK},
 } {
  t.Run(tc.name,func(t *testing.T){
   r:=httptest.NewRequest(http.MethodPost,"/learnham",strings.NewReader("sample!"))
   r.ContentLength=tc.declared
   r.Header.Set("Content-Length",strconv.FormatInt(tc.declared,10))
   data,status:=readControllerTrainingSample(httptest.NewRecorder(),r)
   if status!=tc.want {t.Fatalf("status %d want %d",status,tc.want)}
   if status!=http.StatusOK && data!=nil {t.Fatal("mismatched body reached classifier")}
  })
 }
}
