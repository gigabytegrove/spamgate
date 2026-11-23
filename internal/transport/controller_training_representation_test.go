package transport

import (
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
)

func TestControllerTrainingRepresentation(t *testing.T) {
 tests := []struct{
  name, contentType, encoding string
  want int
 }{
  {"no-content-type", "", "", http.StatusOK},
  {"rfc822", "message/rfc822", "", http.StatusOK},
  {"binary", "application/octet-stream", "", http.StatusOK},
  {"plain", "text/plain", "", http.StatusOK},
  {"mixed-case", "Message/Rfc822", "", http.StatusOK},
  {"multipart", "multipart/form-data; boundary=abc", "", http.StatusUnsupportedMediaType},
  {"json", "application/json", "", http.StatusUnsupportedMediaType},
  {"compressed", "message/rfc822", "gzip", http.StatusUnsupportedMediaType},
  {"identity-encoding", "message/rfc822", "identity", http.StatusUnsupportedMediaType},
  {"parameter", "message/rfc822; charset=utf-8", "", http.StatusUnsupportedMediaType},
  {"invalid", "message/rfc822; charset=", "", http.StatusUnsupportedMediaType},
  {"empty-value", " ", "", http.StatusUnsupportedMediaType},
 }
 for _, tc := range tests {
  t.Run(tc.name,func(t *testing.T){
   r:=httptest.NewRequest(http.MethodPost,"/learnspam",strings.NewReader("From: a@example.test\r\n\r\nbody"))
   if tc.contentType!="" || tc.name=="empty-value" { r.Header.Set("Content-Type",tc.contentType) }
   if tc.encoding!="" {r.Header.Set("Content-Encoding",tc.encoding)}
   if got:=validateControllerTrainingRepresentation(r);got!=tc.want {t.Fatalf("representation status %d want %d",got,tc.want)}
   data,got:=readControllerTrainingSample(httptest.NewRecorder(),r)
   if got!=tc.want {t.Fatalf("read status %d want %d",got,tc.want)}
   if got!=http.StatusOK && data!=nil {t.Fatal("rejected sample leaked to classifier")}
  })
 }
}

func TestControllerTrainingRepresentationDuplicateHeaders(t *testing.T) {
 for _, header := range []string{"Content-Type","Content-Encoding"} {
  t.Run(header,func(t *testing.T){
   r:=httptest.NewRequest(http.MethodPost,"/learnham",strings.NewReader("sample"))
   r.Header.Add(header,"message/rfc822")
   r.Header.Add(header,"message/rfc822")
   if got:=validateControllerTrainingRepresentation(r);got!=http.StatusUnsupportedMediaType {
    t.Fatalf("duplicate %s accepted: %d",header,got)
   }
  })
 }
 r:=httptest.NewRequest(http.MethodPost,"/learnspam",strings.NewReader("sample"))
 r.Header = http.Header{"Content-Type":{"message/rfc822"},"content-type":{"application/json"}}
 if got:=validateControllerTrainingRepresentation(r);got!=http.StatusUnsupportedMediaType {t.Fatalf("mixed-case duplicate content type accepted: %d",got)}
 r.Header = http.Header{"content-encoding":{"gzip"}}
 if got:=validateControllerTrainingRepresentation(r);got!=http.StatusUnsupportedMediaType {t.Fatalf("noncanonical content encoding accepted: %d",got)}
 if got:=validateControllerTrainingRepresentation(nil);got!=http.StatusBadRequest {t.Fatalf("nil request: %d",got)}
}
