package transport

import (
 "crypto/sha256"
 "encoding/base64"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
)

func TestControllerTrainingContentDigest(t *testing.T) {
 sample := "From: test@example.net\r\nSubject: test\r\n\r\nmessage"
 sum := sha256.Sum256([]byte(sample))
 valid := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
 cases := []struct{name string; headers http.Header; want int}{
  {"absent", nil, http.StatusOK},
  {"valid", http.Header{"Content-Digest":{valid}}, http.StatusOK},
  {"mixed-case-name", http.Header{"content-digest":{valid}}, http.StatusOK},
  {"wrong-digest", http.Header{"Content-Digest":{"sha-256=:" + base64.StdEncoding.EncodeToString(make([]byte,32)) + ":"}}, http.StatusBadRequest},
  {"duplicate", http.Header{"Content-Digest":{valid,valid}}, http.StatusBadRequest},
  {"duplicate-alias", http.Header{"Content-Digest":{valid},"content-digest":{valid}}, http.StatusBadRequest},
  {"other-algorithm", http.Header{"Content-Digest":{"sha-512=:YWJj:"}}, http.StatusBadRequest},
  {"malformed-base64", http.Header{"Content-Digest":{"sha-256=:!:"}}, http.StatusBadRequest},
  {"multiple-members", http.Header{"Content-Digest":{valid+", sha-256=:YWJj:"}}, http.StatusBadRequest},
  {"truncated", http.Header{"Content-Digest":{"sha-256=:YWJj:"}}, http.StatusBadRequest},
  {"empty", http.Header{"Content-Digest":{""}}, http.StatusBadRequest},
 }
 for _, tc := range cases {
  t.Run(tc.name,func(t *testing.T){
   r:=httptest.NewRequest(http.MethodPost,"/learnspam",strings.NewReader(sample))
   r.Header=tc.headers
   got,status:=readControllerTrainingSample(httptest.NewRecorder(),r)
   if status!=tc.want {t.Fatalf("status %d want %d",status,tc.want)}
   if status!=http.StatusOK && got!=nil {t.Fatal("rejected sample leaked")}
   if status==http.StatusOK && string(got)!=sample {t.Fatal("accepted sample corrupted")}
  })
 }
}

func TestControllerTrainingContentDigestNil(t *testing.T) {
 if got:=validateControllerTrainingDigest(nil,nil);got!=http.StatusBadRequest {t.Fatalf("nil status %d",got)}
}
