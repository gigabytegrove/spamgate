package transport

import (
 "net"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"

 "github.com/gigabytegrove/spamgate/internal/core"
)

func TestControllerAuthorizationFailClosed(t *testing.T) {
 store, err := core.Open(t.TempDir())
 if err != nil { t.Fatal(err) }
 cidr := &net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(32,32)}
 token := strings.Repeat("s",32)
 cases := []struct {
  name string
  controller *RspamdController
  remote, credential string
  want int
 }{
  {"nil-controller",nil,"127.0.0.1:1234",token,http.StatusServiceUnavailable},
  {"nil-store",&RspamdController{Trusted:[]*net.IPNet{cidr},Token:token},"127.0.0.1:1234",token,http.StatusServiceUnavailable},
  {"invalid-token",&RspamdController{Store:store,Trusted:[]*net.IPNet{cidr},Token:"short"},"127.0.0.1:1234","short",http.StatusServiceUnavailable},
  {"nil-cidr",&RspamdController{Store:store,Trusted:[]*net.IPNet{nil},Token:token},"127.0.0.1:1234",token,http.StatusForbidden},
  {"untrusted",&RspamdController{Store:store,Trusted:[]*net.IPNet{cidr},Token:token},"127.0.0.2:1234",token,http.StatusForbidden},
  {"spoofed-remote",&RspamdController{Store:store,Trusted:[]*net.IPNet{cidr},Token:token},"not-an-address",token,http.StatusForbidden},
  {"bad-password",&RspamdController{Store:store,Trusted:[]*net.IPNet{cidr},Token:token},"127.0.0.1:1234","wrong",http.StatusUnauthorized},
  {"missing-password",&RspamdController{Store:store,Trusted:[]*net.IPNet{cidr},Token:token},"127.0.0.1:1234","",http.StatusUnauthorized},
  {"setup-incomplete",&RspamdController{Store:store,Trusted:[]*net.IPNet{cidr},Token:token},"127.0.0.1:1234",token,http.StatusServiceUnavailable},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   req:=httptest.NewRequest(http.MethodGet,"http://localhost/stat",nil)
   req.RemoteAddr=tc.remote
   if tc.credential!="" { req.Header.Set("Password",tc.credential) }
   req.Header.Set("X-Forwarded-For","127.0.0.1")
   got:=tc.controller.controllerAuthorize(req)
   if got!=tc.want { t.Fatalf("status=%d want=%d",got,tc.want) }
  })
 }
}

func TestControllerRejectsUnauthenticatedRequestsWithoutStore(t *testing.T) {
 controller:=&RspamdController{Token:strings.Repeat("s",32)}
 req:=httptest.NewRequest(http.MethodGet,"http://localhost/ping",nil)
 req.RemoteAddr="127.0.0.1:1234"
 rec:=httptest.NewRecorder()
 controller.Handler().ServeHTTP(rec,req)
 if rec.Code!=http.StatusServiceUnavailable { t.Fatalf("status=%d",rec.Code) }
 if rec.Header().Get("Cache-Control")!="no-store" { t.Fatal("missing no-store") }
 if rec.Header().Get("X-Content-Type-Options")!="nosniff" { t.Fatal("missing nosniff") }
}
