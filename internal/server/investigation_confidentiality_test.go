package server

import (
 "net/http"
 "net/http/httptest"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "github.com/gigabytegrove/spamgate/internal/core"
)

// A missing configured mail log must never disclose its filesystem path to
// an authenticated investigation client.
func TestInvestigationDoesNotDisclosePostfixLogPath(t *testing.T) {
 st, err := core.Open(t.TempDir())
 if err != nil { t.Fatal(err) }
 if err := st.UpdateConfig(func(c *core.Config) error {
  c.SetupComplete = true
  c.Users = []core.User{{Name:"admin", Role:"admin"}}
  return nil
 }); err != nil { t.Fatal(err) }
 m := core.Message{ID:core.ID(), Timestamp:time.Now(), Connector:"milter", MTAQueueID:"A1B2C3D4", Action:"accept"}
 if err := st.Save(m); err != nil { t.Fatal(err) }
 secret := filepath.Join(t.TempDir(),"private-mailhost-credentials.log")
 t.Setenv("SPAMGATE_POSTFIX_LOG_PATH", secret)
 t.Setenv("SPAMGATE_POSTFIX_HOLD_INVENTORY", "false")
 srv := New(st,nil)
 srv.sessions["admin-cookie"] = session{Identity:Identity{Name:"admin",Role:"admin",Session:true},Expires:time.Now().Add(time.Hour)}
 req := httptest.NewRequest(http.MethodGet,"/api/v1/messages/"+m.ID+"/investigation",nil)
 req.AddCookie(&http.Cookie{Name:"spamgate_session",Value:"admin-cookie"})
 w := httptest.NewRecorder()
 srv.Router().ServeHTTP(w,req)
 if w.Code != http.StatusOK {t.Fatalf("investigation status %d: %s",w.Code,w.Body.String())}
 if strings.Contains(w.Body.String(),secret) || strings.Contains(w.Body.String(), "private-mailhost-credentials") {
  t.Fatalf("backend log path disclosed: %s",w.Body.String())
 }
 if !strings.Contains(w.Body.String(),"check server logs") {
  t.Fatalf("missing actionable sanitized diagnostic: %s",w.Body.String())
 }
}

func TestRawHeadersNoStoreEvenWhenUnauthorized(t *testing.T) {
 st,err:=core.Open(t.TempDir())
 if err!=nil {t.Fatal(err)}
 if err:=st.UpdateConfig(func(c *core.Config) error {c.SetupComplete=true;return nil});err!=nil {t.Fatal(err)}
 srv:=New(st,nil)
 req:=httptest.NewRequest(http.MethodGet,"/api/v1/messages/unknown/headers",nil)
 w:=httptest.NewRecorder()
 srv.Router().ServeHTTP(w,req)
 if w.Code!=http.StatusUnauthorized {t.Fatalf("unexpected status %d",w.Code)}
 if w.Header().Get("Cache-Control")!="no-store" {t.Fatalf("unauthorized headers cache policy: %q",w.Header().Get("Cache-Control"))}
}
