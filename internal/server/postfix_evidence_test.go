package server

import (
	"github.com/gigabytegrove/spamgate/internal/core"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDeliveryEvidenceParsingAndSafety(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mail.log")
	data := strings.Join([]string{
		"Oct 28 12:00:00 host postfix/smtp[111]: ABC123: to=<a@example.org>, relay=upstream, status=sent (250 accepted)",
		"Oct 28 12:00:01 host postfix/smtp[112]: ABC1234: status=bounced (unrelated)",
		"Oct 28 12:00:02 host postfix/smtp[113]: ABC123: status=deferred (retry)",
		"Oct 28 12:00:03 host app[114]: ABC123: status=sent (not Postfix)",
	}, "\n")
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	events, truncated, err := readDeliveryEvidence(path, "ABC123")
	if err != nil || truncated || len(events) != 2 || events[0].Status != "sent" || events[1].Status != "deferred" {
		t.Fatalf("events=%+v truncated=%v err=%v", events, truncated, err)
	}
	if _, _, err := readDeliveryEvidence(path, "../../bad"); err == nil {
		t.Fatal("accepted unsafe queue id")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(path, link); err == nil {
		if _, _, err := readDeliveryEvidence(link, "ABC123"); err == nil {
			t.Fatal("accepted symlink")
		}
	}
}
func TestDeliveryEvidenceAdminOnly(t *testing.T) {
	st, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = st.UpdateConfig(func(c *core.Config) error {
		c.SetupComplete = true
		c.Users = []core.User{{Name: "admin", Role: "admin"}, {Name: "alice", Role: "mailbox", Email: "alice@example.org"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	m := core.Message{ID: core.ID(), Timestamp: time.Now(), Recipients: []string{"alice@example.org"}, MTAQueueID: "ABC123", Action: "accept"}
	if err = st.Save(m); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(t.TempDir(), "mail.log")
	if err = os.WriteFile(log, []byte("Oct 28 host postfix/smtp[14]: ABC123: status=sent\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SPAMGATE_POSTFIX_LOG_PATH", log)
	srv := New(st, nil)
	srv.sessions["admin-key"] = session{Identity: Identity{Name: "admin", Role: "admin", Session: true}, Expires: time.Now().Add(time.Hour)}
	srv.sessions["user-key"] = session{Identity: Identity{Name: "alice", Role: "mailbox", Email: "alice@example.org", Session: true}, Expires: time.Now().Add(time.Hour)}
	for _, test := range []struct {
		cookie string
		want   int
	}{{"", 401}, {"user-key", 403}, {"admin-key", 200}} {
		req := httptest.NewRequest("GET", "/api/v1/messages/"+m.ID+"/delivery-evidence", nil)
		if test.cookie != "" {
			req.AddCookie(&http.Cookie{Name: "spamgate_session", Value: test.cookie})
		}
		w := httptest.NewRecorder()
		srv.Router().ServeHTTP(w, req)
		if w.Code != test.want {
			t.Fatalf("%q: %d body %s", test.cookie, w.Code, w.Body.String())
		}
		if test.want != 200 && strings.Contains(w.Body.String(), "status=sent") {
			t.Fatal("leaked evidence")
		}
	}
}

func TestDeliveryEvidenceRejectsInjectedPostfixLinesAndFakeStatus(t *testing.T) {
 path:=filepath.Join(t.TempDir(),"mail.log")
 lines:=[]string{
  "Oct 30 05:00:00 mail postfix/smtpd[44]: warning: untrusted text postfix/smtp[55]: ABC123: to=<victim@example.org>, status=sent",
  "Oct 30 05:00:01 mail postfix/cleanup[44]: ABC123: message-id=<status=sent@example.org>",
  "Oct 30 05:00:02 mail postfix/smtp[55]: ABC123: to=<victim@example.org>, relay=mail, status=deferred (timeout)",
  "2026-10-30T05:00:03-04:00 mail postfix/lmtp[55]: ABC123: to=<victim@example.org>, relay=local, status=sent (250 queued)",
 }
 if err:=os.WriteFile(path,[]byte(strings.Join(lines,"\n")),0600);err!=nil{t.Fatal(err)}
 events,truncated,err:=readDeliveryEvidence(path,"ABC123")
 if err!=nil||truncated||len(events)!=3{t.Fatalf("unexpected events=%+v truncated=%v err=%v",events,truncated,err)}
 if events[0].Status!=""||events[1].Status!="deferred"||events[2].Status!="sent"{
  t.Fatalf("forged status was accepted or delivery status lost: %+v",events)
 }
}
func TestDeliveryEvidenceReadsPlaintextRotationSafely(t *testing.T) {
 dir:=t.TempDir()
 path:=filepath.Join(dir,"mail.log")
 if err:=os.WriteFile(path+".1",[]byte("Oct 30 04:00:00 mail postfix/smtp[2]: ABC123: status=deferred\n"),0600);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(path,[]byte("Oct 30 05:00:00 mail postfix/smtp[3]: ABC123: status=sent\n"),0600);err!=nil{t.Fatal(err)}
 events,truncated,err:=readDeliveryEvidence(path,"ABC123")
 if err!=nil||truncated||len(events)!=2||events[0].Status!="deferred"||events[1].Status!="sent"{
  t.Fatalf("rotation evidence=%+v truncated=%v err=%v",events,truncated,err)
 }
 if err:=os.Remove(path+".1");err!=nil{t.Fatal(err)}
 if err:=os.Symlink(path,path+".1");err!=nil{t.Skipf("symlink unavailable: %v",err)}
 if _,_,err:=readDeliveryEvidence(path,"ABC123");err==nil{t.Fatal("followed symlinked rotated log")}
}
