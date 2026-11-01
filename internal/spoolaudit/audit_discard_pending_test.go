package spoolaudit

import (
 "os"
 "path/filepath"
 "testing"
)

func TestAuditorRecognizesDurableDiscardIntentAndDetectsTampering(t *testing.T) {
 dir := privateDir(t)
 rec := fixture(idA)
 rec.State = "discard_pending"
 rec.StateSHA256 = stateDigest(rec)
 write(t,dir,idA+".json",rec)
 report,err := Audit(dir)
 if err != nil || report.HasFindings() || report.States["discard_pending"] != 1 {
  t.Fatalf("valid pending discard incorrectly flagged: %+v %v",report,err)
 }
 // The auditor must not silently accept an altered state with the old digest.
 rec.State = "queued"
 write(t,dir,idA+".json",rec)
 report,err = Audit(dir)
 if err != nil || !hasCode(report,"unreadable_record") {
  t.Fatalf("tampered pending discard accepted: %+v %v",report,err)
 }
 if _,err := os.Stat(filepath.Join(dir,idA+".json")); err != nil {
  t.Fatalf("read-only audit modified original: %v",err)
 }
}
