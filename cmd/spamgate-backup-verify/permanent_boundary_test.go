package main

import (
 "bytes"
 "os"
 "path/filepath"
 "testing"
)

func TestPermanentDataRestoreBoundaryCannotBeOverridden(t *testing.T) {
 base := t.TempDir()
 active := filepath.Join(base, "different-active")
 backup := filepath.Join(base, "backup")
 if err := os.Mkdir(active, 0700); err != nil { t.Fatal(err) }
 if err := os.Mkdir(backup, 0700); err != nil { t.Fatal(err) }
 cases := []string{"/opt/spamgate/data", "/opt/spamgate/data/child", "/opt/spamgate", "/opt"}
 for _, target := range cases {
  t.Run(target, func(t *testing.T) {
   var output bytes.Buffer
   err := run([]string{"-operation","restore","-backup",backup,"-manifest",filepath.Join(base,"nonexistent-manifest"),"-key-file",filepath.Join(base,"nonexistent-key"),"-active-data",active,"-target",target}, &output)
   if err == nil { t.Fatal("unsafe restore destination accepted") }
   if output.Len() != 0 { t.Fatalf("unexpected success output: %q",output.String()) }
  })
 }
}
