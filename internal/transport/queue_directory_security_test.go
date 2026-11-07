package transport

import (
 "os"
 "path/filepath"
 "runtime"
 "testing"
)

func TestDeliveryQueueDirectoryPermissions(t *testing.T) {
 if runtime.GOOS == "windows" { t.Skip("POSIX directory permissions") }
 root := t.TempDir()
 for _, tc := range []struct{
  name string
  mode os.FileMode
  reject bool
 }{
  {"private", 0700, false},
  {"owner-readonly", 0500, false},
  {"group-readable", 0750, true},
  {"world-readable", 0705, true},
  {"group-writable", 0730, true},
  {"world-writable", 0703, true},
  {"public-default", 0755, true},
 } {
  t.Run(tc.name, func(t *testing.T) {
   path := filepath.Join(root, tc.name)
   if err := os.Mkdir(path, 0700); err != nil { t.Fatal(err) }
   if err := os.Chmod(path, tc.mode); err != nil { t.Fatal(err) }
   info, err := os.Lstat(path)
   if err != nil { t.Fatal(err) }
   if got := validateDeliveryQueueDirectory(info); (got != nil) != tc.reject {
    t.Fatalf("mode %04o: error %v, reject=%v", tc.mode, got, tc.reject)
   }
  })
 }
}

func TestDeliveryQueueDirectoryRejectsNonDirectoryAndSymlink(t *testing.T) {
 if runtime.GOOS == "windows" { t.Skip("POSIX symlink semantics") }
 root := t.TempDir()
 file := filepath.Join(root, "regular")
 if err := os.WriteFile(file, []byte("x"), 0600); err != nil { t.Fatal(err) }
 link := filepath.Join(root, "link")
 if err := os.Symlink(root, link); err != nil { t.Fatal(err) }
 for _, path := range []string{file, link} {
  info, err := os.Lstat(path)
  if err != nil { t.Fatal(err) }
  if err := validateDeliveryQueueDirectory(info); err == nil { t.Fatalf("accepted %s", path) }
 }
 if err := validateDeliveryQueueDirectory(nil); err == nil { t.Fatal("accepted nil metadata") }
}
