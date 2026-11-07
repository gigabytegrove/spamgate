package transport

import (
    "os"
    "path/filepath"
    "runtime"
    "testing"
)

func TestDeliveryQueueDirectoryPathValidatesOpenedDirectory(t *testing.T) {
    if runtime.GOOS == "windows" { t.Skip("POSIX permissions and symlinks") }
    root := t.TempDir()
    good := filepath.Join(root, "good")
    if err := os.Mkdir(good, 0700); err != nil { t.Fatal(err) }
    if err := validateDeliveryQueueDirectoryPath(good); err != nil {
        t.Fatalf("private directory rejected: %v", err)
    }
    bad := filepath.Join(root, "public")
    if err := os.Mkdir(bad, 0700); err != nil { t.Fatal(err) }
    if err := os.Chmod(bad, 0755); err != nil { t.Fatal(err) }
    if err := validateDeliveryQueueDirectoryPath(bad); err == nil {
        t.Fatal("accepted publicly accessible directory")
    }
    link := filepath.Join(root, "link")
    if err := os.Symlink(good, link); err != nil { t.Fatal(err) }
    if err := validateDeliveryQueueDirectoryPath(link); err == nil {
        t.Fatal("accepted symlink to otherwise private directory")
    }
    file := filepath.Join(root, "regular")
    if err := os.WriteFile(file, []byte("not a directory"), 0600); err != nil { t.Fatal(err) }
    if err := validateDeliveryQueueDirectoryPath(file); err == nil {
        t.Fatal("accepted regular file")
    }
    if err := validateDeliveryQueueDirectoryPath(filepath.Join(root, "missing")); err == nil {
        t.Fatal("accepted missing directory")
    }
}

// A descriptor referring to the original directory must not be accepted
// after its pathname is replaced by a different directory. This exercises
// the same inode-identity contract used by the startup validator.
func TestDeliveryQueueDirectoryReplacementChangesIdentity(t *testing.T) {
    if runtime.GOOS == "windows" { t.Skip("POSIX rename semantics") }
    root := t.TempDir()
    path := filepath.Join(root, "queue")
    if err := os.Mkdir(path, 0700); err != nil { t.Fatal(err) }
    before, err := os.Lstat(path)
    if err != nil { t.Fatal(err) }
    if err := os.Rename(path, filepath.Join(root, "old")); err != nil { t.Fatal(err) }
    if err := os.Mkdir(path, 0700); err != nil { t.Fatal(err) }
    fd, err := os.Open(path)
    if err != nil { t.Fatal(err) }
    defer fd.Close()
    after, err := fd.Stat()
    if err != nil { t.Fatal(err) }
    if os.SameFile(before, after) {
        t.Fatal("replaced directory has same identity as inspected directory")
    }
}
