//go:build linux

package backup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRestoredRegularNoFollowRejectsAncestorSymlink(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "message"), []byte("mail"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	if f, err := openRestoredRegularNoFollow(filepath.Join(root, "alias", "message")); err == nil {
		f.Close()
		t.Fatal("followed ancestor symlink")
	}
	f, err := openRestoredRegularNoFollow(filepath.Join(real, "message"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRestoredRegularNoFollowRejectsLeafSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "message"), []byte("mail"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("message", filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	if f, err := openRestoredRegularNoFollow(filepath.Join(root, "alias")); err == nil {
		f.Close()
		t.Fatal("followed leaf symlink")
	}
}
