package updater

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// ensureUpdateDir prevents the updater from following a substituted updates
// directory symlink. Never silently relax the existing directory's permissions.
func ensureUpdateDir(dir string, create bool) error {
	if create {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("update directory must be a real directory")
	}
	if info.Mode().Perm()&0022 != 0 {
		return errors.New("update directory must not be group/world writable")
	}
	return nil
}

// syncUpdateDir makes the renamed update metadata durable on Linux. The
// Windows filesystem has different directory-sync semantics.
func syncUpdateDir(dir string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	closeErr := d.Close()
	if err != nil {
		return err
	}
	return closeErr
}

// atomicUpdateFile publishes a fully written, fsynced file by renaming over
// the old name. Rename replaces a malicious destination symlink itself,
// whereas os.WriteFile would follow that symlink and corrupt its target.
func atomicUpdateFile(dir, name string, content []byte, mode os.FileMode) error {
	if name == "" || filepath.Base(name) != name || name == "." || name == ".." {
		return errors.New("invalid update filename")
	}
	if err := ensureUpdateDir(dir, true); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".spamgate-update-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	n, err := tmp.Write(content)
	if err == nil && n != len(content) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		return err
	}
	if err := syncUpdateDir(dir); err != nil {
		return fmt.Errorf("update file published but directory sync failed: %w", err)
	}
	return nil
}

// openUpdateRegularFile checks identity across Lstat and Open. A symlinked
// metadata file or binary is never accepted as a staged update.
func openUpdateRegularFile(path string) (*os.File, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, nil, errors.New("update file must be regular, not a symlink")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		f.Close()
		return nil, nil, errors.New("update file changed identity during open")
	}
	return f, after, nil
}

func readUpdateRegularFile(path string, limit int64) ([]byte, error) {
	f, before, err := openUpdateRegularFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if before.Size() < 0 || before.Size() > limit {
		return nil, errors.New("update metadata exceeds size limit")
	}
	content, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > limit {
		return nil, errors.New("update metadata exceeds size limit")
	}
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, errors.New("update metadata changed during read")
	}
	return content, nil
}
