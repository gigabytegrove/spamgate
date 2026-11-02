package backup

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// The permanent policy marker is enforcement evidence, not an optional
// advisory cache file. A ZIP with internally correct hashes but a forged
// marker must not pass Verify only to fail the worker's cold startup.
const (
	backupPolicyMarkerPath = ".delivery-policy.initialized"
	backupPolicyMarkerText = "spamgate-delivery-policy-v1\n"
)

// verifySourcePolicyMarker follows the worker's exact file contract: a
// 0600 regular file, a stable inode across open, and exact marker bytes.
// Never repair, chmod, or rewrite forensic evidence during cold backup.
func verifySourcePolicyMarker(source string) error {
	path := filepath.Join(source, backupPolicyMarkerPath)
	before, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect delivery policy backup marker: %w", err)
	}
	if !before.Mode().IsRegular() || before.Mode().Perm() != 0600 ||
		before.Size() != int64(len(backupPolicyMarkerText)) {
		return errors.New("delivery policy backup marker has unsafe metadata")
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open delivery policy backup marker: %w", err)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return errors.New("delivery policy backup marker changed during open")
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(len(backupPolicyMarkerText)+1)))
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, []byte(backupPolicyMarkerText)) {
		return errors.New("delivery policy backup marker has invalid contents")
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) ||
		!after.ModTime().Equal(before.ModTime()) {
		return errors.New("delivery policy backup marker changed during inspection")
	}
	return nil
}

// ZIP mode bits are not authoritative: the restore path creates private 0600
// files regardless of archive headers. Validate the exact marker payload
// instead, after the archive's per-member SHA-256 has been checked.
func verifyArchivePolicyMarker(files map[string]*zip.File) error {
	member, exists := files[backupPolicyMarkerPath]
	if !exists {
		return nil
	}
	if member.UncompressedSize64 != uint64(len(backupPolicyMarkerText)) {
		return errors.New("delivery policy archive marker has invalid size")
	}
	r, err := member.Open()
	if err != nil {
		return err
	}
	raw, readErr := io.ReadAll(io.LimitReader(r, int64(len(backupPolicyMarkerText)+1)))
	closeErr := r.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if !bytes.Equal(raw, []byte(backupPolicyMarkerText)) {
		return errors.New("delivery policy archive marker has invalid contents")
	}
	return nil
}
