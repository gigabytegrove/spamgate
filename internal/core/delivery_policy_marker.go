package core

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// This marker is permanent enforcement evidence. It is not a lock and must
// never be automatically removed or recreated after corruption. A worker
// starting before another worker's first write must still detect later loss.
const deliveryPolicyMarkerName = ".delivery-policy.initialized"
const deliveryPolicyMarkerContents = "spamgate-delivery-policy-v1\n"

func deliveryPolicyMarkerExists(dir string) (bool, error) {
	path := filepath.Join(dir, deliveryPolicyMarkerName)
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm() != 0600 ||
		before.Size() != int64(len(deliveryPolicyMarkerContents)) {
		return false, errors.New("delivery policy initialization evidence has unsafe metadata")
	}
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return false, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return false, errors.New("delivery policy initialization evidence changed during open")
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(len(deliveryPolicyMarkerContents)+1)))
	if err != nil {
		return false, err
	}
	if !bytes.Equal(data, []byte(deliveryPolicyMarkerContents)) {
		return false, errors.New("delivery policy initialization evidence has invalid contents")
	}
	return true, nil
}

// Caller holds the persistent Linux policy lock. O_EXCL refuses existing
// symlinks or other objects; never truncate evidence left by a failed write.
// The file and its parent directory are synced before state publication.
func createDeliveryPolicyMarker(dir string) error {
	path := filepath.Join(dir, deliveryPolicyMarkerName)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create immutable delivery policy initialization evidence: %w", err)
	}
	if _, err := f.WriteString(deliveryPolicyMarkerContents); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return syncAtomicParent(path)
}
