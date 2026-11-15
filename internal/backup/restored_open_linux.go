//go:build linux

package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// openRestoredRegularNoFollow walks each directory component using directory
// descriptors. O_NOFOLLOW on the leaf alone is insufficient: a concurrent
// replacement of an ancestor with a symlink could redirect the read outside
// the restored tree. Every opened ancestor must be a real directory.
func openRestoredRegularNoFollow(path string) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	clean := filepath.Clean(absolute)
	if clean == string(filepath.Separator) {
		return nil, fmt.Errorf("restored file path is a directory")
	}
	dirfd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = syscall.Close(dirfd) }()
	components := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	for _, component := range components[:len(components)-1] {
		next, openErr := syscall.Openat(dirfd, component, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if openErr != nil {
			return nil, fmt.Errorf("restored file ancestor %q: %w", component, openErr)
		}
		syscall.Close(dirfd)
		dirfd = next
	}
	fd, err := syscall.Openat(dirfd, components[len(components)-1], syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open restored leaf: %w", err)
	}
	// Never return a descriptor for a FIFO, socket, device, or directory.
	// O_NONBLOCK avoids a FIFO read hanging before the type can be checked.
	// A device may still have open-time side effects, so restore directories
	// must remain access-controlled and quiescent during verification.
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("stat restored leaf: %w", err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("restored leaf is not a regular file")
	}
	return os.NewFile(uintptr(fd), path), nil
}
