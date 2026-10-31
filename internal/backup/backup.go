package backup

// Offline, integrity-verified backups for SpamGate's standalone data directory.
// Stop SpamGate before creating or restoring a backup. Snapshotting files while
// another process writes can produce a logically inconsistent archive.

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	manifestPath = "spamgate-backup-manifest.json"
	maxFiles     = 100000
	maxBytes     = int64(16) << 30
)

type Entry struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}
type Manifest struct {
	Format  int       `json:"format"`
	Created time.Time `json:"created"`
	Product string    `json:"product"`
	Entries []Entry   `json:"entries"`
}

func safeName(path string) bool {
	return path != "" && path != manifestPath && !strings.HasPrefix(path, "/") && !strings.Contains(path, "\\") && path == filepath.ToSlash(filepath.Clean(path)) &&
		path != "." && path != ".." && !strings.HasPrefix(path, "../") && !strings.Contains(path, "/../") && strings.IndexFunc(path, func(r rune) bool { return r < 0x20 || r == 0x7f }) == -1
}

func Create(source, archive string) (err error) {
	source, err = filepath.Abs(source)
	if err != nil {
		return err
	}
	archive, err = filepath.Abs(archive)
	if err != nil {
		return err
	}
	if archive == source || strings.HasPrefix(archive, source+string(filepath.Separator)) {
		return errors.New("backup destination must be outside the SpamGate data directory")
	}
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("source must be a real data directory")
	}
	if _, err = os.Lstat(archive); err == nil {
		return errors.New("backup destination already exists; refusing overwrite")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// Keep the worker's existing single-writer lock held throughout the
	// snapshot. A live worker must never produce a purportedly consistent
	// offline backup. On Linux this is the same advisory flock primitive.
	release, lockErr := acquireOfflineLock(source)
	if lockErr != nil { return fmt.Errorf("offline backup refused: %w", lockErr) }
	defer release()
	if err = os.MkdirAll(filepath.Dir(archive), 0700); err != nil {
		return err
	}
	// The textual prefix check above cannot detect an archive destination
	// reached through a symlinked parent. Resolve both directory identities
	// before creating a temporary ZIP: otherwise the backup may snapshot its
	// own growing output inside the live data root.
	resolvedSource, resolveErr := filepath.EvalSymlinks(source)
	if resolveErr != nil { return fmt.Errorf("resolve backup source: %w", resolveErr) }
	resolvedParent, resolveErr := filepath.EvalSymlinks(filepath.Dir(archive))
	if resolveErr != nil { return fmt.Errorf("resolve backup destination parent: %w", resolveErr) }
	resolvedArchive := filepath.Join(resolvedParent, filepath.Base(archive))
	if resolvedArchive == resolvedSource || strings.HasPrefix(resolvedArchive, resolvedSource+string(filepath.Separator)) {
		return errors.New("backup destination resolves inside the SpamGate data directory")
	}
	tmp, err := os.CreateTemp(filepath.Dir(archive), ".spamgate-backup-*.tmp")
	if err != nil {
		return err
	}
	defer func() { tmp.Close(); os.Remove(tmp.Name()) }()
	if err = tmp.Chmod(0600); err != nil {
		return err
	}
	zw := zip.NewWriter(tmp)
	manifest := Manifest{Format: 1, Created: time.Now().UTC(), Product: "SpamGate", Entries: []Entry{}}
	var total int64
	walkErr := filepath.WalkDir(source, func(path string, de fs.DirEntry, walkError error) error {
		if walkError != nil {
			return walkError
		}
		if path == source {
			return nil
		}
		info, e := os.Lstat(path)
		if e != nil {
			return e
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink in data: %s", path)
		}
		relative, e := filepath.Rel(source, path)
		if e != nil {
			return e
		}
		relative = filepath.ToSlash(relative)
		// Never archive process-local flock inodes. They are not application
		// state, and restoring root-owned locks can prevent an unprivileged
		// SpamGate worker from starting or accepting/delivering mail.
		// Inspect before skipping so an attacker cannot conceal a directory
		// or symlink by giving it the name of a runtime lock.
		if runtimeLockPath(relative) {
			if !info.Mode().IsRegular() {
				return fmt.Errorf("runtime lock is not a regular file: %s", relative)
			}
			return nil
		}
		if de.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("refusing non-regular data file: %s", path)
		}
		if !safeName(relative) {
			return fmt.Errorf("unsafe data filename: %q", relative)
		}
		if len(manifest.Entries) >= maxFiles || info.Size() > maxBytes-total {
			return errors.New("backup exceeds bounded size or file-count limit")
		}
		f, e := os.Open(path)
		if e != nil {
			return e
		}
		opened, e := f.Stat()
		if e != nil { f.Close(); return e }
		if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
			f.Close()
			return fmt.Errorf("source file changed identity during open: %s", relative)
		}
		w, e := zw.Create(relative)
		if e != nil { f.Close(); return e }
		hash := sha256.New()
		// A growing file must not turn a bounded snapshot into an unbounded copy.
		n, e := io.Copy(io.MultiWriter(w, hash), io.LimitReader(f, info.Size()+1))
		finished, statErr := f.Stat()
		closeErr := f.Close()
		if e == nil { e = statErr }
		if e == nil && (!os.SameFile(info, finished) || finished.Size() != info.Size() || !finished.ModTime().Equal(info.ModTime())) {
			e = fmt.Errorf("source file changed during backup: %s", relative)
		}
		if e == nil {
			e = closeErr
		}
		if e != nil {
			return e
		}
		if n != info.Size() {
			return fmt.Errorf("file changed during backup: %s", relative)
		}
		total += n
		manifest.Entries = append(manifest.Entries, Entry{Path: relative, Bytes: n, SHA256: hex.EncodeToString(hash.Sum(nil))})
		return nil
	})
	if walkErr != nil {
		zw.Close()
		return walkErr
	}
	if len(manifest.Entries) == 0 {
		zw.Close()
		return errors.New("data directory contains no files")
	}
	sort.Slice(manifest.Entries, func(i, j int) bool { return manifest.Entries[i].Path < manifest.Entries[j].Path })
	w, e := zw.Create(manifestPath)
	if e != nil {
		zw.Close()
		return e
	}
	if e = json.NewEncoder(w).Encode(manifest); e != nil {
		zw.Close()
		return e
	}
	if e = zw.Close(); e != nil {
		return e
	}
	if e = tmp.Sync(); e != nil {
		return e
	}
	if e = tmp.Close(); e != nil {
		return e
	}
	// Same-filesystem hard-link publication is atomic and NOREPLACE:
	// a destination created after the initial Lstat must not be overwritten.
	if e = os.Link(tmp.Name(), archive); e != nil {
		return fmt.Errorf("cannot publish backup without overwriting destination: %w", e)
	}
	if runtime.GOOS != "windows" {
		d, openErr := os.Open(filepath.Dir(archive))
		if openErr != nil { return fmt.Errorf("backup published but directory sync failed: %w", openErr) }
		syncErr := d.Sync()
		closeErr := d.Close()
		if syncErr != nil { return fmt.Errorf("backup published but directory sync failed: %w", syncErr) }
		if closeErr != nil { return closeErr }
	}
	return nil
}

func inspect(path string) (Manifest, *zip.ReadCloser, error) {
	// Do not follow a forged backup archive symlink into unrelated host data.
	before, e := os.Lstat(path)
	if e != nil { return Manifest{}, nil, e }
	if !before.Mode().IsRegular() { return Manifest{}, nil, errors.New("backup archive must be a regular file, not a symlink") }
	z, e := zip.OpenReader(path)
	if e != nil {
		return Manifest{}, nil, e
	}
	after, e := os.Lstat(path)
	if e != nil || !os.SameFile(before, after) {
		z.Close()
		return Manifest{}, nil, errors.New("backup archive changed during open")
	}
	fail := func(err error) (Manifest, *zip.ReadCloser, error) { z.Close(); return Manifest{}, nil, err }
	if len(z.File) > maxFiles+1 {
		return fail(errors.New("too many ZIP entries"))
	}
	files := map[string]*zip.File{}
	for _, f := range z.File {
		if f.Name != manifestPath && !safeName(f.Name) {
			return fail(fmt.Errorf("unsafe archive path: %q", f.Name))
		}
		if f.Mode()&os.ModeSymlink != 0 || !f.Mode().IsRegular() {
			return fail(fmt.Errorf("non-regular archive entry %q", f.Name))
		}
		if _, exists := files[f.Name]; exists {
			return fail(fmt.Errorf("duplicate archive entry %q", f.Name))
		}
		files[f.Name] = f
	}
	// A ZIP may contain both "mail" and "mail/message.eml". Such an
	// archive cannot represent a valid directory tree, even if each hash
	// is correct. Reject the topology before extracting any bytes.
	for name := range files {
		for i := strings.LastIndexByte(name, '/'); i >= 0; i = strings.LastIndexByte(name[:i], '/') {
			if _, conflict := files[name[:i]]; conflict {
				return fail(fmt.Errorf("conflicting archive file/directory paths: %q and %q", name[:i], name))
			}
		}
	}
	mf, ok := files[manifestPath]
	if !ok {
		return fail(errors.New("missing backup manifest"))
	}
	if mf.UncompressedSize64 > 1<<20 {
		return fail(errors.New("backup manifest too large"))
	}
	reader, e := mf.Open()
	if e != nil {
		return fail(e)
	}
	data, e := io.ReadAll(io.LimitReader(reader, 1<<20))
	reader.Close()
	if e != nil {
		return fail(e)
	}
	var manifest Manifest
	if e = json.Unmarshal(data, &manifest); e != nil {
		return fail(e)
	}
	if manifest.Format != 1 || manifest.Product != "SpamGate" || len(manifest.Entries) == 0 || len(manifest.Entries) != len(files)-1 {
		return fail(errors.New("unrecognized or incomplete backup manifest"))
	}
	var total uint64
	observed := map[string]bool{}
	for _, entry := range manifest.Entries {
		f, ok := files[entry.Path]
		if !safeName(entry.Path) || !ok || observed[entry.Path] || entry.Bytes < 0 || uint64(entry.Bytes) != f.UncompressedSize64 || len(entry.SHA256) != 64 {
			return fail(fmt.Errorf("invalid manifest entry %q", entry.Path))
		}
		observed[entry.Path] = true
		total, e = addBoundedArchiveBytes(total, f.UncompressedSize64)
		if e != nil { return fail(e) }
		r, e := f.Open()
		if e != nil {
			return fail(e)
		}
		hash := sha256.New()
		n, e := io.Copy(hash, io.LimitReader(r, entry.Bytes+1))
		r.Close()
		if e != nil {
			return fail(e)
		}
		if n != entry.Bytes || hex.EncodeToString(hash.Sum(nil)) != entry.SHA256 {
			return fail(fmt.Errorf("SHA-256 mismatch: %s", entry.Path))
		}
	}
	return manifest, z, nil
}
// addBoundedArchiveBytes checks before adding, so a forged ZIP size cannot
// overflow uint64 and bypass the aggregate 16 GiB restore limit.
func addBoundedArchiveBytes(total, size uint64) (uint64, error) {
	if size > uint64(maxBytes) || total > uint64(maxBytes)-size {
		return total, errors.New("backup exceeds size limit")
	}
	return total + size, nil
}

func Verify(archive string) (Manifest, error) {
	manifest, z, e := inspect(archive)
	if e != nil {
		return Manifest{}, e
	}
	defer z.Close()
	return manifest, nil
}

// Restore only to a path that does not exist. Files are verified before any
// extraction, then staged on the same filesystem and renamed atomically.
func Restore(archive, destination string) error {
	dest, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	if _, err = os.Lstat(dest); err == nil {
		return errors.New("restore destination exists; refusing to overwrite live data")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	manifest, z, err := inspect(archive)
	if err != nil {
		return err
	}
	defer z.Close()
	parent := filepath.Dir(dest)
	if err = os.MkdirAll(parent, 0700); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(parent, ".spamgate-restore-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	files := map[string]*zip.File{}
	for _, f := range z.File {
		files[f.Name] = f
	}
	restoredFiles := 0
	for _, entry := range manifest.Entries {
		// Older backups may contain stale lock inodes. Verify their archive
		// hashes in inspect(), but never restore them to a new worker identity.
		if runtimeLockPath(entry.Path) {
			continue
		}
		target := filepath.Join(stage, filepath.FromSlash(entry.Path))
		if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		r, e := files[entry.Path].Open()
		if e != nil {
			return e
		}
		w, e := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			r.Close()
			return e
		}
		// Verify the bytes actually extracted, not only the earlier archive
		// inspection. The source archive could change between those passes.
		hash := sha256.New()
		n, copyErr := io.Copy(io.MultiWriter(w, hash), io.LimitReader(r, entry.Bytes+1))
		closeReadErr := r.Close()
		if copyErr == nil { copyErr = closeReadErr }
		if copyErr == nil && (n != entry.Bytes || hex.EncodeToString(hash.Sum(nil)) != entry.SHA256) {
			copyErr = fmt.Errorf("restored content failed SHA-256 verification: %s", entry.Path)
		}
		if copyErr == nil { copyErr = w.Sync() }
		closeErr := w.Close()
		if copyErr != nil { return copyErr }
		if closeErr != nil { return closeErr }
		restoredFiles++
	}
	if restoredFiles == 0 {
		return errors.New("backup contains only ephemeral runtime lock files; refusing empty restore")
	}
	if err := syncRestoredTree(stage); err != nil { return fmt.Errorf("restore directory durability: %w", err) }
	return publishRestoredDirectory(stage, dest)
}

