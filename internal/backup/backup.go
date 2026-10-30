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
		path != "." && path != ".." && !strings.HasPrefix(path, "../") && !strings.Contains(path, "/../")
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
	if err = os.MkdirAll(filepath.Dir(archive), 0700); err != nil {
		return err
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
		if de.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("refusing non-regular data file: %s", path)
		}
		relative, e := filepath.Rel(source, path)
		if e != nil {
			return e
		}
		relative = filepath.ToSlash(relative)
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
		w, e := zw.Create(relative)
		if e != nil {
			return e
		}
		hash := sha256.New()
		n, e := io.Copy(io.MultiWriter(w, hash), f)
		closeErr := f.Close()
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
	z, e := zip.OpenReader(path)
	if e != nil {
		return Manifest{}, nil, e
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
	if manifest.Format != 1 || manifest.Product != "SpamGate" || len(manifest.Entries) != len(files)-1 {
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
		total += f.UncompressedSize64
		if total > uint64(maxBytes) {
			return fail(errors.New("backup exceeds size limit"))
		}
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
	for _, entry := range manifest.Entries {
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
		_, e = io.Copy(w, io.LimitReader(r, entry.Bytes+1))
		if e == nil {
			e = w.Sync()
		}
		closeErr := w.Close()
		r.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return os.Rename(stage, dest)
}
