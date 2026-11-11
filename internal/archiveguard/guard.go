// Package archiveguard performs bounded, read-only ZIP inspection. It never extracts files.
package archiveguard

import (
 "archive/zip"
 "errors"
 "fmt"
 "io"
 "path"
 "strings"
)
var ErrLimit = errors.New("archive inspection limit exceeded")
var ErrUnsafe = errors.New("unsafe archive member")

type Limits struct {
 MaxFiles int
 MaxMemberBytes uint64
 MaxTotalBytes uint64
 MaxRatio uint64
}
type Report struct {
 Files int `json:"files"`
 DeclaredBytes uint64 `json:"declared_bytes"`
 ReadBytes uint64 `json:"read_bytes"`
 NestedArchives int `json:"nested_archives"`
}
// Inspect bounds both declared and actually streamed uncompressed bytes.
// A successful inspection is not a malware-clean verdict.
func Inspect(r io.ReaderAt, size int64, limits Limits) (Report, error) {
 var report Report
 if size < 0 || limits.MaxFiles <= 0 || limits.MaxMemberBytes == 0 || limits.MaxTotalBytes == 0 || limits.MaxRatio == 0 {
  return report, fmt.Errorf("invalid archive size or limits")
 }
 if r == nil || limits.MaxMemberBytes > uint64(^uint64(0)>>1)-1 || limits.MaxTotalBytes > uint64(^uint64(0)>>1)-1 { return report, fmt.Errorf("invalid reader or limits") }
 zr, err := zip.NewReader(r, size)
 if err != nil { return report, err }
 if len(zr.File) > limits.MaxFiles { return report, fmt.Errorf("%w: member count", ErrLimit) }
 seen := make(map[string]struct{}, len(zr.File))
 for _, f := range zr.File {
  name := strings.ReplaceAll(f.Name, "\\", "/")
  clean := path.Clean(name)
  if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\x00") || clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(name, ":") {
   return report, fmt.Errorf("%w: member path", ErrUnsafe)
  }
  if f.Flags&1 != 0 { return report, fmt.Errorf("%w: encrypted member", ErrUnsafe) }
  if f.Method != zip.Store && f.Method != zip.Deflate { return report, fmt.Errorf("%w: unsupported compression method %d", ErrUnsafe, f.Method) }
  if clean == "." || strings.HasPrefix(name, "//") || clean != name || strings.HasSuffix(name, "/.") || strings.Contains(name, "//") { return report, fmt.Errorf("%w: invalid member path", ErrUnsafe) }
  key := strings.ToLower(clean)
  if _, exists := seen[key]; exists { return report, fmt.Errorf("%w: duplicate member path", ErrUnsafe) }
  seen[key] = struct{}{}
  if f.Mode()&0o170000 == 0o120000 { return report, fmt.Errorf("%w: symbolic link", ErrUnsafe) }
  if f.FileInfo().IsDir() {
   if !strings.HasSuffix(name, "/") || f.UncompressedSize64 != 0 { return report, fmt.Errorf("%w: malformed directory", ErrUnsafe) }
   continue
  }
  if strings.HasSuffix(name, "/") || !f.Mode().IsRegular() { return report, fmt.Errorf("%w: nonregular member", ErrUnsafe) }
  declared := f.UncompressedSize64
  if declared > limits.MaxMemberBytes || declared > limits.MaxTotalBytes-report.DeclaredBytes {
   return report, fmt.Errorf("%w: declared uncompressed size", ErrLimit)
  }
  if declared > 0 && (f.CompressedSize64 == 0 || declared/f.CompressedSize64 > limits.MaxRatio || (declared/f.CompressedSize64 == limits.MaxRatio && declared%f.CompressedSize64 > 0)) {
   return report, fmt.Errorf("%w: compression ratio", ErrLimit)
  }
  report.DeclaredBytes += declared
  report.Files++
  lower := strings.ToLower(name)
  for _, ext := range []string{".zip", ".7z", ".rar", ".tar", ".gz"} {
   if strings.HasSuffix(lower, ext) { report.NestedArchives++; break }
  }
  rc, err := f.Open()
  if err != nil { return report, err }
  remaining := limits.MaxTotalBytes-report.ReadBytes
  budget := limits.MaxMemberBytes
  if remaining < budget { budget = remaining }
  n, readErr := io.Copy(io.Discard, io.LimitReader(rc, int64(budget)+1))
  closeErr := rc.Close()
  if readErr != nil { return report, readErr }
  if closeErr != nil { return report, closeErr }
  if uint64(n) > budget || uint64(n) != declared { return report, fmt.Errorf("%w: streamed size mismatch", ErrLimit) }
  report.ReadBytes += uint64(n)
 }
 return report, nil
}
