// Package backupverify provides read-only verification of native SpamGate
// data backups before an operator attempts a restore.
package backupverify

import (
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "io"
 "os"
 "path"
 "strings"
)

const MaxFiles = 100000
const MaxFileSize int64 = 1 << 40

type Entry struct {
 Path string `json:"path"`
 Size int64 `json:"size"`
 SHA256 string `json:"sha256"`
}
type Manifest struct {
 Version int `json:"version"`
 Files []Entry `json:"files"`
 Directories []string `json:"directories,omitempty"`
}
type Report struct {
 Files int `json:"files"`
 Bytes int64 `json:"bytes"`
}

// ValidateManifest rejects ambiguous, unsafe or impossible file inventories.
func ValidateManifest(m Manifest) error {
 if m.Version != 1 && m.Version != 2 { return errors.New("unsupported manifest version") }
 if m.Version == 1 && len(m.Directories) != 0 { return errors.New("v1 manifest cannot contain directories") }
 if len(m.Directories) > MaxFiles { return errors.New("too many backup directories") }
 var dirs map[string]bool
 if m.Version == 2 {
  dirs = make(map[string]bool, len(m.Directories))
  for _, dir := range m.Directories {
   if dir == "" || dir == "." || path.IsAbs(dir) || path.Clean(dir) != dir || strings.ContainsAny(dir, "\\:\x00") || dir == ".." || strings.HasPrefix(dir, "../") { return fmt.Errorf("unsafe backup directory %q", dir) }
   if dirs[dir] { return fmt.Errorf("duplicate backup directory %q", dir) }
   dirs[dir] = true
  }
  for dir := range dirs {
   for parent := path.Dir(dir); parent != "."; parent = path.Dir(parent) {
    if !dirs[parent] { return fmt.Errorf("missing parent directory %q", parent) }
   }
  }
 }
 if len(m.Files)==0 || len(m.Files)>MaxFiles { return errors.New("invalid manifest file count") }
 seen:=make(map[string]bool,len(m.Files))
 for _, e:=range m.Files {
  if e.Path=="" || strings.Contains(e.Path,"\\") || strings.ContainsRune(e.Path,0) ||
    path.IsAbs(e.Path) || path.Clean(e.Path)!=e.Path || e.Path=="." ||
    e.Path==".." || strings.HasPrefix(e.Path,"../") ||
    strings.HasPrefix(e.Path,"/") || strings.Contains(e.Path,":") {
   return fmt.Errorf("unsafe backup path %q",e.Path)
  }
  if seen[e.Path] { return fmt.Errorf("duplicate backup path %q",e.Path) }
  seen[e.Path]=true
  if e.Size<0 || e.Size>MaxFileSize { return fmt.Errorf("invalid size for %q",e.Path) }
  if len(e.SHA256)!=64 { return fmt.Errorf("invalid digest for %q",e.Path) }
  decoded,err:=hex.DecodeString(e.SHA256)
  if err!=nil || len(decoded)!=sha256.Size || hex.EncodeToString(decoded)!=e.SHA256 {
   return fmt.Errorf("invalid digest for %q",e.Path)
  }
 }
 for name:=range seen {
  if m.Version == 2 {
   for parent:=path.Dir(name);parent!=".";parent=path.Dir(parent) {
    if !dirs[parent] { return fmt.Errorf("file parent directory absent from manifest %q",parent) }
   }
   if dirs[name] { return fmt.Errorf("file/directory collision at %q",name) }
  }
  for parent:=path.Dir(name);parent!=".";parent=path.Dir(parent) {
   if seen[parent] { return fmt.Errorf("file/directory collision at %q",parent) }
  }
 }
 return nil
}

// Verify checks only regular files under root. It refuses symlinks at every
// path component and uses O_NOFOLLOW on Linux to prevent final-link traversal.
// It never writes, deletes, extracts, or changes the running mail server.
func Verify(root string,m Manifest)(Report,error) {
 var report Report
 if err:=ValidateManifest(m);err!=nil{return report,err}
 info,err:=os.Lstat(root)
 if err!=nil{return report,err}
 if !info.IsDir() || info.Mode()&os.ModeSymlink!=0{return report,errors.New("backup root must be a real directory")}
 for _,e:=range m.Files {
  f,err:=openVerifiedPath(root,e.Path)
  if err!=nil{return report,err}
  st,err:=f.Stat()
  if err!=nil{f.Close();return report,err}
  if !st.Mode().IsRegular() || st.Size()!=e.Size {
   f.Close()
   return report,fmt.Errorf("type or size mismatch %q",e.Path)
  }
  before:=st.ModTime()
  h:=sha256.New()
  n,readErr:=io.Copy(h,io.LimitReader(f,e.Size+1))
  after,statErr:=f.Stat()
  closeErr:=f.Close()
  if statErr!=nil{return report,statErr}
  if !os.SameFile(st,after) || st.Size()!=after.Size() || !before.Equal(after.ModTime()) {return report,fmt.Errorf("backup file changed during verification %q",e.Path)}
  if readErr!=nil{return report,readErr}
  if closeErr!=nil{return report,closeErr}
  if n!=e.Size || hex.EncodeToString(h.Sum(nil))!=e.SHA256 {return report,fmt.Errorf("checksum mismatch %q",e.Path)}
  report.Files++
  report.Bytes+=n
 }
 return report,nil
}
