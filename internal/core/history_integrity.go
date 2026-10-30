package core

import (
 "bufio"
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "time"
)

// HistoryIntegrity is a read-only evidence inventory. It never alters event
// records, retention settings, quarantine, or the on-disk journal. Only the
// authenticated administrator may receive it through the HTTP API.
type HistoryIntegrity struct {
 Status string `json:"status"` // ok, missing, mismatch, corrupt, unreadable
 Detail string `json:"detail"`
 FilePresent bool `json:"file_present"`
 FileBytes int64 `json:"file_bytes"`
 DiskEvents int `json:"disk_events"`
 UniqueScanIDs int `json:"unique_scan_ids"`
 LoadedRetained int `json:"loaded_retained"`
 MissingRetained int `json:"missing_retained"`
 RetentionDays int `json:"retention_days"`
 MaxHistory int `json:"max_history"`
 Oldest time.Time `json:"oldest,omitempty"`
 Newest time.Time `json:"newest,omitempty"`
 SHA256 string `json:"sha256,omitempty"`
}

// AuditHistory performs a bounded-memory disk scan under the Store read lock.
// No content, addresses, subjects or message IDs appear in the result.
func (s *Store) AuditHistory(ctx context.Context) (HistoryIntegrity, error) {
 s.mu.RLock()
 defer s.mu.RUnlock()
 return s.auditHistoryLocked(ctx)
}

func (s *Store) auditHistoryLocked(ctx context.Context) (HistoryIntegrity, error) {
 out := HistoryIntegrity{
  Status:"ok", Detail:"Disk records and loaded retained scans are consistent",
  LoadedRetained:len(s.order),
  RetentionDays:s.cfg.Settings.RetentionDays,
  MaxHistory:s.cfg.Settings.MaxHistory,
 }
 path := filepath.Join(s.dir, "events.jsonl")
 f, err := os.Open(path)
 if errors.Is(err, os.ErrNotExist) {
  out.Status="missing"
  out.Detail="Scan history file is absent; check the configured data directory and any backups"
  if out.LoadedRetained>0 {out.Status="mismatch";out.MissingRetained=out.LoadedRetained}
  return out,nil
 }
 if err!=nil {
  out.Status="unreadable";out.Detail="Unable to open scan history file"
  return out,nil
 }
 defer f.Close()
 info,err:=f.Stat()
 if err!=nil || !info.Mode().IsRegular(){
  out.Status="unreadable";out.Detail="Scan history is not an accessible regular file"
  return out,nil
 }
 out.FilePresent=true
 out.FileBytes=info.Size()
 hash:=sha256.New()
 scanner:=bufio.NewScanner(io.TeeReader(f,hash))
 scanner.Buffer(make([]byte,64*1024),16*1024*1024)
 type event struct {
  ID string `json:"id"`
  Action string `json:"action"`
  Timestamp time.Time `json:"timestamp"`
 }
 last:=make(map[string]event, len(s.order))
 for scanner.Scan() {
  if out.DiskEvents%128==0 {
   if err:=ctx.Err();err!=nil{return HistoryIntegrity{},err}
  }
  var e event
  if err:=json.Unmarshal(scanner.Bytes(),&e);err!=nil || e.ID=="" {
   out.Status="corrupt"
   out.Detail=fmt.Sprintf("Malformed or missing-ID scan event at line %d; original file preserved",out.DiskEvents+1)
   return out,nil
  }
  out.DiskEvents++
  last[e.ID]=e
  if !e.Timestamp.IsZero(){
   if out.Oldest.IsZero()||e.Timestamp.Before(out.Oldest){out.Oldest=e.Timestamp}
   if out.Newest.IsZero()||e.Timestamp.After(out.Newest){out.Newest=e.Timestamp}
  }
 }
 if err:=scanner.Err();err!=nil {
  out.Status="unreadable";out.Detail="Error reading scan history or a record exceeds the supported line size"
  return out,nil
 }
 if err:=ctx.Err();err!=nil{return HistoryIntegrity{},err}
 out.SHA256=hex.EncodeToString(hash.Sum(nil))
 out.UniqueScanIDs=len(last)
 for _,id:=range s.order {
  inMemory:=s.messages[id]
  onDisk,ok:=last[id]
  if !ok||onDisk.Action!=inMemory.Action||!onDisk.Timestamp.Equal(inMemory.Timestamp){
   out.MissingRetained++
  }
 }
 if out.MissingRetained!=0 {
  out.Status="mismatch"
  out.Detail=fmt.Sprintf("%d loaded retained scan(s) are missing or inconsistent on disk; preserve evidence",out.MissingRetained)
 } else if out.DiskEvents==0 {
  out.Detail="History file is empty; there are no scan records on disk"
 } else if out.LoadedRetained==0 {
  out.Detail="Disk contains scan records but none are retained in memory; inspect retention settings"
 } else if out.DiskEvents>out.LoadedRetained {
  out.Detail="Disk includes superseded or expired records; current retained scans match"
 }
 return out,nil
}
