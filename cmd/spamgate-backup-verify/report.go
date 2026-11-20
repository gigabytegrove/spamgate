package main

import (
 "encoding/json"
 "errors"
 "fmt"
 "io"
)

// backupResult contains only aggregate counts; no paths, keys, message data,
// or manifest contents may enter automation output.
type backupResult struct {
 Operation string `json:"operation"`
 Status string `json:"status"`
 Files int64 `json:"files"`
 Bytes int64 `json:"bytes"`
 MailServicesChanged bool `json:"mail_services_changed"`
}

func writeBackupResult(out io.Writer, format, operation string, files, bytes int64) error {
 if out == nil { return errors.New("result writer required") }
 if operation != "verify" && operation != "restore" { return errors.New("invalid backup operation") }
 if files < 0 || bytes < 0 { return errors.New("negative backup totals") }
 switch format {
 case "text":
  _, err := fmt.Fprintf(out, "%s successful: %d files, %d bytes; no mail services changed\n", operation, files, bytes)
  return err
 case "json":
  return json.NewEncoder(out).Encode(backupResult{Operation:operation,Status:"success",Files:files,Bytes:bytes,MailServicesChanged:false})
 default:
  return errors.New("output must be text or json")
 }
}
