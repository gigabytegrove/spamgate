package spoolaudit

import (
 "errors"
 "os"
)

// verifyRecordPathStable prevents an audit from accepting a detached inode
// after a concurrent rename, unlink, or pathname substitution. The opened
// descriptor alone cannot prove that the published spool pathname survived.
func verifyRecordPathStable(path string, opened os.FileInfo) error {
 current, err := os.Lstat(path)
 if err != nil {
  return errors.New("spool pathname disappeared during read")
 }
 if !current.Mode().IsRegular() || !os.SameFile(opened,current) {
  return errors.New("spool pathname replaced during read")
 }
 if current.Size()!=opened.Size() || !current.ModTime().Equal(opened.ModTime()) || !sameAuditChangeTime(opened,current) {
  return errors.New("spool pathname metadata changed during read")
 }
 if err:=validateAuditRecordMetadata(path,current);err!=nil {
  return err
 }
 return nil
}
