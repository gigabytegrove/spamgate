package core

import (
 "bufio"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "path/filepath"
)

// Called with both the Store mutex and the native cross-process journal lease.
// A stale Store must never compact another process's accepted-mail evidence.
func (s *Store) refreshHistoryLocked() error {
 path:=filepath.Join(s.dir,"events.jsonl")
 before,err:=os.Lstat(path)
 if errors.Is(err,os.ErrNotExist) {
  if s.journalKnown {return errors.New("history journal disappeared; refusing recreation")}
  return nil
 }
 if err!=nil{return err}
 if !before.Mode().IsRegular()||before.Mode().Perm()&0022!=0 {
  return errors.New("history journal must be a private regular file")
 }
 if s.journalKnown&&s.journalInfo!=nil&&os.SameFile(before,s.journalInfo)&&
  before.Size()==s.journalSize&&before.ModTime().Equal(s.journalInfo.ModTime()) {
  return nil
 }
 f,err:=os.Open(path);if err!=nil{return err};defer f.Close()
 opened,err:=f.Stat();if err!=nil{return err}
 if !opened.Mode().IsRegular()||!os.SameFile(before,opened) {
  return errors.New("history journal changed before reading")
 }
 if opened.Size()>0 {
  var last [1]byte
  if _,err:=f.ReadAt(last[:],opened.Size()-1);err!=nil{return err}
  if last[0]!='\n'{return errors.New("history journal has incomplete trailing line")}
 }
 messages:=make(map[string]Message)
 order:=make([]string,0)
 scanner:=bufio.NewScanner(f)
 scanner.Buffer(make([]byte,64*1024),16*1024*1024)
 for scanner.Scan() {
  var m Message
  if err:=json.Unmarshal(scanner.Bytes(),&m);err!=nil{return fmt.Errorf("corrupt shared history: %w",err)}
  if m.ID==""{return errors.New("shared history has missing scan ID")}
  if _,ok:=messages[m.ID];!ok{order=append(order,m.ID)}
  messages[m.ID]=m
 }
 if err:=scanner.Err();err!=nil{return err}
 after,err:=f.Stat();if err!=nil{return err}
 current,err:=os.Lstat(path);if err!=nil{return err}
 if !os.SameFile(opened,after)||!os.SameFile(opened,current)||
  after.Size()!=opened.Size()||!after.ModTime().Equal(opened.ModTime()) {
  return errors.New("history journal changed during reconciliation")
 }
 s.messages=messages
 s.order=order
 s.journalSize=after.Size()
 s.journalKnown=true
 s.journalInfo=after
 s.pruneLocked()
 return nil
}
