//go:build linux

package core

import (
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "sync"
 "syscall"
 "time"
)

// Keep this inode permanently. Removing it while processes are alive
// permits different workers to lock different inodes.
func acquireHistoryWriteLock(dir string)(func(),error){
 root,err:=os.Lstat(dir);if err!=nil{return nil,err}
 if !root.IsDir()||root.Mode()&os.ModeSymlink!=0||root.Mode().Perm()&0022!=0{
  return nil,errors.New("history directory must be a private real directory")
 }
 path:=filepath.Join(dir,".events-journal.lock")
 fd,err:=syscall.Open(path,syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,0600)
 if err!=nil{return nil,fmt.Errorf("open private history lock: %w",err)}
 f:=os.NewFile(uintptr(fd),path)
 if f==nil{_ = syscall.Close(fd);return nil,errors.New("invalid history lock handle")}
 fail:=func(err error)(func(),error){_ = f.Close();return nil,err}
 opened,err:=f.Stat();if err!=nil{return fail(err)}
 current,err:=os.Lstat(path);if err!=nil{return fail(err)}
 var st syscall.Stat_t
 if err:=syscall.Fstat(fd,&st);err!=nil{return fail(err)}
 if !opened.Mode().IsRegular()||!current.Mode().IsRegular()||
  !os.SameFile(opened,current)||opened.Mode().Perm()!=0600||
  st.Nlink!=1||st.Uid!=uint32(os.Geteuid()){
  return fail(errors.New("history lock must be private, unchanged and owned by the writer"))
 }
 deadline:=time.Now().Add(2*time.Second)
 for {
  err:=syscall.Flock(fd,syscall.LOCK_EX|syscall.LOCK_NB)
  if err==nil{
   current,statErr:=os.Lstat(path)
   if statErr!=nil||!current.Mode().IsRegular()||!os.SameFile(opened,current){
    _ = syscall.Flock(fd,syscall.LOCK_UN)
    return fail(errors.New("history lock changed during acquisition"))
   }
   var once sync.Once
   return func(){once.Do(func(){_ = syscall.Flock(fd,syscall.LOCK_UN);_ = f.Close()})},nil
  }
  if err!=syscall.EWOULDBLOCK&&err!=syscall.EAGAIN&&err!=syscall.EINTR{
   return fail(fmt.Errorf("acquire history lock: %w",err))
  }
  if time.Now().After(deadline){return fail(errors.New("shared history journal busy; refusing write"))}
  time.Sleep(20*time.Millisecond)
 }
}
