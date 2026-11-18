//go:build linux

package backupverify

import (
 "os"
 "syscall"
)

func openRegularNoFollow(name string)(*os.File,error){
 fd,err:=syscall.Open(name,syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,0)
 if err!=nil{return nil,err}
 return os.NewFile(uintptr(fd),name),nil
}
