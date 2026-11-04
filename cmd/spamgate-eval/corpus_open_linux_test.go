//go:build linux

package main

import (
    "os"
    "path/filepath"
    "syscall"
    "testing"
    "time"
)

func TestCorpusDescriptorRejectsSymlinkEvenWhenTargetRegular(t *testing.T) {
    dir := t.TempDir()
    target := filepath.Join(dir, "target.jsonl")
    link := filepath.Join(dir, "link.jsonl")
    if err := os.WriteFile(target, []byte("{}\n"), 0600); err != nil { t.Fatal(err) }
    if err := os.Symlink(target, link); err != nil { t.Fatal(err) }
    f, err := openEvaluationCorpusDescriptor(link)
    if f != nil { f.Close(); t.Fatal("symlink was opened") }
    if err == nil { t.Fatal("symlink must be refused at open syscall") }
}

func TestCorpusDescriptorRejectsFIFOWithoutBlocking(t *testing.T) {
    path := filepath.Join(t.TempDir(), "swapped-fifo")
    if err := syscall.Mkfifo(path, 0600); err != nil { t.Fatal(err) }
    finished := make(chan error, 1)
    go func() {
        f, err := openEvaluationCorpusDescriptor(path)
        if f != nil { f.Close() }
        finished <- err
    }()
    select {
    case <-finished:
        // O_NONBLOCK may open a FIFO; the caller's f.Stat rejects it.
    case <-time.After(2 * time.Second):
        t.Fatal("opening a swapped FIFO blocked")
    }
    f, _, err := openEvaluationCorpus(path)
    if f != nil { f.Close() }
    if err == nil { t.Fatal("FIFO accepted as corpus") }
}

func TestCorpusDescriptorOpensRegularFile(t *testing.T) {
    path := filepath.Join(t.TempDir(), "corpus.jsonl")
    if err := os.WriteFile(path, []byte("{}\n"), 0600); err != nil { t.Fatal(err) }
    f, _, err := openEvaluationCorpus(path)
    if err != nil { t.Fatal(err) }
    defer f.Close()
    buf := make([]byte, 3)
    if n, err := f.Read(buf); n != 3 || err != nil || string(buf) != "{}\n" {
        t.Fatalf("regular file read: n=%d err=%v data=%q", n, err, buf)
    }
}
