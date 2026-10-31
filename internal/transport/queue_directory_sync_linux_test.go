//go:build linux

package transport

import (
    "errors"
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestSpoolDirectorySyncBeforeAndAfterRename(t *testing.T) {
    q, _, _ := newIntegrityQueue(t)
    msg := pendingTestMessage()
    calls := 0
    q.syncDirForTest = func() error {
        calls++
        pending, err := filepath.Glob(filepath.Join(q.dir, ".pending-*"))
        if err != nil {
            t.Fatalf("sync %d pending inventory failed: %v", calls, err)
        }
        if calls == 1 && len(pending) != 1 {
            t.Fatalf("pre-rename sync must retain pending original: %v", pending)
        }
        if calls == 2 && len(pending) != 0 {
            t.Fatalf("post-rename sync must have published pending original: %v", pending)
        }
        _, publishedErr := os.Stat(q.path(msg.ID))
        if calls == 1 && !errors.Is(publishedErr, os.ErrNotExist) {
            t.Fatalf("first directory sync happened after publication: %v", publishedErr)
        }
        if calls == 2 && publishedErr != nil {
            t.Fatalf("second directory sync happened before publication: %v", publishedErr)
        }
        return nil
    }
    if err := q.Enqueue(msg, []byte("Subject: durable\r\n\r\nbody")); err != nil {
        t.Fatal(err)
    }
    if calls != 2 {
        t.Fatalf("expected pre-rename and post-rename directory sync, got %d", calls)
    }
}

func TestPreRenameDirectorySyncFailureRetainsUnpublishedOriginal(t *testing.T) {
    q, _, _ := newIntegrityQueue(t)
    msg := pendingTestMessage()
    q.syncDirForTest = func() error { return errors.New("injected pre-rename directory fsync failure") }
    err := q.Enqueue(msg, []byte("Subject: preserved\r\n\r\nbody"))
    if err == nil || !strings.Contains(err.Error(), "directory durability is unconfirmed") {
        t.Fatalf("SMTP intake did not refuse unconfirmed durability: %v", err)
    }
    if _, err := os.Stat(q.path(msg.ID)); !errors.Is(err, os.ErrNotExist) {
        t.Fatalf("record published despite pre-rename failure: %v", err)
    }
    pending, err := filepath.Glob(filepath.Join(q.dir, ".pending-*"))
    if err != nil || len(pending) != 1 {
        t.Fatalf("failed intake erased forensic original: %v %v", pending, err)
    }
    q.syncDirForTest = nil
    summary, err := q.Snapshot()
    if err != nil || summary.PendingTemps != 1 || summary.Total != 0 {
        t.Fatalf("unpublished original not inventoried: %+v %v", summary, err)
    }
}

func TestPostRenameDirectorySyncFailureRetainsPublishedOriginal(t *testing.T) {
    q, _, _ := newIntegrityQueue(t)
    msg := pendingTestMessage()
    calls := 0
    q.syncDirForTest = func() error {
        calls++
        if calls == 2 { return errors.New("injected post-rename directory fsync failure") }
        return nil
    }
    err := q.Enqueue(msg, []byte("Subject: ambiguous\r\n\r\nbody"))
    if err == nil || calls != 2 {
        t.Fatalf("expected failed second directory sync, calls=%d err=%v", calls, err)
    }
    q.syncDirForTest = nil
    summary, err := q.Snapshot()
    if err != nil || summary.Total != 1 || summary.Queued != 1 {
        t.Fatalf("published original lost after uncertain acknowledgement: %+v %v", summary, err)
    }
}
