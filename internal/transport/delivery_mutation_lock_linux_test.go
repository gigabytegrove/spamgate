//go:build linux

package transport

import (
    "context"
    "errors"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "testing"
    "time"

    "github.com/gigabytegrove/spamgate/internal/core"
)

func TestCrossProcessIntakeRejectsDuplicateIDWithoutReplacingOriginal(t *testing.T) {
    dir := t.TempDir()
    store, err := core.Open(dir)
    if err != nil { t.Fatal(err) }
    send := func(context.Context, core.Message, []byte) error { return nil }
    a, err := NewDeliveryQueue(dir, store, send)
    if err != nil { t.Fatal(err) }
    b, err := NewDeliveryQueue(dir, store, send)
    if err != nil { t.Fatal(err) }
    id := core.ID()
    m := core.Message{ID:id, Sender:"sender@example.org", Recipients:[]string{"user@example.org"}}
    originals := [][]byte{[]byte("Subject: A\r\n\r\nOriginal A"), []byte("Subject: B\r\n\r\nOriginal B")}
    start := make(chan struct{})
    results := make(chan struct { index int; err error }, 2)
    var wg sync.WaitGroup
    for i, q := range []*DeliveryQueue{a,b} {
        wg.Add(1)
        go func(i int, q *DeliveryQueue) {
            defer wg.Done()
            <-start
            results <- struct { index int; err error }{i, q.Enqueue(m, originals[i])}
        }(i,q)
    }
    close(start)
    wg.Wait()
    close(results)
    winner, successes := -1, 0
    for r := range results {
        if r.err == nil { winner = r.index; successes++ } else if !strings.Contains(r.err.Error(), "already exists") {
            t.Fatalf("unexpected competing intake error: %v", r.err)
        }
    }
    if successes != 1 { t.Fatalf("expected one accepted original, got %d", successes) }
    rec, err := b.get(id)
    if err != nil { t.Fatal(err) }
    if string(rec.RawRFC822) != string(originals[winner]) || rec.IntegritySHA256 != spoolDigest(rec) {
        t.Fatal("duplicate intake replaced or damaged the accepted original")
    }
    snap, err := a.Snapshot()
    if err != nil || snap.Total != 1 { t.Fatalf("unexpected spool: %+v %v", snap, err) }
}

func TestIntakeLockRejectsUnsafeFilesystemWithoutAcknowledging(t *testing.T) {
    for _, tc := range []struct{name string; prepare func(*testing.T,string)}{
        {"symlink",func(t *testing.T, dir string) {
            target := filepath.Join(t.TempDir(),"target")
            if err := os.WriteFile(target,nil,0600); err != nil { t.Fatal(err) }
            if err := os.Symlink(target,filepath.Join(dir,deliveryIntakeLockName)); err != nil { t.Fatal(err) }
        }},
        {"hardlink",func(t *testing.T, dir string) {
            target := filepath.Join(dir,"target")
            if err := os.WriteFile(target,nil,0600); err != nil { t.Fatal(err) }
            if err := os.Link(target,filepath.Join(dir,deliveryIntakeLockName)); err != nil { t.Fatal(err) }
        }},
        {"writable",func(t *testing.T, dir string) {
            p := filepath.Join(dir,deliveryIntakeLockName)
            if err := os.WriteFile(p,nil,0600); err != nil { t.Fatal(err) }
            if err := os.Chmod(p,0666); err != nil { t.Fatal(err) }
        }},
    } {
        t.Run(tc.name,func(t *testing.T) {
            root := t.TempDir()
            store, err := core.Open(root)
            if err != nil { t.Fatal(err) }
            q, err := NewDeliveryQueue(root,store,func(context.Context,core.Message,[]byte)error{return nil})
            if err != nil { t.Fatal(err) }
            tc.prepare(t,q.dir)
            m := core.Message{ID:core.ID(),Sender:"s@example.org",Recipients:[]string{"r@example.org"}}
            if err := q.Enqueue(m,[]byte("Subject: test\r\n\r\nbody")); err == nil {
                t.Fatal("accepted original with unsafe shared intake lock")
            }
            snap, err := q.Snapshot()
            if err != nil || snap.Total != 0 { t.Fatalf("unsafe intake wrote spool: %+v %v",snap,err) }
        })
    }
}

func TestManualMutationsCannotRaceActiveCrossProcessDelivery(t *testing.T) {
    dir := t.TempDir()
    store, err := core.Open(dir)
    if err != nil { t.Fatal(err) }
    entered := make(chan struct{})
    release := make(chan struct{})
    defer func(){ select { case <-release: default: close(release) } }()
    send := func(context.Context,core.Message,[]byte)error{ close(entered); <-release; return nil }
    a, err := NewDeliveryQueue(dir,store,send)
    if err != nil { t.Fatal(err) }
    b, err := NewDeliveryQueue(dir,store,send)
    if err != nil { t.Fatal(err) }
    m := core.Message{ID:core.ID(),Sender:"s@example.org",Recipients:[]string{"r@example.org"}}
    if err := a.Enqueue(m,[]byte("Subject: original\r\n\r\nbody")); err != nil { t.Fatal(err) }
    done := make(chan error,1)
    go func(){done<-a.ProcessDue(context.Background())}()
    select {
    case <-entered:
    case err := <-done: t.Fatalf("worker stopped before relay: %v",err)
    case <-time.After(5*time.Second): t.Fatal("worker did not start")
    }
    for name, fn := range map[string]func()error{
        "retry":func()error{return b.Retry(m.ID)},
        "discard":func()error{return b.Discard(m.ID)},
        "audited discard":func()error{return b.DiscardWithAudit(m.ID,"admin")},
    } {
        if err := fn(); !errors.Is(err,ErrDeliveryWorkerBusy) { t.Errorf("%s raced active delivery: %v",name,err) }
    }
    rec, err := b.get(m.ID)
    if err != nil || rec.State != "delivering" { t.Fatalf("active original was changed: %+v %v",rec.QueuedMessage,err) }
    close(release)
    select {
    case err := <-done: if err != nil { t.Fatal(err) }
    case <-time.After(5*time.Second): t.Fatal("worker did not finish")
    }
    snap, err := b.Snapshot()
    if err != nil || snap.Total != 0 { t.Fatalf("original not finalized: %+v %v",snap,err) }
}

func TestNewIntakeDoesNotWaitForSlowUpstreamRelay(t *testing.T) {
    dir := t.TempDir()
    store, err := core.Open(dir)
    if err != nil { t.Fatal(err) }
    entered, release := make(chan struct{}), make(chan struct{})
    defer func(){ select { case <-release: default: close(release) } }()
    send := func(_ context.Context,m core.Message,_ []byte)error{
        if m.Subject == "slow" { close(entered); <-release }
        return nil
    }
    a, err := NewDeliveryQueue(dir,store,send)
    if err != nil { t.Fatal(err) }
    b, err := NewDeliveryQueue(dir,store,send)
    if err != nil { t.Fatal(err) }
    first := core.Message{ID:core.ID(),Subject:"slow",Sender:"s@example.org",Recipients:[]string{"r@example.org"}}
    second := core.Message{ID:core.ID(),Subject:"new",Sender:"s@example.org",Recipients:[]string{"r@example.org"}}
    if err := a.Enqueue(first,[]byte("Subject: slow\r\n\r\nbody")); err != nil { t.Fatal(err) }
    done := make(chan error,1)
    go func(){done<-a.ProcessDue(context.Background())}()
    select {
    case <-entered:
    case err := <-done: t.Fatalf("worker stopped: %v",err)
    case <-time.After(5*time.Second): t.Fatal("worker did not start")
    }
    start := time.Now()
    if err := b.Enqueue(second,[]byte("Subject: new\r\n\r\nbody")); err != nil { t.Fatalf("new intake blocked by slow relay: %v",err) }
    if time.Since(start) > time.Second { t.Fatal("new intake waited on upstream relay") }
    rec, err := b.get(second.ID)
    if err != nil || rec.State != "queued" { t.Fatalf("new original not persisted: %+v %v",rec.QueuedMessage,err) }
    close(release)
    select {
    case err := <-done: if err != nil { t.Fatal(err) }
    case <-time.After(5*time.Second): t.Fatal("worker did not finish")
    }
    if err := b.ProcessDue(context.Background()); err != nil { t.Fatal(err) }
    snap, err := b.Snapshot()
    if err != nil || snap.Total != 0 { t.Fatalf("new intake did not relay: %+v %v",snap,err) }
}
