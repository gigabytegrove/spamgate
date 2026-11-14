package transport

import (
    "context"
    "errors"
    "net"
    "testing"
    "time"
)

func TestRspamdListenPreCanceledContextDoesNotBind(t *testing.T) {
    ctx, cancel := context.WithCancel(context.Background())
    cancel()
    worker := &RspamdWorker{ListenAddress: "127.0.0.1:0"}
    if err := worker.Listen(ctx); !errors.Is(err, context.Canceled) {
        t.Fatalf("Listen canceled context: got %v, want context.Canceled", err)
    }
}

func TestRspamdListenOccupiedPortReturnsPromptly(t *testing.T) {
    listener, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil {
        t.Fatal(err)
    }
    defer listener.Close()
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    worker := &RspamdWorker{ListenAddress: listener.Addr().String()}
    start := time.Now()
    if err := worker.Listen(ctx); err == nil {
        t.Fatal("Listen accepted an occupied port")
    }
    if elapsed := time.Since(start); elapsed > 2*time.Second {
        t.Fatalf("occupied port failure took %s", elapsed)
    }
}

func TestRspamdListenStopsOnContextCancellation(t *testing.T) {
    probe, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil {
        t.Fatal(err)
    }
    addr := probe.Addr().String()
    if err := probe.Close(); err != nil {
        t.Fatal(err)
    }
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    worker := &RspamdWorker{ListenAddress: addr}
    result := make(chan error, 1)
    go func() { result <- worker.Listen(ctx) }()
    deadline := time.After(3*time.Second)
    for {
        select {
        case err := <-result:
            t.Fatalf("worker exited before cancellation: %v", err)
        case <-deadline:
            t.Fatal("worker did not bind before deadline")
        default:
        }
        conn, dialErr := net.DialTimeout("tcp", addr, 50*time.Millisecond)
        if dialErr == nil {
            conn.Close()
            break
        }
        time.Sleep(10*time.Millisecond)
    }
    cancel()
    select {
    case err := <-result:
        if err != nil {
            t.Fatalf("shutdown returned %v", err)
        }
    case <-time.After(7*time.Second):
        t.Fatal("worker did not stop after cancellation")
    }
}
