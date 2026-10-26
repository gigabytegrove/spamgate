package core

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

func TestClamAVWireAndFailureModes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	t.Setenv("SPAMGATE_CLAMAV_ADDRESS", "tcp://"+ln.Addr().String())
	done := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		header := make([]byte, 10)
		if _, err = io.ReadFull(c, header); err != nil {
			done <- err
			return
		}
		if string(header) != "zINSTREAM\x00" {
			done <- io.ErrUnexpectedEOF
			return
		}
		var raw []byte
		for {
			var size [4]byte
			if _, err = io.ReadFull(c, size[:]); err != nil {
				done <- err
				return
			}
			n := binary.BigEndian.Uint32(size[:])
			if n == 0 {
				break
			}
			b := make([]byte, n)
			if _, err = io.ReadFull(c, b); err != nil {
				done <- err
				return
			}
			raw = append(raw, b...)
		}
		if string(raw) != "EICAR-test" {
			done <- io.ErrUnexpectedEOF
			return
		}
		_, err = c.Write([]byte("stream: Eicar-Test-Signature FOUND\x00"))
		done <- err
	}()
	virus, err := ClamAVScan(context.Background(), []byte("EICAR-test"))
	if err != nil || virus != "Eicar-Test-Signature" {
		t.Fatalf("virus=%q err=%v", virus, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	t.Setenv("SPAMGATE_CLAMAV_ADDRESS", "")
	virus, err = ClamAVScan(context.Background(), []byte("test"))
	if virus != "" || err != nil {
		t.Fatal(virus, err)
	}
	t.Setenv("SPAMGATE_CLAMAV_ADDRESS", "bad socket")
	if _, err = ClamAVScan(context.Background(), []byte("test")); err == nil {
		t.Fatal("invalid socket accepted")
	}
}
