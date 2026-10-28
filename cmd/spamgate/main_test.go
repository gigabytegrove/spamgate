package main

import (
	"os"
	"testing"
)

func TestManagementDefaultBindsHostInterfaces(t *testing.T) {
	prior, ok := os.LookupEnv("SPAMGATE_WEB_LISTEN")
	defer func() {
		if ok {
			_ = os.Setenv("SPAMGATE_WEB_LISTEN", prior)
		} else {
			_ = os.Unsetenv("SPAMGATE_WEB_LISTEN")
		}
	}()
	_ = os.Unsetenv("SPAMGATE_WEB_LISTEN")
	if actual := defaultListen(); actual != "0.0.0.0:38470" {
		t.Fatalf("default management listener: %s", actual)
	}
	if err := os.Setenv("SPAMGATE_WEB_LISTEN", "127.0.0.1:49000"); err != nil {
		t.Fatal(err)
	}
	if actual := defaultListen(); actual != "127.0.0.1:49000" {
		t.Fatalf("env override ignored: %s", actual)
	}
}
