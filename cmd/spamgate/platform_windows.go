//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"unsafe"
)

// Native Windows Service Control Manager support, implemented with the Windows
// API so published executables do not require an external service wrapper.
const (
	serviceWin32OwnProcess = 0x00000010
	serviceControlStop     = 0x00000001
	serviceShutdown        = 0x00000005
	serviceAcceptStop      = 0x00000001
	serviceAcceptShutdown  = 0x00000004
	serviceStopped         = 0x00000001
	serviceStartPending    = 0x00000002
	serviceStopPending     = 0x00000003
	serviceRunning         = 0x00000004
	errorNotService        = syscall.Errno(1063)
)

type serviceTableEntry struct {
	name *uint16
	main uintptr
}

type serviceStatus struct {
	serviceType, currentState, controlsAccepted, win32ExitCode,
	serviceSpecificExitCode, checkpoint, waitHint uint32
}

var (
	advapi                       = syscall.NewLazyDLL("advapi32.dll")
	startServiceCtrlDispatcher   = advapi.NewProc("StartServiceCtrlDispatcherW")
	registerServiceCtrlHandlerEx = advapi.NewProc("RegisterServiceCtrlHandlerExW")
	setServiceStatus             = advapi.NewProc("SetServiceStatus")
	serviceName, _               = syscall.UTF16PtrFromString("SpamGate")
	serviceRun                   func(context.Context) error
	serviceError                 error
	serviceStopCh                chan struct{}
	stopOnce                     sync.Once
	statusHandle                 uintptr
)

func winServiceStatus(state uint32, accepted uint32, code uint32) {
	status := serviceStatus{serviceType: serviceWin32OwnProcess, currentState: state, controlsAccepted: accepted, win32ExitCode: code}
	if state == serviceStartPending || state == serviceStopPending {
		status.waitHint = 15000
		status.checkpoint = 1
	}
	if r, _, e := setServiceStatus.Call(statusHandle, uintptr(unsafe.Pointer(&status))); r == 0 {
		slog.Error("SetServiceStatus failed", "error", e)
	}
}

func serviceControlHandler(control, _, _, _ uintptr) uintptr {
	if control == serviceControlStop || control == serviceShutdown {
		stopOnce.Do(func() { close(serviceStopCh) })
	}
	return 0
}

func serviceMain(_, _ uintptr) uintptr {
	statusHandle, _, _ = registerServiceCtrlHandlerEx.Call(
		uintptr(unsafe.Pointer(serviceName)),
		syscall.NewCallback(serviceControlHandler), 0,
	)
	if statusHandle == 0 {
		serviceError = errors.New("cannot register SpamGate service control handler")
		return 0
	}
	winServiceStatus(serviceStartPending, 0, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- serviceRun(ctx) }()
	winServiceStatus(serviceRunning, serviceAcceptStop|serviceAcceptShutdown, 0)
	select {
	case err := <-finished:
		serviceError = err
	case <-serviceStopCh:
		winServiceStatus(serviceStopPending, 0, 0)
		cancel()
		serviceError = <-finished
	}
	code := uint32(0)
	if serviceError != nil {
		code = 1
		slog.Error("SpamGate service failed", "error", serviceError)
	}
	winServiceStatus(serviceStopped, 0, code)
	return 0
}

func runPlatform(app func(context.Context) error) error {
	serviceRun = app
	serviceStopCh = make(chan struct{})
	entry := [2]serviceTableEntry{
		{name: serviceName, main: syscall.NewCallback(serviceMain)},
		{},
	}
	r, _, e := startServiceCtrlDispatcher.Call(uintptr(unsafe.Pointer(&entry[0])))
	if r != 0 {
		return serviceError
	}
	if errors.Is(e, errorNotService) {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return app(ctx)
	}
	return fmt.Errorf("StartServiceCtrlDispatcher: %w", e)
}
