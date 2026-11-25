package leafabi

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// SharedLogger routes log lines from state that outlives any one engine
// instance into leaf's log.
//
// A Go protocol library is often built around one long-lived client that
// serves every connection, with one logger for all of it. A plugin that keeps
// such a client per outbound -- because the protocol has state that must
// survive from one connection to the next -- has no single instance to hand
// that logger to. SharedLogger is that logger: each instance attaches its Host
// while it is alive and detaches when it goes, and a line goes to the host of
// any instance attached at the time. They are all the same leaf, the same log
// and the same target, so which one carries it does not matter. A line logged
// while none is attached is dropped, as one logged after Destroy would be.
//
// Its methods are the logger interface sing and libraries built on it expect,
// with and without a context, so a *SharedLogger can be passed to them as it
// is. Fatal and Panic log at error level and return: a plugin must never exit
// the process or unwind into the host, whatever a library thinks of the
// situation.
type SharedLogger struct {
	mu    sync.Mutex
	hosts map[any]Host
}

// NewSharedLogger returns a logger with nothing attached.
func NewSharedLogger() *SharedLogger {
	return &SharedLogger{hosts: map[any]Host{}}
}

// Attach makes host available to carry lines until Detach is called with the
// same owner. owner is any comparable value unique to the instance, usually
// the instance itself.
func (l *SharedLogger) Attach(owner any, host Host) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hosts[owner] = host
}

// Detach withdraws what Attach registered for owner.
func (l *SharedLogger) Detach(owner any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.hosts, owner)
}

func (l *SharedLogger) log(level Level, args []any) {
	l.mu.Lock()
	var host Host
	found := false
	for _, h := range l.hosts {
		host, found = h, true
		break
	}
	l.mu.Unlock()
	if !found {
		return
	}
	host.Log(level, strings.TrimSpace(fmt.Sprint(args...)))
}

func (l *SharedLogger) Trace(args ...any) { l.log(LevelTrace, args) }
func (l *SharedLogger) Debug(args ...any) { l.log(LevelDebug, args) }
func (l *SharedLogger) Info(args ...any)  { l.log(LevelInfo, args) }
func (l *SharedLogger) Warn(args ...any)  { l.log(LevelWarn, args) }
func (l *SharedLogger) Error(args ...any) { l.log(LevelError, args) }
func (l *SharedLogger) Fatal(args ...any) { l.log(LevelError, args) }
func (l *SharedLogger) Panic(args ...any) { l.log(LevelError, args) }

func (l *SharedLogger) TraceContext(_ context.Context, args ...any) { l.Trace(args...) }
func (l *SharedLogger) DebugContext(_ context.Context, args ...any) { l.Debug(args...) }
func (l *SharedLogger) InfoContext(_ context.Context, args ...any)  { l.Info(args...) }
func (l *SharedLogger) WarnContext(_ context.Context, args ...any)  { l.Warn(args...) }
func (l *SharedLogger) ErrorContext(_ context.Context, args ...any) { l.Error(args...) }
func (l *SharedLogger) FatalContext(_ context.Context, args ...any) { l.Fatal(args...) }
func (l *SharedLogger) PanicContext(_ context.Context, args ...any) { l.Panic(args...) }
