package leafabi

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
)

// host_ctx is opaque. leaf puts a small instance number in it -- 1, 2, 3 --
// and the ABI allows any value at all. The SDK must never hold it as a Go
// pointer: the collector checks every pointer it finds on a stack, and one
// pointing at address 1 stops the process with "invalid pointer found on
// stack". That is what happened the first time a plugin that allocates
// heavily -- uTLS building ClientHellos -- ran under leaf.
//
// The check that fires is the one the runtime makes when it copies a stack to
// grow it: every pointer in every frame is adjusted, and one that cannot be a
// heap address stops the process. So each call here is made from a fresh
// goroutine at a different recursion depth, which puts a stack growth at the
// call into the C callback sooner or later -- with the frame holding host_ctx
// live. Before the fix this crashed on the first few hundred depths.
func TestHostContextIsNeverAGoPointer(t *testing.T) {
	for _, ctx := range []uintptr{1, 2, 7, 4095} {
		host := testHost(ctx)
		var stop atomic.Bool
		var collector sync.WaitGroup
		collector.Add(1)
		go func() {
			defer collector.Done()
			for !stop.Load() {
				runtime.GC()
			}
		}()
		for depth := range 1500 {
			done := make(chan struct{})
			go func() {
				defer close(done)
				callAtDepth(depth, host)
			}()
			<-done
		}
		stop.Store(true)
		collector.Wait()
	}
}

//go:noinline
func callAtDepth(depth int, host Host) {
	var pad [64]byte
	if depth == 0 {
		host.Wake()
		host.Log(LevelDebug, string(pad[:1]))
		return
	}
	callAtDepth(depth-1, host)
	pad[0]++
}
