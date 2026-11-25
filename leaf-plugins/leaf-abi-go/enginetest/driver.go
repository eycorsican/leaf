// Package enginetest drives a stream engine the way the leaf plugin host does,
// so that a plugin's own tests can exercise it over a real connection without
// loading it into leaf.
//
// The host owns every socket and calls into an engine one call at a time: it
// reads PollState, pushes what the engine asks for, pulls what it offers, and
// repeats. Driver does exactly that, with the network side wired to a net.Conn
// the test supplies -- a pipe to an in-process server, or a TCP connection to a
// real one. The one liberty it takes is polling where the host would wait on
// the wake callback, which a Go test cannot install: wake is a C function
// pointer.
//
// A test that goes through Driver is therefore testing the same loop leaf runs,
// including the parts a shortcut around it would hide: short pushes, output
// that arrives in pieces, and a close that has to travel through the engine
// rather than around it.
package enginetest

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	leafabi "leaf-plugins/leaf-abi-go"
)

// pollPeriod is how long the driver sleeps when an engine has nothing to offer.
// The host would park on the wake callback instead.
const pollPeriod = 200 * time.Microsecond

// Driver runs one engine instance. It does not own the engine: Stop leaves it
// alive so the test can inspect it, and the test calls Destroy itself.
type Driver struct {
	// calls is the host's promise that no two calls on one instance overlap.
	calls  sync.Mutex
	engine leafabi.StreamEngine
	wire   net.Conn

	appMu     sync.Mutex
	app       bytes.Buffer
	appClosed bool
	failure   error
	// netClosed is set once the wire has ended and the engine has been told
	// with CloseNet. The host reports end of stream from then on as soon as
	// the engine has nothing left to deliver and is not BLOCKED, whether or
	// not it ever says PEER_CLOSED; so does this.
	netClosed bool

	stopOnce sync.Once
	stopped  chan struct{}
	wg       sync.WaitGroup
}

// Start begins driving engine over wire. Stop must be called once the test is
// done with it.
func Start(engine leafabi.StreamEngine, wire net.Conn) *Driver {
	d := &Driver{engine: engine, wire: wire, stopped: make(chan struct{})}
	d.wg.Add(2)
	go func() {
		defer d.wg.Done()
		d.readWire()
	}()
	go func() {
		defer d.wg.Done()
		d.drain()
	}()
	return d
}

// readWire is the host reading the socket and handing the bytes over. A short
// count from Push is backpressure, so the remainder is offered again.
func (d *Driver) readWire() {
	buf := make([]byte, 16*1024)
	for {
		n, err := d.wire.Read(buf)
		data := buf[:n]
		for len(data) > 0 {
			d.calls.Lock()
			taken, pushErr := d.engine.Push(leafabi.SideNet, data)
			d.calls.Unlock()
			if pushErr != nil {
				d.fail(fmt.Errorf("push(net): %w", pushErr))
				return
			}
			data = data[taken:]
			if taken == 0 {
				if d.isStopped() {
					return
				}
				time.Sleep(pollPeriod)
			}
		}
		if err != nil {
			d.calls.Lock()
			_ = d.engine.Close(leafabi.CloseNet)
			d.calls.Unlock()
			d.appMu.Lock()
			d.netClosed = true
			d.appMu.Unlock()
			return
		}
		if d.isStopped() {
			return
		}
	}
}

// drain is the host moving whatever the engine offers: network output to the
// socket, application output to the reader.
func (d *Driver) drain() {
	out := make([]byte, 32*1024)
	for !d.isStopped() {
		d.calls.Lock()
		flags := d.engine.PollState()
		var netBytes []byte
		var appOut int
		var pullErr error
		if flags.Has(leafabi.StateHasNetOutput) {
			var n int
			n, pullErr = d.engine.Pull(leafabi.SideNet, out)
			if n > 0 {
				netBytes = append([]byte(nil), out[:n]...)
			}
		}
		if pullErr == nil && flags.Has(leafabi.StateHasAppOutput) {
			appOut, pullErr = d.engine.Pull(leafabi.SideApp, out)
			if appOut > 0 {
				d.appMu.Lock()
				d.app.Write(out[:appOut])
				d.appMu.Unlock()
			}
		}
		d.calls.Unlock()

		if len(netBytes) > 0 {
			if _, err := d.wire.Write(netBytes); err != nil {
				d.fail(fmt.Errorf("writing the wire: %w", err))
				return
			}
		}
		if pullErr != nil {
			d.fail(fmt.Errorf("pull: %w", pullErr))
			return
		}
		if flags.Has(leafabi.StateFatal) && len(netBytes) == 0 && appOut == 0 {
			d.fail(errors.New("the engine reported FATAL"))
			return
		}
		d.appMu.Lock()
		drained := !flags.Has(leafabi.StateHasAppOutput) && appOut == 0
		if drained && (flags.Has(leafabi.StatePeerClosed) ||
			(d.netClosed && !flags.Has(leafabi.StateBlocked))) {
			d.appClosed = true
		}
		d.appMu.Unlock()
		if len(netBytes) == 0 && appOut == 0 {
			time.Sleep(pollPeriod)
		}
	}
}

func (d *Driver) fail(err error) {
	d.appMu.Lock()
	defer d.appMu.Unlock()
	if d.failure == nil {
		d.failure = err
	}
}

func (d *Driver) isStopped() bool {
	select {
	case <-d.stopped:
		return true
	default:
		return false
	}
}

// Write pushes data until the engine has taken all of it, which is how the
// host deals with a short count.
func (d *Driver) Write(data []byte, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for len(data) > 0 {
		if err := d.Err(); err != nil {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the engine never took the last %d bytes", len(data))
		}
		d.calls.Lock()
		n, err := d.engine.Push(leafabi.SideApp, data)
		d.calls.Unlock()
		if err != nil {
			return fmt.Errorf("push(app): %w", err)
		}
		data = data[n:]
		if n == 0 {
			time.Sleep(pollPeriod)
		}
	}
	return nil
}

// ReadFull waits for exactly n application bytes.
func (d *Driver) ReadFull(n int, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	for {
		d.appMu.Lock()
		have, closed, failure := d.app.Len(), d.appClosed, d.failure
		if have >= n {
			out := append([]byte(nil), d.app.Next(n)...)
			d.appMu.Unlock()
			return out, nil
		}
		d.appMu.Unlock()
		if failure != nil {
			return nil, fmt.Errorf("after %d of %d bytes: %w", have, n, failure)
		}
		if closed {
			return nil, fmt.Errorf("the peer closed after %d of %d bytes", have, n)
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("only %d of %d application bytes arrived", have, n)
		}
		time.Sleep(pollPeriod)
	}
}

// ReadToEnd collects application bytes until the engine reports the peer
// closed, the engine fails, or the timeout passes. The error says which of the
// last two ended it; a clean end of stream returns nil.
func (d *Driver) ReadToEnd(timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	for {
		d.appMu.Lock()
		closed, failure := d.appClosed, d.failure
		if closed || failure != nil {
			out := append([]byte(nil), d.app.Bytes()...)
			d.app.Reset()
			d.appMu.Unlock()
			return out, failure
		}
		d.appMu.Unlock()
		if time.Now().After(deadline) {
			return nil, errors.New("the connection never ended")
		}
		time.Sleep(pollPeriod)
	}
}

// WaitFor polls the engine's state until want is set or the timeout passes,
// and returns the last state it saw.
func (d *Driver) WaitFor(want leafabi.StateFlags, timeout time.Duration) (leafabi.StateFlags, bool) {
	deadline := time.Now().Add(timeout)
	for {
		state := d.State()
		if state.Has(want) {
			return state, true
		}
		if time.Now().After(deadline) {
			return state, false
		}
		time.Sleep(pollPeriod)
	}
}

// Err is the first failure the driver saw on the engine's side of the loop:
// a failed call, or FATAL with nothing left to drain.
func (d *Driver) Err() error {
	d.appMu.Lock()
	defer d.appMu.Unlock()
	return d.failure
}

// CloseApp is the application ending its side of the conversation.
func (d *Driver) CloseApp() {
	d.calls.Lock()
	defer d.calls.Unlock()
	_ = d.engine.Close(leafabi.CloseApp)
}

// State reads the engine's state flags.
func (d *Driver) State() leafabi.StateFlags {
	d.calls.Lock()
	defer d.calls.Unlock()
	return d.engine.PollState()
}

// Stop ends the loops and closes the wire. The engine is left for the caller
// to destroy, which is the order the host uses too: no call is in flight when
// destroy_instance runs.
func (d *Driver) Stop() {
	d.stopOnce.Do(func() { close(d.stopped) })
	_ = d.wire.Close()
	d.wg.Wait()
}
