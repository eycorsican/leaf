package leafabi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

// driver runs an engine the way the plugin host does: one call at a time, the
// network side wired to a real conn, and everything else driven from the state
// the engine reports.
//
// It exists so that these tests exercise the same loop leaf runs rather than a
// convenient shortcut around it. It polls where the host would wait on the wake
// callback, which a test cannot install: wake is a C function pointer.
type driver struct {
	// calls is the host's promise that no two calls on one instance overlap.
	calls  sync.Mutex
	engine StreamEngine
	wire   net.Conn

	appMu sync.Mutex
	app   bytes.Buffer

	stopOnce sync.Once
	stopped  chan struct{}
	wg       sync.WaitGroup
}

const drivePeriod = 200 * time.Microsecond

func newDriver(engine StreamEngine, wire net.Conn) *driver {
	d := &driver{engine: engine, wire: wire, stopped: make(chan struct{})}
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

// readWire is the host reading the socket and handing the bytes to the engine.
func (d *driver) readWire() {
	buf := make([]byte, 4096)
	for {
		n, err := d.wire.Read(buf)
		if n > 0 {
			d.calls.Lock()
			_, _ = d.engine.Push(SideNet, buf[:n])
			d.calls.Unlock()
		}
		if err != nil {
			d.calls.Lock()
			_ = d.engine.Close(CloseNet)
			d.calls.Unlock()
			return
		}
		select {
		case <-d.stopped:
			return
		default:
		}
	}
}

// drain is the host moving whatever the engine offers: network output to the
// socket, application output to the reader.
func (d *driver) drain() {
	out := make([]byte, 16*1024)
	for {
		select {
		case <-d.stopped:
			return
		default:
		}

		d.calls.Lock()
		flags := d.engine.PollState()
		var netOut, appOut int
		if flags.Has(StateHasNetOutput) {
			netOut, _ = d.engine.Pull(SideNet, out)
		}
		var netBytes []byte
		if netOut > 0 {
			netBytes = append([]byte(nil), out[:netOut]...)
		}
		if flags.Has(StateHasAppOutput) {
			appOut, _ = d.engine.Pull(SideApp, out)
			if appOut > 0 {
				d.appMu.Lock()
				d.app.Write(out[:appOut])
				d.appMu.Unlock()
			}
		}
		d.calls.Unlock()

		if len(netBytes) > 0 {
			if _, err := d.wire.Write(netBytes); err != nil {
				return
			}
		}
		if netOut == 0 && appOut == 0 {
			time.Sleep(drivePeriod)
		}
	}
}

// writeApp pushes until the engine has taken everything, which is how the host
// deals with a short count.
func (d *driver) writeApp(t *testing.T, data []byte) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(data) > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the engine never took the last %d bytes", len(data))
		}
		d.calls.Lock()
		n, err := d.engine.Push(SideApp, data)
		d.calls.Unlock()
		if err != nil {
			t.Fatalf("push(app) failed: %v", err)
		}
		data = data[n:]
		if n == 0 {
			time.Sleep(drivePeriod)
		}
	}
}

func (d *driver) readApp(t *testing.T, n int) []byte {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		d.appMu.Lock()
		have := d.app.Len()
		d.appMu.Unlock()
		if have >= n {
			d.appMu.Lock()
			defer d.appMu.Unlock()
			return d.app.Next(n)
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d application bytes came back", have, n)
		}
		time.Sleep(drivePeriod)
	}
}

func (d *driver) closeApp() {
	d.calls.Lock()
	defer d.calls.Unlock()
	_ = d.engine.Close(CloseApp)
}

func (d *driver) pollState() StateFlags {
	d.calls.Lock()
	defer d.calls.Unlock()
	return d.engine.PollState()
}

func (d *driver) stop() {
	d.stopOnce.Do(func() { close(d.stopped) })
	_ = d.wire.Close()
	d.wg.Wait()
}

// A real TLS handshake and a real exchange over it, driven exactly as the host
// drives an engine. This is the case ConnEngine exists for: crypto/tls insists
// on blocking, and the ABI forbids it.
func TestConnEngineCarriesATLSSession(t *testing.T) {
	serverConfig := testServerTLSConfig(t)
	clientSide, serverSide := net.Pipe()

	serverDone := make(chan error, 1)
	go func() {
		server := tls.Server(serverSide, serverConfig)
		if err := server.Handshake(); err != nil {
			serverDone <- err
			return
		}
		// Echo until the client half closes, then say goodbye.
		_, err := io.Copy(server, server)
		_ = server.Close()
		serverDone <- err
	}()

	engine, err := NewConnEngine(ConnEngineConfig{
		Wrap: func(inner net.Conn) (net.Conn, error) {
			return tls.Client(inner, &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			}), nil
		},
	})
	if err != nil {
		t.Fatalf("NewConnEngine failed: %v", err)
	}
	d := newDriver(engine, clientSide)
	defer func() {
		d.stop()
		engine.Destroy()
	}()

	payload := []byte("hello over a real handshake")
	d.writeApp(t, payload)
	if got := d.readApp(t, len(payload)); !bytes.Equal(got, payload) {
		t.Fatalf("echoed %q, want %q", got, payload)
	}

	// A second exchange: a handshake that leaves the engine in a bad state
	// still passes the first.
	again := []byte("and again")
	d.writeApp(t, again)
	if got := d.readApp(t, len(again)); !bytes.Equal(got, again) {
		t.Fatalf("echoed %q, want %q", got, again)
	}

	if flags := d.pollState(); !flags.Has(StateEstablished) {
		t.Fatalf("state = %#x, want StateEstablished once data is flowing", uint32(flags))
	}

	d.closeApp()
	select {
	case err := <-serverDone:
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("the server side ended with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the half close never reached the server")
	}
}

// identityWrap is a transport that adds nothing, which is what the tests that
// are about the engine's own bookkeeping want.
func identityWrap(inner net.Conn) (net.Conn, error) { return inner, nil }

// An engine that has taken all it can hold must say so by consuming less, not
// by growing without limit: a short count is the only backpressure signal the
// host acts on.
func TestConnEngineReportsBackpressureOnApplicationInput(t *testing.T) {
	const capacity = 1024
	engine, err := NewConnEngine(ConnEngineConfig{
		Wrap:               identityWrap,
		MaxPendingAppInput: capacity,
	})
	if err != nil {
		t.Fatalf("NewConnEngine failed: %v", err)
	}
	defer engine.Destroy()

	// Nothing drains the network side here, so the write loop parks on the
	// first Write and the buffer is what fills up.
	total := 0
	input := make([]byte, capacity)
	for range 8 {
		n, err := engine.Push(SideApp, input)
		if err != nil {
			t.Fatalf("push(app) failed: %v", err)
		}
		total += n
		if n < len(input) {
			break
		}
	}
	if total > 2*capacity {
		t.Fatalf("the engine took %d bytes with a %d byte cap", total, capacity)
	}

	deadline := time.Now().Add(2 * time.Second)
	for engine.PollState().Has(StateWantAppInput) {
		if time.Now().After(deadline) {
			t.Fatal("the engine kept asking for application input while full")
		}
		time.Sleep(drivePeriod)
	}
}

// BLOCKED means "I have everything I can use and am working on it"; it is only
// safe to report when something will actually arrive to un-block it. Reporting
// it with nothing in hand would park the host forever.
func TestConnEngineReportsBlockedOnlyWithInputInHand(t *testing.T) {
	engine, err := NewConnEngine(ConnEngineConfig{Wrap: identityWrap})
	if err != nil {
		t.Fatalf("NewConnEngine failed: %v", err)
	}
	defer engine.Destroy()

	if flags := engine.PollState(); flags.Has(StateBlocked) {
		t.Fatalf("state = %#x, want no StateBlocked on a fresh engine", uint32(flags))
	}
	if flags := engine.PollState(); !flags.Has(StateWantNetInput) {
		t.Fatalf("state = %#x, want StateWantNetInput while waiting on the peer", uint32(flags))
	}

	// Bytes the read loop has not picked up yet are exactly the state BLOCKED
	// describes, and it must clear again once they turn into output.
	if _, err := engine.Push(SideNet, []byte("payload")); err != nil {
		t.Fatalf("push(net) failed: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if engine.PollState().Has(StateHasAppOutput) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pushed network input never became application output")
		}
		time.Sleep(drivePeriod)
	}
	if flags := engine.PollState(); flags.Has(StateBlocked) {
		t.Fatalf("state = %#x, want no StateBlocked once there is output to take", uint32(flags))
	}
}

// The ABI lets destroy block, and requires it to: once it returns, nothing the
// plugin owns may still be able to call the host back.
func TestConnEngineDestroyJoinsItsGoroutinesEvenMidHandshake(t *testing.T) {
	before := runtime.NumGoroutine()
	started := make(chan struct{})
	engine, err := NewConnEngine(ConnEngineConfig{
		Wrap: identityWrap,
		// A handshake that can only end when the conn under it is closed,
		// which is what destroy has to be able to do.
		Handshake: func(c net.Conn) error {
			close(started)
			_, err := io.ReadAll(c)
			return err
		},
	})
	if err != nil {
		t.Fatalf("NewConnEngine failed: %v", err)
	}
	<-started

	done := make(chan struct{})
	go func() {
		engine.Destroy()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Destroy did not return while the handshake was still running")
	}

	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before+2 {
		if time.Now().After(deadline) {
			t.Fatalf("goroutines went from %d to %d and stayed there",
				before, runtime.NumGoroutine())
		}
		time.Sleep(drivePeriod)
	}
}

// A handshake that fails has to reach the host as a fatal engine, not as a
// connection that hangs.
func TestConnEngineReportsAFailedHandshakeAsFatal(t *testing.T) {
	engine, err := NewConnEngine(ConnEngineConfig{
		Wrap:      identityWrap,
		Handshake: func(net.Conn) error { return errors.New("no common cipher") },
	})
	if err != nil {
		t.Fatalf("NewConnEngine failed: %v", err)
	}
	defer engine.Destroy()

	deadline := time.Now().Add(2 * time.Second)
	for !engine.PollState().Has(StateFatal) {
		if time.Now().After(deadline) {
			t.Fatal("a failed handshake never showed up as StateFatal")
		}
		time.Sleep(drivePeriod)
	}
	if _, err := engine.Pull(SideApp, make([]byte, 16)); err == nil {
		t.Fatal("pull succeeded on a fatal engine")
	} else if statusOf(err) != StatusPluginFailure {
		t.Fatalf("pull reported %v, want a plugin failure", statusOf(err))
	}
}

func TestNewConnEngineRefusesAConfigItCannotUse(t *testing.T) {
	if _, err := NewConnEngine(ConnEngineConfig{}); err == nil {
		t.Fatal("expected an error when Wrap is nil")
	}
	if _, err := NewConnEngine(ConnEngineConfig{
		Wrap: func(net.Conn) (net.Conn, error) { return nil, nil },
	}); err == nil {
		t.Fatal("expected an error when Wrap returns no conn")
	}
	sentinel := errors.New("cannot build the config")
	if _, err := NewConnEngine(ConnEngineConfig{
		Wrap: func(net.Conn) (net.Conn, error) { return nil, sentinel },
	}); !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the error Wrap returned", err)
	}
}

func TestConnEngineRejectsAnUnknownSide(t *testing.T) {
	engine, err := NewConnEngine(ConnEngineConfig{Wrap: identityWrap})
	if err != nil {
		t.Fatalf("NewConnEngine failed: %v", err)
	}
	defer engine.Destroy()

	if _, err := engine.Push(Side(9), []byte("x")); statusOf(err) != StatusInvalidArgument {
		t.Errorf("push status = %v, want %v", statusOf(err), StatusInvalidArgument)
	}
	if _, err := engine.Pull(Side(9), make([]byte, 8)); statusOf(err) != StatusInvalidArgument {
		t.Errorf("pull status = %v, want %v", statusOf(err), StatusInvalidArgument)
	}
}

func testServerTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key failed: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "leafabi-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"leafabi-test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a certificate failed: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	}
}
