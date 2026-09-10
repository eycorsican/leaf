package leafabi

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// ConnEngine adapts an implementation that insists on a blocking net.Conn to
// the engine contract, which forbids blocking.
//
// Most of Go's protocol and transport libraries -- crypto/tls above all -- are
// written against a net.Conn and expect to block on it. An engine may not, so
// this runs that code on goroutines of its own over an in-memory pipe, and
// reports StateBlocked with a call to Host.Wake when those goroutines are what
// it is waiting on. Destroy joins them before returning, which is what the ABI
// requires of a plugin holding threads of its own.
//
// An engine that is a pure state machine over buffers -- most protocol codecs
// are -- wants none of this and should implement StreamEngine directly.
type ConnEngine struct {
	mu   sync.Mutex
	cond sync.Cond
	wg   sync.WaitGroup

	host  Host
	outer net.Conn
	inner *memConn

	handshake func(net.Conn) error
	readChunk int
	maxAppIn  int

	appHint   int
	netHint   int
	batchHint int

	netIn  bytes.Buffer
	netOut bytes.Buffer
	appIn  bytes.Buffer
	appOut bytes.Buffer

	handshakeDone   bool
	closedAppIn     bool
	closedNetIn     bool
	peerClosed      bool
	transportClosed bool
	fatal           error
}

// Handshaker is implemented by conns that have a handshake to finish before
// application data moves; *tls.Conn is one. ConnEngine calls it automatically
// unless ConnEngineConfig.Handshake says otherwise.
type Handshaker interface {
	Handshake() error
}

// ConnEngineConfig describes one ConnEngine.
type ConnEngineConfig struct {
	// Host is the instance's host handle, from CreateArgs.
	Host Host

	// Wrap layers the plugin's protocol over the network side. It is handed a
	// net.Conn carrying the bytes on the socket and returns the conn that
	// carries application bytes -- for TLS, tls.Client(inner, config).
	//
	// Required.
	Wrap func(inner net.Conn) (net.Conn, error)

	// Handshake, if set, runs once on the wrapped conn before application data
	// moves. When it is nil and the wrapped conn implements Handshaker, that is
	// used instead; when neither applies the engine reports itself established
	// straight away.
	Handshake func(outer net.Conn) error

	// ReadChunk is how much is read from the wrapped conn at a time.
	// Defaults to 4096.
	ReadChunk int

	// MaxPendingAppInput caps how much application input the engine buffers
	// before it starts reporting backpressure. Defaults to 256 KiB.
	MaxPendingAppInput int

	// AppOutputSize, NetOutputSize and OutputBatch are the hints the engine
	// gives the host. Zero means the SDK's default.
	AppOutputSize int
	NetOutputSize int
	OutputBatch   int
}

const (
	defaultConnReadChunk  = 4096
	defaultMaxPendingApp  = 256 * 1024
	connEngineNetworkName = "leaf-plugin-memory"
)

// NewConnEngine builds a ConnEngine and starts the goroutines that drive it.
//
// The returned engine is a StreamEngine; the caller hands it straight back from
// StreamEngineSpec.New.
func NewConnEngine(cfg ConnEngineConfig) (*ConnEngine, error) {
	if cfg.Wrap == nil {
		return nil, Errorf(StatusInvalidArgument, "ConnEngineConfig.Wrap must not be nil")
	}
	e := &ConnEngine{
		host:      cfg.Host,
		handshake: cfg.Handshake,
		readChunk: cfg.ReadChunk,
		maxAppIn:  cfg.MaxPendingAppInput,
		appHint:   cfg.AppOutputSize,
		netHint:   cfg.NetOutputSize,
		batchHint: cfg.OutputBatch,
	}
	if e.readChunk <= 0 {
		e.readChunk = defaultConnReadChunk
	}
	if e.maxAppIn <= 0 {
		e.maxAppIn = defaultMaxPendingApp
	}
	if e.appHint <= 0 {
		e.appHint = defaultAppOutputSize
	}
	if e.netHint <= 0 {
		e.netHint = defaultNetOutputSize
	}
	if e.batchHint <= 0 {
		e.batchHint = defaultOutputBatch
	}
	e.cond.L = &e.mu
	e.inner = &memConn{engine: e}

	outer, err := cfg.Wrap(e.inner)
	if err != nil {
		return nil, err
	}
	if outer == nil {
		return nil, Errorf(StatusPluginFailure, "ConnEngineConfig.Wrap returned no conn")
	}
	e.outer = outer
	if e.handshake == nil {
		if h, ok := outer.(Handshaker); ok {
			e.handshake = func(net.Conn) error { return h.Handshake() }
		}
	}

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.run()
	}()
	return e, nil
}

// Conn is the wrapped conn, for a plugin that needs to look at it once the
// handshake is done -- the negotiated ALPN, say.
func (e *ConnEngine) Conn() net.Conn { return e.outer }

// --- the StreamEngine side -------------------------------------------------

func (e *ConnEngine) PollState() StateFlags {
	e.mu.Lock()
	defer e.mu.Unlock()

	var flags StateFlags
	if e.fatal != nil {
		flags |= StateFatal
	}
	if e.handshakeDone {
		flags |= StateEstablished
	} else {
		flags |= StateHandshaking
	}
	if e.netOut.Len() > 0 {
		flags |= StateHasNetOutput
	}
	if e.appOut.Len() > 0 {
		flags |= StateHasAppOutput
	}
	if !e.closedAppIn && e.appIn.Len() < e.maxAppIn {
		flags |= StateWantAppInput
	}
	if !e.closedNetIn {
		flags |= StateWantNetInput
	}
	if e.peerClosed {
		flags |= StatePeerClosed
	}
	// Network input has been handed over but the goroutines have not turned it
	// into output yet. Feeding more would not help; consuming it wakes the
	// host, which is what gets it polling again.
	//
	// Only netIn counts. Pending application input does not mean progress is
	// coming: the write loop may be waiting on a handshake that is itself
	// waiting for the host to read from the peer, and reporting BLOCKED then
	// would park the host on a wake that can never arrive.
	if e.fatal == nil && !e.transportClosed &&
		e.netOut.Len() == 0 && e.appOut.Len() == 0 && e.netIn.Len() > 0 {
		flags |= StateBlocked
	}
	return flags
}

func (e *ConnEngine) Push(side Side, input []byte) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	switch side {
	case SideApp:
		if e.closedAppIn {
			return 0, Errorf(StatusPluginFailure, "push(app) after the application side was closed")
		}
		room := e.maxAppIn - e.appIn.Len()
		if room <= 0 {
			// Backpressure: the host keeps the bytes and offers them again.
			return 0, nil
		}
		n := min(room, len(input))
		if n > 0 {
			_, _ = e.appIn.Write(input[:n])
			e.notifyLocked()
		}
		return n, nil
	case SideNet:
		if len(input) > 0 {
			_, _ = e.netIn.Write(input)
			e.notifyLocked()
		}
		return len(input), nil
	default:
		return 0, Errorf(StatusInvalidArgument, "invalid stream side for push: %d", uint32(side))
	}
}

func (e *ConnEngine) Pull(side Side, output []byte) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	var source *bytes.Buffer
	switch side {
	case SideApp:
		source = &e.appOut
	case SideNet:
		source = &e.netOut
	default:
		return 0, Errorf(StatusInvalidArgument, "invalid stream side for pull: %d", uint32(side))
	}
	// Output the peer already produced outlives a failure: the host is entitled
	// to drain what is there before the error takes the connection down.
	if source.Len() == 0 && e.fatal != nil {
		return 0, &Error{Status: StatusPluginFailure, Message: e.fatal.Error()}
	}
	n, _ := source.Read(output)
	return n, nil
}

func (e *ConnEngine) Close(flags CloseFlags) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if flags.Has(CloseApp) {
		e.closedAppIn = true
	}
	if flags.Has(CloseNet) {
		e.closedNetIn = true
	}
	e.notifyLocked()
	return nil
}

func (e *ConnEngine) Destroy() {
	e.mu.Lock()
	e.transportClosed = true
	e.notifyLocked()
	e.mu.Unlock()

	_ = e.outer.Close()
	// The ABI lets destroy block, and only destroy: nothing here may still be
	// running once it returns.
	e.wg.Wait()
}

func (e *ConnEngine) SuggestOutputSize(side Side) int {
	switch side {
	case SideApp:
		return e.appHint
	case SideNet:
		return e.netHint
	default:
		return fallbackOutputSize
	}
}

func (e *ConnEngine) SuggestOutputBatch(Side) int { return e.batchHint }

// --- the goroutines --------------------------------------------------------

// notifyLocked wakes both the engine's goroutines and the host. Called with
// e.mu held wherever host-visible state changes.
func (e *ConnEngine) notifyLocked() {
	e.cond.Broadcast()
	e.host.Wake()
}

func (e *ConnEngine) setFatalLocked(err error) {
	if err == nil || e.fatal != nil {
		return
	}
	e.fatal = err
	e.host.Log(LevelError, err.Error())
	e.notifyLocked()
}

func (e *ConnEngine) run() {
	if e.handshake != nil {
		if err := e.handshake(e.outer); err != nil {
			e.mu.Lock()
			if !e.transportClosed {
				e.setFatalLocked(err)
			}
			e.mu.Unlock()
			return
		}
	}

	e.mu.Lock()
	if e.transportClosed {
		e.mu.Unlock()
		return
	}
	e.handshakeDone = true
	e.notifyLocked()
	e.mu.Unlock()

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.writeLoop()
	}()
	e.readLoop()
}

func (e *ConnEngine) writeLoop() {
	for {
		e.mu.Lock()
		for e.appIn.Len() == 0 && !e.closedAppIn && e.fatal == nil && !e.transportClosed {
			e.cond.Wait()
		}
		if e.fatal != nil || e.transportClosed {
			e.mu.Unlock()
			return
		}
		if e.appIn.Len() == 0 && e.closedAppIn {
			e.mu.Unlock()
			// The application is done writing, so whatever the protocol says
			// about that -- a TLS close notify, say -- goes out now. Closing
			// the wrapped conn is what emits it; it also closes the memory
			// conn under it, which ends the read loop.
			_ = e.outer.Close()
			return
		}
		data := append([]byte(nil), e.appIn.Bytes()...)
		e.appIn.Reset()
		// Taking the input is what makes room, so the host has to be told even
		// though nothing was produced yet.
		e.notifyLocked()
		e.mu.Unlock()

		n, err := e.outer.Write(data)
		if n < len(data) {
			e.mu.Lock()
			prependBuffer(&e.appIn, data[n:])
			e.mu.Unlock()
		}
		if err != nil {
			e.mu.Lock()
			e.setFatalLocked(err)
			e.mu.Unlock()
			return
		}
	}
}

func (e *ConnEngine) readLoop() {
	scratch := make([]byte, e.readChunk)
	for {
		n, err := e.outer.Read(scratch)
		if n > 0 {
			e.mu.Lock()
			_, _ = e.appOut.Write(scratch[:n])
			e.notifyLocked()
			e.mu.Unlock()
		}
		if err != nil {
			e.mu.Lock()
			if errors.Is(err, io.EOF) {
				e.peerClosed = true
			} else if !e.closedNetIn && !e.closedAppIn && !e.transportClosed {
				e.setFatalLocked(err)
			}
			e.notifyLocked()
			e.mu.Unlock()
			return
		}
	}
}

func prependBuffer(buf *bytes.Buffer, data []byte) {
	if len(data) == 0 {
		return
	}
	var next bytes.Buffer
	_, _ = next.Write(data)
	_, _ = next.Write(buf.Bytes())
	*buf = next
}

// --- the in-memory socket --------------------------------------------------

// memConn is the net.Conn the wrapped implementation thinks it is talking to.
// Reads block until the host pushes network input; writes land in the buffer
// the host pulls network output from.
type memConn struct {
	engine *ConnEngine
}

func (c *memConn) Read(p []byte) (int, error) {
	e := c.engine
	e.mu.Lock()
	defer e.mu.Unlock()

	for e.netIn.Len() == 0 && !e.closedNetIn && !e.transportClosed {
		e.cond.Wait()
	}
	if e.netIn.Len() > 0 {
		n, err := e.netIn.Read(p)
		// Taking the input clears the reason the host was told to wait, so it
		// has to be told again even though nothing was produced yet.
		e.notifyLocked()
		return n, err
	}
	return 0, io.EOF
}

func (c *memConn) Write(p []byte) (int, error) {
	e := c.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.transportClosed {
		return 0, io.ErrClosedPipe
	}
	n, err := e.netOut.Write(p)
	e.notifyLocked()
	return n, err
}

func (c *memConn) Close() error {
	e := c.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	e.transportClosed = true
	e.notifyLocked()
	return nil
}

func (c *memConn) LocalAddr() net.Addr              { return memAddr("local") }
func (c *memConn) RemoteAddr() net.Addr             { return memAddr("remote") }
func (c *memConn) SetDeadline(time.Time) error      { return nil }
func (c *memConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memConn) SetWriteDeadline(time.Time) error { return nil }

type memAddr string

func (a memAddr) Network() string { return connEngineNetworkName }
func (a memAddr) String() string  { return string(a) }
