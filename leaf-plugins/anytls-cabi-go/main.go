// Command anytls-cabi-go is an AnyTLS client plugin for the leaf C ABI.
//
// It does not implement AnyTLS. The protocol -- authentication, the session
// and stream framing, the padding scheme and its updates from the server -- is
// github.com/anytls/sing-anytls, the AnyTLS author's own library, used as it
// is. What lives here is the adapter between that library and the ABI: the
// arguments, the TLS configuration, the address conversion, and the one
// ConnEngine that turns a blocking net.Conn implementation into an engine the
// host can drive without blocking.
//
// The engine uses leafabi.ConnectProxyTCP, so the outbound sets host and port
// to the AnyTLS server. TLS is part of the plugin rather than a separate
// outbound in a chain, and has to be: the padding scheme is defined over TLS
// records, which only the code writing the records can control. A TLS layer
// below the plugin would merge and split the writes the scheme is made of.
//
// There is no datagram engine. AnyTLS carries UDP as udp-over-tcp inside a
// stream, behind the same TLS handshake, and a datagram engine cannot run a
// handshake: it produces output only when it is handed a datagram. See the
// README.
//
// args is JSON:
//
//	{
//	  "password": "...",
//	  "server_name": "example.com",
//	  "alpn": ["h2"],
//	  "certificate": "/path/to/ca.pem",
//	  "insecure": false,
//	  "fingerprint": "chrome"
//	}
//
// password is required, and so is server_name unless insecure is set.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	anytls "github.com/anytls/sing-anytls"
	M "github.com/sagernet/sing/common/metadata"

	leafabi "leaf-plugins/leaf-abi-go"
)

func main() {}

func init() {
	leafabi.Register(leafabi.Plugin{
		Name:      "leaf-anytls-cabi-go-plugin",
		Version:   "0.1.0",
		LogTarget: "leaf.plugin.anytls",
		Stream: &leafabi.StreamEngineSpec{
			ConnectType: leafabi.ConnectProxyTCP,
			New:         newEngine,
		},
	})
}

type pluginArgs struct {
	Password    string   `json:"password"`
	ServerName  string   `json:"server_name"`
	ALPN        []string `json:"alpn"`
	Certificate string   `json:"certificate"`
	Insecure    bool     `json:"insecure"`
	Fingerprint string   `json:"fingerprint"`
}

func parsePluginArgs(input string) (pluginArgs, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return pluginArgs{}, errors.New("anytls plugin args must not be empty")
	}
	if !strings.HasPrefix(trimmed, "{") {
		// No bare-password shorthand: it could not carry server_name, and an
		// AnyTLS client that cannot check its server's certificate is one any
		// middlebox can impersonate.
		return pluginArgs{}, errors.New("anytls plugin args must be a JSON object")
	}
	var args pluginArgs
	decoder := json.NewDecoder(strings.NewReader(trimmed))
	// A misspelt key would otherwise be a setting that silently does nothing,
	// and the ones here are about whether the server is authenticated.
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&args); err != nil {
		return pluginArgs{}, fmt.Errorf("anytls plugin args: %w", err)
	}
	if args.Password == "" {
		return pluginArgs{}, errors.New("anytls plugin args missing password")
	}
	if args.ServerName == "" && !args.Insecure {
		// The engine never learns which server the host dialled, so there is
		// nothing to check the certificate against unless it is named here.
		return pluginArgs{}, errors.New("anytls plugin args need server_name unless insecure is set")
	}
	return args, nil
}

// outbound is everything that belongs to one outbound rather than to one
// connection: the TLS configuration and the AnyTLS client.
//
// The client is shared on purpose. AnyTLS servers can send a padding scheme of
// their own, and the protocol has the client use it on every later session to
// the same server. A client per connection would forget it each time, and keep
// sending the default scheme to a server that has said it wants another.
type outbound struct {
	client    *anytls.Client
	handshake tlsHandshake
	logger    *leafabi.SharedLogger
}

var (
	outboundsMu sync.Mutex
	outbounds   = map[string]*outbound{}
)

// outboundFor returns the shared state for one args string, building it the
// first time. Building it may read a certificate from disk, which is why it is
// done once rather than on every connection.
func outboundFor(raw string) (*outbound, error) {
	outboundsMu.Lock()
	defer outboundsMu.Unlock()
	if existing, ok := outbounds[raw]; ok {
		return existing, nil
	}
	args, err := parsePluginArgs(raw)
	if err != nil {
		return nil, err
	}
	handshake, err := newTLSHandshake(args)
	if err != nil {
		return nil, err
	}
	o := &outbound{handshake: handshake, logger: leafabi.NewSharedLogger()}
	client, err := anytls.NewClient(context.Background(), anytls.ClientConfig{
		Password: args.Password,
		// Every engine instance is one connection the host owns, so there
		// is no idle session for the library to keep: the host closes the
		// socket when the instance goes. Without this the library would park
		// the session for reuse and the next connection would try to write
		// into a socket that no longer exists.
		DisableReuse: true,
		DialOut:      o.dialOut,
		Logger:       o.logger,
	})
	if err != nil {
		return nil, err
	}
	o.client = client
	outbounds[raw] = o
	return o, nil
}

// connKey carries one engine instance's connection to dialOut. The library
// asks for a connection by calling a function, and the connection it has to
// get is the one the host already made.
type connKey struct{}

func (o *outbound) dialOut(ctx context.Context) (net.Conn, error) {
	raw, ok := ctx.Value(connKey{}).(net.Conn)
	if !ok {
		return nil, errors.New("anytls: no connection for this session")
	}
	return o.handshake(ctx, raw)
}

func newEngine(args leafabi.CreateArgs) (leafabi.StreamEngine, error) {
	o, err := outboundFor(args.Args)
	if err != nil {
		return nil, leafabi.Errorf(leafabi.StatusInvalidArgument, "%v", err)
	}
	destination, err := socksaddr(args.Destination)
	if err != nil {
		return nil, err
	}
	host := args.Host
	host.Logf(leafabi.LevelDebug, "creating AnyTLS engine for %s", destination)
	return leafabi.NewConnEngine(leafabi.ConnEngineConfig{
		Host: host,
		Wrap: func(inner net.Conn) (net.Conn, error) {
			return newProxyConn(o, host, inner, destination), nil
		},
		AppOutputSize: 16 * 1024,
		NetOutputSize: 18 * 1024,
		ReadChunk:     16 * 1024,
	})
}

// socksaddr converts the host's destination into the library's.
func socksaddr(address leafabi.Address) (M.Socksaddr, error) {
	if err := address.Validate(); err != nil {
		return M.Socksaddr{}, err
	}
	switch address.Kind {
	case leafabi.AddressDomain:
		return M.ParseSocksaddrHostPort(string(address.Bytes), address.Port), nil
	default:
		return M.SocksaddrFrom(M.AddrFromIP(net.IP(address.Bytes)), address.Port), nil
	}
}

// proxyConn is the conn ConnEngine drives: Handshake opens the AnyTLS stream,
// and Read and Write are the stream's from then on.
type proxyConn struct {
	outbound    *outbound
	inner       net.Conn
	destination M.Socksaddr

	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	stream net.Conn
	closed bool
}

func newProxyConn(o *outbound, host leafabi.Host, inner net.Conn, destination M.Socksaddr) *proxyConn {
	ctx, cancel := context.WithCancel(context.Background())
	c := &proxyConn{
		outbound:    o,
		inner:       inner,
		destination: destination,
		ctx:         context.WithValue(ctx, connKey{}, inner),
		cancel:      cancel,
	}
	o.logger.Attach(c, host)
	return c
}

// Handshake runs the TLS handshake, authenticates, and opens the one stream
// this connection carries, with the destination as its first bytes.
func (c *proxyConn) Handshake() error {
	stream, err := c.outbound.client.CreateProxy(c.ctx, c.destination)
	if err != nil {
		return fmt.Errorf("anytls: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		_ = stream.Close()
		return net.ErrClosed
	}
	c.stream = stream
	return nil
}

func (c *proxyConn) current() (net.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stream == nil {
		return nil, errors.New("anytls: stream used before the handshake")
	}
	return c.stream, nil
}

func (c *proxyConn) Read(p []byte) (int, error) {
	stream, err := c.current()
	if err != nil {
		return 0, err
	}
	return stream.Read(p)
}

func (c *proxyConn) Write(p []byte) (int, error) {
	stream, err := c.current()
	if err != nil {
		return 0, err
	}
	return stream.Write(p)
}

// Close ends the stream, which with reuse disabled ends the session and the
// TLS connection under it. Before the handshake has produced a stream it
// cancels the handshake instead, by closing the connection it is running on.
func (c *proxyConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	stream := c.stream
	c.mu.Unlock()

	c.cancel()
	if stream != nil {
		_ = stream.Close()
	}
	err := c.inner.Close()
	c.outbound.logger.Detach(c)
	return err
}

func (c *proxyConn) LocalAddr() net.Addr  { return c.inner.LocalAddr() }
func (c *proxyConn) RemoteAddr() net.Addr { return c.inner.RemoteAddr() }

// Deadlines are the host's business: it owns the socket and its timeouts. The
// library sets them on the stream for its own purposes, and those go through.
func (c *proxyConn) SetDeadline(t time.Time) error {
	if stream, err := c.current(); err == nil {
		return stream.SetDeadline(t)
	}
	return nil
}

func (c *proxyConn) SetReadDeadline(t time.Time) error {
	if stream, err := c.current(); err == nil {
		return stream.SetReadDeadline(t)
	}
	return nil
}

func (c *proxyConn) SetWriteDeadline(t time.Time) error {
	if stream, err := c.current(); err == nil {
		return stream.SetWriteDeadline(t)
	}
	return nil
}
