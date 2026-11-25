// Command shadowtls-cabi-go is a ShadowTLS v3 client plugin for the leaf C ABI.
//
// It does not implement ShadowTLS. The protocol -- the HMAC in the ClientHello
// session ID, reading the ServerRandom, telling the shadow server from the
// real one, and the HMAC chain on every record afterwards -- is
// github.com/sagernet/sing-shadowtls, at the version sing-box itself ships,
// and the ClientHello is uTLS, the fork sing-box and mihomo both use for this.
// What lives here is the adapter: the arguments, the TLS configuration, and a
// ConnEngine around the library's blocking net.Conn.
//
// ShadowTLS is a transport. The engine uses leafabi.ConnectNext: it layers
// over the stream the next actor in a chain dials, and carries whatever
// protocol the chain puts inside it -- usually Shadowsocks, since ShadowTLS
// authenticates the data but does not encrypt it. A chain of
// [shadowtls, shadowsocks] is the usual deployment, with the Shadowsocks actor
// naming the ShadowTLS server as its address.
//
// args is JSON:
//
//	{
//	  "password": "...",
//	  "server_name": "www.example.com",
//	  "alpn": ["h2", "http/1.1"],
//	  "certificate": "/path/to/ca.pem",
//	  "insecure": false,
//	  "fingerprint": "chrome",
//	  "strict": true
//	}
//
// password and server_name are required. server_name is the real site whose
// handshake the server borrows, and the one whose certificate is checked: a
// client that completes a handshake with a certificate it did not verify
// cannot tell a ShadowTLS server from a box in the middle. strict, on unless
// it is set to false, refuses a handshake that was not TLS 1.3, which is what
// protocol version 3 depends on to detect a hijacked connection.
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

	shadowtls "github.com/sagernet/sing-shadowtls"

	leafabi "leaf-plugins/leaf-abi-go"
)

func main() {}

func init() {
	leafabi.Register(leafabi.Plugin{
		Name:      "leaf-shadowtls-cabi-go-plugin",
		Version:   "0.1.0",
		LogTarget: "leaf.plugin.shadowtls",
		Stream: &leafabi.StreamEngineSpec{
			ConnectType: leafabi.ConnectNext,
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
	Strict      *bool    `json:"strict"`
}

func (a pluginArgs) strict() bool { return a.Strict == nil || *a.Strict }

func parsePluginArgs(input string) (pluginArgs, error) {
	trimmed := strings.TrimSpace(input)
	if !strings.HasPrefix(trimmed, "{") {
		return pluginArgs{}, errors.New("shadowtls plugin args must be a JSON object")
	}
	var args pluginArgs
	decoder := json.NewDecoder(strings.NewReader(trimmed))
	// A misspelt key would otherwise be a setting that silently does nothing,
	// and "strict" and "insecure" decide what the client is willing to trust.
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&args); err != nil {
		return pluginArgs{}, fmt.Errorf("shadowtls plugin args: %w", err)
	}
	if args.Password == "" {
		return pluginArgs{}, errors.New("shadowtls plugin args missing password")
	}
	if args.ServerName == "" {
		// Unlike most TLS clients, this one has nothing else to send as the
		// SNI: the server picks the handshake site by it.
		return pluginArgs{}, errors.New("shadowtls plugin args missing server_name")
	}
	return args, nil
}

// outbound is what one outbound's connections share: the client, which holds
// nothing per connection, and the logger it writes to. Building it may read a
// certificate from disk, so it is built once per args string.
type outbound struct {
	client *shadowtls.Client
	logger *leafabi.SharedLogger
}

var (
	outboundsMu sync.Mutex
	outbounds   = map[string]*outbound{}
)

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
	o := &outbound{logger: leafabi.NewSharedLogger()}
	o.client, err = shadowtls.NewClient(shadowtls.ClientConfig{
		Version:      3,
		Password:     args.Password,
		StrictMode:   args.strict(),
		TLSHandshake: handshake,
		Logger:       o.logger,
	})
	if err != nil {
		return nil, err
	}
	outbounds[raw] = o
	return o, nil
}

func newEngine(args leafabi.CreateArgs) (leafabi.StreamEngine, error) {
	o, err := outboundFor(args.Args)
	if err != nil {
		return nil, leafabi.Errorf(leafabi.StatusInvalidArgument, "%v", err)
	}
	host := args.Host
	return leafabi.NewConnEngine(leafabi.ConnEngineConfig{
		Host: host,
		Wrap: func(inner net.Conn) (net.Conn, error) {
			return newShadowConn(o, host, inner), nil
		},
		AppOutputSize: 16 * 1024,
		NetOutputSize: 18 * 1024,
		ReadChunk:     16 * 1024,
	})
}

// shadowConn is the conn ConnEngine drives: Handshake runs the borrowed TLS
// handshake through the library, and Read and Write go through the verified
// conn it returns from then on.
type shadowConn struct {
	outbound *outbound
	inner    net.Conn

	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	verified net.Conn
	closed   bool
}

func newShadowConn(o *outbound, host leafabi.Host, inner net.Conn) *shadowConn {
	ctx, cancel := context.WithCancel(context.Background())
	c := &shadowConn{outbound: o, inner: inner, ctx: ctx, cancel: cancel}
	o.logger.Attach(c, host)
	return c
}

func (c *shadowConn) Handshake() error {
	verified, err := c.outbound.client.DialContextConn(c.ctx, c.inner)
	if err != nil {
		return fmt.Errorf("shadowtls: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		_ = verified.Close()
		return net.ErrClosed
	}
	c.verified = verified
	return nil
}

func (c *shadowConn) current() (net.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.verified == nil {
		return nil, errors.New("shadowtls: connection used before the handshake")
	}
	return c.verified, nil
}

func (c *shadowConn) Read(p []byte) (int, error) {
	conn, err := c.current()
	if err != nil {
		return 0, err
	}
	return conn.Read(p)
}

func (c *shadowConn) Write(p []byte) (int, error) {
	conn, err := c.current()
	if err != nil {
		return 0, err
	}
	return conn.Write(p)
}

// Close closes the connection underneath. ShadowTLS has no close message of
// its own -- the TLS session it borrowed was never used for data, so there is
// no close_notify to send that the server could check -- and closing the
// socket is how both reference implementations end a connection.
func (c *shadowConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	verified := c.verified
	c.mu.Unlock()

	c.cancel()
	if verified != nil {
		_ = verified.Close()
	}
	err := c.inner.Close()
	c.outbound.logger.Detach(c)
	return err
}

// CloseWrite ends the sending side and leaves the receiving side open, which
// is what the host's half close asks for. ShadowTLS has no message for it --
// the data phase is records and nothing else -- so there is nothing to send:
// the host shuts down the socket's sending side itself, and the server sees
// the end of the stream there.
func (c *shadowConn) CloseWrite() error {
	_, err := c.current()
	return err
}

func (c *shadowConn) LocalAddr() net.Addr  { return c.inner.LocalAddr() }
func (c *shadowConn) RemoteAddr() net.Addr { return c.inner.RemoteAddr() }

// Deadlines belong to the host, which owns the socket. The library sets them
// for its own purposes, on a conn that cannot enforce them; they are accepted
// and do nothing.
func (c *shadowConn) SetDeadline(time.Time) error      { return nil }
func (c *shadowConn) SetReadDeadline(time.Time) error  { return nil }
func (c *shadowConn) SetWriteDeadline(time.Time) error { return nil }
