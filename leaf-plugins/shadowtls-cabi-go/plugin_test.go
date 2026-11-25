package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/metacubex/utls"
	shadowtls "github.com/sagernet/sing-shadowtls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	leafabi "leaf-plugins/leaf-abi-go"
	"leaf-plugins/leaf-abi-go/enginetest"
)

// These tests run the plugin against the server half of the same library, in
// process, with a real TLS server standing in for the site whose handshake is
// borrowed, and the engine driven the way the host drives it. The end-to-end
// suite does the same against the server binaries -- shadow-tls, sing-box and
// mihomo -- through a real leaf. What this file adds is the ground a
// deployment cannot reach on demand: a connection hijacked to the real site,
// a site that only speaks TLS 1.2, a HelloRetryRequest, and a record altered
// on the way.

const step = 10 * time.Second

// --- certificates ----------------------------------------------------------

type testCert struct {
	tls     tls.Certificate
	pemCert string
}

var (
	certOnce sync.Once
	cert     testCert
)

func siteCert() testCert {
	certOnce.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "localhost"},
			DNSNames:              []string{"localhost"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			panic(err)
		}
		cert = testCert{
			tls:     tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
			pemCert: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		}
	})
	return cert
}

// --- the handshake site ----------------------------------------------------

// site is the real TLS server a ShadowTLS server borrows its handshake from.
// It answers any request the way a web server would, and counts the requests
// it answered: a client that was hijacked to it is supposed to make one.
type site struct {
	listener net.Listener
	requests atomic.Int32
	wg       sync.WaitGroup
}

type siteOptions struct {
	// tls12 limits the site to TLS 1.2, which ShadowTLS v3 strict refuses.
	tls12 bool
	// hrr makes the site prefer a group no client offers a key share for,
	// so every handshake starts with a HelloRetryRequest.
	hrr bool
}

func startSite(t *testing.T, options siteOptions) *site {
	t.Helper()
	config := &tls.Config{Certificates: []tls.Certificate{siteCert().tls}}
	if options.tls12 {
		config.MaxVersion = tls.VersionTLS12
	}
	if options.hrr {
		config.CurvePreferences = []tls.CurveID{tls.CurveP384}
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	s := &site{listener: listener}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(step))
				buf := make([]byte, 4096)
				if n, err := conn.Read(buf); err == nil && n > 0 {
					s.requests.Add(1)
					_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		s.wg.Wait()
	})
	return s
}

func (s *site) addr() string { return s.listener.Addr().String() }

// --- the shadow server -----------------------------------------------------

// shadowServer is sing-shadowtls's v3 server on a loopback port, handing
// every authenticated connection to an echo.
type shadowServer struct {
	listener net.Listener
	service  *shadowtls.Service
	accepted atomic.Int32
	wg       sync.WaitGroup
}

func startShadowServer(t *testing.T, password string, site *site, strict bool) *shadowServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &shadowServer{listener: listener}
	s.service, err = shadowtls.NewService(shadowtls.ServiceConfig{
		Version:    3,
		Users:      []shadowtls.User{{Name: "test", Password: password}},
		Handshake:  shadowtls.HandshakeConfig{Server: M.ParseSocksaddr(site.addr()), Dialer: N.SystemDialer},
		StrictMode: strict,
		Handler:    s,
		Logger:     logger.NOP(),
	})
	if err != nil {
		t.Fatal(err)
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer conn.Close()
				_ = s.service.NewConnection(context.Background(), conn, M.SocksaddrFromNet(conn.RemoteAddr()), M.Socksaddr{}, nil)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		s.wg.Wait()
	})
	return s
}

func (s *shadowServer) addr() string { return s.listener.Addr().String() }

func (s *shadowServer) NewConnectionEx(_ context.Context, conn net.Conn, _ M.Socksaddr, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	s.accepted.Add(1)
	_, _ = io.Copy(conn, conn)
	_ = conn.Close()
}

// --- the client ------------------------------------------------------------

type client struct {
	engine leafabi.StreamEngine
	driver *enginetest.Driver
}

func dial(t *testing.T, addr, args string) *client {
	t.Helper()
	wire, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	return dialOver(t, wire, args)
}

func dialOver(t *testing.T, wire net.Conn, args string) *client {
	t.Helper()
	// A transport engine is never told a destination: the protocol inside it
	// carries that.
	engine, err := newEngine(leafabi.CreateArgs{Args: args})
	if err != nil {
		t.Fatalf("newEngine: %v", err)
	}
	c := &client{engine: engine, driver: enginetest.Start(engine, wire)}
	t.Cleanup(func() {
		c.driver.Stop()
		c.engine.Destroy()
	})
	return c
}

// argsFor builds args with a password of the test's own; extra overrides.
func argsFor(t *testing.T, extra map[string]any) (string, string) {
	t.Helper()
	password := "pw-" + t.Name()
	args := map[string]any{
		"password":    password,
		"server_name": "localhost",
		"certificate": siteCert().pemCert,
	}
	for k, v := range extra {
		args[k] = v
	}
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded), password
}

func echo(t *testing.T, c *client, payload []byte) {
	t.Helper()
	if err := c.driver.Write(payload, step); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := c.driver.ReadFull(len(payload), step)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo differs: sent %q, got %q", payload, got)
	}
}

// refused asserts the connection fails rather than carrying data: nothing
// comes back, and the engine either reports FATAL or ends.
func refused(t *testing.T, c *client, why string) {
	t.Helper()
	_ = c.driver.Write([]byte("must not arrive"), step)
	got, _ := c.driver.ReadToEnd(step)
	if len(got) > 0 {
		t.Fatalf("%s, yet %q came back", why, got)
	}
}

// --- tests -----------------------------------------------------------------

func TestEchoWithEveryFingerprint(t *testing.T) {
	for _, name := range []string{"none", "chrome", "firefox", "safari", "ios", "edge"} {
		t.Run(name, func(t *testing.T) {
			args, password := argsFor(t, map[string]any{"fingerprint": name})
			server := startShadowServer(t, password, startSite(t, siteOptions{}), true)
			c := dial(t, server.addr(), args)
			echo(t, c, []byte("hello"))
			echo(t, c, []byte("and again, through "+name))
		})
	}
}

func TestBulkInBothDirections(t *testing.T) {
	args, password := argsFor(t, map[string]any{"fingerprint": "chrome"})
	server := startShadowServer(t, password, startSite(t, siteOptions{}), true)
	c := dial(t, server.addr(), args)

	payload := make([]byte, 4<<20)
	_, _ = rand.Read(payload)
	done := make(chan error, 1)
	go func() { done <- c.driver.Write(payload, 30*time.Second) }()
	got, err := c.driver.ReadFull(len(payload), 30*time.Second)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("write: %v", err)
	}
	if sha256.Sum256(got) != sha256.Sum256(payload) {
		t.Fatal("4 MiB echoed back corrupted")
	}
}

// A HelloRetryRequest means two ServerHellos, and the HMAC chain has to be
// seeded from the first: the case sing-shadowtls fixed in May 2026, and the
// one most likely to differ between implementations.
func TestHelloRetryRequest(t *testing.T) {
	for _, name := range []string{"none", "chrome"} {
		t.Run(name, func(t *testing.T) {
			args, password := argsFor(t, map[string]any{"fingerprint": name})
			server := startShadowServer(t, password, startSite(t, siteOptions{hrr: true}), true)
			c := dial(t, server.addr(), args)
			echo(t, c, []byte("after a retry"))
		})
	}
}

// With the wrong password the server takes the client for a probe and hands
// the whole connection to the real site. The client completes a handshake with
// a perfectly valid certificate -- and must still notice that nobody answered
// with the shadow server's HMAC.
// The fingerprint has to survive the session ID being signed. With uTLS's own
// hook it does not: the ClientHello on the wire is Go's, whatever was asked
// for. This compares the extensions the plugin actually sent with the ones the
// same uTLS parrot sends with no ShadowTLS involved.
func TestFingerprintReachesTheWire(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   utls.ClientHelloID
	}{
		{"chrome", utls.HelloChrome_Auto},
		{"firefox", utls.HelloFirefox_Auto},
		{"safari", utls.HelloSafari_Auto},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args, password := argsFor(t, map[string]any{"fingerprint": tc.name})
			server := startShadowServer(t, password, startSite(t, siteOptions{}), true)
			relay := startTamperRelay(t, server.addr())
			relay.passive = true
			echo(t, dial(t, relay.addr(), args), []byte("hello"))

			sent := extensionSet(t, relay.clientHello())
			want := extensionSet(t, parrotClientHello(t, tc.id))
			if sent != want {
				t.Fatalf("the plugin sent extensions\n  %s\nbut the %s parrot sends\n  %s", sent, tc.name, want)
			}
			if golang := extensionSet(t, parrotClientHello(t, utls.HelloGolang)); sent == golang {
				t.Fatalf("the plugin sent Go's own ClientHello for fingerprint %s", tc.name)
			}
		})
	}
}

func TestWrongPasswordIsTreatedAsHijack(t *testing.T) {
	args, _ := argsFor(t, map[string]any{"fingerprint": "chrome"})
	site := startSite(t, siteOptions{})
	server := startShadowServer(t, "a-password-the-client-does-not-have", site, true)
	c := dial(t, server.addr(), args)
	refused(t, c, "the server did not know the password")
	if server.accepted.Load() != 0 {
		t.Fatal("the server accepted a client with the wrong password")
	}
}

// A connection redirected straight to the real site -- what a censor does to
// find out whether a server is a ShadowTLS one -- must fail the same way.
func TestConnectionHijackedToTheRealSiteIsRefused(t *testing.T) {
	args, _ := argsFor(t, nil)
	site := startSite(t, siteOptions{})
	c := dial(t, site.addr(), args)
	refused(t, c, "the connection reached the real site instead of the shadow server")
}

// Version 3 depends on TLS 1.3 to detect hijacking, so by default a site that
// only offers TLS 1.2 is refused; with strict off it is accepted.
func TestTLS12Site(t *testing.T) {
	t.Run("strict", func(t *testing.T) {
		args, password := argsFor(t, nil)
		server := startShadowServer(t, password, startSite(t, siteOptions{tls12: true}), false)
		refused(t, dial(t, server.addr(), args), "strict mode met a TLS 1.2 site")
	})
	t.Run("not-strict", func(t *testing.T) {
		args, password := argsFor(t, map[string]any{"strict": false})
		server := startShadowServer(t, password, startSite(t, siteOptions{tls12: true}), false)
		echo(t, dial(t, server.addr(), args), []byte("over TLS 1.2"))
	})
}

func TestCertificateIsVerified(t *testing.T) {
	args, password := argsFor(t, map[string]any{"certificate": otherCertPEM(t)})
	server := startShadowServer(t, password, startSite(t, siteOptions{}), true)
	refused(t, dial(t, server.addr(), args), "the site's certificate was signed by nobody the client trusts")
}

// Every data record carries an HMAC chained over everything before it. One
// changed byte from the server must end the connection, not reach the
// application.
func TestTamperedRecordIsRejected(t *testing.T) {
	args, password := argsFor(t, nil)
	server := startShadowServer(t, password, startSite(t, siteOptions{}), true)
	relay := startTamperRelay(t, server.addr())
	c := dial(t, relay.addr(), args)
	_ = c.driver.Write([]byte("hello"), step)
	got, _ := c.driver.ReadToEnd(step)
	if bytes.Contains(got, []byte("hello")) || len(got) > 0 {
		t.Fatalf("a record with a flipped byte was delivered: %q", got)
	}
	if !relay.tampered.Load() {
		t.Fatal("the relay never saw a data record to alter, so this proved nothing")
	}
}

func TestDestroyDuringHandshakeReturns(t *testing.T) {
	args, _ := argsFor(t, nil)
	silent, peer := net.Pipe()
	defer peer.Close()
	engine, err := newEngine(leafabi.CreateArgs{Args: args})
	if err != nil {
		t.Fatal(err)
	}
	driver := enginetest.Start(engine, silent)
	done := make(chan struct{})
	go func() {
		time.Sleep(50 * time.Millisecond)
		driver.Stop()
		engine.Destroy()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(step):
		t.Fatal("Destroy did not return while the handshake was pending")
	}
}

func TestParsePluginArgs(t *testing.T) {
	parsed, err := parsePluginArgs(`{"password":"x","server_name":"www.example.com","fingerprint":"chrome"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.strict() {
		t.Error("strict must default to on")
	}
	off, err := parsePluginArgs(`{"password":"x","server_name":"a","strict":false}`)
	if err != nil || off.strict() {
		t.Errorf("strict:false not honoured: %+v %v", off, err)
	}
	for _, bad := range []string{
		"",
		"just-a-password",
		`{"password":"x"}`,
		`{"server_name":"a"}`,
		`{"password":"x","server_name":"a","stirct":false}`,
	} {
		if _, err := parsePluginArgs(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := newTLSHandshake(pluginArgs{Password: "x", ServerName: "a", Fingerprint: "netscape"}); err == nil {
		t.Error("accepted an unknown fingerprint")
	}
}

// --- helpers ---------------------------------------------------------------

func otherCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "some other CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// tamperRelay forwards both ways and flips one byte in the first data-phase
// record the server sends. The data phase starts after the client's second
// application data record: the first is its encrypted Finished, which goes to
// the real site.
type tamperRelay struct {
	listener      net.Listener
	clientRecords atomic.Int32
	tampered      atomic.Bool
	// passive turns tampering off, for a test that only wants the
	// ClientHello. Set before the first connection.
	passive bool

	mu    sync.Mutex
	hello []byte
	wg    sync.WaitGroup
}

// clientHello is the first handshake record the client sent, without its
// record header.
func (r *tamperRelay) clientHello() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hello
}

func startTamperRelay(t *testing.T, upstream string) *tamperRelay {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &tamperRelay{listener: listener}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		for {
			down, err := listener.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", upstream)
			if err != nil {
				_ = down.Close()
				continue
			}
			r.wg.Add(2)
			go func() {
				defer r.wg.Done()
				r.copyRecords(up, down, func(kind byte, body []byte) {
					if kind == 23 {
						r.clientRecords.Add(1)
					}
					if kind == 22 {
						r.mu.Lock()
						if r.hello == nil {
							r.hello = append([]byte(nil), body...)
						}
						r.mu.Unlock()
					}
				})
				_ = up.Close()
			}()
			go func() {
				defer r.wg.Done()
				r.copyRecords(down, up, func(kind byte, body []byte) {
					if !r.passive && kind == 23 && r.clientRecords.Load() >= 2 && !r.tampered.Load() && len(body) > 4 {
						body[len(body)-1] ^= 0x01
						r.tampered.Store(true)
					}
				})
				_ = down.Close()
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		r.wg.Wait()
	})
	return r
}

func (r *tamperRelay) addr() string { return r.listener.Addr().String() }

func (r *tamperRelay) copyRecords(dst io.Writer, src io.Reader, inspect func(kind byte, body []byte)) {
	for {
		header := make([]byte, 5)
		if _, err := io.ReadFull(src, header); err != nil {
			return
		}
		body := make([]byte, binary.BigEndian.Uint16(header[3:5]))
		if _, err := io.ReadFull(src, body); err != nil {
			return
		}
		inspect(header[0], body)
		if _, err := dst.Write(append(header, body...)); err != nil {
			return
		}
	}
}

// parrotClientHello is the ClientHello a uTLS parrot sends on its own, with no
// session ID hook, captured off a socket.
func parrotClientHello(t *testing.T, id utls.ClientHelloID) []byte {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	got := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer conn.Close()
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			got <- nil
			return
		}
		body := make([]byte, binary.BigEndian.Uint16(header[3:5]))
		_, _ = io.ReadFull(conn, body)
		got <- body
	}()
	raw, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	go func() {
		_ = utls.UClient(raw, &utls.Config{ServerName: "localhost", InsecureSkipVerify: true}, id).Handshake()
	}()
	hello := <-got
	if hello == nil {
		t.Fatal("captured no ClientHello")
	}
	return hello
}

// extensionSet is a ClientHello's extension types, sorted -- Chrome shuffles
// their order on every connection -- with every GREASE value written as
// "grease", since those are random too.
func extensionSet(t *testing.T, hello []byte) string {
	t.Helper()
	if len(hello) < 4+2+32+1 || hello[0] != 1 {
		t.Fatalf("not a ClientHello: % x", hello[:min(len(hello), 8)])
	}
	p := 4 + 2 + 32
	p += 1 + int(hello[p])                              // session id
	p += 2 + int(binary.BigEndian.Uint16(hello[p:p+2])) // cipher suites
	p += 1 + int(hello[p])                              // compression
	end := p + 2 + int(binary.BigEndian.Uint16(hello[p:p+2]))
	p += 2
	var names []string
	for p+4 <= end {
		kind := binary.BigEndian.Uint16(hello[p : p+2])
		if kind&0x0f0f == 0x0a0a && kind>>8 == kind&0xff {
			names = append(names, "grease")
		} else {
			names = append(names, fmt.Sprintf("%04x", kind))
		}
		p += 4 + int(binary.BigEndian.Uint16(hello[p+2:p+4]))
	}
	sort.Strings(names)
	return strings.Join(names, " ")
}
