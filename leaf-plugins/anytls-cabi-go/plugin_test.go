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
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	leafabi "leaf-plugins/leaf-abi-go"
	"leaf-plugins/leaf-abi-go/enginetest"
)

// These tests run the plugin against the server half of the same library, in
// process, with the engine driven the way the host drives it. The end-to-end
// suite does the same against real server binaries -- anytls-go, sing-box and
// mihomo -- through a real leaf; what this file adds is the ground a
// deployment cannot reach: the exact records on the wire, a server that
// changes its padding scheme, and the failure paths one at a time.

const step = 10 * time.Second

// --- the server ------------------------------------------------------------

type testCert struct {
	tls     tls.Certificate
	pemCert string
}

var (
	certOnce sync.Once
	cert     testCert
)

func serverCert(t *testing.T) testCert {
	t.Helper()
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

// connection is one stream the server accepted, as its handler saw it.
type connection struct {
	destination M.Socksaddr
}

// server is an AnyTLS server on a loopback port: crypto/tls in front of
// sing-anytls's Service, with a handler that echoes, or refuses on request.
type server struct {
	t        *testing.T
	listener net.Listener
	service  *anytls.Service
	accepted chan connection
	refuse   bool
	wg       sync.WaitGroup
}

type serverOptions struct {
	password      string
	paddingScheme string
	refuse        bool
}

func startServer(t *testing.T, options serverOptions) *server {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &server{t: t, listener: listener, accepted: make(chan connection, 64), refuse: options.refuse}
	scheme := []byte(options.paddingScheme)
	if len(scheme) == 0 {
		scheme = defaultPaddingScheme
	}
	s.service, err = anytls.NewService(anytls.ServiceConfig{
		PaddingScheme: scheme,
		Users:         []anytls.User{{Name: "test", Password: options.password}},
		Handler:       s,
		Logger:        logger.NOP(),
	})
	if err != nil {
		t.Fatalf("anytls service: %v", err)
	}
	config := &tls.Config{Certificates: []tls.Certificate{serverCert(t).tls}, MinVersion: tls.VersionTLS13}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				conn := tls.Server(raw, config)
				defer conn.Close()
				_ = s.service.NewConnection(context.Background(), conn, M.SocksaddrFromNet(raw.RemoteAddr()), nil)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		s.wg.Wait()
	})
	return s
}

func (s *server) addr() string { return s.listener.Addr().String() }

// NewConnectionEx is the server's outbound: it reports the stream open --
// which is what sends SYNACK to a version 2 client -- and echoes.
func (s *server) NewConnectionEx(_ context.Context, conn net.Conn, _ M.Socksaddr, destination M.Socksaddr, _ N.CloseHandlerFunc) {
	s.accepted <- connection{destination: destination}
	if s.refuse {
		_ = N.ReportHandshakeFailure(conn, errors.New("connection refused"))
		_ = conn.Close()
		return
	}
	_ = N.ReportHandshakeSuccess(conn)
	_, _ = io.Copy(conn, conn)
	_ = conn.Close()
}

func (s *server) nextConnection(t *testing.T) connection {
	t.Helper()
	select {
	case c := <-s.accepted:
		return c
	case <-time.After(step):
		t.Fatal("the server never saw a stream")
		return connection{}
	}
}

// --- the client ------------------------------------------------------------

type client struct {
	engine leafabi.StreamEngine
	driver *enginetest.Driver
}

// dial makes an engine the way the host does -- from the args and the
// destination -- connects its network side to wire, and starts driving it.
func dial(t *testing.T, wire net.Conn, args string, destination leafabi.Address) *client {
	t.Helper()
	engine, err := newEngine(leafabi.CreateArgs{Args: args, Destination: destination})
	if err != nil {
		t.Fatalf("newEngine: %v", err)
	}
	c := &client{engine: engine, driver: enginetest.Start(engine, wire)}
	t.Cleanup(c.close)
	return c
}

func (c *client) close() {
	c.driver.Stop()
	c.engine.Destroy()
}

func dialTCP(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	return conn
}

// argsFor builds a JSON args string. Each test uses a password of its own,
// because the plugin keeps state per args string -- the server's padding
// scheme -- and a test must not inherit another's.
func argsFor(t *testing.T, extra map[string]any) (string, string) {
	t.Helper()
	password := "pw-" + t.Name()
	args := map[string]any{
		"password":    password,
		"server_name": "localhost",
		"certificate": serverCert(t).pemCert,
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

func ipv4(port uint16) leafabi.Address {
	a, _ := leafabi.IPAddress(net.IPv4(127, 0, 0, 1), port)
	return a
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
		t.Fatalf("echo differs: sent %d bytes, got %d back, first difference at %d",
			len(payload), len(got), firstDifference(got, payload))
	}
}

func firstDifference(a, b []byte) int {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}

// --- tests -----------------------------------------------------------------

func TestEchoAndDestinationEveryAddressKind(t *testing.T) {
	ipv6, _ := leafabi.IPAddress(net.ParseIP("2001:db8::7"), 8443)
	for _, tc := range []struct {
		name string
		addr leafabi.Address
		want string
	}{
		{"ipv4", ipv4(9001), "127.0.0.1:9001"},
		{"ipv6", ipv6, "[2001:db8::7]:8443"},
		{"domain", leafabi.DomainAddress("origin.example", 443), "origin.example:443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args, password := argsFor(t, nil)
			s := startServer(t, serverOptions{password: password})
			c := dial(t, dialTCP(t, s.addr()), args, tc.addr)
			echo(t, c, []byte("hello"))
			echo(t, c, []byte("and again"))
			if got := s.nextConnection(t).destination.String(); got != tc.want {
				t.Fatalf("server saw destination %s, want %s", got, tc.want)
			}
		})
	}
}

func TestBulkInBothDirections(t *testing.T) {
	args, password := argsFor(t, nil)
	s := startServer(t, serverOptions{password: password})
	c := dial(t, dialTCP(t, s.addr()), args, ipv4(80))

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
		t.Fatalf("4 MiB echoed back corrupted, first difference at %d", firstDifference(got, payload))
	}
}

func TestFingerprints(t *testing.T) {
	// Not "random": a randomised ClientHello may offer only TLS 1.2, which
	// this server -- TLS 1.3 only, for the record arithmetic below -- refuses.
	for _, name := range []string{"chrome", "firefox", "safari", "ios", "edge"} {
		t.Run(name, func(t *testing.T) {
			args, password := argsFor(t, map[string]any{"fingerprint": name})
			s := startServer(t, serverOptions{password: password})
			c := dial(t, dialTCP(t, s.addr()), args, ipv4(80))
			echo(t, c, []byte("through a "+name+" ClientHello"))
		})
	}
}

// The padding scheme is the point of AnyTLS, and it is defined over TLS
// records. This reads the records the plugin actually put on the wire and
// checks the first ones against the default scheme:
//
//	0=30-30                 authentication: 32 + 2 + 30 bytes of padding
//	1=100-400               settings, SYN and the destination, padded
//	2=400-500,c,...         the first application write, padded up to one record
//
// It is the test that fails if anything between the library and the socket --
// the TLS stack, ConnEngine, the host's pull loop -- merges or splits writes.
func TestRecordsFollowTheDefaultPaddingScheme(t *testing.T) {
	args, password := argsFor(t, nil)
	s := startServer(t, serverOptions{password: password})
	relay := startRecordRelay(t, s.addr())
	c := dial(t, dialTCP(t, relay.addr()), args, ipv4(80))
	echo(t, c, []byte("hello"))

	records := relay.clientRecords()
	// TLS 1.3: the client's first encrypted record is its Finished. What the
	// scheme governs starts after it.
	if len(records) < 4 {
		t.Fatalf("only %d application data records from the client", len(records))
	}
	plaintext := func(i int) int { return records[i] - tls13Overhead }
	if got := plaintext(1); got != 32+2+30 {
		t.Errorf("authentication record carries %d bytes, want %d", got, 32+2+30)
	}
	if got := plaintext(2); got < 100 || got > 400 {
		t.Errorf("settings record carries %d bytes, want 100..400", got)
	}
	if got := plaintext(3); got < 400 || got > 500 {
		t.Errorf("first data record carries %d bytes, want 400..500", got)
	}
}

// A server may prefer a scheme of its own. It says so on the first session,
// and the protocol has the client use the new scheme from the next session to
// that server on. That only works because every connection of one outbound
// shares one client.
func TestServerPaddingSchemeIsUsedFromTheNextConnection(t *testing.T) {
	const scheme = "stop=3\n0=50-50\n1=200-200\n2=300-300"
	args, password := argsFor(t, nil)
	s := startServer(t, serverOptions{password: password, paddingScheme: scheme})
	relay := startRecordRelay(t, s.addr())

	first := dial(t, dialTCP(t, relay.addr()), args, ipv4(80))
	echo(t, first, []byte("learns the scheme"))
	first.close()

	before := len(relay.clientRecords())
	second := dial(t, dialTCP(t, relay.addr()), args, ipv4(80))
	echo(t, second, []byte("uses it"))

	records := relay.clientRecords()[before:]
	if len(records) < 4 {
		t.Fatalf("only %d records on the second connection", len(records))
	}
	want := []int{32 + 2 + 50, 200, 300}
	for i, size := range want {
		if got := records[i+1] - tls13Overhead; got != size {
			t.Errorf("record %d of the second connection carries %d bytes, want %d (the server's scheme)", i, got, size)
		}
	}
}

func TestWrongPasswordIsRefused(t *testing.T) {
	args, _ := argsFor(t, nil)
	s := startServer(t, serverOptions{password: "not-the-one-the-client-has"})
	c := dial(t, dialTCP(t, s.addr()), args, ipv4(80))
	if err := c.driver.Write([]byte("hello"), step); err != nil {
		return // refused before the write was even taken
	}
	got, err := c.driver.ReadToEnd(step)
	if err == nil && len(got) == 0 {
		return // closed
	}
	if len(got) > 0 {
		t.Fatalf("a server that rejected the password echoed %q", got)
	}
}

// An outbound connection the server could not make is reported back to a
// version 2 client, which ends the stream rather than leaving the application
// waiting for a reply that will never come.
func TestRefusedDestinationEndsTheConnection(t *testing.T) {
	args, password := argsFor(t, nil)
	s := startServer(t, serverOptions{password: password, refuse: true})
	c := dial(t, dialTCP(t, s.addr()), args, ipv4(80))
	_ = c.driver.Write([]byte("hello"), step)
	got, _ := c.driver.ReadToEnd(step)
	if len(got) > 0 {
		t.Fatalf("a refused stream delivered %q", got)
	}
}

// AnyTLS has no half close: a FIN frame ends the stream in both directions.
// Ending the application side must therefore end the connection, promptly and
// on both ends, rather than leave a stream nobody can finish.
func TestClosingTheApplicationSideEndsTheConnection(t *testing.T) {
	args, password := argsFor(t, nil)
	s := startServer(t, serverOptions{password: password})
	c := dial(t, dialTCP(t, s.addr()), args, ipv4(80))
	echo(t, c, []byte("hello"))
	c.driver.CloseApp()
	if _, err := c.driver.ReadToEnd(step); err != nil && !strings.Contains(err.Error(), "FATAL") {
		t.Fatalf("after closing the application side: %v", err)
	}
}

func TestCertificateIsVerified(t *testing.T) {
	args, password := argsFor(t, map[string]any{"server_name": "not-localhost.example"})
	s := startServer(t, serverOptions{password: password})
	c := dial(t, dialTCP(t, s.addr()), args, ipv4(80))
	_ = c.driver.Write([]byte("hello"), step)
	if _, err := c.driver.ReadFull(5, step); err == nil {
		t.Fatal("a certificate for another name was accepted")
	}
	if state := c.driver.State(); !state.Has(leafabi.StateFatal) {
		t.Fatalf("state after a failed verification is %#x, want FATAL", uint32(state))
	}
}

// The host may destroy an instance at any point, including while the
// handshake is waiting on a server that never answers. Destroy has to return
// anyway, and leave nothing running.
func TestDestroyDuringHandshakeReturns(t *testing.T) {
	args, _ := argsFor(t, nil)
	silent, peer := net.Pipe()
	defer peer.Close()
	engine, err := newEngine(leafabi.CreateArgs{Args: args, Destination: ipv4(80)})
	if err != nil {
		t.Fatal(err)
	}
	driver := enginetest.Start(engine, silent)
	done := make(chan struct{})
	go func() {
		// Long enough for the ClientHello to be on its way and the
		// handshake to be waiting on a reply that will never come.
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
	parsed, err := parsePluginArgs(`{"password":"x","server_name":"a.example","fingerprint":"chrome","alpn":["h2"]}`)
	if err != nil {
		t.Fatalf("valid args: %v", err)
	}
	if parsed.Password != "x" || parsed.ServerName != "a.example" || parsed.Fingerprint != "chrome" || len(parsed.ALPN) != 1 {
		t.Fatalf("parsed %+v", parsed)
	}
	if _, err := parsePluginArgs(`{"password":"x","insecure":true}`); err != nil {
		t.Fatalf("insecure without server_name is allowed: %v", err)
	}
	for _, bad := range []string{
		"",
		"bare-password",
		`{"server_name":"a.example"}`,
		`{"password":"x"}`,
		`{"password":"x","server_name":"a.example","fingerprnt":"chrome"}`,
		`{"password":"x",`,
	} {
		if _, err := parsePluginArgs(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := newTLSHandshake(pluginArgs{Password: "x", ServerName: "a", Fingerprint: "netscape"}); err == nil {
		t.Error("accepted an unknown fingerprint")
	}
	if _, err := newEngine(leafabi.CreateArgs{Args: "bare-" + t.Name(), Destination: ipv4(80)}); err == nil {
		t.Error("created an engine from args it cannot parse")
	}
}

// --- a relay that reads TLS records ----------------------------------------

// tls13Overhead is what TLS 1.3 adds to a record's length field: the inner
// content type byte and a 16-byte AEAD tag. Go negotiates only AEAD suites
// with 16-byte tags.
const tls13Overhead = 1 + 16

// recordRelay forwards TCP both ways, and parses what the client sends into
// TLS records so a test can see where the writes were cut.
type recordRelay struct {
	listener net.Listener
	upstream string
	mu       sync.Mutex
	records  []int
	wg       sync.WaitGroup
}

func startRecordRelay(t *testing.T, upstream string) *recordRelay {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &recordRelay{listener: listener, upstream: upstream}
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
				r.forwardRecords(up, down)
				_ = up.Close()
			}()
			go func() {
				defer r.wg.Done()
				_, _ = io.Copy(down, up)
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

func (r *recordRelay) addr() string { return r.listener.Addr().String() }

// forwardRecords copies one TLS record at a time, noting the length of each
// application data record.
func (r *recordRelay) forwardRecords(dst io.Writer, src io.Reader) {
	header := make([]byte, 5)
	for {
		if _, err := io.ReadFull(src, header); err != nil {
			return
		}
		length := int(binary.BigEndian.Uint16(header[3:5]))
		body := make([]byte, length)
		if _, err := io.ReadFull(src, body); err != nil {
			return
		}
		if header[0] == 23 {
			r.mu.Lock()
			r.records = append(r.records, length)
			r.mu.Unlock()
		}
		if _, err := dst.Write(append(header, body...)); err != nil {
			return
		}
		header = make([]byte, 5)
	}
}

func (r *recordRelay) clientRecords() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]int(nil), r.records...)
}

// defaultPaddingScheme is the scheme the protocol specifies, spelled out here
// rather than taken from the library so that the test states what it checks.
var defaultPaddingScheme = []byte(`stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000`)
