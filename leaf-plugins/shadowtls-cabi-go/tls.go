package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	utls "github.com/metacubex/utls"
	shadowtls "github.com/sagernet/sing-shadowtls"
)

// fingerprints are the ClientHellos the plugin can present instead of Go's own.
// The names are the ones sing-box and mihomo use for the same setting, so a
// configuration written for either carries over.
var fingerprints = map[string]utls.ClientHelloID{
	"chrome":     utls.HelloChrome_Auto,
	"firefox":    utls.HelloFirefox_Auto,
	"safari":     utls.HelloSafari_Auto,
	"ios":        utls.HelloIOS_Auto,
	"edge":       utls.HelloEdge_Auto,
	"android":    utls.HelloAndroid_11_OkHttp,
	"360":        utls.Hello360_Auto,
	"qq":         utls.HelloQQ_Auto,
	"random":     utls.HelloRandomized,
	"randomized": utls.HelloRandomized,
}

// newTLSHandshake is the handshake the library runs against the handshake
// site, through the shadow server. The library supplies the session ID
// generator -- the HMAC that tells the server this client knows the password
// -- and uTLS calls it with the ClientHello it is about to send, whichever
// ClientHello that is.
//
// The session is thrown away once the handshake is done: ShadowTLS carries
// data in records of its own, so the keys negotiated here never encrypt a
// byte. What the handshake is for is looking like one, and proving the
// handshake site was real.
func newTLSHandshake(args pluginArgs) (shadowtls.TLSHandshakeFunc, error) {
	roots, err := rootsFor(args)
	if err != nil {
		return nil, err
	}
	base := &utls.Config{
		ServerName:         args.ServerName,
		NextProtos:         append([]string(nil), args.ALPN...),
		InsecureSkipVerify: args.Insecure,
		RootCAs:            roots,
		// A resumed session would carry a PSK binder computed over the
		// ClientHello, which the session ID generator then changes.
		SessionTicketsDisabled: true,
	}
	if args.strict() {
		base.MinVersion = utls.VersionTLS13
	} else {
		base.MinVersion = utls.VersionTLS12
	}

	name := strings.ToLower(strings.TrimSpace(args.Fingerprint))
	var hello *utls.ClientHelloID
	if name != "" && name != "none" {
		id, ok := fingerprints[name]
		if !ok {
			return nil, fmt.Errorf("unknown fingerprint %q", args.Fingerprint)
		}
		hello = &id
	}

	return func(ctx context.Context, conn net.Conn, sessionID shadowtls.TLSSessionIDGeneratorFunc) error {
		config := base.Clone()
		if hello == nil {
			// Go's own ClientHello: uTLS's hook is the right tool here, and
			// is what sing-box uses.
			config.SessionIDGenerator = sessionID
			return utls.Client(conn, config).HandshakeContext(ctx)
		}
		uconn := utls.UClient(conn, config, *hello)
		if sessionID != nil {
			if err := signClientHello(uconn, sessionID); err != nil {
				return err
			}
		}
		return uconn.HandshakeContext(ctx)
	}, nil
}

// signClientHello puts the ShadowTLS session ID into a uTLS ClientHello
// without going through Config.SessionIDGenerator.
//
// That hook, in every metacubex/utls release up to v1.9.0-alpha.1, re-marshals
// the ClientHello with Go's own encoder to compute the HMAC. On a UClient the
// result is that the parrot is discarded: what goes on the wire is Go's
// ClientHello, whichever fingerprint was asked for -- and when the server
// answers with a HelloRetryRequest, the second ClientHello is rebuilt from the
// parrot with its original random session ID, which RFC 8446 forbids and a
// server rejects with illegal_parameter.
//
// Here the parrot is built first, and the session ID is computed over its own
// bytes and set in its own state, so both ClientHellos carry the parrot and
// the same signed ID. The generator is handed the ClientHello with a zero
// session ID, which is what the hook handed it, so the HMAC is the one a
// server expects.
func signClientHello(uconn *utls.UConn, generate shadowtls.TLSSessionIDGeneratorFunc) error {
	if err := uconn.BuildHandshakeState(); err != nil {
		return fmt.Errorf("building the ClientHello: %w", err)
	}
	hello := uconn.HandshakeState.Hello
	hello.SessionId = make([]byte, 32)
	if err := uconn.MarshalClientHello(); err != nil {
		return fmt.Errorf("encoding the ClientHello: %w", err)
	}
	signed := make([]byte, 32)
	if err := generate(hello.Raw, signed); err != nil {
		return fmt.Errorf("signing the ClientHello: %w", err)
	}
	hello.SessionId = signed
	if err := uconn.MarshalClientHello(); err != nil {
		return fmt.Errorf("encoding the signed ClientHello: %w", err)
	}
	return nil
}

// rootsFor is the trust store: the system's, or only the certificate the args
// name, which is how a private CA is pinned. Nil with insecure set, where
// nothing is checked.
func rootsFor(args pluginArgs) (*x509.CertPool, error) {
	if args.Insecure {
		return nil, nil
	}
	if args.Certificate == "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			return x509.NewCertPool(), nil
		}
		return pool, nil
	}
	pem := []byte(args.Certificate)
	if !strings.Contains(args.Certificate, "-----BEGIN") {
		data, err := os.ReadFile(args.Certificate)
		if err != nil {
			return nil, err
		}
		pem = data
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("certificate: no PEM certificate found")
	}
	return pool, nil
}
