package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	utls "github.com/metacubex/utls"
)

// tlsHandshake turns the host's connection into an established TLS one.
type tlsHandshake func(ctx context.Context, raw net.Conn) (net.Conn, error)

// fingerprints are the ClientHellos the plugin can present instead of Go's own.
// The names are the ones sing-box and mihomo use for the same setting, so a
// configuration written for either carries over. The library behind them is
// the uTLS fork both of those use.
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

func newTLSHandshake(args pluginArgs) (tlsHandshake, error) {
	roots, err := rootsFor(args)
	if err != nil {
		return nil, err
	}
	name := strings.ToLower(strings.TrimSpace(args.Fingerprint))
	if name == "" || name == "none" {
		config := &tls.Config{
			ServerName:         args.ServerName,
			NextProtos:         append([]string(nil), args.ALPN...),
			InsecureSkipVerify: args.Insecure,
			RootCAs:            roots,
			MinVersion:         tls.VersionTLS12,
		}
		return func(ctx context.Context, raw net.Conn) (net.Conn, error) {
			conn := tls.Client(raw, config)
			if err := conn.HandshakeContext(ctx); err != nil {
				return nil, fmt.Errorf("tls handshake: %w", err)
			}
			return conn, nil
		}, nil
	}

	hello, ok := fingerprints[name]
	if !ok {
		return nil, fmt.Errorf("unknown fingerprint %q", args.Fingerprint)
	}
	config := &utls.Config{
		ServerName:         args.ServerName,
		NextProtos:         append([]string(nil), args.ALPN...),
		InsecureSkipVerify: args.Insecure,
		RootCAs:            roots,
		MinVersion:         utls.VersionTLS12,
	}
	return func(ctx context.Context, raw net.Conn) (net.Conn, error) {
		conn := utls.UClient(raw, config.Clone(), hello)
		if err := conn.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("tls handshake (%s): %w", name, err)
		}
		return conn, nil
	}, nil
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
