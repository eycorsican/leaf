// Command tls-cabi-go is a TLS transport plugin for the leaf C ABI, built as a
// Go c-shared library on top of the leaf-abi-go SDK. It is the reference for
// what a transport plugin written in Go looks like, and the counterpart of the
// Rust tls-cabi-rs plugin.
//
// It exports one stream engine with leafabi.ConnectNext: the host hands it
// whatever stream the previous outbound in the chain produced and it layers
// crypto/tls over it, so the outbound must not set a host or port of its own.
//
// args is either a bare server name or JSON:
//
//	{
//	  "server_name": "example.com",
//	  "alpn": ["h2", "http/1.1"],
//	  "certificate": "/path/to/ca.pem",
//	  "insecure": false
//	}
//
// server_name is required. certificate is either a path to a PEM file or the
// PEM text itself, and replaces the system root pool rather than adding to it.
// insecure skips verification altogether -- for testing only.
//
// crypto/tls insists on a blocking net.Conn, which the ABI forbids an engine
// call from being. leafabi.ConnEngine is what bridges that: it runs the
// handshake and the record layer on their own goroutines over an in-memory
// pipe, reports leafabi.StateBlocked while they are what it is waiting on, and
// joins them in Destroy. Everything below is therefore about TLS and nothing
// about the boundary.
//
// Building this as a c-shared library pins the host thread that loads it: the
// Go runtime's thread-exit hook does not return, which is why the ABI warns
// that only long-lived executor threads may call into such a plugin.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"

	leafabi "leaf-plugins/leaf-abi-go"
)

func main() {}

func init() {
	leafabi.Register(leafabi.Plugin{
		Name:      "leaf-tls-cabi-go-plugin",
		Version:   "0.2.0",
		LogTarget: "leaf.plugin.tls.go",
		Stream: &leafabi.StreamEngineSpec{
			ConnectType: leafabi.ConnectNext,
			New:         newEngine,
		},
	})
}

type pluginArgs struct {
	ServerName  string   `json:"server_name"`
	ALPN        []string `json:"alpn"`
	Certificate string   `json:"certificate"`
	Insecure    bool     `json:"insecure"`
}

func newEngine(args leafabi.CreateArgs) (leafabi.StreamEngine, error) {
	parsed, err := parsePluginArgs(args.Args)
	if err != nil {
		return nil, err
	}
	config, err := buildTLSConfig(parsed)
	if err != nil {
		return nil, err
	}
	args.Host.Logf(leafabi.LevelInfo, "creating TLS engine for server_name=%s", parsed.ServerName)
	return leafabi.NewConnEngine(leafabi.ConnEngineConfig{
		Host: args.Host,
		Wrap: func(inner net.Conn) (net.Conn, error) {
			// *tls.Conn implements leafabi.Handshaker, so the SDK runs the
			// handshake before it reports the engine established.
			return tls.Client(inner, config), nil
		},
		// A TLS record is at most 16 KiB of plaintext plus its overhead, so
		// these are the sizes that make one pull carry one record.
		AppOutputSize: 16 * 1024,
		NetOutputSize: 18 * 1024,
	})
}

func parsePluginArgs(input string) (pluginArgs, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return pluginArgs{}, errors.New("tls plugin args must not be empty")
	}
	if !strings.HasPrefix(trimmed, "{") {
		return pluginArgs{ServerName: trimmed}, nil
	}
	var args pluginArgs
	if err := json.Unmarshal([]byte(trimmed), &args); err != nil {
		return pluginArgs{}, err
	}
	if strings.TrimSpace(args.ServerName) == "" {
		return pluginArgs{}, errors.New("tls plugin args missing server_name")
	}
	return args, nil
}

func buildTLSConfig(args pluginArgs) (*tls.Config, error) {
	config := &tls.Config{
		ServerName:         args.ServerName,
		InsecureSkipVerify: args.Insecure,
		NextProtos:         append([]string(nil), args.ALPN...),
		MinVersion:         tls.VersionTLS12,
	}
	if args.Insecure {
		return config, nil
	}
	if args.Certificate == "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		config.RootCAs = pool
		return config, nil
	}

	pool := x509.NewCertPool()
	pem := []byte(args.Certificate)
	if !strings.Contains(args.Certificate, "-----BEGIN") {
		data, err := os.ReadFile(args.Certificate)
		if err != nil {
			return nil, err
		}
		pem = data
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("failed to parse certificate PEM")
	}
	config.RootCAs = pool
	return config, nil
}
