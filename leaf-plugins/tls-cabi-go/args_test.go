package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The args string is the whole of a plugin's configuration surface, so what it
// accepts is what an operator can write.
func TestParsePluginArgsAcceptsBothForms(t *testing.T) {
	bare, err := parsePluginArgs("  example.com  ")
	if err != nil {
		t.Fatalf("bare server name: unexpected error %v", err)
	}
	if bare.ServerName != "example.com" {
		t.Fatalf("ServerName = %q, want %q", bare.ServerName, "example.com")
	}

	structured, err := parsePluginArgs(`{"server_name":"example.com","alpn":["h2"],"insecure":true}`)
	if err != nil {
		t.Fatalf("json args: unexpected error %v", err)
	}
	if structured.ServerName != "example.com" || !structured.Insecure {
		t.Fatalf("parsed %+v", structured)
	}
	if len(structured.ALPN) != 1 || structured.ALPN[0] != "h2" {
		t.Fatalf("ALPN = %v", structured.ALPN)
	}
}

func TestParsePluginArgsRejectsWhatItCannotUse(t *testing.T) {
	for name, input := range map[string]string{
		"empty":             "",
		"blank":             "   ",
		"malformed json":    `{"server_name":`,
		"json without name": `{"alpn":["h2"]}`,
		"json blank name":   `{"server_name":"  "}`,
	} {
		if _, err := parsePluginArgs(input); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestBuildTLSConfigHonoursInsecure(t *testing.T) {
	config, err := buildTLSConfig(pluginArgs{ServerName: "example.com", Insecure: true})
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	if !config.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = false")
	}
	if config.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want TLS 1.2", config.MinVersion)
	}
	// Nothing may be verified against a pool that was never built.
	if config.RootCAs != nil {
		t.Error("an insecure config carries a root pool")
	}
}

// A certificate replaces the system pool rather than adding to it, and may
// arrive either as a path or as the PEM itself.
func TestBuildTLSConfigReadsACertificateEitherWay(t *testing.T) {
	pem := selfSignedPEM(t)

	inline, err := buildTLSConfig(pluginArgs{ServerName: "example.com", Certificate: pem})
	if err != nil {
		t.Fatalf("inline PEM: unexpected error %v", err)
	}
	if inline.RootCAs == nil {
		t.Fatal("inline PEM: no root pool was built")
	}

	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, []byte(pem), 0o600); err != nil {
		t.Fatalf("writing the certificate failed: %v", err)
	}
	fromFile, err := buildTLSConfig(pluginArgs{ServerName: "example.com", Certificate: path})
	if err != nil {
		t.Fatalf("certificate path: unexpected error %v", err)
	}
	if fromFile.RootCAs == nil {
		t.Fatal("certificate path: no root pool was built")
	}
}

func TestBuildTLSConfigRejectsABadCertificate(t *testing.T) {
	if _, err := buildTLSConfig(pluginArgs{
		ServerName:  "example.com",
		Certificate: "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n",
	}); err == nil {
		t.Error("expected an error for an unparsable PEM")
	}
	if _, err := buildTLSConfig(pluginArgs{
		ServerName:  "example.com",
		Certificate: filepath.Join(t.TempDir(), "missing.pem"),
	}); err == nil {
		t.Error("expected an error for a certificate path that does not exist")
	}
}

func selfSignedPEM(t *testing.T) string {
	t.Helper()
	// A real certificate, because AppendCertsFromPEM parses it. What is under
	// test is whether the plugin gets it into a pool, not whether it trusts
	// anyone in particular.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key failed: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tls-cabi-go-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a certificate failed: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
