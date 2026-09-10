package leafabi

import (
	"bytes"
	"errors"
	"net"
	"strings"
	"testing"
)

func TestAddressValidateAcceptsWhatTheABICanCarry(t *testing.T) {
	valid := map[string]Address{
		"ipv4":       {Kind: AddressIPv4, Port: 80, Bytes: []byte{1, 2, 3, 4}},
		"ipv6":       {Kind: AddressIPv6, Port: 443, Bytes: make([]byte, 16)},
		"domain":     DomainAddress("example.com", 8080),
		"max domain": DomainAddress(strings.Repeat("a", MaxDomainLength), 1),
	}
	for name, address := range valid {
		if err := address.Validate(); err != nil {
			t.Errorf("%s: unexpected error %v", name, err)
		}
	}
}

func TestAddressValidateRejectsWhatItCannot(t *testing.T) {
	invalid := map[string]Address{
		"short ipv4":   {Kind: AddressIPv4, Bytes: []byte{1, 2, 3}},
		"long ipv6":    {Kind: AddressIPv6, Bytes: make([]byte, 17)},
		"empty domain": {Kind: AddressDomain},
		"long domain":  DomainAddress(strings.Repeat("a", MaxDomainLength+1), 1),
		"unknown kind": {Kind: AddressKind(9), Bytes: []byte{1}},
	}
	for name, address := range invalid {
		err := address.Validate()
		if err == nil {
			t.Errorf("%s: expected an error", name)
			continue
		}
		if got := statusOf(err); got != StatusInvalidArgument {
			t.Errorf("%s: status = %v, want %v", name, got, StatusInvalidArgument)
		}
	}
}

func TestIPAddressPicksTheKindFromTheAddress(t *testing.T) {
	v4, err := IPAddress(net.ParseIP("192.0.2.1"), 80)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	if v4.Kind != AddressIPv4 || len(v4.Bytes) != 4 {
		t.Fatalf("v4 = %+v, want a four byte AddressIPv4", v4)
	}
	// An IPv4 address written the long way is still IPv4 on the wire, which is
	// what a proxy header has to say.
	mapped, err := IPAddress(net.ParseIP("::ffff:192.0.2.1"), 80)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	if mapped.Kind != AddressIPv4 {
		t.Fatalf("mapped kind = %v, want AddressIPv4", mapped.Kind)
	}

	v6, err := IPAddress(net.ParseIP("2001:db8::1"), 443)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	if v6.Kind != AddressIPv6 || len(v6.Bytes) != 16 {
		t.Fatalf("v6 = %+v, want a sixteen byte AddressIPv6", v6)
	}

	if _, err := IPAddress(nil, 80); err == nil {
		t.Fatal("expected an error for a nil IP")
	}
}

func TestSocksAddressRoundTrips(t *testing.T) {
	addresses := []Address{
		{Kind: AddressIPv4, Port: 80, Bytes: []byte{192, 0, 2, 1}},
		{Kind: AddressIPv6, Port: 443, Bytes: net.ParseIP("2001:db8::1").To16()},
		DomainAddress("origin.e2e.invalid", 8080),
		DomainAddress(strings.Repeat("d", MaxDomainLength), 65535),
	}
	for _, want := range addresses {
		encoded, err := AppendSocksAddress(nil, want)
		if err != nil {
			t.Fatalf("%s: encode failed: %v", want, err)
		}
		if len(encoded) != SocksAddressLen(want) {
			t.Fatalf("%s: encoded %d bytes, SocksAddressLen said %d",
				want, len(encoded), SocksAddressLen(want))
		}
		if len(encoded) > MaxSocksAddressLen {
			t.Fatalf("%s: encoded %d bytes, over the stated maximum %d",
				want, len(encoded), MaxSocksAddressLen)
		}
		// Trailing bytes must be left alone: on a stream one address is
		// followed by whatever comes next.
		got, n, err := ParseSocksAddress(append(encoded, 'x', 'y'))
		if err != nil {
			t.Fatalf("%s: decode failed: %v", want, err)
		}
		if n != len(encoded) {
			t.Fatalf("%s: consumed %d bytes, want %d", want, n, len(encoded))
		}
		if got.Kind != want.Kind || got.Port != want.Port || !bytes.Equal(got.Bytes, want.Bytes) {
			t.Fatalf("%s: decoded %+v, want %+v", want, got, want)
		}
	}
}

// A prefix of an address is the ordinary case on a byte stream, and must be
// reported as incomplete right up until the last byte arrives.
func TestParseSocksAddressReportsAPrefixAsIncomplete(t *testing.T) {
	for _, address := range []Address{
		{Kind: AddressIPv4, Port: 80, Bytes: []byte{192, 0, 2, 1}},
		{Kind: AddressIPv6, Port: 443, Bytes: net.ParseIP("2001:db8::1").To16()},
		DomainAddress("example.com", 53),
	} {
		encoded, err := AppendSocksAddress(nil, address)
		if err != nil {
			t.Fatalf("%s: encode failed: %v", address, err)
		}
		for n := 0; n < len(encoded); n++ {
			_, _, err := ParseSocksAddress(encoded[:n])
			if !errors.Is(err, ErrIncomplete) {
				t.Fatalf("%s: %d/%d bytes: err = %v, want ErrIncomplete",
					address, n, len(encoded), err)
			}
		}
	}
}

// A malformed address is a hard error rather than something to wait out --
// waiting on it would hang the connection instead of failing it.
func TestParseSocksAddressRejectsMalformedInput(t *testing.T) {
	for name, input := range map[string][]byte{
		"unknown type": {0x7f, 1, 2, 3, 4, 0, 80},
		"empty domain": {socksTypeDomain, 0x00, 0, 80},
	} {
		_, _, err := ParseSocksAddress(input)
		if err == nil || errors.Is(err, ErrIncomplete) {
			t.Fatalf("%s: err = %v, want a hard error", name, err)
		}
	}
}

func TestAppendSocksAddressRefusesAnInvalidAddress(t *testing.T) {
	if _, err := AppendSocksAddress(nil, Address{Kind: AddressIPv4, Bytes: []byte{1}}); err == nil {
		t.Fatal("expected an error for a short IPv4 address")
	}
}

func TestAddressStringNamesTheHostAndPort(t *testing.T) {
	cases := []struct {
		address Address
		want    string
	}{
		{Address{Kind: AddressIPv4, Port: 80, Bytes: []byte{192, 0, 2, 1}}, "192.0.2.1:80"},
		{Address{Kind: AddressIPv6, Port: 443, Bytes: net.ParseIP("2001:db8::1").To16()}, "[2001:db8::1]:443"},
		{DomainAddress("example.com", 8080), "example.com:8080"},
	}
	for _, c := range cases {
		if got := c.address.String(); got != c.want {
			t.Errorf("String() = %q, want %q", got, c.want)
		}
	}
}
