package leafabi

/*
#cgo CFLAGS: -I${SRCDIR}/../../leaf-plugin-abi/include
#include "abi.h"
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"
)

// AddressKind says how to read an Address's Bytes.
type AddressKind uint16

const (
	// AddressIPv4 means four octets in network order.
	AddressIPv4 AddressKind = C.LEAF_ADDRESS_KIND_IPV4
	// AddressIPv6 means sixteen octets in network order.
	AddressIPv6 AddressKind = C.LEAF_ADDRESS_KIND_IPV6
	// AddressDomain means a domain name as UTF-8, without a trailing NUL. The
	// host rejects an empty one.
	AddressDomain AddressKind = C.LEAF_ADDRESS_KIND_DOMAIN
)

// MaxDomainLength is the longest domain the SOCKS-style wire form can carry,
// and therefore the longest one an engine should expect to encode.
const MaxDomainLength = 255

// Address is where a session is headed, in the shape the ABI passes it. Port is
// in host byte order, as it is on the wire struct.
type Address struct {
	Kind  AddressKind
	Port  uint16
	Bytes []byte
}

// IPAddress builds an Address from an IP.
func IPAddress(ip net.IP, port uint16) (Address, error) {
	if v4 := ip.To4(); v4 != nil {
		return Address{Kind: AddressIPv4, Port: port, Bytes: append([]byte(nil), v4...)}, nil
	}
	if v6 := ip.To16(); v6 != nil {
		return Address{Kind: AddressIPv6, Port: port, Bytes: append([]byte(nil), v6...)}, nil
	}
	return Address{}, Errorf(StatusInvalidArgument, "not an IP address: %v", ip)
}

// DomainAddress builds an Address from a name.
func DomainAddress(name string, port uint16) Address {
	return Address{Kind: AddressDomain, Port: port, Bytes: []byte(name)}
}

// Validate reports whether the address is one the ABI can carry.
func (a Address) Validate() error {
	switch a.Kind {
	case AddressIPv4:
		if len(a.Bytes) != 4 {
			return Errorf(StatusInvalidArgument, "IPv4 address is %d bytes", len(a.Bytes))
		}
	case AddressIPv6:
		if len(a.Bytes) != 16 {
			return Errorf(StatusInvalidArgument, "IPv6 address is %d bytes", len(a.Bytes))
		}
	case AddressDomain:
		if len(a.Bytes) == 0 {
			return Errorf(StatusInvalidArgument, "domain is empty")
		}
		if len(a.Bytes) > MaxDomainLength {
			return Errorf(StatusInvalidArgument, "domain is %d bytes", len(a.Bytes))
		}
	default:
		return Errorf(StatusInvalidArgument, "invalid address kind %d", uint16(a.Kind))
	}
	return nil
}

// IP returns the address as an IP, or nil for a domain.
func (a Address) IP() net.IP {
	switch a.Kind {
	case AddressIPv4, AddressIPv6:
		return net.IP(a.Bytes)
	default:
		return nil
	}
}

// Domain returns the name, or the empty string for an IP.
func (a Address) Domain() string {
	if a.Kind != AddressDomain {
		return ""
	}
	return string(a.Bytes)
}

func (a Address) String() string {
	switch a.Kind {
	case AddressIPv4, AddressIPv6:
		return net.JoinHostPort(net.IP(a.Bytes).String(), fmt.Sprint(a.Port))
	case AddressDomain:
		return net.JoinHostPort(string(a.Bytes), fmt.Sprint(a.Port))
	default:
		return fmt.Sprintf("address(kind %d)", uint16(a.Kind))
	}
}

// SOCKS-style address type bytes, as SOCKS5 defines them and as shadowsocks,
// trojan and vmess reuse them.
const (
	socksTypeIPv4   byte = 0x01
	socksTypeDomain byte = 0x03
	socksTypeIPv6   byte = 0x04
)

// AppendSocksAddress appends the SOCKS-style encoding of a -- the type byte,
// the address, then the port in network order -- to dst.
//
// This is the form SOCKS5, trojan, shadowsocks and vmess all put their
// destination in, which is why it lives here rather than in any one plugin.
func AppendSocksAddress(dst []byte, a Address) ([]byte, error) {
	if err := a.Validate(); err != nil {
		return dst, err
	}
	switch a.Kind {
	case AddressIPv4:
		dst = append(dst, socksTypeIPv4)
		dst = append(dst, a.Bytes...)
	case AddressIPv6:
		dst = append(dst, socksTypeIPv6)
		dst = append(dst, a.Bytes...)
	case AddressDomain:
		dst = append(dst, socksTypeDomain, byte(len(a.Bytes)))
		dst = append(dst, a.Bytes...)
	}
	return binary.BigEndian.AppendUint16(dst, a.Port), nil
}

// SocksAddressLen is how many bytes AppendSocksAddress will add for a.
func SocksAddressLen(a Address) int {
	switch a.Kind {
	case AddressIPv4:
		return 1 + 4 + 2
	case AddressIPv6:
		return 1 + 16 + 2
	case AddressDomain:
		return 1 + 1 + len(a.Bytes) + 2
	default:
		return 0
	}
}

// MaxSocksAddressLen is the largest SOCKS-style address, which is what an
// engine should reserve when it does not know the kind in advance.
const MaxSocksAddressLen = 1 + 1 + MaxDomainLength + 2

// ParseSocksAddress reads one SOCKS-style address off the front of input and
// reports how many bytes it took.
//
// An input that stops inside the address yields ErrIncomplete, which on a
// reliable transport means "read more and call again" rather than "this is
// broken".
func ParseSocksAddress(input []byte) (Address, int, error) {
	if len(input) < 1 {
		return Address{}, 0, ErrIncomplete
	}
	switch input[0] {
	case socksTypeIPv4:
		if len(input) < 1+4+2 {
			return Address{}, 0, ErrIncomplete
		}
		return Address{
			Kind:  AddressIPv4,
			Port:  binary.BigEndian.Uint16(input[5:7]),
			Bytes: append([]byte(nil), input[1:5]...),
		}, 7, nil
	case socksTypeIPv6:
		if len(input) < 1+16+2 {
			return Address{}, 0, ErrIncomplete
		}
		return Address{
			Kind:  AddressIPv6,
			Port:  binary.BigEndian.Uint16(input[17:19]),
			Bytes: append([]byte(nil), input[1:17]...),
		}, 19, nil
	case socksTypeDomain:
		if len(input) < 2 {
			return Address{}, 0, ErrIncomplete
		}
		n := int(input[1])
		if n == 0 {
			return Address{}, 0, Errorf(StatusPluginFailure, "socks address has an empty domain")
		}
		if len(input) < 2+n+2 {
			return Address{}, 0, ErrIncomplete
		}
		return Address{
			Kind:  AddressDomain,
			Port:  binary.BigEndian.Uint16(input[2+n : 4+n]),
			Bytes: append([]byte(nil), input[2:2+n]...),
		}, 4 + n, nil
	default:
		return Address{}, 0, Errorf(StatusPluginFailure, "invalid socks address type %d", input[0])
	}
}

// addressFromC copies an address the host passed in. The bytes it points at are
// borrowed only for the call, so they are copied rather than aliased.
func addressFromC(address *C.PluginAddress) (Address, error) {
	if address == nil {
		return Address{}, Errorf(StatusInvalidArgument, "missing address")
	}
	out := Address{
		Kind: AddressKind(address.kind),
		Port: uint16(address.port),
	}
	if address.data != nil && address.data_len > 0 {
		out.Bytes = append(
			[]byte(nil),
			unsafe.Slice((*byte)(unsafe.Pointer(address.data)), int(address.data_len))...,
		)
	}
	if err := out.Validate(); err != nil {
		return Address{}, err
	}
	return out, nil
}

// addressToC writes a into the buffer the host supplied.
//
// The host owns that buffer and its capacity arrives in data_len, so the
// pointer must not be replaced and an address that does not fit is a
// StatusBufferTooSmall rather than a truncation.
func addressToC(a Address, out *C.PluginAddress) error {
	if out == nil {
		return Errorf(StatusInvalidArgument, "missing address output")
	}
	if err := a.Validate(); err != nil {
		return err
	}
	capacity := int(out.data_len)
	out.kind = C.leaf_address_kind_t(a.Kind)
	out.port = C.uint16_t(a.Port)
	if len(a.Bytes) > capacity || (len(a.Bytes) > 0 && out.data == nil) {
		out.data_len = 0
		return Errorf(
			StatusBufferTooSmall,
			"address does not fit the host's buffer: need %d, got %d",
			len(a.Bytes), capacity,
		)
	}
	if len(a.Bytes) > 0 {
		copy(unsafe.Slice((*byte)(unsafe.Pointer(out.data)), capacity), a.Bytes)
	}
	out.data_len = C.size_t(len(a.Bytes))
	return nil
}
