// Command trojan-cabi-go is a Trojan protocol plugin for the leaf C ABI, built
// as a Go c-shared library on top of the leaf-abi-go SDK.
//
// It exports both engines. The stream engine uses leafabi.ConnectProxyTCP and
// writes the Trojan header -- the hashed password, the command and the
// destination address -- ahead of the application's first bytes, so the
// outbound must set host and port. The datagram engine is
// leafabi.TransportReliable: Trojan carries UDP in length-prefixed frames over
// the same stream, so the host runs it over the stream transport the chain
// already established and this engine frames each datagram itself. That is what
// DecodePacket's consumed count is for, and framing_test.go covers the partial
// and batched cases.
//
// args is either a bare password or JSON, {"password": "..."}. Both the stream
// and the datagram engine of one outbound read the same args.
//
// Everything the engines do is pure computation over buffers the host supplies,
// so unlike the TLS plugin they need no goroutines of their own and never
// report leafabi.StateBlocked. That is also why they implement
// leafabi.StreamEngine directly instead of going through leafabi.ConnEngine.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	leafabi "leaf-plugins/leaf-abi-go"
)

const (
	commandTCP byte = 0x01
	commandUDP byte = 0x03
	// The length prefix of a UDP frame is two bytes, so a datagram cannot be
	// larger than this whatever the transport under it would allow.
	maxDatagramPayload = 65535
)

func main() {}

func init() {
	leafabi.Register(leafabi.Plugin{
		Name:      "leaf-trojan-cabi-go-plugin",
		Version:   "0.2.0",
		LogTarget: "leaf.plugin.trojan.go",
		Stream: &leafabi.StreamEngineSpec{
			ConnectType: leafabi.ConnectProxyTCP,
			New:         newStreamEngine,
		},
		Datagram: &leafabi.DatagramEngineSpec{
			TransportType: leafabi.TransportReliable,
			New:           newDatagramEngine,
		},
	})
}

type pluginArgs struct {
	Password string `json:"password"`
}

func parsePluginArgs(input string) (pluginArgs, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return pluginArgs{}, errors.New("trojan plugin args must not be empty")
	}
	if !strings.HasPrefix(trimmed, "{") {
		return pluginArgs{Password: trimmed}, nil
	}
	var args pluginArgs
	if err := json.Unmarshal([]byte(trimmed), &args); err != nil {
		return pluginArgs{}, err
	}
	args.Password = strings.TrimSpace(args.Password)
	if args.Password == "" {
		return pluginArgs{}, errors.New("trojan plugin args missing password")
	}
	return args, nil
}

// buildHeader assembles hex(sha224(password)) CRLF CMD ADDR CRLF, which is what
// Trojan puts in front of a session in both directions.
func buildHeader(args leafabi.CreateArgs, command byte) ([]byte, error) {
	parsed, err := parsePluginArgs(args.Args)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum224([]byte(parsed.Password))
	password := hex.EncodeToString(digest[:])

	header := make([]byte, 0, len(password)+2+1+leafabi.MaxSocksAddressLen+2)
	header = append(header, password...)
	header = append(header, '\r', '\n')
	header = append(header, command)
	header, err = leafabi.AppendSocksAddress(header, args.Destination)
	if err != nil {
		return nil, err
	}
	return append(header, '\r', '\n'), nil
}

// --- stream engine ---------------------------------------------------------

// streamEngine is a pass-through with a header in front of it: once the header
// is out, Trojan adds nothing to the stream in either direction.
type streamEngine struct {
	host leafabi.Host

	header     []byte
	headerSent bool

	netOut bytes.Buffer
	appOut bytes.Buffer

	closedAppIn bool
	closedNetIn bool
	peerClosed  bool
}

func newStreamEngine(args leafabi.CreateArgs) (leafabi.StreamEngine, error) {
	header, err := buildHeader(args, commandTCP)
	if err != nil {
		return nil, err
	}
	args.Host.Logf(leafabi.LevelInfo, "created Trojan stream engine for %s", args.Destination)
	return &streamEngine{host: args.Host, header: header}, nil
}

func (e *streamEngine) PollState() leafabi.StateFlags {
	// Nothing here ever waits on work of its own, so ESTABLISHED from the
	// start and never BLOCKED.
	flags := leafabi.StateEstablished
	if e.netOut.Len() > 0 {
		flags |= leafabi.StateHasNetOutput
	}
	if e.appOut.Len() > 0 {
		flags |= leafabi.StateHasAppOutput
	}
	if !e.closedAppIn {
		flags |= leafabi.StateWantAppInput
	}
	if !e.closedNetIn {
		flags |= leafabi.StateWantNetInput
	}
	if e.peerClosed {
		flags |= leafabi.StatePeerClosed
	}
	return flags
}

func (e *streamEngine) Push(side leafabi.Side, input []byte) (int, error) {
	switch side {
	case leafabi.SideApp:
		if e.closedAppIn {
			return 0, leafabi.Errorf(leafabi.StatusPluginFailure,
				"push(app) after the application side was closed")
		}
		if !e.headerSent {
			e.netOut.Write(e.header)
			e.headerSent = true
			e.host.Log(leafabi.LevelDebug, "emitted Trojan request header")
		}
		e.netOut.Write(input)
		return len(input), nil
	case leafabi.SideNet:
		if e.closedNetIn {
			return 0, leafabi.Errorf(leafabi.StatusPluginFailure,
				"push(net) after the network side was closed")
		}
		e.appOut.Write(input)
		return len(input), nil
	default:
		return 0, leafabi.Errorf(leafabi.StatusInvalidArgument,
			"invalid stream side for push: %d", uint32(side))
	}
}

func (e *streamEngine) Pull(side leafabi.Side, output []byte) (int, error) {
	switch side {
	case leafabi.SideApp:
		n, _ := e.appOut.Read(output)
		return n, nil
	case leafabi.SideNet:
		n, _ := e.netOut.Read(output)
		return n, nil
	default:
		return 0, leafabi.Errorf(leafabi.StatusInvalidArgument,
			"invalid stream side for pull: %d", uint32(side))
	}
}

func (e *streamEngine) Close(flags leafabi.CloseFlags) error {
	if flags.Has(leafabi.CloseApp) {
		e.closedAppIn = true
		e.host.Log(leafabi.LevelDebug, "marked application input as closed")
	}
	if flags.Has(leafabi.CloseNet) {
		e.closedNetIn = true
		e.peerClosed = true
		e.host.Log(leafabi.LevelDebug, "marked network input as closed")
	}
	return nil
}

func (e *streamEngine) Destroy() {}

// --- datagram engine -------------------------------------------------------

// datagramEngine frames datagrams as ADDR || uint16 length || CRLF || payload,
// with the session header in front of the first one.
type datagramEngine struct {
	host leafabi.Host

	header     []byte
	headerSent bool
}

func newDatagramEngine(args leafabi.CreateArgs) (leafabi.DatagramEngine, error) {
	header, err := buildHeader(args, commandUDP)
	if err != nil {
		return nil, err
	}
	args.Host.Logf(leafabi.LevelInfo, "created Trojan datagram engine for %s", args.Destination)
	return &datagramEngine{host: args.Host, header: header}, nil
}

func (e *datagramEngine) EncodePacket(payload []byte, target leafabi.Address, output []byte) (int, error) {
	if len(payload) > maxDatagramPayload {
		return 0, leafabi.Errorf(leafabi.StatusInvalidArgument,
			"datagram of %d bytes does not fit a Trojan length prefix", len(payload))
	}
	required := leafabi.SocksAddressLen(target) + 2 + 2 + len(payload)
	if !e.headerSent {
		required += len(e.header)
	}
	if len(output) < required {
		// Consuming nothing here is what lets the host grow the buffer and
		// offer the same datagram again.
		return 0, fmt.Errorf("encoded datagram needs %d bytes, got %d: %w",
			required, len(output), leafabi.ErrBufferTooSmall)
	}

	frame := output[:0]
	if !e.headerSent {
		frame = append(frame, e.header...)
	}
	frame, err := leafabi.AppendSocksAddress(frame, target)
	if err != nil {
		return 0, err
	}
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(payload)))
	frame = append(frame, '\r', '\n')
	frame = append(frame, payload...)

	if !e.headerSent {
		e.headerSent = true
		e.host.Log(leafabi.LevelDebug, "emitted Trojan UDP session header")
	}
	return len(frame), nil
}

func (e *datagramEngine) DecodePacket(input, payload []byte) (int, int, leafabi.Address, error) {
	address, decoded, frameLen, err := decodeUDPFrame(input)
	if err != nil {
		return 0, 0, leafabi.Address{}, err
	}
	if len(payload) < len(decoded) {
		return 0, 0, leafabi.Address{}, fmt.Errorf("decoded datagram needs %d bytes, got %d: %w",
			len(decoded), len(payload), leafabi.ErrBufferTooSmall)
	}
	copy(payload, decoded)
	return frameLen, len(decoded), address, nil
}

func (e *datagramEngine) MaxOutputSize(inputLen int, direction leafabi.Direction) int {
	if direction != leafabi.DirectionEncode {
		return inputLen
	}
	size := inputLen + leafabi.MaxSocksAddressLen + 4
	if !e.headerSent {
		size += len(e.header)
	}
	return size
}

func (e *datagramEngine) MaxAddressSize(leafabi.Direction) int { return leafabi.MaxDomainLength }

func (e *datagramEngine) Destroy() {}

// decodeUDPFrame parses the leading frame out of a reliable-transport buffer.
// Trojan carries UDP over the TCP stream as ADDR || uint16 length || CRLF ||
// payload, so input may stop anywhere inside that and may hold more than one
// frame; only the first is parsed and its total length is returned so the
// caller can drop exactly those bytes.
//
// A buffer that stops mid-frame yields leafabi.ErrIncomplete, which the SDK
// turns into "consumed nothing" rather than into a failure.
func decodeUDPFrame(input []byte) (leafabi.Address, []byte, int, error) {
	address, addressLen, err := leafabi.ParseSocksAddress(input)
	if err != nil {
		return leafabi.Address{}, nil, 0, err
	}
	if len(input) < addressLen+4 {
		return leafabi.Address{}, nil, 0, leafabi.ErrIncomplete
	}
	size := int(binary.BigEndian.Uint16(input[addressLen : addressLen+2]))
	if input[addressLen+2] != '\r' || input[addressLen+3] != '\n' {
		return leafabi.Address{}, nil, 0, leafabi.Errorf(leafabi.StatusPluginFailure,
			"invalid trojan datagram separator")
	}
	start := addressLen + 4
	frameLen := start + size
	if len(input) < frameLen {
		return leafabi.Address{}, nil, 0, leafabi.ErrIncomplete
	}
	return address, input[start:frameLen], frameLen, nil
}
