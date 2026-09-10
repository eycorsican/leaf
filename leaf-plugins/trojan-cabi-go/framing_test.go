package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	leafabi "leaf-plugins/leaf-abi-go"
)

// udpFrame builds ADDR || uint16 length || CRLF || payload for an IPv4
// destination, which is what the peer sends back over the stream.
func udpFrame(t *testing.T, ip [4]byte, port uint16, payload []byte) []byte {
	t.Helper()
	frame, err := leafabi.AppendSocksAddress(nil, leafabi.Address{
		Kind:  leafabi.AddressIPv4,
		Port:  port,
		Bytes: ip[:],
	})
	if err != nil {
		t.Fatalf("encoding the address failed: %v", err)
	}
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(payload)))
	frame = append(frame, '\r', '\n')
	return append(frame, payload...)
}

// A frame that arrives a byte at a time must report "incomplete" rather than
// failing, right up until its last byte shows up.
func TestDecodeFrameAcceptsAFrameArrivingInPieces(t *testing.T) {
	payload := []byte("hello udp")
	frame := udpFrame(t, [4]byte{1, 2, 3, 4}, 5353, payload)

	for n := range len(frame) {
		_, _, _, err := decodeUDPFrame(frame[:n])
		if !errors.Is(err, leafabi.ErrIncomplete) {
			t.Fatalf("prefix of %d/%d bytes: err = %v, want ErrIncomplete",
				n, len(frame), err)
		}
	}

	address, got, consumed, err := decodeUDPFrame(frame)
	if err != nil {
		t.Fatalf("whole frame: unexpected error %v", err)
	}
	if consumed != len(frame) {
		t.Fatalf("consumed %d bytes, want %d", consumed, len(frame))
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
	if address.Port != 5353 {
		t.Fatalf("port = %d, want 5353", address.Port)
	}
}

// Several frames in one read must come back one at a time, each reporting only
// its own bytes as consumed, and a trailing partial frame must be left alone.
func TestDecodeFrameConsumesOneFrameAtATime(t *testing.T) {
	first := udpFrame(t, [4]byte{1, 2, 3, 4}, 53, []byte("one"))
	second := udpFrame(t, [4]byte{5, 6, 7, 8}, 5353, []byte("two"))
	third := udpFrame(t, [4]byte{9, 9, 9, 9}, 80, []byte("three"))
	buf := append(append(append([]byte{}, first...), second...), third[:len(third)-2]...)

	for _, want := range []string{"one", "two"} {
		_, payload, consumed, err := decodeUDPFrame(buf)
		if err != nil {
			t.Fatalf("frame %q: unexpected error %v", want, err)
		}
		if string(payload) != want {
			t.Fatalf("payload = %q, want %q", payload, want)
		}
		buf = buf[consumed:]
	}

	if _, _, _, err := decodeUDPFrame(buf); !errors.Is(err, leafabi.ErrIncomplete) {
		t.Fatalf("trailing partial frame: err = %v, want ErrIncomplete", err)
	}
}

// An empty payload is a legitimate frame and must not be mistaken for a buffer
// that has not filled up yet.
func TestDecodeFrameAcceptsAnEmptyPayload(t *testing.T) {
	frame := udpFrame(t, [4]byte{1, 2, 3, 4}, 53, nil)
	_, payload, consumed, err := decodeUDPFrame(frame)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	if len(payload) != 0 || consumed != len(frame) {
		t.Fatalf("payload %d bytes, consumed %d, want 0 and %d", len(payload), consumed, len(frame))
	}
}

// A malformed frame is a hard error, not something to wait out.
func TestDecodeFrameRejectsMalformedFrames(t *testing.T) {
	for name, input := range map[string][]byte{
		"invalid address type": {0x7f, 0, 0, 0, 0, 0, 0, 0},
		"missing separator":    {0x01, 1, 2, 3, 4, 0, 53, 0, 3, 'x', 'y'},
	} {
		_, _, _, err := decodeUDPFrame(input)
		if err == nil || errors.Is(err, leafabi.ErrIncomplete) {
			t.Fatalf("%s: err = %v, want a hard error", name, err)
		}
	}
}

// What the engine encodes is what it decodes, and the session header rides in
// front of the first datagram only.
func TestDatagramEngineRoundTripsAndSendsTheHeaderOnce(t *testing.T) {
	engine := newTestDatagramEngine(t)
	target := leafabi.Address{Kind: leafabi.AddressIPv4, Port: 53, Bytes: []byte{9, 9, 9, 9}}
	payload := []byte("a query")

	out := make([]byte, engine.MaxOutputSize(len(payload), leafabi.DirectionEncode))
	first, err := engine.EncodePacket(payload, target, out)
	if err != nil {
		t.Fatalf("first encode failed: %v", err)
	}
	header, err := buildHeader(testCreateArgs(), commandUDP)
	if err != nil {
		t.Fatalf("building the reference header failed: %v", err)
	}
	if !bytes.HasPrefix(out[:first], header) {
		t.Fatal("the first datagram does not start with the session header")
	}

	second, err := engine.EncodePacket(payload, target, out)
	if err != nil {
		t.Fatalf("second encode failed: %v", err)
	}
	if second != first-len(header) {
		t.Fatalf("second datagram is %d bytes, want %d without the header",
			second, first-len(header))
	}

	// The frame after the header is what a peer sends back, so decoding it is
	// what says the two halves agree.
	got := make([]byte, len(payload))
	consumed, n, address, err := engine.DecodePacket(out[:second], got)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if consumed != second || n != len(payload) || !bytes.Equal(got[:n], payload) {
		t.Fatalf("decoded %d bytes of %d consumed: %q", n, consumed, got[:n])
	}
	if address.String() != target.String() {
		t.Fatalf("address = %s, want %s", address, target)
	}
}

// An output buffer that cannot hold the frame is reported as such and consumes
// nothing, which is what lets the host grow it and try the same datagram again.
func TestDatagramEngineReportsATooSmallBuffer(t *testing.T) {
	engine := newTestDatagramEngine(t)
	target := leafabi.Address{Kind: leafabi.AddressIPv4, Port: 53, Bytes: []byte{9, 9, 9, 9}}
	payload := []byte("a query")

	n, err := engine.EncodePacket(payload, target, make([]byte, 4))
	if !errors.Is(err, leafabi.ErrBufferTooSmall) {
		t.Fatalf("encode err = %v, want ErrBufferTooSmall", err)
	}
	if n != 0 {
		t.Fatalf("encode produced %d bytes while reporting a short buffer", n)
	}

	out := make([]byte, engine.MaxOutputSize(len(payload), leafabi.DirectionEncode))
	written, err := engine.EncodePacket(payload, target, out)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	consumed, decoded, _, err := engine.DecodePacket(out[len(headerOf(t)):written], make([]byte, 1))
	if !errors.Is(err, leafabi.ErrBufferTooSmall) {
		t.Fatalf("decode err = %v, want ErrBufferTooSmall", err)
	}
	if consumed != 0 || decoded != 0 {
		t.Fatalf("decode consumed %d and produced %d while reporting a short buffer",
			consumed, decoded)
	}
}

// A datagram larger than the length prefix can describe has to be refused
// rather than silently truncated.
func TestDatagramEngineRefusesAnOversizedPayload(t *testing.T) {
	engine := newTestDatagramEngine(t)
	target := leafabi.Address{Kind: leafabi.AddressIPv4, Port: 53, Bytes: []byte{9, 9, 9, 9}}
	payload := make([]byte, maxDatagramPayload+1)
	if _, err := engine.EncodePacket(payload, target, make([]byte, len(payload)+512)); err == nil {
		t.Fatal("expected an error for a payload the length prefix cannot describe")
	}
}

// The stream engine is a pass-through with a header in front, and the header
// goes out exactly once, ahead of the first application byte.
func TestStreamEnginePrefixesTheHeaderOnce(t *testing.T) {
	engine, err := newStreamEngine(testCreateArgs())
	if err != nil {
		t.Fatalf("newStreamEngine failed: %v", err)
	}
	defer engine.Destroy()

	if flags := engine.PollState(); !flags.Has(leafabi.StateWantAppInput | leafabi.StateWantNetInput) {
		t.Fatalf("state = %#x, want both sides open", uint32(flags))
	}

	payload := []byte("GET / HTTP/1.1\r\n\r\n")
	if n, err := engine.Push(leafabi.SideApp, payload); err != nil || n != len(payload) {
		t.Fatalf("push(app) = %d, %v", n, err)
	}
	more := []byte("second write")
	if n, err := engine.Push(leafabi.SideApp, more); err != nil || n != len(more) {
		t.Fatalf("second push(app) = %d, %v", n, err)
	}

	out := make([]byte, 4096)
	n, err := engine.Pull(leafabi.SideNet, out)
	if err != nil {
		t.Fatalf("pull(net) failed: %v", err)
	}
	want := append(append(append([]byte(nil), headerOf(t)...), payload...), more...)
	if !bytes.Equal(out[:n], want) {
		t.Fatalf("net output = %q, want %q", out[:n], want)
	}

	// Bytes from the peer are handed straight to the application.
	reply := []byte("HTTP/1.1 200 OK\r\n\r\n")
	if n, err := engine.Push(leafabi.SideNet, reply); err != nil || n != len(reply) {
		t.Fatalf("push(net) = %d, %v", n, err)
	}
	n, err = engine.Pull(leafabi.SideApp, out)
	if err != nil {
		t.Fatalf("pull(app) failed: %v", err)
	}
	if !bytes.Equal(out[:n], reply) {
		t.Fatalf("app output = %q, want %q", out[:n], reply)
	}

	if err := engine.Close(leafabi.CloseNet); err != nil {
		t.Fatalf("close(net) failed: %v", err)
	}
	if flags := engine.PollState(); !flags.Has(leafabi.StatePeerClosed) {
		t.Fatalf("state = %#x, want StatePeerClosed after close(net)", uint32(flags))
	}
	if _, err := engine.Push(leafabi.SideApp, []byte("x")); err != nil {
		t.Fatalf("push(app) after close(net) failed: %v", err)
	}
	if err := engine.Close(leafabi.CloseApp); err != nil {
		t.Fatalf("close(app) failed: %v", err)
	}
	if _, err := engine.Push(leafabi.SideApp, []byte("x")); err == nil {
		t.Fatal("push(app) succeeded after the application side was closed")
	}
}

func TestStreamEngineRejectsAnUnknownSide(t *testing.T) {
	engine, err := newStreamEngine(testCreateArgs())
	if err != nil {
		t.Fatalf("newStreamEngine failed: %v", err)
	}
	defer engine.Destroy()

	if _, err := engine.Push(leafabi.Side(9), []byte("x")); err == nil {
		t.Error("push accepted an unknown side")
	}
	if _, err := engine.Pull(leafabi.Side(9), make([]byte, 8)); err == nil {
		t.Error("pull accepted an unknown side")
	}
}

// The header a plugin writes is where a wrong password or a destination it
// cannot encode shows up, so both engines have to refuse those at creation.
func TestEnginesRefuseArgsTheyCannotUse(t *testing.T) {
	bad := []leafabi.CreateArgs{
		{Args: "", Destination: testDestination()},
		{Args: "{", Destination: testDestination()},
		{Args: `{"password":"  "}`, Destination: testDestination()},
		{Args: "hunter2", Destination: leafabi.Address{Kind: leafabi.AddressIPv4, Bytes: []byte{1}}},
		{Args: "hunter2", Destination: leafabi.DomainAddress(strings.Repeat("a", 256), 80)},
	}
	for _, args := range bad {
		if _, err := newStreamEngine(args); err == nil {
			t.Errorf("stream engine accepted %+v", args)
		}
		if _, err := newDatagramEngine(args); err == nil {
			t.Errorf("datagram engine accepted %+v", args)
		}
	}
}

func TestParsePluginArgsAcceptsBothForms(t *testing.T) {
	bare, err := parsePluginArgs("  hunter2 ")
	if err != nil || bare.Password != "hunter2" {
		t.Fatalf("bare password: %+v, %v", bare, err)
	}
	structured, err := parsePluginArgs(`{"password":"hunter2"}`)
	if err != nil || structured.Password != "hunter2" {
		t.Fatalf("json password: %+v, %v", structured, err)
	}
}

func testDestination() leafabi.Address {
	return leafabi.DomainAddress("origin.e2e.invalid", 80)
}

func testCreateArgs() leafabi.CreateArgs {
	return leafabi.CreateArgs{Args: "e2e-password", Destination: testDestination()}
}

func newTestDatagramEngine(t *testing.T) leafabi.DatagramEngine {
	t.Helper()
	engine, err := newDatagramEngine(testCreateArgs())
	if err != nil {
		t.Fatalf("newDatagramEngine failed: %v", err)
	}
	return engine
}

func headerOf(t *testing.T) []byte {
	t.Helper()
	header, err := buildHeader(testCreateArgs(), commandTCP)
	if err != nil {
		t.Fatalf("building the reference header failed: %v", err)
	}
	return header
}
