package leafabi

import (
	"errors"
	"fmt"
	"testing"
)

// The host refuses a descriptor that does not describe an engine it can drive,
// and it refuses it at load time, when the operator is watching. Catching the
// same mistakes here turns a failed deployment into a failed build.
func TestValidateRegistrationRejectsWhatTheHostWould(t *testing.T) {
	good := func() Plugin {
		return Plugin{
			Name:    "example",
			Version: "0.1.0",
			Stream: &StreamEngineSpec{
				ConnectType: ConnectProxyTCP,
				New:         func(CreateArgs) (StreamEngine, error) { return nil, nil },
			},
		}
	}

	cases := map[string]func(*Plugin){
		"no name":          func(p *Plugin) { p.Name = "" },
		"no version":       func(p *Plugin) { p.Version = "" },
		"no engine":        func(p *Plugin) { p.Stream = nil },
		"no stream ctor":   func(p *Plugin) { p.Stream.New = nil },
		"bad connect type": func(p *Plugin) { p.Stream.ConnectType = ConnectType(0) },
		"no datagram ctor": func(p *Plugin) { p.Datagram = &DatagramEngineSpec{TransportType: TransportReliable} },
		"bad transport type": func(p *Plugin) {
			p.Datagram = &DatagramEngineSpec{
				TransportType: TransportType(0),
				New:           func(CreateArgs) (DatagramEngine, error) { return nil, nil },
			}
		},
	}
	for name, corrupt := range cases {
		plugin := good()
		corrupt(&plugin)
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: validateRegistration accepted %+v", name, plugin)
				}
			}()
			validateRegistration(plugin)
		}()
	}

	// The shapes the ABI does allow: either engine alone, or both.
	plugin := good()
	validateRegistration(plugin)
	plugin.Datagram = &DatagramEngineSpec{
		TransportType: TransportUnreliable,
		New:           func(CreateArgs) (DatagramEngine, error) { return nil, nil },
	}
	validateRegistration(plugin)
	plugin.Stream = nil
	validateRegistration(plugin)
}

// A plugin's own error status has to survive the trip to the host; anything
// else it returns is a plugin failure, which is what tears the connection down.
func TestStatusOfClassifiesErrors(t *testing.T) {
	cases := []struct {
		err  error
		want Status
	}{
		{nil, StatusOK},
		{errors.New("something"), StatusPluginFailure},
		{ErrBufferTooSmall, StatusBufferTooSmall},
		{ErrUnsupported, StatusUnsupported},
		{Errorf(StatusInvalidArgument, "no such side %d", 7), StatusInvalidArgument},
		// Wrapped, because an engine that adds context to an error must not
		// lose the status with it.
		{fmt.Errorf("while encoding: %w", ErrBufferTooSmall), StatusBufferTooSmall},
	}
	for _, c := range cases {
		if got := statusOf(c.err); got != c.want {
			t.Errorf("statusOf(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

func TestFlagHelpers(t *testing.T) {
	flags := StateHasNetOutput | StateWantNetInput | StateEstablished
	if !flags.Has(StateHasNetOutput) {
		t.Error("Has(StateHasNetOutput) = false")
	}
	if !flags.Has(StateHasNetOutput | StateWantNetInput) {
		t.Error("Has of two set flags = false")
	}
	if flags.Has(StateHasNetOutput | StateBlocked) {
		t.Error("Has returned true for a flag that is not set")
	}
	if (CloseApp | CloseNet).Has(CloseNet) != true {
		t.Error("CloseFlags.Has(CloseNet) = false")
	}
	if CloseApp.Has(CloseNet) {
		t.Error("CloseApp.Has(CloseNet) = true")
	}
}

// The SDK's constants have to be the ABI's, not a copy that drifted: they are
// taken straight from the header, and this is what says so out loud.
func TestConstantsMatchTheABI(t *testing.T) {
	if ABIMajor == 0 {
		t.Fatal("ABIMajor is zero")
	}
	if StatusOK != 0 {
		t.Errorf("StatusOK = %d, want 0", StatusOK)
	}
	for _, status := range []Status{
		StatusInvalidArgument, StatusBufferTooSmall, StatusUnsupported, StatusPluginFailure,
	} {
		if status >= 0 {
			t.Errorf("%v = %d, want a negative code", status, int32(status))
		}
	}
	if SideApp == SideNet {
		t.Error("the two stream sides share a value")
	}
	if ConnectProxyTCP == ConnectDirect || ConnectDirect == ConnectNext {
		t.Error("two connect types share a value")
	}
	if TransportReliable == TransportUnreliable {
		t.Error("the two transport types share a value")
	}
	if DirectionEncode == DirectionDecode {
		t.Error("the two datagram directions share a value")
	}
}

func TestStatusAndSideNameThemselves(t *testing.T) {
	if got := StatusBufferTooSmall.String(); got != "buffer too small" {
		t.Errorf("StatusBufferTooSmall.String() = %q", got)
	}
	if got := Status(-99).String(); got != "status(-99)" {
		t.Errorf("unknown status String() = %q", got)
	}
	if got := SideApp.String(); got != "app" {
		t.Errorf("SideApp.String() = %q", got)
	}
	if got := Side(9).String(); got != "side(9)" {
		t.Errorf("unknown side String() = %q", got)
	}
}

// The zero Host is what a plugin's own tests hold, and what an engine is left
// with after the host has taken its callbacks back. Neither may crash.
func TestZeroHostIsInert(t *testing.T) {
	var host Host
	host.Log(LevelError, "dropped")
	host.Logf(LevelInfo, "dropped %d", 1)
	host.Wake()
	host.revoke()
	if host.CanWake() {
		t.Error("the zero Host claims it can wake the host")
	}
}

// A host that offered no wake callback cannot un-block an engine, so the SDK
// must never let one park on it.
func TestRevokedHostStopsClaimingItCanWake(t *testing.T) {
	host := Host{s: &hostState{}}
	if host.CanWake() {
		t.Error("a host with no wake callback claims it can wake")
	}
	host.revoke()
	host.Log(LevelError, "dropped")
	host.Wake()
	if host.CanWake() {
		t.Error("a revoked host claims it can wake")
	}
}
