package leafabi

import (
	"errors"
	"fmt"
)

// Error carries a status code alongside a message, so an engine can say
// exactly which of the ABI's outcomes it means. Any other error an engine
// returns is reported to the host as StatusPluginFailure.
type Error struct {
	Status  Status
	Message string
}

func (e *Error) Error() string { return e.Message }

// Errorf builds an Error with the given status.
func Errorf(status Status, format string, args ...any) error {
	return &Error{Status: status, Message: fmt.Sprintf(format, args...)}
}

// ErrBufferTooSmall tells the host the output buffer could not hold the result.
// An engine returning it must have consumed nothing, so the host can grow the
// buffer and offer the same input again.
var ErrBufferTooSmall = &Error{Status: StatusBufferTooSmall, Message: "output buffer too small"}

// ErrUnsupported tells the host the engine does not implement the operation at
// all, so retrying cannot help.
var ErrUnsupported = &Error{Status: StatusUnsupported, Message: "unsupported"}

// ErrIncomplete says the input stops in the middle of a frame.
//
// On a reliable transport that is an ordinary outcome rather than a failure:
// DecodePacket returning it makes the SDK report success having consumed
// nothing, which is how the host is told to read more bytes and call again.
// Address parsing uses it for the same reason.
var ErrIncomplete = errors.New("incomplete frame")

// statusOf is the code the host is told about err.
func statusOf(err error) Status {
	if err == nil {
		return StatusOK
	}
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Status
	}
	return StatusPluginFailure
}
