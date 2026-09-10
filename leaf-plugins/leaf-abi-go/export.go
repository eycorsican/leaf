package leafabi

/*
#cgo CFLAGS: -I${SRCDIR}/../../leaf-plugin-abi/include
#include "abi.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// This file is the whole of the boundary. Every entry here does the same four
// things: refuse a call the ABI says cannot happen, resolve the instance, run
// the engine, and translate whatever comes back -- including a panic -- into a
// status code. Nothing above this file sees a C pointer; nothing below it sees
// a Go error.

func panicMessage(r any) string {
	return fmt.Sprintf("panic across the ABI boundary: %v", r)
}

// recoverStatus turns a panic into StatusPluginFailure, having first zeroed
// whatever the call would otherwise have left the host reading.
func recoverStatus(inst *instance, status *C.leaf_engine_status_t, sizes ...*C.size_t) {
	r := recover()
	if r == nil {
		return
	}
	for _, size := range sizes {
		if size != nil {
			*size = 0
		}
	}
	message := panicMessage(r)
	if inst != nil {
		inst.setError(StatusPluginFailure, message)
		inst.host.Log(LevelError, message)
	}
	*status = C.leaf_engine_status_t(StatusPluginFailure)
}

func recoverSize(inst *instance, fallback C.size_t, value *C.size_t) {
	r := recover()
	if r == nil {
		return
	}
	message := panicMessage(r)
	if inst != nil {
		inst.setError(StatusPluginFailure, message)
		inst.host.Log(LevelError, message)
	}
	*value = fallback
}

func recoverCreate(slot *createError, host Host, result *unsafe.Pointer) {
	r := recover()
	if r == nil {
		return
	}
	message := panicMessage(r)
	host.Log(LevelError, message)
	slot.set(StatusPluginFailure, message)
	*result = nil
}

func recoverVoid(inst *instance) {
	if r := recover(); r != nil {
		message := panicMessage(r)
		if inst != nil {
			inst.host.Log(LevelError, message)
		}
	}
}

// writeLastError answers the host's two-pass error query: once with no buffer,
// to learn the length, and again with one that size. A non-zero return would
// mean there is nothing to say, so this always succeeds and reports an empty
// message instead.
func writeLastError(
	status Status,
	text string,
	code *C.leaf_engine_status_t,
	output *C.uint8_t,
	outputCap C.size_t,
	written *C.size_t,
) C.leaf_engine_status_t {
	if code == nil || written == nil {
		return C.leaf_engine_status_t(StatusInvalidArgument)
	}
	if outputCap > 0 && output == nil {
		return C.leaf_engine_status_t(StatusInvalidArgument)
	}
	*code = C.leaf_engine_status_t(status)
	*written = C.size_t(len(text))
	if outputCap > 0 {
		*written = C.size_t(copy(hostBytes(output, outputCap), text))
	}
	return C.leaf_engine_status_t(StatusOK)
}

// --- stream engine ---------------------------------------------------------

//export leafabi_stream_create
func leafabi_stream_create(args *C.EngineCreateArgs) (result unsafe.Pointer) {
	var host Host
	if args != nil {
		host = hostFromCallbacks(args.host_callbacks)
	}
	defer recoverCreate(&streamCreateError, host, &result)

	spec := registered.Stream
	if spec == nil {
		streamCreateError.set(StatusUnsupported, "this plugin exports no stream engine")
		return nil
	}
	created, err := createArgsFrom(args)
	if err != nil {
		host.Log(LevelError, err.Error())
		streamCreateError.set(statusOf(err), err.Error())
		return nil
	}
	engine, err := spec.New(created)
	if err != nil {
		created.Host.Log(LevelError, err.Error())
		streamCreateError.set(statusOf(err), err.Error())
		return nil
	}
	if engine == nil {
		message := "the plugin's stream constructor returned no engine"
		created.Host.Log(LevelError, message)
		streamCreateError.set(StatusPluginFailure, message)
		return nil
	}
	streamCreateError.clear()
	inst := allocInstance(&instance{host: created.Host, stream: engine})
	if inst == nil {
		engine.Destroy()
		created.Host.revoke()
		streamCreateError.set(StatusPluginFailure, "out of memory allocating the instance handle")
		return nil
	}
	return inst
}

//export leafabi_stream_destroy
func leafabi_stream_destroy(p unsafe.Pointer) {
	inst, handle, ok := loadInstance(p)
	// The handle goes either way: leaking it would keep the engine and every
	// buffer it holds alive for the life of the process. recoverVoid has to be
	// deferred directly, not called from inside another deferred function, or
	// its recover would see nothing.
	defer freeInstance(p, handle, ok)
	defer recoverVoid(inst)
	if !ok || inst.stream == nil {
		return
	}
	inst.stream.Destroy()
	// From here the host may reclaim host_ctx, so nothing the plugin still
	// holds may call back into it.
	inst.host.revoke()
}

//export leafabi_stream_poll_state
func leafabi_stream_poll_state(
	p unsafe.Pointer,
	stateFlags *C.leaf_stream_state_flags_t,
) (status C.leaf_engine_status_t) {
	inst, _, ok := loadInstance(p)
	defer recoverStatus(inst, &status)
	if !ok || inst.stream == nil || stateFlags == nil {
		return C.leaf_engine_status_t(StatusInvalidArgument)
	}
	flags := inst.stream.PollState()
	// An engine that cannot wake the host must not park it. Masking here means
	// a plugin can report BLOCKED unconditionally and still work against a host
	// that offered no wake callback.
	if !inst.host.CanWake() {
		flags &^= StateBlocked
	}
	*stateFlags = C.leaf_stream_state_flags_t(flags)
	inst.clearError()
	return C.leaf_engine_status_t(StatusOK)
}

//export leafabi_stream_push
func leafabi_stream_push(
	p unsafe.Pointer,
	side C.leaf_stream_side_t,
	input *C.uint8_t,
	inputLen C.size_t,
	consumed *C.size_t,
) (status C.leaf_engine_status_t) {
	inst, _, ok := loadInstance(p)
	defer recoverStatus(inst, &status, consumed)
	if !ok || inst.stream == nil || consumed == nil {
		return C.leaf_engine_status_t(StatusInvalidArgument)
	}
	*consumed = 0
	if inputLen > 0 && input == nil {
		return inst.fail(Errorf(StatusInvalidArgument, "push was given no input buffer for %d bytes", int(inputLen)))
	}
	n, err := inst.stream.Push(Side(side), hostBytes(input, inputLen))
	if err != nil {
		return inst.fail(err)
	}
	if n < 0 || n > int(inputLen) {
		return inst.fail(Errorf(
			StatusPluginFailure,
			"push(%s) reported %d of %d bytes consumed", Side(side), n, int(inputLen),
		))
	}
	*consumed = C.size_t(n)
	inst.clearError()
	return C.leaf_engine_status_t(StatusOK)
}

//export leafabi_stream_pull
func leafabi_stream_pull(
	p unsafe.Pointer,
	side C.leaf_stream_side_t,
	output *C.uint8_t,
	outputCap C.size_t,
	produced *C.size_t,
) (status C.leaf_engine_status_t) {
	inst, _, ok := loadInstance(p)
	defer recoverStatus(inst, &status, produced)
	if !ok || inst.stream == nil || produced == nil {
		return C.leaf_engine_status_t(StatusInvalidArgument)
	}
	*produced = 0
	if outputCap > 0 && output == nil {
		return inst.fail(Errorf(StatusInvalidArgument, "pull was given no output buffer for %d bytes", int(outputCap)))
	}
	n, err := inst.stream.Pull(Side(side), hostBytes(output, outputCap))
	if err != nil {
		return inst.fail(err)
	}
	if n < 0 || n > int(outputCap) {
		return inst.fail(Errorf(
			StatusPluginFailure,
			"pull(%s) reported %d bytes into a buffer of %d", Side(side), n, int(outputCap),
		))
	}
	*produced = C.size_t(n)
	inst.clearError()
	return C.leaf_engine_status_t(StatusOK)
}

//export leafabi_stream_close
func leafabi_stream_close(
	p unsafe.Pointer,
	closeFlags C.leaf_stream_close_flags_t,
) (status C.leaf_engine_status_t) {
	inst, _, ok := loadInstance(p)
	defer recoverStatus(inst, &status)
	if !ok || inst.stream == nil {
		return C.leaf_engine_status_t(StatusInvalidArgument)
	}
	if err := inst.stream.Close(CloseFlags(closeFlags)); err != nil {
		return inst.fail(err)
	}
	inst.clearError()
	return C.leaf_engine_status_t(StatusOK)
}

//export leafabi_stream_last_error
func leafabi_stream_last_error(
	p unsafe.Pointer,
	code *C.leaf_engine_status_t,
	output *C.uint8_t,
	outputCap C.size_t,
	written *C.size_t,
) (status C.leaf_engine_status_t) {
	inst, _, ok := loadInstance(p)
	defer recoverStatus(inst, &status, written)
	if !ok {
		last, text := streamCreateError.get()
		return writeLastError(last, text, code, output, outputCap, written)
	}
	return writeLastError(inst.errCode, inst.errText, code, output, outputCap, written)
}

//export leafabi_stream_output_size
func leafabi_stream_output_size(p unsafe.Pointer, side C.leaf_stream_side_t) (value C.size_t) {
	inst, _, ok := loadInstance(p)
	defer recoverSize(inst, fallbackOutputSize, &value)
	if !ok || inst.stream == nil {
		return fallbackOutputSize
	}
	hint := outputSizeHint(inst.stream, Side(side))
	if hint <= 0 {
		return fallbackOutputSize
	}
	return C.size_t(hint)
}

//export leafabi_stream_output_batch
func leafabi_stream_output_batch(p unsafe.Pointer, side C.leaf_stream_side_t) (value C.size_t) {
	inst, _, ok := loadInstance(p)
	defer recoverSize(inst, defaultOutputBatch, &value)
	if !ok || inst.stream == nil {
		return defaultOutputBatch
	}
	hint := outputBatchHint(inst.stream, Side(side))
	if hint <= 0 {
		return defaultOutputBatch
	}
	return C.size_t(hint)
}

// --- datagram engine -------------------------------------------------------

//export leafabi_datagram_create
func leafabi_datagram_create(args *C.EngineCreateArgs) (result unsafe.Pointer) {
	var host Host
	if args != nil {
		host = hostFromCallbacks(args.host_callbacks)
	}
	defer recoverCreate(&datagramCreateError, host, &result)

	spec := registered.Datagram
	if spec == nil {
		datagramCreateError.set(StatusUnsupported, "this plugin exports no datagram engine")
		return nil
	}
	created, err := createArgsFrom(args)
	if err != nil {
		host.Log(LevelError, err.Error())
		datagramCreateError.set(statusOf(err), err.Error())
		return nil
	}
	engine, err := spec.New(created)
	if err != nil {
		created.Host.Log(LevelError, err.Error())
		datagramCreateError.set(statusOf(err), err.Error())
		return nil
	}
	if engine == nil {
		message := "the plugin's datagram constructor returned no engine"
		created.Host.Log(LevelError, message)
		datagramCreateError.set(StatusPluginFailure, message)
		return nil
	}
	datagramCreateError.clear()
	inst := allocInstance(&instance{host: created.Host, dgram: engine})
	if inst == nil {
		engine.Destroy()
		created.Host.revoke()
		datagramCreateError.set(StatusPluginFailure, "out of memory allocating the instance handle")
		return nil
	}
	return inst
}

//export leafabi_datagram_destroy
func leafabi_datagram_destroy(p unsafe.Pointer) {
	inst, handle, ok := loadInstance(p)
	defer freeInstance(p, handle, ok)
	defer recoverVoid(inst)
	if !ok || inst.dgram == nil {
		return
	}
	inst.dgram.Destroy()
	inst.host.revoke()
}

//export leafabi_datagram_encode
func leafabi_datagram_encode(
	p unsafe.Pointer,
	payload *C.uint8_t,
	payloadLen C.size_t,
	target *C.PluginAddress,
	output *C.uint8_t,
	outputCap C.size_t,
	produced *C.size_t,
) (status C.leaf_engine_status_t) {
	inst, _, ok := loadInstance(p)
	defer recoverStatus(inst, &status, produced)
	if !ok || inst.dgram == nil || produced == nil {
		return C.leaf_engine_status_t(StatusInvalidArgument)
	}
	*produced = 0
	if payloadLen > 0 && payload == nil {
		return inst.fail(Errorf(StatusInvalidArgument, "encode_packet was given no payload buffer for %d bytes", int(payloadLen)))
	}
	if outputCap > 0 && output == nil {
		return inst.fail(Errorf(StatusInvalidArgument, "encode_packet was given no output buffer for %d bytes", int(outputCap)))
	}
	address, err := addressFromC(target)
	if err != nil {
		return inst.fail(err)
	}
	n, err := inst.dgram.EncodePacket(hostBytes(payload, payloadLen), address, hostBytes(output, outputCap))
	if err != nil {
		return inst.fail(err)
	}
	if n < 0 || n > int(outputCap) {
		return inst.fail(Errorf(
			StatusPluginFailure,
			"encode_packet reported %d bytes into a buffer of %d", n, int(outputCap),
		))
	}
	*produced = C.size_t(n)
	inst.clearError()
	return C.leaf_engine_status_t(StatusOK)
}

//export leafabi_datagram_decode
func leafabi_datagram_decode(
	p unsafe.Pointer,
	input *C.uint8_t,
	inputLen C.size_t,
	consumed *C.size_t,
	payloadOut *C.uint8_t,
	payloadCap C.size_t,
	payloadLen *C.size_t,
	addressOut *C.PluginAddress,
) (status C.leaf_engine_status_t) {
	inst, _, ok := loadInstance(p)
	defer recoverStatus(inst, &status, consumed, payloadLen)
	if !ok || inst.dgram == nil || consumed == nil || payloadLen == nil || addressOut == nil {
		return C.leaf_engine_status_t(StatusInvalidArgument)
	}
	*consumed = 0
	*payloadLen = 0
	if inputLen > 0 && input == nil {
		return inst.fail(Errorf(StatusInvalidArgument, "decode_packet was given no input buffer for %d bytes", int(inputLen)))
	}
	if payloadCap > 0 && payloadOut == nil {
		return inst.fail(Errorf(StatusInvalidArgument, "decode_packet was given no payload buffer for %d bytes", int(payloadCap)))
	}

	took, wrote, address, err := inst.dgram.DecodePacket(
		hostBytes(input, inputLen),
		hostBytes(payloadOut, payloadCap),
	)
	switch {
	case errors.Is(err, ErrIncomplete):
		// Not a failure on a reliable transport: consuming nothing is how the
		// host is told to read more and offer the frame again.
		inst.clearError()
		return C.leaf_engine_status_t(StatusOK)
	case err != nil:
		return inst.fail(err)
	}
	if took < 0 || took > int(inputLen) {
		return inst.fail(Errorf(
			StatusPluginFailure,
			"decode_packet reported %d of %d bytes consumed", took, int(inputLen),
		))
	}
	if wrote < 0 || wrote > int(payloadCap) {
		return inst.fail(Errorf(
			StatusPluginFailure,
			"decode_packet reported %d bytes into a payload buffer of %d", wrote, int(payloadCap),
		))
	}
	if wrote > 0 {
		if err := addressToC(address, addressOut); err != nil {
			return inst.fail(err)
		}
	}
	*consumed = C.size_t(took)
	*payloadLen = C.size_t(wrote)
	inst.clearError()
	return C.leaf_engine_status_t(StatusOK)
}

//export leafabi_datagram_max_output_size
func leafabi_datagram_max_output_size(
	p unsafe.Pointer,
	inputLen C.size_t,
	direction C.leaf_datagram_direction_t,
) (value C.size_t) {
	inst, _, ok := loadInstance(p)
	defer recoverSize(inst, inputLen, &value)
	if !ok || inst.dgram == nil {
		return inputLen
	}
	hint := inst.dgram.MaxOutputSize(int(inputLen), Direction(direction))
	if hint <= 0 {
		return inputLen
	}
	return C.size_t(hint)
}

//export leafabi_datagram_max_address_size
func leafabi_datagram_max_address_size(
	p unsafe.Pointer,
	direction C.leaf_datagram_direction_t,
) (value C.size_t) {
	inst, _, ok := loadInstance(p)
	defer recoverSize(inst, MaxDomainLength, &value)
	if !ok || inst.dgram == nil {
		return MaxDomainLength
	}
	hint := inst.dgram.MaxAddressSize(Direction(direction))
	if hint <= 0 {
		return MaxDomainLength
	}
	return C.size_t(hint)
}

//export leafabi_datagram_last_error
func leafabi_datagram_last_error(
	p unsafe.Pointer,
	code *C.leaf_engine_status_t,
	output *C.uint8_t,
	outputCap C.size_t,
	written *C.size_t,
) (status C.leaf_engine_status_t) {
	inst, _, ok := loadInstance(p)
	defer recoverStatus(inst, &status, written)
	if !ok {
		last, text := datagramCreateError.get()
		return writeLastError(last, text, code, output, outputCap, written)
	}
	return writeLastError(inst.errCode, inst.errText, code, output, outputCap, written)
}
