# leaf-e2e

End-to-end tests for leaf's plugin host.

A case starts real leaf instances -- a client node, usually a server node, and
an origin server -- and drives them from the outside over SOCKS5. That covers
the path a deployment actually takes: config parsing, plugin loading, routing,
the dispatcher, and the C ABI data plane. Nothing here reaches into leaf's
internals to construct a handler by hand.

## Running

```bash
cargo test -p leaf-e2e                      # everything
cargo test -p leaf-e2e -- --list            # what there is, builds nothing
cargo test -p leaf-e2e -- interop           # substring filter
cargo test -p leaf-e2e -- --tag go          # only the Go plugin cases
cargo test -p leaf-e2e -- --tag hostile     # only the misbehaving-plugin lane
cargo test -p leaf-e2e -- --tag cli         # only the cases that run the real binary
cargo test -p leaf-e2e -- --tag stress      # only the loads
cargo test -p leaf-e2e -- --no-tag perf     # skip the cost meters
cargo test -p leaf-e2e -- --no-tag slow     # skip the bulk transfers and the loads
cargo test -p leaf-e2e -- --tag soak        # the nightly lane, minutes per case
cargo test -p leaf-e2e -- --strict          # a skipped case is a failure
```

Plugins are built by the harness, not by you: it invokes `cargo build`,
`go build`, the C compiler and `zig build-lib` for the artifacts the selected
cases need, into the same target directory, so nothing is recompiled twice.
Filtering down to one case builds only what that case needs. `CC` selects the C
compiler, so a cross or sanitized lane can point at the one cargo is using.

When a toolchain is missing, the cases that need it are reported as `ignored`
with the reason. `--strict` (which CI passes) turns that into a failure, so the
suite cannot go green by quietly running nothing.

The plugins' own unit tests are not part of this suite -- they need no leaf at
all. `make plugin-test` runs them.

### On Windows

The suite runs on Windows. It has been run green on Windows 11 on ARM64
(`aarch64-pc-windows-msvc`), the Go lane included; an x86-64 host has not been
tried, so the notes below that are specific to ARM64 say so. What differs from a
Unix run:

- The two black-box cases that ask a running `leaf` to shut itself down are not
  registered there, because the interrupt they send has no Windows equivalent
  the two sides agree on. Nothing else in the suite is platform-specific, and
  the plugin host itself is exercised in-process.
- The `cpu-cost` meter is Unix-only and is simply absent.

Two things the harness had to learn to run here, both of which cost a case its
meaning rather than merely its speed, and both of which come down to the same
thing -- a pause on Windows is never shorter than the timer granularity, about
16ms:

- A case that wants a peer to dribble bytes cannot pause between every one of
  them. `framing.rs` bounds the number of pauses instead, so a reply still
  arrives in pieces and still costs milliseconds rather than half a minute.
- A case that bursts datagrams at an inbound has to pause with a timer and not
  a yield. A yield re-queues the sending task without giving the node's own
  threads a turn, and Windows then drops four fifths of the burst.

Toolchains, all of which must be on `PATH`:

| Need | Why | Note |
| --- | --- | --- |
| Rust (MSVC or GNU host) | leaf, the harness, the Rust plugins | either host toolchain works; the plugins are plain C ABI DLLs |
| CMake, and NASM on x86-64 | leaf's default crypto backend | `aws-lc-sys` builds them on Windows. A build that fails inside that crate rather than in leaf is this line |
| A GCC-style C compiler | the C plugin, and cgo for the Go plugins | MSYS2 `mingw-w64-x86_64-gcc`, or a Clang named in `CC`. `cl` will not do: the plugin is built with GCC-style flags. On ARM64 the MinGW `gcc` distributions are x86-64 and produce a DLL leaf cannot load, and cgo additionally needs the GNU ABI rather than the MSVC one -- see the Go section below for the two variables that sort this out |
| Go | the Go plugins | `go build -buildmode=c-shared` needs `CGO_ENABLED=1` and the compiler above. On ARM64 read the next section before spending time on it |
| Zig 0.16 | the Zig plugin | the harness targets `*-windows-gnu` so Zig's bundled mingw-w64 is used and Visual Studio is not required. On ARM64 install the **x86-64** release: the `aarch64-windows` build of 0.16.0 faults on any compilation at all, and Zig cross-compiles to `aarch64-windows-gnu` perfectly well from x86-64 under emulation |

#### The Go lane, and why `LEAF_E2E_CC` exists

cgo on Windows wants a GNU toolchain, and says nothing when it does not get
one. A `c-shared` library built with an MSVC-targeted compiler -- which is what
plain `clang` is on Windows -- links without complaint, loads without
complaint, and then hangs on the first call through any exported symbol: the
runtime of such a library is started from a constructor the GNU CRT runs, the
MSVC one never runs it, and the cgo entry stub waits forever for an
initialisation that never began. No Go code runs at all, an `init()` included,
which is the quickest way to tell this apart from a plugin that is merely slow.

So the plugins want a GNU compiler while cargo's own C dependencies --
`aws-lc-sys` above all -- want one built for the Rust target, and on ARM64
those are not the same program. `CC` cannot serve both. Leave `CC` to cargo and
give the harness `LEAF_E2E_CC`, which it uses for the C plugin and hands to
cgo:

```powershell
$env:CC = "clang"                                  # cargo's C dependencies
$env:LEAF_E2E_CC = "zig cc -target aarch64-windows-gnu"   # the plugins and cgo
```

Any GNU toolchain does; `zig cc` is convenient because the Zig install is
already required. Both variables are split on whitespace, so a driver that
needs a flag to be the right compiler at all can be named in full.

Once it is building, the Go lane needs nothing further here, and it is worth
knowing why -- because the hazard it avoids is real and Windows is the only
platform that runs into it. `FreeLibrary` on a live Go `c-shared` library is
fatal: the Go runtime's threads are not something any reference the host holds
can account for, and it reproduces outside leaf in ten lines -- load, call an
export, `FreeLibrary`, die. Linux and macOS decline to unmap such a library at
all, so nothing there ever asks the question. This is what
`LEAF_PLUGIN_FLAG_EMBEDS_RUNTIME` is for: the Go SDK sets it, and the host keeps
any library that declares it mapped for the life of the process. A plugin that
embeds a runtime and does *not* set the flag would hit this, on Windows only,
and at teardown rather than in the behaviour -- which is the shape to recognise
if a plugin of your own ever does.

One more thing worth knowing if a Go toolchain misbehaves: the Windows
installers for different architectures all target `C:\Program Files\Go`, so
installing two of them leaves a tree with source files from both. It shows up
as the standard library failing to compile -- `uint64pow10 redeclared` and
friends -- which looks like a broken Go release and is really two of them.

Then, from the repository root in a shell that has all four on `PATH`:

```powershell
# Everything except the nightly lane. --strict fails the run if a case is
# skipped, so a missing toolchain cannot look like a pass.
cargo test -p leaf-e2e --test e2e -- --strict --no-tag soak

# Without the Go toolchain set up as the section above describes:
cargo test -p leaf-e2e --test e2e -- --strict --no-tag soak --no-tag go

# The host's own tests and each plugin's, without `make`:
cargo test -p leaf --features plugin --lib
cargo test -p leaf-plugin-abi
cargo test -p tls-cabi-rs -p shadowsocks-cabi-rs
```

If a toolchain is missing, drop its lane rather than the `--strict`: for
example `--no-tag go --no-tag zig` still covers the loader, the ABI validation,
the C plugin and the hostile lane. Run without `--strict` once first if you
want to see what would be skipped:

```powershell
cargo test -p leaf-e2e --test e2e -- --list
```

A failing case leaves its logs and configs under
`target\debug\e2e-artifacts\<case>\`; send that directory and the console
output.

### Options

| Flag | Environment | Meaning |
| --- | --- | --- |
| `--strict` | `LEAF_E2E_STRICT=1` | A case skipped for a missing fixture fails instead |
| `--tag <t>` / `--no-tag <t>` | -- | Select by label: `native`, `plugin`, `go`, `cc`, `zig`, `differential`, `perf`, `hostile`, `cli`, `stress`, `soak`, `slow` |
| -- | `TCP_INBOUND_ABORT_ON_CLOSE` | leaf's own option, inherited by the nodes a case starts. Turning it on runs the suite against inbound sockets that are reset rather than closed |
| -- | `LEAF_CONFORMANCE_DESCRIPTOR` | Which descriptor the conformance plugin publishes; set per case, not by hand |
| `--timeout-scale <f>` | `LEAF_E2E_TIMEOUT_SCALE` | Multiplies every deadline; for slow or sanitized runs |
| `--in-process` | `LEAF_E2E_IN_PROCESS=1` | Runs cases in the harness process, for a debugger; use with `--test-threads 1` |
| -- | `LEAF_E2E_BULK_BYTES` | How much the bulk behaviour moves (default 4 MiB). Raise it for a soak run |
| -- | `LEAF_E2E_LOG_LEVEL` | The level nodes log at (default `trace`). The bulk and load cases turn it down themselves |
| -- | `LEAF_E2E_CC` | The compiler for the C plugin and for cgo, falling back to `CC`. Split on whitespace. Use it where `CC` has to stay what cargo's own C dependencies need |
| -- | `LEAF_E2E_PROFILE_DIR` | The `target/<profile>` directory cargo built into. The harness derives this from its own path; set it for a layout the derivation does not recognise, which is what the error says when it cannot |
| -- | `LEAF_E2E_STRESS_SCALE` | Multiplies every load's concurrency and duration (default 1). CI runs the lane at a quarter; a soak run raises it |
| -- | `LEAF_E2E_METER_REPS` | How many times each side of a meter is measured (default 3). More of them buys a steadier ratio on a noisy machine |

Everything else is passed through to the test reporter, so `--exact`,
`--test-threads`, `--nocapture` and friends work as usual.

## Isolation

Each case runs in its own process, spawned from the harness binary. This is not
incidental:

* Cases deliberately load plugins that misbehave, so a case has to be able to
  crash without taking the run with it. A segfault is reported as one failed
  case, with the signal.
* A plugin's load-time behaviour is chosen through the environment, and cannot
  be changed once the library is mapped. A case owns its process, so it owns
  that choice.
* A hang is killed at the case's deadline and reported, rather than stalling
  the suite.

Each case's stdout and stderr, which include the nodes' trace logs, are written
to `target/<profile>/e2e-artifacts/<case>/`. The tail of both is inlined into a
failure message; the whole thing stays on disk.

## Adding a case

Write an `async fn` returning `anyhow::Result<()>`, and register it:

```rust
Scenario::new("interop/my-plugin/tcp", "interop", || boxed(my_case()))
    .tags(&[Tag::Plugin])
    .needs(&[Fixture::MyPlugin])
    .timeout(Duration::from_secs(30))
```

Inside, build a topology out of `Node`, `Origin` and `Socks5`, and run a
behaviour from `flow`. Ports come from the operating system; never hard-code
one.

## Differential cases

Most plugin coverage lives in `differential/`. A case there runs one behaviour
twice -- once over a topology built entirely from leaf's own protocols, once
with a plugin substituted for one stage of it -- and requires the two to have
observed the same thing. The server is stock leaf in both, so these are
interoperability tests: what a plugin puts on the wire has to be the protocol,
not merely something the same plugin can read back.

That structure also tells the two kinds of failure apart. If the native run
fails, the case says so and never blames the plugin. This is how the harness's
own early bugs were found, and how the read-side stall in the plugin host was
narrowed down: the native shadowsocks chain carried 64 MiB without trouble while
the plugin one delivered zero bytes.

Behaviours live in `src/behaviours.rs` and record normalised facts -- no
timings, no ports, nothing that differs between two runs of the same topology.
Adding one there adds it to every implementation in the matrix at once, or to
every one that can carry it: a candidate names a `Suite`, so a plugin with no
datagram engine runs the stream behaviours and no others.

Normalised means the invariant, not the incident. `peer-closes-first` records
that the client was told the connection ended, not whether it arrived as an end
of stream or a reset: the plugin path and the native path reach that point
differently, reproducibly, and for good reasons on both sides. Recording the
manner would assert a difference that is not a defect.

## Cost

`perf/` measures the same work over both topologies in the same run and asserts
the *ratio*: throughput as a fraction of native, round-trip and connection setup
as a multiple of it. Absolute numbers from a shared runner say more about the
runner than about the code, and a ratio measured back to back on one machine
does not.

The budgets are loose -- a quarter of native throughput, five times its latency
-- because this is a guard against a regression that turns a bulk copy into a
byte-at-a-time loop, not a benchmark. Measured headroom is three to five times.

The meters are chosen so that each can fail alone: one stream and eight of
them, because a per-connection cost and a contended one are different
regressions; each direction on its own, because an echo hides a broken decode
path behind a working encode path; small messages rather than bytes, because
the per-call cost of the engine's state machine is invisible in a bulk copy;
and, in the nightly lane, latency under load and bytes per second of processor
time, because loopback is fast enough to absorb a path that does twice the
work.

A meter moves a payload that is generated once and never hashed, and the
uplink meter ends on an acknowledgement from the origin rather than on a
half-close. Both are the same lesson: a fixed cost inside a timed region is
worse than a slow one, because it flattens the very ratio the meter exists to
watch. Generating four megabytes and hashing them twice costs about half a
second in a debug build against twenty milliseconds of actual transfer, and
waiting for a close that leaf's websocket transport cannot express costs the
ten-second idle timeout. Both were measured here before they were fixed --
`throughput` read 2.9 MiB/s on a chain carrying 280, and `uplink` read 0.4 on
one carrying 92. Integrity is the differential behaviours' job, and they check
every byte.

Every meter also writes what it measured -- both sides, every repetition, the
ratio and the budget -- to `meters.json` in the case's artifact directory. The
ratio is what fails a build; the file is what tells anyone looking whether both
sides halved while the ratio held. Each side is measured after a warm-up run
that is thrown away, and the best of `LEAF_E2E_METER_REPS` runs is kept:
scheduling noise only ever makes a run worse.

## Load

`stress/` runs sustained load over the same topologies: sixty-four connections
at once, a connection storm at a fixed arrival rate with transfers running
underneath it, a reader that stops reading for five seconds, and many datagram
sessions at once. `soak/` is the same idea for minutes rather than seconds, and
is excluded from every lane but the nightly one.

These assert invariants, never timings -- every iteration completed, every byte
came back in order, every engine instance the host created was destroyed, and
the process is not holding more at the end than in the middle. What a load
costs belongs to the meters, where it is asked against native rather than
against a number someone picked. Each load runs over the native topology first,
for the same reason the differential cases do: a machine that cannot carry
sixty-four connections says nothing about a plugin.

Two things the load generator does deliberately, both learned the hard way:

* **It backs off after a failed connect, and opens replacement connections at a
  fixed rate.** Reconnecting as fast as possible is not a harder test but a
  different one -- it overruns the listener's backlog, exhausts the machine's
  ephemeral ports, and makes every case running beside it fail with the
  harness's symptoms instead of the host's.
* **It derives its concurrency from the descriptor limit**, after raising the
  soft limit towards the hard one. A chain puts five or six descriptors behind
  every connection, both leaf nodes run in the case's process, and the default
  soft limit on a Mac is 256. A case that asked for more than fits is told what
  it got, in the line it prints.

A load that opens a connection per iteration is judged on completing 99% of
them rather than all of them: hundreds of arrivals a second through two leaf
nodes will occasionally meet a listener backlog that is momentarily full, or an
ephemeral port the machine has just handed back. A load that holds its
connections open is exposed to none of that and has to be perfect.

## The conformance plugin

`plugins/conformance-cabi` is a plugin that misbehaves on request. It exists
because the host's defences against a wrong plugin -- rejecting a `consumed`
larger than the input, a `produced` larger than the buffer, clamping absurd size
hints, refusing a malformed descriptor -- are only worth as much as they are
exercised across a real `dlopen`.

Two things are configurable, and they are configured differently because the
host learns them at different times:

* the **descriptor** comes from `LEAF_CONFORMANCE_DESCRIPTOR`, read when the
  library is mapped. A case selects one by owning its process; this is one of
  the reasons cases get their own.
* the **engine's behaviour** comes from the outbound's plugin arguments
  (`fault=<name>`), chosen per instance.

Without a fault it is a plain relay, so a fault is judged against the same
traffic that works without one. It also exports `leaf_conformance_stats` outside
the ABI, which lets a case check that every engine instance was destroyed, or
that two tags on one file mapped the library once -- without the ABI growing a
hole for a test's benefit.

Its datagram engine carries a trivial framing that `src/framing.rs` speaks from
the other end, on UDP and over a byte stream. That is what makes the reliable
transport's cases possible: the peer decides whether a reply arrives as half a
frame, as three frames in one write, or with keepalives mixed in, and those are
exactly the shapes `decode_packet` has to report differently through `consumed`.
Producing them from the peer keeps the engine honest, so the host stays the only
thing under test.

Run this lane under a sanitizer as well as plainly. CI does: see
`plugin-e2e-asan`. The case that most wants it is
`hostile/wake-from-a-plugin-thread`: the host's readiness callback stays valid
only until `destroy_instance` returns, so a plugin calling it from its own
thread while connections come and go is where an instance context released too
early becomes a use-after-free.

## Black-box cases

Almost everything runs leaf in-process. The `cli` lane runs the shipped binary
instead, for the things that live only there:

- whether the configs in `examples/` still parse (`leaf -T`);
- whether `--verify-plugin` reports what the loader itself would do -- the same
  connect type, the same endpoint rule, a digest that the pin check then
  accepts, and a refusal where the loader refuses;
- whether traffic actually goes through a plugin loaded by the real binary;
- whether the process exits after a plugin has pulled a language runtime of its
  own into it. The ABI warns about this one, and no in-process test can observe
  it.

## Known defects

A case that hits a defect nobody has fixed yet is marked with
`.known_defect("what is wrong")`. It is then reported as ignored with that
reason instead of failing, so a real bug does not train everyone to ignore a red
suite -- and it *fails* the day it starts passing, which is when the marker
should come off. Mark a defect, never delete the case.

## Reading a failure

Prefer to add the leaf-native equivalent of a plugin case -- see
`smoke/native/socks-direct/*`, and `smoke/harness/loopback-bulk`, which uses no
leaf at all. When all of them fail, the harness is at fault; when only the
plugin case fails, the plugin or the host is.

Two things the harness learned the hard way and now encodes:

* Teardown is its own question, so a bulk transfer does not answer it by
  accident: `flow::bulk_echo` leaves the socket open and reads back exactly
  what it sent, and the cases that are about teardown say so in their names.
  leaf used to give every inbound socket `SO_LINGER = 0`, which cost such a
  transfer its tail; that is now `TCP_INBOUND_ABORT_ON_CLOSE` and off by
  default, but a session leaf ends on its own -- an idle timeout, a relay error
  -- can still end in a reset, and `teardown/` is where that is examined.
* A stalled transfer is reported as "stopped after N of M bytes, sender had
  written K" rather than as a deadline the runner had to kill. That single line
  is usually the whole diagnosis.
