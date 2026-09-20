# Design decisions

Reasoning for choices that are not obvious from the code. Newest at the bottom.

## Phase 0

### `unsafe` lives in a separate crate, not a module

The brief asks for `#![forbid(unsafe_code)]` everywhere except one thin FFI
wrapper module. `forbid` at a crate root cannot be overridden by `allow` in a
child module — that is the difference between `forbid` and `deny`. Using `deny`
would let any module quietly opt back in. So the wrapper is its own crate,
`netscope-ffi`, whose root is `#![deny(unsafe_code)]` with exactly one
`#[allow(unsafe_code)]` module (`win.rs`, the Windows token/DLL probes). The
application crate `netscope` is `#![forbid(unsafe_code)]` and never names a
`pcap` or `windows-sys` type.

### Pull loop (`next_packet`) instead of `pcap_loop` callbacks

The capture thread calls `pcap_next_ex` with a 100 ms read timeout and checks an
`AtomicBool` between reads. `pcap_loop` with `pcap_breakloop` is marginally
cheaper per frame, but `pcap_breakloop` is only reliable from the same thread on
Windows and requires the read timeout anyway. A clean stop path matters more
than a few nanoseconds per frame; the loop is not the bottleneck (dissection is).

### Delay-loading `wpcap.dll` on Windows

Linking `wpcap.lib` normally puts `wpcap.dll` in the import table, so a machine
without Npcap fails at process start with a loader dialog — before any preflight
can run. The binary is linked with `/DELAYLOAD:wpcap.dll`, and
`netscope_ffi::wpcap_available()` (which also calls `SetDllDirectory` on
`System32\Npcap`) runs before any `pcap` call. Consequence: **every** pcap entry
point must be gated behind a successful preflight, otherwise a missing DLL turns
into a crash inside the delay-load thunk. The UI enforces this by refusing to
enumerate or start when the preflight is `Fail`.

### Preflight does not self-elevate

On Windows, capture usually works without elevation (Npcap's default install
does not restrict the driver to Administrators). Relaunching elevated
speculatively would prompt UAC on every start for most users. The preflight
therefore reports "not elevated" as a warning with the fix, and lets the real
`open` error decide. On Linux the fix is `setcap` on the binary, which the app
cannot apply to itself; on macOS it is BPF device permissions. In all cases the
message names the exact command.

### Microsecond timestamps for live capture

libpcap can be asked for nanosecond timestamps on live handles, but Npcap and
most Linux drivers do not honour it and the `pcap` crate does not expose
`pcap_get_tstamp_precision`, so the app could not tell which unit it got.
Live frames are read as microseconds and widened to nanoseconds in `Timestamp`.
Nanosecond resolution is preserved where it actually occurs: pcapng files,
which netscope parses itself (Phase 5).

### Drop policy: the channel drops, not the capture thread

The bounded channel between capture and dissection uses `try_send`. When it is
full, the frame is discarded and `dropped_channel` incremented. This is the only
policy that satisfies "the capture thread must never block on a consumer";
blocking would push drops into the driver where they are reported less
precisely (`ps_drop` is a 32-bit counter and its semantics vary by platform).
The status bar shows channel, driver and interface drops separately so the user
can tell which stage is saturated.

### Kernel stats are polled, not pushed

`pcap_stats` is called every 1,000 frames and on every read timeout. Calling it
per frame would double the per-frame syscall cost for a number that only needs
to be current at UI refresh rate.
