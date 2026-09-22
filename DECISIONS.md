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

## Phase 1

### Chunked ring buffer, eviction in 4,096-frame units

The store keeps sealed, immutable `Arc<Chunk>`s of 4,096 frames plus one open
chunk. A UI snapshot is therefore ~250 `Arc` clones for a million frames plus a
copy of the open chunk's `Arc<Frame>` pointers — measured at 9 µs — and row
lookup is two array indexes. The price is that the frame/byte limits are
honoured to within one chunk (documented in the options dialog). Frame-by-frame
eviction would need per-frame bookkeeping the UI would have to re-read every
repaint; being 4k frames over a 1e6 limit is invisible.

### Frame numbers are assigned by the dequeuing worker, not the store

Numbers must follow arrival order even once dissection runs on several threads.
The single thread that pulls from the capture channel is the only place that
sees arrival order, so it numbers frames before handing them to dissection.
The store checks continuity and renumbers on a mismatch rather than trusting
the producer blindly.

### The UI polls a store version counter

The store bumps an `AtomicU64` on every append; the UI compares it with its
snapshot's version each repaint and only re-snapshots on change. This avoids
a channel from worker to UI and keeps the UI's read path to one atomic load
when nothing changed.

### Absolute times are UTC

There is no time-zone database in the fixed stack and `std` cannot query the
local offset portably. The column header says "(UTC)". Local-time display is
a candidate for a later phase if it matters.

### Memory accounting counts the tree, and it is expensive

`Frame::approx_size` includes the dissection tree's label strings. On the 1e6
benchmark the stub tree alone costs ~1 KB per frame on top of the payload,
because labels are pre-formatted `String`s. This is the number to watch in
Phase 2: if real dissectors push it past the 500k frames/s target, labels will
become lazy (formatted on display from `Value`) rather than eager.

## Phase 2

### Labels are formatted on demand, not stored

The Phase 1 benchmark showed pre-formatted label strings dominating both
dissection time and memory. Nodes now carry only a field id, a typed value and
a byte range; `registry::label` formats the text when a row is drawn. The
registry is therefore the single owner of field names, value symbolics and
number bases, which is also what the display filter needs. Nodes that need
free text (malformed reasons, option summaries, TLS extension detail) keep it
in an optional `text`, and protocol-layer summaries ("TCP, Src Port: 443, ...")
are rendered from templates over child values so no string is built per layer.

### The stored tree is flat

Dissectors still return the spec's `Node` pointer tree; it is the natural
shape to build. What the store keeps is `Tree`: the same nodes flattened
depth-first into one array of 28-byte records plus a byte arena for strings.
A TCP frame has ~66 nodes; at 104 bytes per `Node` plus a heap allocation per
child vector that was 8.5 KB and hundreds of allocations per frame, which
paged the machine at 1e6 frames. Flat: ~1.9 KB per frame, two allocations.
Structure (children, ancestors) is recovered from `depth`, which is cheap for
a tree that is only ever walked top-down.

### Measured throughput and the remaining gap

Ethernet/IPv4/TCP path, single thread, release, idle machine: **219-227k
frames/s** (4.4-4.6 µs/frame) for a 66-node tree, at 3.0 KB accounted per
frame. Through the store as well (dissect + append): 195k frames/s. The
target is 500k/s/core, so this misses by a factor of about 2.2.

Where the time goes, measured per frame: `tcp::dissect` 1.20 µs,
`ipv4::dissect` 0.69 µs, `eth::dissect` 0.15 µs, `Tree::from_layers` 0.91 µs,
`Ctx::new` 0.03 µs. The dissectors cost about 30 ns per node produced,
dominated by building the intermediate `Node` tree — a 104-byte record moved
into a child `Vec`, an allocation for every parent with children — and then a
second pass to flatten it.

Two contained wins were taken. Checksum status became a numeric enum field
instead of an allocated `String` (five allocations per frame), and the
field-id index uses FNV-1a rather than SipHash, since the keys are short
`&'static str` literals and not attacker-controlled; a lookup went from 47 ns
to 16 ns. Together they moved 190k to ~225k frames/s and halved memory.

Closing the remaining gap means dissectors writing flat records directly
through a builder on `Ctx` (`ctx.leaf(...)`, `ctx.begin(...)`/`ctx.end()`),
which removes both the intermediate tree and the flatten pass — together about
45% of the current cost. That changes the dissector signature from
`-> Result<Node>` to `-> Result<()>`, and the brief fixes that signature as
`(&[u8], &mut Ctx) -> Result<Node, DissectError>`. Changing a stated
non-negotiable is the owner's call, so the measurement is reported here and
the rewrite has not been taken unilaterally.

Benchmarks are sensitive to machine load: the same binary measures 132-144k
frames/s while sixteen fuzz targets are running. The figures above are from an
otherwise idle machine, which is the number to compare against the target.

### Reassembled data is a second data source

Node ranges index a data source; source 0 is the captured frame and
reassembly registers further sources. The IPv4 reassembly node and every
node dissected from the reassembled datagram carry `source = 1`, the hex pane
shows a tab per source, and highlighting stays exact. The alternative — a
"virtual" range space — would have broken the byte-range invariant the hex
pane and filter engine rely on.

### DNS compression: strictly backward pointers plus a hop cap

A pointer must target an offset before the pointer itself. That alone makes
loops impossible (the offset decreases monotonically); a hop limit of 32 is
kept as a second guard. Forward pointers are rejected as malformed, which
matches how the major resolvers behave and what RFC 1035 §4.1.4 ("a prior
occurrence") describes.

### Checksums are verified and reported, never used to reject

IPv4/ICMP/ICMPv6/TCP/UDP checksums are computed and shown as Good/Bad/
Unverified (truncated segments and ICMP-quoted headers are Unverified). On the
capturing host, offload makes outgoing checksums wrong before the NIC fixes
them, so Bad is informational; the Phase 4 expert flag will be a preference.

### Layer nodes cover their header, not their payload

A protocol layer's range is the bytes that layer decodes: `tcp` covers its
header, and the payload appears as the next layer (`http`, `tls`, `data`)
which is a sibling, not a child. Selecting the TCP row therefore highlights
the TCP header rather than the whole segment. The consequence is that
`tcp.payload` and `udp.payload` are filter-only fields with no tree row of
their own; Phase 3 derives their bytes from the layer's extent. Bytes that no
layer claimed (Ethernet padding, an 802.3 trailer) are accounted for once by
the driver, which is the only place that sees the whole frame.

An invariant test enforces the resulting structure over every fixture frame,
every truncation of every fixture frame, and single-byte corruptions at every
offset of the first frames: a node's range lies inside its data source, and a
child's range lies inside its parent's when they share a source. Writing that
test found four places where a node hung off a layer whose range did not cover
it (ARP and IPv4 padding, the IPv4 fragment note, UDP/TCP payload markers) and
one where a DNS section did not extend over a trailing malformed record.

### One dissection worker, numbering before dissection

Frame numbers are assigned by the thread that dequeues from the capture
channel, so parallel dissection (when it comes) cannot reorder them. IPv4
reassembly state lives in that worker; parallelising later means sharding
by flow, which the `FragKey` already supports.

### Fuzzing found an integer-overflow class the tests did not

`cargo-fuzz` builds with debug assertions on, so arithmetic that silently
wraps in release panics under the fuzzer. It found `len * 8` and `len + 2`
computed on `u8` values read straight from the packet (ICMPv6 option length,
IPv6 option length) — a length byte above 31 was enough. Those are now widened
before the arithmetic. The lesson is kept as a rule: any value read from a
packet is widened to `usize`/`u64` before it takes part in arithmetic, even
when the result is only used to format a label.
