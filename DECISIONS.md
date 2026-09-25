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

### The tree is flat

A frame's tree is one array of 28-byte records plus a byte arena for strings,
written depth-first as the dissectors run. A TCP frame has ~65 nodes; as a
pointer tree at 104 bytes per node plus a heap allocation per child vector
that was 8.5 KB and hundreds of allocations per frame, which paged the machine
at 1e6 frames. Flat: ~1.9 KB per frame, two allocations. Structure (children,
ancestors, subtree extent) is recovered from each node's `depth`, which is
cheap for a tree that is only ever walked top-down.

### Dissectors write flat records; measured throughput

Ethernet/IPv4/TCP path, single thread, release, idle machine: **538-559k
frames/s** (1.79-1.86 µs/frame) for a 65-node tree, at 3.0 KB accounted per
frame. Through the store as well (dissect + append): 366k frames/s. The target
was 500k/s/core.

Getting there needed the dissector signature to change from
`(&[u8], &mut Ctx) -> Result<Node, DissectError>`, which the brief fixed, to
`-> Result<(), DissectError>` with the tree written through `ctx.begin`,
`ctx.leaf` and `ctx.end`. That was the owner's decision, taken explicitly
rather than assumed: the intermediate pointer tree and the pass that flattened
it were together about 45% of the cost, and no amount of tuning inside the old
shape reaches the target.

The route from 219k to 545k, each step measured:

| change | frames/s |
|---|---|
| returning a `Node` tree, flattened afterwards | 219-227k |
| dissectors write flat records directly | 372-413k |
| summary addresses kept typed, formatted only when drawn | 442k |
| label text formatted into the arena, no `String` | 468k |
| flag names joined in a stack buffer, not a `Vec` | 538-559k |

Two smaller wins came earlier: checksum status became a numeric enum field
rather than an allocated `String` (five allocations per frame), and the
field-id index uses FNV-1a with a memo keyed on the `&'static str` pointer,
taking a lookup from 47 ns to 2.3 ns. The keys are compile-time literals and
not attacker-controlled, so a weak hash is appropriate; the memo is verified
by pointer equality, so a collision is a miss, never a wrong answer.

What remains, for reference: writing the 65 nodes costs ~670 ns, `Ctx::new`
~64 ns (it allocates the builder's two buffers), and the dissectors' own
parsing the rest. Benchmarks are sensitive to machine load — the same binary
measures 132-144k while sixteen fuzz targets are running — so the figures
above are from an otherwise idle machine.

### Builder discipline: depth is restored centrally

A dissector may return `Err` from inside one or more open containers. Rather
than unwinding by hand at every `?`, the caller records `ctx.depth()` before
the call and restores it on error: the driver does this per layer, and option
loops do it per option. The partial subtree is kept, and the layer's own range
is fitted to the fields it did parse (`TreeBuilder::fit_range`), so a
truncated IPv6 header now shows its addresses rather than vanishing.

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

### Live traffic found what neither tests nor fuzzing did

Running the capture against a real Wi-Fi interface surfaced 2.7 KB and 9.4 KB
"frames" carrying `ip.len = 0` and a zero header checksum. These are TCP
segmentation offload: the NIC splits the buffer and fills both fields in per
segment, after libpcap has already seen the packet. The dissector derived a
zero-length payload from the zero total length, handed TCP nothing, and
reported `[Malformed Packet: tcp]`.

Neither the fixtures nor the fuzzers would have found it. The fixtures were
built from the specification, where total length is never zero; the fuzzers
did generate zero-length frames, but a zero total length only *looks* wrong
in the absence of knowledge about offload — nothing crashed, so nothing was
reported. It took traffic from a real NIC on a real host.

The rule taken from it: every phase gets a live run against real traffic, and
any frame carrying a `[Malformed]` node is triaged rather than assumed to be
genuinely malformed. `examples/find_malformed.rs` exists for exactly that.

## Phase 3 — the display filter language

### The filter reads the stored tree; it never re-dissects

A display filter is compiled to a `Test` tree and evaluated against the
`Node` records already in the store. Every node carries the byte range it was
decoded from, which is what makes this possible: a field comparison is a walk
to the matching nodes and a read of their bytes, not a re-parse of the frame.
`View::filtered` therefore holds the very same `Arc<Frame>`s the store does,
which `store::view::filtering_does_not_redissect` asserts by pointer
identity rather than by value, because value equality would still pass if the
frames had been rebuilt.

The alternative â re-running the dissectors under the filter, the way a
capture-time filter must â would make every keystroke in the filter bar cost
a full pass over the capture, and would mean a filter could disagree with the
detail tree the user is looking at.

### Repeated fields match if any occurrence matches

`ip.addr` in a tunnelled packet, `dns.a` in a multi-answer response and
`tcp.option.kind` in almost any segment all occur more than once in a frame.
A comparison against such a field succeeds if **any** occurrence satisfies
it, which is what Wireshark does.

This is worth stating plainly because it makes `!=` asymmetric with `==` in
a way that surprises people: `ip.addr != 10.0.0.1` reads as "no address is
10.0.0.1" and means "some address is not 10.0.0.1", which is true of almost
every packet. Matching Wireshark was chosen over being locally more logical,
because a filter language whose operators read the same but mean something
different from the tool everyone already knows is worse than one with a
documented quirk. The quirk is documented in the README, with `!(ip.addr ==
10.0.0.1)` given as the way to say the other thing.

### One registry entry can stand for several fields

`ip.addr`, `ipv6.addr`, `eth.addr`, `arp.addr`, `tcp.port` and `udp.port`
have no nodes of their own â no dissector ever writes one. They are registry
entries carrying `members: &["ip.src", "ip.dst"]`, and the type checker
resolves them to the set of real field ids before the evaluator ever runs.

Keeping them in the registry rather than special-casing them in the compiler
preserves the rule that the registry is the only place field knowledge lives:
they complete in the filter bar, they report their kind in a type error, and
`every_registered_field_can_be_compiled` covers them like anything else.

### `contains` on a protocol searches its payload, not its header

Layer nodes cover their own header only â `tcp` is 20 bytes plus options, not
the segment. That is right for the hex pane and for `tcp.len`, but it makes
`tcp contains "GET"` find nothing, which is not what anyone typing it means.

So when the target is a protocol and no slice is given, the evaluator searches
from the layer's start to the end of its data source: header and everything
after it, in whichever buffer that layer was dissected from. A slice on a
protocol still reads the header, because `ip[0:1]` is asking about the header
by construction.

### `matches` uses the `regex` crate

The `regex` crate is the one dependency in the project that parses something
on behalf of a user. It was allowed deliberately: writing a regex engine is
not what this project is about, the crate has no backtracking and so no
catastrophic-blowup class of failure on hostile patterns, and a pattern that
does not compile is reported with the same column-carrying error type as the
rest of the language rather than as a panic. Patterns are compiled once at
filter-compile time and reused for every frame.

The ban on parsing crates in the brief is about protocol dissection, which
remains entirely hand-written.

### Type errors are reported when the filter compiles

`tcp.port == "http"` fails at compile time with the column of the literal and
the kinds that would have been accepted, not at evaluation time on frame
600,000. This is the reason the pipeline has a distinct type-check pass
between the AST and the evaluator at all: the evaluator is total, every
`Test` it can be handed is one whose operand kinds already agree, and it has
no error path to take in the middle of a pass over a million frames.

### Colour rules are display filters, and nothing else

A colour rule is a `(name, display filter, background, foreground)` tuple,
and the first enabled rule that matches a frame colours its row. There is no
separate matching language, no protocol-name special case and no hard-coded
list: `defaults()` in `src/app/colour_rules.rs` is twelve strings that go
through the same lexer, parser, type checker and evaluator as anything typed
into the filter bar.

That is what makes them worth having in Phase 3 rather than Phase 1. It also
means a rule that does not compile is a first-class, reportable state: the
editor shows the message and the column beneath the offending rule, and
`Rules::matching` skips it rather than failing the frame, so one bad rule
does not stop the other eleven colouring.

Ordering is the whole design. Most frames match several rules — a DNS query
is also UDP, also IP, also Ethernet — so the rule list is a priority list
read top to bottom, and "Bad checksum" sits above the protocol rules
precisely so a broken packet does not hide behind being TCP. The tests in
`tests/filter.rs` assert *which* rule claims each frame of each fixture, not
merely that one does, because the ordering is the part that can silently
regress.

A selected row keeps the selection highlight instead of its rule colour.
Painting both would mean the user cannot tell what is selected, and the
selection is the more urgent piece of information.

### Writing the colour rules found a third fixture bug

The rules were run over the checked-in fixtures to see which claimed what,
and the first DNS frame came back "Bad checksum". The query frame was built
with `eth_ipv4`, which writes an `IP_A -> IP_B` header, while its UDP
checksum had been computed over a pseudo-header addressed to the resolver at
192.168.1.1. The checksum was correct for a datagram the frame did not
contain.

This is the same class as the ICMP fixture bug found while writing the filter
expectations: a hand-built fixture that is internally inconsistent in a way
no dissector can object to, because each field is individually well-formed.
The general lesson is that a new way of *reading* the fixtures is also a new
way of checking them, and is worth running over the whole corpus once as soon
as it works.

### Find moves the selection; it does not change what is displayed

Ctrl+F searches the *displayed* rows, not the store. A find that would hit a
frame the current display filter hides simply does not hit. The alternative —
having find search the whole capture and silently widen the filter to reveal
its answer — would make two independent controls fight over one list, and
leave the user unsure which of the two produced what they are looking at.

Find takes three kinds of needle, each reusing machinery that already exists:
a display filter (the Phase 3 compiler and evaluator, unchanged), a string,
or a hex byte sequence. String and hex searches take an explicit scope —
packet list, packet details, or packet bytes — because the three differ by
orders of magnitude in cost. Searching details formats every node label of
every frame scanned; making that an explicit choice is more honest than
silently searching everything and being slow.

A string searched in packet bytes is matched as its own bytes. Packet
payloads are not text, and transcoding a needle into some guessed encoding
before comparing would produce matches the user cannot account for.

The search wraps, so repeating it cycles through every hit and always finds
one if one exists. The backward walk is biased by the row count rather than
subtracting towards zero, because the obvious `r - 1` underflows at row zero —
the same class of bug fuzzing found in the dissectors, and the reason the
wrap-around cases are pinned by tests rather than reasoned about once.

### Fuzzing the filter language found two crashes the tests did not

Two targets were added for Phase 3: `filter`, which compiles arbitrary text
and asserts the reported error column stays inside the input, and
`filter_eval`, which runs a compiled filter over an arbitrary frame. Both
crashed within seconds.

**Non-ASCII text panicked the completer.** `word_at` walked back to the start
of the word under the caret with `rfind(...).map_or(0, |i| i + 1)`. For an
ASCII separator that is the next character; for a multi-byte one such as `é`
it is a byte *inside* the separator, and slicing there panics. Typing an
accented character into the filter bar would have taken the whole UI down.
Both ends of the slice are now kept on character boundaries: the caret is
clamped down to one, and the word start steps back by the separator's own
`len_utf8`.

**Deep nesting overflowed the stack.** `!!!!…tcp` and `((((…tcp…))))` recurse
once per level in the parser, and the resulting tree is then walked
recursively by the type checker, the evaluator and `Drop`. Nesting is now
capped at 64 levels and refused as an ordinary `FilterError` with a column,
which is what a user pasting something strange should get.

The cap alone was not enough, because `a || b || c || …` built a *left-leaning
chain* whose depth grows with the operand count while the parser's own
recursion stays flat — so a long chain could still overflow the later walks.
`And` and `Or` now hold `Vec<Expr>` rather than two boxed operands: a chain of
the same operator is one flat node, nesting depth reflects only genuine
nesting, and the evaluator becomes `all`/`any` over a slice. A 500-operand
chain now parses and evaluates without recursing at all.

This is the second time a class of bug has been found by fuzzing that the
expectation suite could not have reached: 173 hand-written filter expectations
all use sensible filters, because a person writing expectations writes filters
they can predict the answer to.

| Target | Runs (120s) | Edges | Result |
|---|---|---|---|
| `filter` | 150,013 | 1,104 | no crash |
| `filter_eval` | 1,468,860 | 1,146 | no crash |

Before the fixes both targets died in seconds, at 571 and 829 edges; the
coverage roughly doubled once they could run to completion.

### The field-id memo was keyed on where the linker happened to put things

Phase 3 measured ~3% slower at dissection than Phase 2 â 539k frames/s against
556k, ten alternating runs of the two builds all in the same direction, so not
thermal drift and not run order. The only change under `src/dissect` was
`FieldDef` gaining a `members` slice and five alias entries, none of which the
dissectors touch.

The cause was the memo in front of `field_id`. It is direct-mapped on
`(ptr >> 3) & 511`, which was fine in isolation: abbrevs are `&'static str`
literals, so the same field is the same pointer. But literals sit packed and
roughly contiguous in `.rodata`, so shifting by three maps whole
neighbourhoods of abbrevs onto the same slots, and *which* of the 65 hot
fields in a frame collide is then decided by link order. Adding five strings
reshuffled it into a worse arrangement.

`memo_slot` now multiplies the pointer by a 64-bit odd constant and takes
high bits, which mixes the whole address instead of one byte-range of it.
Dissection went to 561-577k frames/s, at or slightly above the Phase 2
figures on the same machine in the same session, and the whole-frame
microbenchmark from 1925 ns to 1766 ns.

The lesson is not about the constant. It is that a cache keyed on an address
has a hit rate decided by the linker, so it will drift for reasons that have
nothing to do with the change in front of you. Measuring the old commit and
the new one alternately, on the same machine in the same session, is what
separated a real 3% from the 460k-540k spread the same binary produces
depending on how warm the machine is.

Reported honestly: the 538-559k figure quoted at the end of Phase 2 is a
burst number. Sustained over repeated runs on a warm machine this laptop
gives roughly 460-540k for that build. The target in the brief is 500k
frames/s/core, and on the current build the same measurement gives 541-577k.

### Checksum validation ships off, and changing it dissects again

Running the filter engine against live Wi-Fi showed the default "Bad
checksum" colour rule claiming 20-47% of every capture. The breakdown was
consistent across runs: zero bad IPv4 header checksums, but 62-89 bad TCP and
30-75 bad UDP. That is checksum offload. The NIC computes the transport
checksums, which cover a pseudo-header, after libpcap has already seen the
packet; the IPv4 header checksum is done in software and is therefore right.
The rule was working correctly and the packets were fine.

Four options were on the table and the choice was made explicitly: netscope
now has two preferences, "Validate IPv4 header and ICMPv4 checksums" and
"Validate TCP, UDP and ICMPv6 checksums", both **off by default**, as
Wireshark ships. With them off the status reports `Unverified` rather than a
verdict, which is the honest answer: we did not check.

This does not undo the Phase 2 decision that checksums are never used to
reject a packet. `Options` alters what a dissector *reports*, never which
bytes it parses or how the layers nest, and a test asserts exactly that over
every fixture frame.

(Amended in Phase 4: that test originally compared whole trees node for node.
Once a verified-bad checksum began raising an expert finding, the two trees
legitimately differ — a finding is a node. The comparison now covers every
node that is not part of an expert record, and separately asserts that no
checksum finding is raised while validation is off.)

The library default is the opposite of the application default. `dissect()`
verifies; `netscope` passes `Options::no_checksums()`. A caller who has not
thought about offload is better served by being told a packet looks wrong
than by silence, and it keeps every fixture and snapshot exercising the
verification code.

**Changing the setting re-dissects what is already stored.** Filtering never
re-dissects, but a dissection preference is the case that must: the stored
trees are what the detail pane, the filter engine and the colour rules all
read, so leaving them would display verdicts the settings say were never
made. It costs one pass at dissection speed, about two seconds per million
frames, and is only reachable while not capturing.

That needed `Store::replace`. The obvious `clear` then `append` is wrong:
`clear` resets the numbering to 1 and `append` renumbers to match, so a store
that had evicted its first chunks would come back numbered from 1 claiming
nothing had ever been evicted. `replace` keeps the numbering, the start
timestamp and the eviction counters, and a test drives it through an actual
eviction rather than trusting the reasoning.

## Phase 4 — conversations, analysis and desegmentation

### The benchmark had stopped measuring what it was named after

Wiring desegmentation in dropped dissection from ~565k frames/s to ~395k, a
third gone, and below the 500k the brief asks for. The obvious suspects were
the new per-frame work: a conversation lookup, the sequence analyser, and a
check for pending bytes.

Switching those maps from SipHash to the FNV hasher already in the registry,
and folding the lookup and the analysis into one hash of the 5-tuple, bought
back only about 15k. The cause was elsewhere.

`synthetic::raw_frame` varied the source address *and* the source port with
the frame index, so a million generated frames opened a million connections.
That was harmless while nothing tracked conversations. Once something did,
the benchmark was measuring the worst case for a conversation table — an
insert every frame, a hit never — under the name of the dissection path.

The generator now spreads frames over 64 flows with sequence numbers that
follow from the bytes each flow has already sent, which is what traffic looks
like. Dissection measures 509-541k frames/s: above the target, and about 5%
below the pre-Phase-4 figure, which is the honest cost of the lookup, the
analyser and one extra node per frame.

The lesson is that a benchmark encodes assumptions about its input, and those
assumptions expire. This one assumed nothing upstream cared how many distinct
5-tuples it emitted, and that silently stopped being true.

### Coherent generated traffic found a false positive

Giving each flow sequence numbers that follow from its payloads made it worth
asserting that generated traffic produces no expert findings at all. It
produced one: every one-byte segment was reported as a TCP keep-alive.

A keep-alive re-sends the last byte already sent, so it sits at
`next_seq - 1`. The check was comparing against `next_seq` *after* folding
the segment in, by which point an ordinary one-byte segment sits at exactly
`next_seq - 1` too. It now compares against what the direction expected
before the segment arrived.

Nothing in the hand-written fixtures would have caught it: they contain one
deliberate keep-alive and no other one-byte writes. It took traffic generated
by a rule rather than chosen by hand.

### Follow Stream reconstructs what was captured, not what was sent

The two are not the same, and the difference is the whole difficulty. A
retransmission contributes nothing, because the application received those
bytes once and a transcript showing them twice misrepresents the
conversation. An overlap keeps the bytes seen first and takes only what is
new. A hole nothing fills is reported and counted rather than closed up —
joining the bytes either side of a gap produces a stream the sender never
sent, and a stream with a hole in it must not look like a stream without one.

Those three are unit-tested directly rather than through fixtures, because a
fixture that exercises them is a fixture whose expectations are themselves
hard to be sure of. Writing the tests corrected one of my own: I asserted the
`tcp_analysis` fixture would report missing bytes, and it correctly reports
none, because both of its gaps are later filled — one by an out-of-order
segment and one by a fast retransmission.

### The conversations table keys on the stream id, not the five-tuple

Keying on addresses and ports alone looks obviously right and is wrong for
the same reason it was wrong in the stream table: ports are reused. The
fixture has two connections sharing a five-tuple exactly, and without the
stream id in the key they were added together into one row describing traffic
that never shared a conversation.

Both the table and Follow Stream are built on demand from a snapshot rather
than maintained incrementally by the dissection worker. Incremental totals
would disagree with the store as soon as the ring evicted anything, and a
statistics table that does not describe the frames the packet list is showing
is worse than no table at all.

### A count is not evidence

The live run reported TCP keep-alives on 34% of frames, which looked exactly
like the false positive found a few commits earlier. It was not: explaining
the frames showed one-byte ACK-only segments re-sending the last byte, from
long-lived push connections that send them every few seconds.

The distinction could not be drawn from the count, so `examples/live_filter`
gained `NETSCOPE_EXPLAIN`, which prints the first few matching frames field
by field, and two filters that settle this particular question by
construction: 61 one-byte segments, 56 called keep-alives and 5 not. Had the
heuristic been flagging every one-byte segment the second count would be
zero.

This is the second time a live run has produced a large number that needed
explaining rather than fixing — the first was checksum offload — and both
times the count alone pointed the wrong way.

### Phase 4 fuzzing, and a benchmark number that was the machine

Nineteen targets, 60 seconds each: **31,843,856 executions, no crashes, no
artifacts.** Coverage rose across the dissectors where Phase 4 added code —
`tcp` 599 to 896 edges, `http` 460 to 673, `tls` 662 to 740, `frame` 2,132 to
2,480 — which is the expected shape, since the new code is reached through
those paths.

One artifact appeared, a `slow-unit` in `pcapng`. Re-run on its own it
executes in 2 ms; it was recorded while nineteen targets had been running
back to back. It is now a corpus seed rather than a finding.

The run counts are not comparable to earlier sweeps. As corpora grow, more of
a fixed 60-second budget goes on replaying the corpus before fuzzing starts:
`filter` managed 150,013 runs in a standalone 120-second run and 8,456 in
this sweep's 60. That is worth knowing before reading a drop in runs as a
regression.

The benchmark taught the same lesson in a sharper form. Measured immediately
after the sweep, dissection came in at 142-166k frames/s against the 509-541k
recorded earlier the same day — a two-thirds drop, and exactly the shape of a
serious regression. It was not one. Building the *Phase 2* commit and
alternating the two showed it measuring 143-187k as well, against the
548-565k it had given that morning. The laptop was throttled, both builds
equally, and the comparison — which is the part that matters — showed Phase 4
level with Phase 2.

So: absolute throughput figures in this file are only meaningful against a
cool machine, and only comparable within one session. The method that
survives that is measuring the old commit and the new one alternately, in the
state the machine happens to be in.
