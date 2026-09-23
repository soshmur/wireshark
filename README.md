# netscope

A cross-platform packet capture and protocol analysis application, written from
scratch in Rust. Hand-written dissectors, a Wireshark-style display filter
language, TCP stream reassembly, and pcap/pcapng read/write — all in a single
native binary with an immediate-mode UI.

> **Capture only on networks and hosts you own or are authorised to monitor.**
> Intercepting other people's traffic without permission is illegal in most
> jurisdictions. netscope shows this notice on first launch and will not
> capture until it is acknowledged.

## Status

| Phase | Scope | State |
|---|---|---|
| 0 | Device enumeration, privilege preflight, capture thread skeleton, window | done |
| 1 | Packet list, hex/ASCII pane, ring buffer, BPF capture filter | done |
| 2 | Dissectors: Ethernet … TLS, IPv4 reassembly, detail tree, fuzz targets | done |
| 3 | Display filter language, filter bar, colour rules, find | done |
| 4 | Conversations, TCP/UDP reassembly, Follow Stream, expert info | — |
| 5 | pcap/pcapng I/O, statistics | — |

Dissection runs at 538-559k frames/s on one core for the Ethernet/IPv4/TCP
path; see [DECISIONS.md](DECISIONS.md) for the measurements.

## Building

Requires stable Rust (2021 edition) and a libpcap implementation.

### Windows

1. Install [Npcap](https://npcap.com) (any install mode; WinPcap-compatible
   mode is not required — netscope adds `System32\Npcap` to its DLL search path).
2. Unpack the [Npcap SDK](https://npcap.com/#download) to `C:\npcap-sdk`, or
   point `NPCAP_SDK_LIB` at the directory containing `wpcap.lib`.
3. MSVC Build Tools with the C++ workload (for the linker).
4. `cargo run --release`

If Npcap was installed with *"Restrict Npcap driver's access to Administrators
only"*, run netscope elevated.

### Linux

```sh
sudo apt install libpcap-dev          # or the equivalent for your distribution
cargo build --release
sudo setcap cap_net_raw,cap_net_admin+eip target/release/netscope
target/release/netscope
```

### macOS

libpcap ships with the OS. Capture needs read/write access to `/dev/bpf*`:
either run with `sudo`, or install Wireshark's *ChmodBPF* helper which grants
the `access_bpf` group access.

```sh
cargo run --release
```

## Running the demo

```sh
cargo run --release
```

Pick an interface in the Interfaces window (double-click starts), and frames
appear in the packet list as they arrive. Click a row (or use the arrow keys,
PageUp/PageDown, Home/End) to see its dissection in the detail tree and its
bytes in the hex pane. Selecting a tree node highlights its bytes; clicking a
byte selects the innermost node covering it; Enter expands or collapses the
selected node, and the arrow keys move within whichever pane was clicked last.
Reassembled IPv4 datagrams appear as a second tab in the hex pane. *View > Time
display* switches between absolute (UTC), seconds since capture start, and
delta from the previous packet. *Capture > Options* sets the snapshot length
and the ring-buffer limits (default 1,000,000 frames or 2 GB, whichever first).
The BPF field is a libpcap *capture* filter, applied in the driver. The
separate **Display filter** bar below it selects among the frames already
captured — see below.

The status bar shows frames held, evictions, memory, capture rate, drops at
each stage (channel / driver / interface) and the UI frame time.

## Display filters

The bar above the packet list takes a display filter and narrows the list to
the frames that match. It is evaluated against the stored dissection: nothing
is re-dissected when a filter changes, so filtering a million frames costs one
pass over their trees and no parsing at all.

The bar tints as you type â green for the filter in force, amber for one that
compiles but has not been applied yet, red for one that does not compile, with
the message and the column it points at underneath. **Ctrl+K** focuses it,
**Enter** applies, **Escape** clears. Field names complete from the same
registry the detail tree renders from, with Tab or the arrow keys to accept.

### Grammar

```
tcp                            # the protocol is present
tcp.port                       # the field is present
tcp.port == 443                # == != > >= < <=
http.host contains "example"   # substring, on strings and byte fields
http.host matches "^api\."     # regular expression
ip.proto in {1, 6, 17}         # set membership
eth.src[0:3] == aa:bb:cc       # byte slice: offset and length
eth.src[5] == 0x0a             # single byte
tcp.flags.syn == true && !tcp.flags.ack
(dns || dhcp) && ip.addr == 10.0.0.0/8
```

`!` binds tighter than `&&`, which binds tighter than `||`; parentheses
override. Literals may be decimal, hex (`0x1f`), a quoted string, an IPv4
address, an IPv4 CIDR prefix, an IPv6 address, or a MAC/byte sequence
(`aa:bb:cc`). Enumerated fields accept either the number or the name
(`arp.opcode == "reply"`). Comparing a CIDR prefix matches the prefix:
`ip.addr == 10.0.0.0/8` selects the whole block.

A field that occurs more than once in a frame â `ip.addr` in a tunnelled
packet, `dns.a` in a multi-answer response â matches if **any** occurrence
matches, as Wireshark does. `ip.addr != 10.0.0.1` therefore means "some
address is not 10.0.0.1", not "no address is"; write `!(ip.addr == 10.0.0.1)`
for that.

Type errors are reported when the filter is compiled, not when it is
evaluated, so `tcp.port == "http"` fails immediately with the column of the
literal and the kinds that would have been accepted.

### Colour rules

*View > Colouring rulesâ¦* edits the list of rules the packet list is coloured
by. Each rule is a display filter with a foreground and a background colour,
and the first enabled rule that matches a frame colours its row â so the list
is a priority order, with "Malformed" and "Bad checksum" above the protocol
rules. A rule that does not compile shows its error in the editor and is
skipped. Rules persist to the config file. *View > Colourise packet list*
turns the whole thing off.

### Find

**Ctrl+F** opens the find bar, which moves the selection through the
*displayed* rows rather than changing what is displayed. The needle can be a
display filter, a string, or a hex byte sequence (`08:00`, `0800` and
`08 00` are the same), and string and hex searches take a scope: the packet
list columns, the detail tree labels, or the raw bytes. **Enter** or **F3**
finds the next match, **Shift+Enter** or **Shift+F3** the previous, and the
search wraps. **Escape** closes the bar.

Developer aids:

```sh
cargo run --release -- --synthetic 1000000                   # 1e6 generated rows, no network
cargo run --release --example capture_smoke -- "Wi-Fi" 5     # headless pipeline check
cargo run --release --example read_pcapng -- tests/fixtures/dns.pcapng   # dissect a file
cargo run --release --example bench_dissect                  # dissector throughput
cargo run --release --example bench_store                    # dissect+store throughput
cargo run --release --example filter_probe -- dns "dns.qry.name contains \"example\""  # try a filter on a fixture
NETSCOPE_REGEN=1 cargo test --test fixtures                  # regenerate fixture captures
cargo insta review                                           # review dissection snapshots
cd fuzz && cargo +nightly fuzz run tcp -- -max_total_time=60   # fuzz one dissector
powershell fuzz/run_all.ps1 -Seconds 60                       # fuzz every target
```

Fuzzing needs the nightly toolchain, `cargo-fuzz`, and the MSVC ASan runtime
(`clang_rt.asan_dynamic-x86_64.dll`) on `PATH`; `fuzz/run_all.ps1` finds it.

Protocols: Ethernet II / 802.3, 802.1Q (incl. QinQ), LLC/SNAP, ARP, IPv4 with
options and fragment reassembly, IPv6 with hop-by-hop / destination / routing /
fragment headers, ICMPv4 (incl. quoted headers), ICMPv6 with NDP, UDP, TCP with
MSS / window scale / SACK / timestamps, DNS with compression, DHCP, HTTP/1.x,
TLS record layer with ClientHello / ServerHello (SNI, ALPN, versions, cipher
suites). Malformed input yields a `[Malformed Packet]` node; nothing panics.

## Architecture

Three decoupled stages, each on its own thread(s):

1. **Capture** — the libpcap loop only. Pushes `RawFrame { ts, caplen,
   orig_len, bytes }` into a bounded channel. If the channel is full the frame
   is dropped and counted; the capture thread never blocks on a consumer.
2. **Dissection** — workers parse frames into a tree and append to the store.
3. **UI** — renders from an immutable snapshot; never parses, never blocks.

`unsafe` is confined to the `netscope-ffi` crate. The application crate is
`#![forbid(unsafe_code)]`.

See [DECISIONS.md](DECISIONS.md) for the reasoning behind non-obvious choices.

## License

MIT
