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

Dissection runs at 538-559k frames/s on one core for the Ethernet/IPv4/TCP
path; see [DECISIONS.md](DECISIONS.md) for the measurements.
| 3 | Display filter language | — |
| 4 | Conversations, reassembly, expert info | — |
| 5 | pcap/pcapng I/O, statistics | — |

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
The BPF field is a libpcap *capture* filter, applied in the driver — not a
display filter (Phase 3).

The status bar shows frames held, evictions, memory, capture rate, drops at
each stage (channel / driver / interface) and the UI frame time.

Developer aids:

```sh
cargo run --release -- --synthetic 1000000                   # 1e6 generated rows, no network
cargo run --release --example capture_smoke -- "Wi-Fi" 5     # headless pipeline check
cargo run --release --example read_pcapng -- tests/fixtures/dns.pcapng   # dissect a file
cargo run --release --example bench_dissect                  # dissector throughput
cargo run --release --example bench_store                    # dissect+store throughput
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
