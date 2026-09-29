#![no_main]
use libfuzzer_sys::fuzz_target;

// The whole file-open path: sniffing, both parsers, and the loader glue that
// turns either into interfaces plus packets. A capture file is untrusted
// input, and this is the entry point a user points at one.
fuzz_target!(|data: &[u8]| {
    let Ok(loaded) = netscope::capture::file::load(data) else {
        return;
    };
    // A packet must name an interface that exists, or dissecting it would
    // pick a link type from nowhere.
    for (iface, frame) in &loaded.packets {
        assert!(
            *iface < loaded.interfaces.len().max(1),
            "packet names interface {iface} of {}",
            loaded.interfaces.len()
        );
        assert_eq!(frame.bytes.len(), frame.caplen as usize);
        assert!(frame.ts.nanos < 1_000_000_000);
    }
    // Dissecting must not panic on anything that loaded, and re-encoding
    // what was read must itself be readable: a file netscope writes is a
    // file netscope can open.
    let frames = loaded.dissect_all(netscope::dissect::Options::no_checksums());
    for format in [
        netscope::capture::file::SaveFormat::Pcapng,
        netscope::capture::file::SaveFormat::Pcap,
    ] {
        if let Ok((bytes, saved)) = netscope::capture::file::encode(&frames, format) {
            let back = netscope::capture::file::load(&bytes)
                .expect("netscope must be able to read what it wrote");
            assert_eq!(back.packets.len(), saved.frames);
        }
    }
});
