#![no_main]
use libfuzzer_sys::fuzz_target;

// A savefile is untrusted input. Every length in it is attacker-controlled,
// and the only acceptable outcomes are a parsed file or a named error.
fuzz_target!(|data: &[u8]| {
    match netscope::pcap::read(data) {
        Ok(file) => {
            for f in &file.frames {
                // What the reader returns has to be internally consistent, or
                // the dissector downstream reads bytes the file did not
                // describe.
                assert_eq!(f.bytes.len(), f.caplen as usize);
                assert!(f.caplen <= f.orig_len || f.orig_len == 0);
                assert!(f.ts.nanos < 1_000_000_000);
            }
            // A truncation point must be inside the file it describes.
            if let Some(at) = file.truncated_at {
                assert!(at <= data.len());
            }
        }
        Err(_) => {}
    }
    // Sniffing must agree with reading: anything read successfully as pcap
    // must have been identified as pcap, or the file dialog would pick the
    // wrong parser.
    if netscope::pcap::read(data).is_ok() {
        assert_eq!(netscope::pcap::sniff(data), netscope::pcap::Format::Pcap);
    }
});
