#![no_main]

use libfuzzer_sys::fuzz_target;
use memcordon_core::sealed_provider::envelope;

fuzz_target!(|data: &[u8]| {
    if let Ok(status) = std::str::from_utf8(data)
        && let Ok(parsed) = envelope::parse_proc_status(status)
    {
        let with_unrelated_field = format!("{status}\nName:\tprovider-fuzz\n");
        assert_eq!(
            envelope::parse_proc_status(&with_unrelated_field),
            Ok(parsed)
        );
        for field in [
            "Uid:",
            "Gid:",
            "Groups:",
            "NoNewPrivs:",
            "CapInh:",
            "CapPrm:",
            "CapEff:",
            "CapBnd:",
            "CapAmb:",
        ] {
            let missing = status
                .lines()
                .filter(|line| !line.starts_with(field))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(envelope::parse_proc_status(&missing).is_err());
        }
    }
});
