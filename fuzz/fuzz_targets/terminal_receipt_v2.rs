#![no_main]

use libfuzzer_sys::fuzz_target;
use memcordon_core::sealed_provider::terminal::parse_terminal;

fuzz_target!(|data: &[u8]| {
    if let Ok(receipt) = parse_terminal(data) {
        let text = std::str::from_utf8(data).expect("accepted receipt is UTF-8");
        let mut lines = text.lines().collect::<Vec<_>>();
        lines.reverse();
        let reordered = format!("{}\n", lines.join("\n"));
        assert_eq!(parse_terminal(reordered.as_bytes()), Ok(receipt));
        let duplicate = format!("{text}schema-version=2\n");
        assert!(parse_terminal(duplicate.as_bytes()).is_err());
        let unknown = format!("{text}unreviewed-authority=true\n");
        assert!(parse_terminal(unknown.as_bytes()).is_err());
        assert!(parse_terminal(text.trim_end_matches('\n').as_bytes()).is_err());
    }
});
