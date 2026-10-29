use super::LiteralRun;
pub(super) fn translate(command: &str, flavor: u8) -> Option<LiteralRun> {
    match (command, flavor) {
        (
            "./target/ci/release/memcordon-ci release prepare-readiness-tools --build-source .release/build-source.json",
            0 | 4,
        ) => Some(LiteralRun::R1725),
        (
            "./target/ci/release/memcordon-ci release prepare-readiness-tools --build-source .release/build-source.json",
            1 | 5,
        ) => Some(LiteralRun::R1726),
        (
            "./.release/rehearsal-tool/memcordon-release-rehearsal run --publisher .release/tool/memcordon-ci --input .release/rehearsal-input --report-dir .release/rehearsal-results --jobs 2",
            0,
        ) => Some(LiteralRun::R543),
        (
            "./.release/rehearsal-tool/memcordon-release-rehearsal run --publisher .release/tool/memcordon-ci --input .release/rehearsal-input --report-dir .release/rehearsal-results --jobs 2",
            1,
        ) => Some(LiteralRun::R543),
        (
            "./.release/rehearsal-tool/memcordon-release-rehearsal run --publisher .release/tool/memcordon-ci --input .release/rehearsal-input --report-dir .release/rehearsal-results --jobs 2",
            2,
        ) => Some(LiteralRun::R543),
        (
            "./.release/rehearsal-tool/memcordon-release-rehearsal run --publisher .release/tool/memcordon-ci --input .release/rehearsal-input --report-dir .release/rehearsal-results --jobs 2",
            3,
        ) => Some(LiteralRun::R543),
        (
            "./.release/rehearsal-tool/memcordon-release-rehearsal run --publisher .release/tool/memcordon-ci --input .release/rehearsal-input --report-dir .release/rehearsal-results --jobs 2",
            4,
        ) => Some(LiteralRun::R543),
        (
            "./.release/rehearsal-tool/memcordon-release-rehearsal run --publisher .release/tool/memcordon-ci --input .release/rehearsal-input --report-dir .release/rehearsal-results --jobs 2",
            5,
        ) => Some(LiteralRun::R543),
        ("./.release/tool/memcordon-ci ci bootstrap-cache-context", 0) => Some(LiteralRun::R332),
        ("./.release/tool/memcordon-ci ci bootstrap-cache-context", 1) => Some(LiteralRun::R332),
        ("./.release/tool/memcordon-ci ci bootstrap-cache-context", 2) => Some(LiteralRun::R332),
        ("./.release/tool/memcordon-ci ci bootstrap-cache-context", 3) => Some(LiteralRun::R332),
        ("./.release/tool/memcordon-ci ci bootstrap-cache-context", 4) => Some(LiteralRun::R332),
        ("./.release/tool/memcordon-ci ci bootstrap-cache-context", 5) => Some(LiteralRun::R332),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-audit --shard complete",
            0,
        ) => Some(LiteralRun::R369),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-audit --shard complete",
            1,
        ) => Some(LiteralRun::R369),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-audit --shard complete",
            2,
        ) => Some(LiteralRun::R369),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-audit --shard complete",
            3,
        ) => Some(LiteralRun::R369),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-audit --shard complete",
            4,
        ) => Some(LiteralRun::R369),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-audit --shard complete",
            5,
        ) => Some(LiteralRun::R369),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-audit --shard complete --for-save",
            0,
        ) => Some(LiteralRun::R378),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-audit --shard complete --for-save",
            1,
        ) => Some(LiteralRun::R378),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-audit --shard complete --for-save",
            2,
        ) => Some(LiteralRun::R378),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-audit --shard complete --for-save",
            3,
        ) => Some(LiteralRun::R378),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-audit --shard complete --for-save",
            4,
        ) => Some(LiteralRun::R378),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-audit --shard complete --for-save",
            5,
        ) => Some(LiteralRun::R378),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-deny --shard complete",
            0,
        ) => Some(LiteralRun::R371),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-deny --shard complete",
            1,
        ) => Some(LiteralRun::R371),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-deny --shard complete",
            2,
        ) => Some(LiteralRun::R371),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-deny --shard complete",
            3,
        ) => Some(LiteralRun::R371),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-deny --shard complete",
            4,
        ) => Some(LiteralRun::R371),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-deny --shard complete",
            5,
        ) => Some(LiteralRun::R371),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-deny --shard complete --for-save",
            0,
        ) => Some(LiteralRun::R379),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-deny --shard complete --for-save",
            1,
        ) => Some(LiteralRun::R379),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-deny --shard complete --for-save",
            2,
        ) => Some(LiteralRun::R379),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-deny --shard complete --for-save",
            3,
        ) => Some(LiteralRun::R379),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-deny --shard complete --for-save",
            4,
        ) => Some(LiteralRun::R379),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-deny --shard complete --for-save",
            5,
        ) => Some(LiteralRun::R379),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete",
            0,
        ) => Some(LiteralRun::R443),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete",
            1,
        ) => Some(LiteralRun::R443),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete",
            2,
        ) => Some(LiteralRun::R443),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete",
            3,
        ) => Some(LiteralRun::R443),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete",
            4,
        ) => Some(LiteralRun::R443),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete",
            5,
        ) => Some(LiteralRun::R443),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete --for-save",
            0,
        ) => Some(LiteralRun::R501),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete --for-save",
            1,
        ) => Some(LiteralRun::R501),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete --for-save",
            2,
        ) => Some(LiteralRun::R501),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete --for-save",
            3,
        ) => Some(LiteralRun::R501),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete --for-save",
            4,
        ) => Some(LiteralRun::R501),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete --for-save",
            5,
        ) => Some(LiteralRun::R501),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R452),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R452),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R452),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R452),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R452),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R452),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets --for-save",
            0,
        ) => Some(LiteralRun::R500),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets --for-save",
            1,
        ) => Some(LiteralRun::R500),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets --for-save",
            2,
        ) => Some(LiteralRun::R500),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets --for-save",
            3,
        ) => Some(LiteralRun::R500),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets --for-save",
            4,
        ) => Some(LiteralRun::R500),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets --for-save",
            5,
        ) => Some(LiteralRun::R500),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R449),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R449),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R449),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R449),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R449),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R449),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets --for-save",
            0,
        ) => Some(LiteralRun::R497),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets --for-save",
            1,
        ) => Some(LiteralRun::R497),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets --for-save",
            2,
        ) => Some(LiteralRun::R497),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets --for-save",
            3,
        ) => Some(LiteralRun::R497),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets --for-save",
            4,
        ) => Some(LiteralRun::R497),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets --for-save",
            5,
        ) => Some(LiteralRun::R497),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R450),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R450),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R450),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R450),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R450),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R450),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets --for-save",
            0,
        ) => Some(LiteralRun::R498),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets --for-save",
            1,
        ) => Some(LiteralRun::R498),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets --for-save",
            2,
        ) => Some(LiteralRun::R498),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets --for-save",
            3,
        ) => Some(LiteralRun::R498),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets --for-save",
            4,
        ) => Some(LiteralRun::R498),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets --for-save",
            5,
        ) => Some(LiteralRun::R498),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R451),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R451),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R451),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R451),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R451),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R451),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets --for-save",
            0,
        ) => Some(LiteralRun::R499),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets --for-save",
            1,
        ) => Some(LiteralRun::R499),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets --for-save",
            2,
        ) => Some(LiteralRun::R499),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets --for-save",
            3,
        ) => Some(LiteralRun::R499),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets --for-save",
            4,
        ) => Some(LiteralRun::R499),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets --for-save",
            5,
        ) => Some(LiteralRun::R499),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-four",
            0,
        ) => Some(LiteralRun::R401),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-four",
            1,
        ) => Some(LiteralRun::R401),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-four",
            2,
        ) => Some(LiteralRun::R401),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-four",
            3,
        ) => Some(LiteralRun::R401),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-four",
            4,
        ) => Some(LiteralRun::R401),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-four",
            5,
        ) => Some(LiteralRun::R401),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-four --for-save",
            0,
        ) => Some(LiteralRun::R433),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-four --for-save",
            1,
        ) => Some(LiteralRun::R433),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-four --for-save",
            2,
        ) => Some(LiteralRun::R433),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-four --for-save",
            3,
        ) => Some(LiteralRun::R433),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-four --for-save",
            4,
        ) => Some(LiteralRun::R433),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-four --for-save",
            5,
        ) => Some(LiteralRun::R433),
        ("./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-one", 0) => {
            Some(LiteralRun::R398)
        }
        ("./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-one", 1) => {
            Some(LiteralRun::R398)
        }
        ("./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-one", 2) => {
            Some(LiteralRun::R398)
        }
        ("./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-one", 3) => {
            Some(LiteralRun::R398)
        }
        ("./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-one", 4) => {
            Some(LiteralRun::R398)
        }
        ("./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-one", 5) => {
            Some(LiteralRun::R398)
        }
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-one --for-save",
            0,
        ) => Some(LiteralRun::R430),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-one --for-save",
            1,
        ) => Some(LiteralRun::R430),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-one --for-save",
            2,
        ) => Some(LiteralRun::R430),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-one --for-save",
            3,
        ) => Some(LiteralRun::R430),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-one --for-save",
            4,
        ) => Some(LiteralRun::R430),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-one --for-save",
            5,
        ) => Some(LiteralRun::R430),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-three",
            0,
        ) => Some(LiteralRun::R399),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-three",
            1,
        ) => Some(LiteralRun::R399),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-three",
            2,
        ) => Some(LiteralRun::R399),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-three",
            3,
        ) => Some(LiteralRun::R399),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-three",
            4,
        ) => Some(LiteralRun::R399),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-three",
            5,
        ) => Some(LiteralRun::R399),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-three --for-save",
            0,
        ) => Some(LiteralRun::R431),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-three --for-save",
            1,
        ) => Some(LiteralRun::R431),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-three --for-save",
            2,
        ) => Some(LiteralRun::R431),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-three --for-save",
            3,
        ) => Some(LiteralRun::R431),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-three --for-save",
            4,
        ) => Some(LiteralRun::R431),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-three --for-save",
            5,
        ) => Some(LiteralRun::R431),
        ("./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-two", 0) => {
            Some(LiteralRun::R400)
        }
        ("./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-two", 1) => {
            Some(LiteralRun::R400)
        }
        ("./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-two", 2) => {
            Some(LiteralRun::R400)
        }
        ("./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-two", 3) => {
            Some(LiteralRun::R400)
        }
        ("./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-two", 4) => {
            Some(LiteralRun::R400)
        }
        ("./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-two", 5) => {
            Some(LiteralRun::R400)
        }
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-two --for-save",
            0,
        ) => Some(LiteralRun::R432),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-two --for-save",
            1,
        ) => Some(LiteralRun::R432),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-two --for-save",
            2,
        ) => Some(LiteralRun::R432),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-two --for-save",
            3,
        ) => Some(LiteralRun::R432),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-two --for-save",
            4,
        ) => Some(LiteralRun::R432),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose miri --shard quarter-two --for-save",
            5,
        ) => Some(LiteralRun::R432),
        ("./.release/tool/memcordon-ci ci cache-context --purpose msrv --shard complete", 0) => {
            Some(LiteralRun::R356)
        }
        ("./.release/tool/memcordon-ci ci cache-context --purpose msrv --shard complete", 1) => {
            Some(LiteralRun::R356)
        }
        ("./.release/tool/memcordon-ci ci cache-context --purpose msrv --shard complete", 2) => {
            Some(LiteralRun::R356)
        }
        ("./.release/tool/memcordon-ci ci cache-context --purpose msrv --shard complete", 3) => {
            Some(LiteralRun::R356)
        }
        ("./.release/tool/memcordon-ci ci cache-context --purpose msrv --shard complete", 4) => {
            Some(LiteralRun::R356)
        }
        ("./.release/tool/memcordon-ci ci cache-context --purpose msrv --shard complete", 5) => {
            Some(LiteralRun::R356)
        }
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose msrv --shard complete --for-save",
            0,
        ) => Some(LiteralRun::R364),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose msrv --shard complete --for-save",
            1,
        ) => Some(LiteralRun::R364),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose msrv --shard complete --for-save",
            2,
        ) => Some(LiteralRun::R364),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose msrv --shard complete --for-save",
            3,
        ) => Some(LiteralRun::R364),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose msrv --shard complete --for-save",
            4,
        ) => Some(LiteralRun::R364),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose msrv --shard complete --for-save",
            5,
        ) => Some(LiteralRun::R364),
        ("./.release/tool/memcordon-ci ci cache-context --purpose quality --shard complete", 0) => {
            Some(LiteralRun::R345)
        }
        ("./.release/tool/memcordon-ci ci cache-context --purpose quality --shard complete", 1) => {
            Some(LiteralRun::R345)
        }
        ("./.release/tool/memcordon-ci ci cache-context --purpose quality --shard complete", 2) => {
            Some(LiteralRun::R345)
        }
        ("./.release/tool/memcordon-ci ci cache-context --purpose quality --shard complete", 3) => {
            Some(LiteralRun::R345)
        }
        ("./.release/tool/memcordon-ci ci cache-context --purpose quality --shard complete", 4) => {
            Some(LiteralRun::R345)
        }
        ("./.release/tool/memcordon-ci ci cache-context --purpose quality --shard complete", 5) => {
            Some(LiteralRun::R345)
        }
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose quality --shard complete --for-save",
            0,
        ) => Some(LiteralRun::R353),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose quality --shard complete --for-save",
            1,
        ) => Some(LiteralRun::R353),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose quality --shard complete --for-save",
            2,
        ) => Some(LiteralRun::R353),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose quality --shard complete --for-save",
            3,
        ) => Some(LiteralRun::R353),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose quality --shard complete --for-save",
            4,
        ) => Some(LiteralRun::R353),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose quality --shard complete --for-save",
            5,
        ) => Some(LiteralRun::R353),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose rehearsal-tool --shard complete",
            0,
        ) => Some(LiteralRun::R384),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose rehearsal-tool --shard complete",
            1,
        ) => Some(LiteralRun::R384),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose rehearsal-tool --shard complete",
            2,
        ) => Some(LiteralRun::R384),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose rehearsal-tool --shard complete",
            3,
        ) => Some(LiteralRun::R384),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose rehearsal-tool --shard complete",
            4,
        ) => Some(LiteralRun::R384),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose rehearsal-tool --shard complete",
            5,
        ) => Some(LiteralRun::R384),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose rehearsal-tool --shard complete --for-save",
            0,
        ) => Some(LiteralRun::R392),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose rehearsal-tool --shard complete --for-save",
            1,
        ) => Some(LiteralRun::R392),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose rehearsal-tool --shard complete --for-save",
            2,
        ) => Some(LiteralRun::R392),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose rehearsal-tool --shard complete --for-save",
            3,
        ) => Some(LiteralRun::R392),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose rehearsal-tool --shard complete --for-save",
            4,
        ) => Some(LiteralRun::R392),
        (
            "./.release/tool/memcordon-ci ci cache-context --purpose rehearsal-tool --shard complete --for-save",
            5,
        ) => Some(LiteralRun::R392),
        ("./.release/tool/memcordon-ci ci cache-context --purpose supply --shard complete", 0) => {
            Some(LiteralRun::R367)
        }
        ("./.release/tool/memcordon-ci ci cache-context --purpose supply --shard complete", 1) => {
            Some(LiteralRun::R367)
        }
        ("./.release/tool/memcordon-ci ci cache-context --purpose supply --shard complete", 2) => {
            Some(LiteralRun::R367)
        }
        ("./.release/tool/memcordon-ci ci cache-context --purpose supply --shard complete", 3) => {
            Some(LiteralRun::R367)
        }
        ("./.release/tool/memcordon-ci ci cache-context --purpose supply --shard complete", 4) => {
            Some(LiteralRun::R367)
        }
        ("./.release/tool/memcordon-ci ci cache-context --purpose supply --shard complete", 5) => {
            Some(LiteralRun::R367)
        }
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four --stage build",
            0,
        ) => Some(LiteralRun::R490),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four --stage build",
            1,
        ) => Some(LiteralRun::R490),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four --stage build",
            2,
        ) => Some(LiteralRun::R490),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four --stage build",
            3,
        ) => Some(LiteralRun::R490),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four --stage build",
            4,
        ) => Some(LiteralRun::R490),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four --stage build",
            5,
        ) => Some(LiteralRun::R490),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one --stage build",
            0,
        ) => Some(LiteralRun::R473),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one --stage build",
            1,
        ) => Some(LiteralRun::R473),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one --stage build",
            2,
        ) => Some(LiteralRun::R473),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one --stage build",
            3,
        ) => Some(LiteralRun::R473),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one --stage build",
            4,
        ) => Some(LiteralRun::R473),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one --stage build",
            5,
        ) => Some(LiteralRun::R473),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three --stage build",
            0,
        ) => Some(LiteralRun::R474),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three --stage build",
            1,
        ) => Some(LiteralRun::R474),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three --stage build",
            2,
        ) => Some(LiteralRun::R474),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three --stage build",
            3,
        ) => Some(LiteralRun::R474),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three --stage build",
            4,
        ) => Some(LiteralRun::R474),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three --stage build",
            5,
        ) => Some(LiteralRun::R474),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two --stage build",
            0,
        ) => Some(LiteralRun::R489),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two --stage build",
            1,
        ) => Some(LiteralRun::R489),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two --stage build",
            2,
        ) => Some(LiteralRun::R489),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two --stage build",
            3,
        ) => Some(LiteralRun::R489),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two --stage build",
            4,
        ) => Some(LiteralRun::R489),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two --stage build",
            5,
        ) => Some(LiteralRun::R489),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-four --stage build",
            0,
        ) => Some(LiteralRun::R440),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-four --stage build",
            1,
        ) => Some(LiteralRun::R440),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-four --stage build",
            2,
        ) => Some(LiteralRun::R440),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-four --stage build",
            3,
        ) => Some(LiteralRun::R440),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-four --stage build",
            4,
        ) => Some(LiteralRun::R440),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-four --stage build",
            5,
        ) => Some(LiteralRun::R440),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-one --stage build",
            0,
        ) => Some(LiteralRun::R434),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-one --stage build",
            1,
        ) => Some(LiteralRun::R434),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-one --stage build",
            2,
        ) => Some(LiteralRun::R434),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-one --stage build",
            3,
        ) => Some(LiteralRun::R434),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-one --stage build",
            4,
        ) => Some(LiteralRun::R434),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-one --stage build",
            5,
        ) => Some(LiteralRun::R434),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-three --stage build",
            0,
        ) => Some(LiteralRun::R436),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-three --stage build",
            1,
        ) => Some(LiteralRun::R436),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-three --stage build",
            2,
        ) => Some(LiteralRun::R436),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-three --stage build",
            3,
        ) => Some(LiteralRun::R436),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-three --stage build",
            4,
        ) => Some(LiteralRun::R436),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-three --stage build",
            5,
        ) => Some(LiteralRun::R436),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-two --stage build",
            0,
        ) => Some(LiteralRun::R438),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-two --stage build",
            1,
        ) => Some(LiteralRun::R438),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-two --stage build",
            2,
        ) => Some(LiteralRun::R438),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-two --stage build",
            3,
        ) => Some(LiteralRun::R438),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-two --stage build",
            4,
        ) => Some(LiteralRun::R438),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-two --stage build",
            5,
        ) => Some(LiteralRun::R438),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose msrv --shard complete --stage build",
            0,
        ) => Some(LiteralRun::R365),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose msrv --shard complete --stage build",
            1,
        ) => Some(LiteralRun::R365),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose msrv --shard complete --stage build",
            2,
        ) => Some(LiteralRun::R365),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose msrv --shard complete --stage build",
            3,
        ) => Some(LiteralRun::R365),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose msrv --shard complete --stage build",
            4,
        ) => Some(LiteralRun::R365),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose msrv --shard complete --stage build",
            5,
        ) => Some(LiteralRun::R365),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose quality --shard complete --stage build",
            0,
        ) => Some(LiteralRun::R354),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose quality --shard complete --stage build",
            1,
        ) => Some(LiteralRun::R354),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose quality --shard complete --stage build",
            2,
        ) => Some(LiteralRun::R354),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose quality --shard complete --stage build",
            3,
        ) => Some(LiteralRun::R354),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose quality --shard complete --stage build",
            4,
        ) => Some(LiteralRun::R354),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose quality --shard complete --stage build",
            5,
        ) => Some(LiteralRun::R354),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose rehearsal-tool --shard complete --stage build",
            0,
        ) => Some(LiteralRun::R393),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose rehearsal-tool --shard complete --stage build",
            1,
        ) => Some(LiteralRun::R393),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose rehearsal-tool --shard complete --stage build",
            2,
        ) => Some(LiteralRun::R393),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose rehearsal-tool --shard complete --stage build",
            3,
        ) => Some(LiteralRun::R393),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose rehearsal-tool --shard complete --stage build",
            4,
        ) => Some(LiteralRun::R393),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind compiled --purpose rehearsal-tool --shard complete --stage build",
            5,
        ) => Some(LiteralRun::R393),
        ("./.release/tool/memcordon-ci ci cache-snapshot --kind registry-archives", 0) => {
            Some(LiteralRun::R339)
        }
        ("./.release/tool/memcordon-ci ci cache-snapshot --kind registry-archives", 1) => {
            Some(LiteralRun::R339)
        }
        ("./.release/tool/memcordon-ci ci cache-snapshot --kind registry-archives", 2) => {
            Some(LiteralRun::R339)
        }
        ("./.release/tool/memcordon-ci ci cache-snapshot --kind registry-archives", 3) => {
            Some(LiteralRun::R339)
        }
        ("./.release/tool/memcordon-ci ci cache-snapshot --kind registry-archives", 4) => {
            Some(LiteralRun::R339)
        }
        ("./.release/tool/memcordon-ci ci cache-snapshot --kind registry-archives", 5) => {
            Some(LiteralRun::R339)
        }
        ("./.release/tool/memcordon-ci ci cache-snapshot --kind registry-index", 0) => {
            Some(LiteralRun::R341)
        }
        ("./.release/tool/memcordon-ci ci cache-snapshot --kind registry-index", 1) => {
            Some(LiteralRun::R341)
        }
        ("./.release/tool/memcordon-ci ci cache-snapshot --kind registry-index", 2) => {
            Some(LiteralRun::R341)
        }
        ("./.release/tool/memcordon-ci ci cache-snapshot --kind registry-index", 3) => {
            Some(LiteralRun::R341)
        }
        ("./.release/tool/memcordon-ci ci cache-snapshot --kind registry-index", 4) => {
            Some(LiteralRun::R341)
        }
        ("./.release/tool/memcordon-ci ci cache-snapshot --kind registry-index", 5) => {
            Some(LiteralRun::R341)
        }
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-audit --shard complete --stage build",
            0,
        ) => Some(LiteralRun::R380),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-audit --shard complete --stage build",
            1,
        ) => Some(LiteralRun::R380),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-audit --shard complete --stage build",
            2,
        ) => Some(LiteralRun::R380),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-audit --shard complete --stage build",
            3,
        ) => Some(LiteralRun::R380),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-audit --shard complete --stage build",
            4,
        ) => Some(LiteralRun::R380),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-audit --shard complete --stage build",
            5,
        ) => Some(LiteralRun::R380),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-deny --shard complete --stage build",
            0,
        ) => Some(LiteralRun::R382),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-deny --shard complete --stage build",
            1,
        ) => Some(LiteralRun::R382),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-deny --shard complete --stage build",
            2,
        ) => Some(LiteralRun::R382),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-deny --shard complete --stage build",
            3,
        ) => Some(LiteralRun::R382),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-deny --shard complete --stage build",
            4,
        ) => Some(LiteralRun::R382),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-deny --shard complete --stage build",
            5,
        ) => Some(LiteralRun::R382),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete --stage build",
            0,
        ) => Some(LiteralRun::R502),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete --stage build",
            1,
        ) => Some(LiteralRun::R502),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete --stage build",
            2,
        ) => Some(LiteralRun::R502),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete --stage build",
            3,
        ) => Some(LiteralRun::R502),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete --stage build",
            4,
        ) => Some(LiteralRun::R502),
        (
            "./.release/tool/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete --stage build",
            5,
        ) => Some(LiteralRun::R502),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            0,
        ) => Some(LiteralRun::R492),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            1,
        ) => Some(LiteralRun::R492),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            2,
        ) => Some(LiteralRun::R492),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            3,
        ) => Some(LiteralRun::R492),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            4,
        ) => Some(LiteralRun::R492),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            5,
        ) => Some(LiteralRun::R492),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            0,
        ) => Some(LiteralRun::R475),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            1,
        ) => Some(LiteralRun::R475),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            2,
        ) => Some(LiteralRun::R475),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            3,
        ) => Some(LiteralRun::R475),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            4,
        ) => Some(LiteralRun::R475),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            5,
        ) => Some(LiteralRun::R475),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            0,
        ) => Some(LiteralRun::R476),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            1,
        ) => Some(LiteralRun::R476),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            2,
        ) => Some(LiteralRun::R476),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            3,
        ) => Some(LiteralRun::R476),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            4,
        ) => Some(LiteralRun::R476),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            5,
        ) => Some(LiteralRun::R476),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            0,
        ) => Some(LiteralRun::R491),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            1,
        ) => Some(LiteralRun::R491),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            2,
        ) => Some(LiteralRun::R491),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            3,
        ) => Some(LiteralRun::R491),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            4,
        ) => Some(LiteralRun::R491),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            5,
        ) => Some(LiteralRun::R491),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-four",
            0,
        ) => Some(LiteralRun::R441),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-four",
            1,
        ) => Some(LiteralRun::R441),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-four",
            2,
        ) => Some(LiteralRun::R441),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-four",
            3,
        ) => Some(LiteralRun::R441),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-four",
            4,
        ) => Some(LiteralRun::R441),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-four",
            5,
        ) => Some(LiteralRun::R441),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-one",
            0,
        ) => Some(LiteralRun::R435),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-one",
            1,
        ) => Some(LiteralRun::R435),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-one",
            2,
        ) => Some(LiteralRun::R435),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-one",
            3,
        ) => Some(LiteralRun::R435),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-one",
            4,
        ) => Some(LiteralRun::R435),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-one",
            5,
        ) => Some(LiteralRun::R435),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-three",
            0,
        ) => Some(LiteralRun::R437),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-three",
            1,
        ) => Some(LiteralRun::R437),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-three",
            2,
        ) => Some(LiteralRun::R437),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-three",
            3,
        ) => Some(LiteralRun::R437),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-three",
            4,
        ) => Some(LiteralRun::R437),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-three",
            5,
        ) => Some(LiteralRun::R437),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-two",
            0,
        ) => Some(LiteralRun::R439),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-two",
            1,
        ) => Some(LiteralRun::R439),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-two",
            2,
        ) => Some(LiteralRun::R439),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-two",
            3,
        ) => Some(LiteralRun::R439),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-two",
            4,
        ) => Some(LiteralRun::R439),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-two",
            5,
        ) => Some(LiteralRun::R439),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose msrv --shard complete",
            0,
        ) => Some(LiteralRun::R366),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose msrv --shard complete",
            1,
        ) => Some(LiteralRun::R366),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose msrv --shard complete",
            2,
        ) => Some(LiteralRun::R366),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose msrv --shard complete",
            3,
        ) => Some(LiteralRun::R366),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose msrv --shard complete",
            4,
        ) => Some(LiteralRun::R366),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose msrv --shard complete",
            5,
        ) => Some(LiteralRun::R366),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose quality --shard complete",
            0,
        ) => Some(LiteralRun::R355),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose quality --shard complete",
            1,
        ) => Some(LiteralRun::R355),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose quality --shard complete",
            2,
        ) => Some(LiteralRun::R355),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose quality --shard complete",
            3,
        ) => Some(LiteralRun::R355),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose quality --shard complete",
            4,
        ) => Some(LiteralRun::R355),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose quality --shard complete",
            5,
        ) => Some(LiteralRun::R355),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose rehearsal-tool --shard complete",
            0,
        ) => Some(LiteralRun::R394),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose rehearsal-tool --shard complete",
            1,
        ) => Some(LiteralRun::R394),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose rehearsal-tool --shard complete",
            2,
        ) => Some(LiteralRun::R394),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose rehearsal-tool --shard complete",
            3,
        ) => Some(LiteralRun::R394),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose rehearsal-tool --shard complete",
            4,
        ) => Some(LiteralRun::R394),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose rehearsal-tool --shard complete",
            5,
        ) => Some(LiteralRun::R394),
        ("./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind registry-archives", 0) => {
            Some(LiteralRun::R340)
        }
        ("./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind registry-archives", 1) => {
            Some(LiteralRun::R340)
        }
        ("./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind registry-archives", 2) => {
            Some(LiteralRun::R340)
        }
        ("./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind registry-archives", 3) => {
            Some(LiteralRun::R340)
        }
        ("./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind registry-archives", 4) => {
            Some(LiteralRun::R340)
        }
        ("./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind registry-archives", 5) => {
            Some(LiteralRun::R340)
        }
        ("./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind registry-index", 0) => {
            Some(LiteralRun::R342)
        }
        ("./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind registry-index", 1) => {
            Some(LiteralRun::R342)
        }
        ("./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind registry-index", 2) => {
            Some(LiteralRun::R342)
        }
        ("./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind registry-index", 3) => {
            Some(LiteralRun::R342)
        }
        ("./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind registry-index", 4) => {
            Some(LiteralRun::R342)
        }
        ("./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind registry-index", 5) => {
            Some(LiteralRun::R342)
        }
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete",
            0,
        ) => Some(LiteralRun::R381),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete",
            1,
        ) => Some(LiteralRun::R381),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete",
            2,
        ) => Some(LiteralRun::R381),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete",
            3,
        ) => Some(LiteralRun::R381),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete",
            4,
        ) => Some(LiteralRun::R381),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete",
            5,
        ) => Some(LiteralRun::R381),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete",
            0,
        ) => Some(LiteralRun::R383),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete",
            1,
        ) => Some(LiteralRun::R383),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete",
            2,
        ) => Some(LiteralRun::R383),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete",
            3,
        ) => Some(LiteralRun::R383),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete",
            4,
        ) => Some(LiteralRun::R383),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete",
            5,
        ) => Some(LiteralRun::R383),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete",
            0,
        ) => Some(LiteralRun::R503),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete",
            1,
        ) => Some(LiteralRun::R503),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete",
            2,
        ) => Some(LiteralRun::R503),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete",
            3,
        ) => Some(LiteralRun::R503),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete",
            4,
        ) => Some(LiteralRun::R503),
        (
            "./.release/tool/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete",
            5,
        ) => Some(LiteralRun::R503),
        ("./.release/tool/memcordon-ci ci download-cache-context --family fuzz", 0) => {
            Some(LiteralRun::R444)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family fuzz", 1) => {
            Some(LiteralRun::R444)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family fuzz", 2) => {
            Some(LiteralRun::R444)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family fuzz", 3) => {
            Some(LiteralRun::R444)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family fuzz", 4) => {
            Some(LiteralRun::R444)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family fuzz", 5) => {
            Some(LiteralRun::R444)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family tool-cargo-audit", 0) => {
            Some(LiteralRun::R368)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family tool-cargo-audit", 1) => {
            Some(LiteralRun::R368)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family tool-cargo-audit", 2) => {
            Some(LiteralRun::R368)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family tool-cargo-audit", 3) => {
            Some(LiteralRun::R368)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family tool-cargo-audit", 4) => {
            Some(LiteralRun::R368)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family tool-cargo-audit", 5) => {
            Some(LiteralRun::R368)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family tool-cargo-deny", 0) => {
            Some(LiteralRun::R370)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family tool-cargo-deny", 1) => {
            Some(LiteralRun::R370)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family tool-cargo-deny", 2) => {
            Some(LiteralRun::R370)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family tool-cargo-deny", 3) => {
            Some(LiteralRun::R370)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family tool-cargo-deny", 4) => {
            Some(LiteralRun::R370)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family tool-cargo-deny", 5) => {
            Some(LiteralRun::R370)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family tool-cargo-fuzz", 0) => {
            Some(LiteralRun::R442)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family tool-cargo-fuzz", 1) => {
            Some(LiteralRun::R442)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family tool-cargo-fuzz", 2) => {
            Some(LiteralRun::R442)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family tool-cargo-fuzz", 3) => {
            Some(LiteralRun::R442)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family tool-cargo-fuzz", 4) => {
            Some(LiteralRun::R442)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family tool-cargo-fuzz", 5) => {
            Some(LiteralRun::R442)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family workspace", 0) => {
            Some(LiteralRun::R333)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family workspace", 1) => {
            Some(LiteralRun::R333)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family workspace", 2) => {
            Some(LiteralRun::R333)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family workspace", 3) => {
            Some(LiteralRun::R333)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family workspace", 4) => {
            Some(LiteralRun::R333)
        }
        ("./.release/tool/memcordon-ci ci download-cache-context --family workspace", 5) => {
            Some(LiteralRun::R333)
        }
        ("./.release/tool/memcordon-ci ci fetch-downloads --family workspace", 0) => {
            Some(LiteralRun::R338)
        }
        ("./.release/tool/memcordon-ci ci fetch-downloads --family workspace", 1) => {
            Some(LiteralRun::R338)
        }
        ("./.release/tool/memcordon-ci ci fetch-downloads --family workspace", 2) => {
            Some(LiteralRun::R338)
        }
        ("./.release/tool/memcordon-ci ci fetch-downloads --family workspace", 3) => {
            Some(LiteralRun::R338)
        }
        ("./.release/tool/memcordon-ci ci fetch-downloads --family workspace", 4) => {
            Some(LiteralRun::R338)
        }
        ("./.release/tool/memcordon-ci ci fetch-downloads --family workspace", 5) => {
            Some(LiteralRun::R338)
        }
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            0,
        ) => Some(LiteralRun::R484),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            1,
        ) => Some(LiteralRun::R484),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            2,
        ) => Some(LiteralRun::R484),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            3,
        ) => Some(LiteralRun::R484),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            4,
        ) => Some(LiteralRun::R484),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            5,
        ) => Some(LiteralRun::R484),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            0,
        ) => Some(LiteralRun::R467),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            1,
        ) => Some(LiteralRun::R467),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            2,
        ) => Some(LiteralRun::R467),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            3,
        ) => Some(LiteralRun::R467),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            4,
        ) => Some(LiteralRun::R467),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            5,
        ) => Some(LiteralRun::R467),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            0,
        ) => Some(LiteralRun::R468),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            1,
        ) => Some(LiteralRun::R468),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            2,
        ) => Some(LiteralRun::R468),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            3,
        ) => Some(LiteralRun::R468),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            4,
        ) => Some(LiteralRun::R468),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            5,
        ) => Some(LiteralRun::R468),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            0,
        ) => Some(LiteralRun::R483),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            1,
        ) => Some(LiteralRun::R483),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            2,
        ) => Some(LiteralRun::R483),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            3,
        ) => Some(LiteralRun::R483),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            4,
        ) => Some(LiteralRun::R483),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            5,
        ) => Some(LiteralRun::R483),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-four",
            0,
        ) => Some(LiteralRun::R421),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-four",
            1,
        ) => Some(LiteralRun::R421),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-four",
            2,
        ) => Some(LiteralRun::R421),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-four",
            3,
        ) => Some(LiteralRun::R421),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-four",
            4,
        ) => Some(LiteralRun::R421),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-four",
            5,
        ) => Some(LiteralRun::R421),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-one",
            0,
        ) => Some(LiteralRun::R415),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-one",
            1,
        ) => Some(LiteralRun::R415),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-one",
            2,
        ) => Some(LiteralRun::R415),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-one",
            3,
        ) => Some(LiteralRun::R415),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-one",
            4,
        ) => Some(LiteralRun::R415),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-one",
            5,
        ) => Some(LiteralRun::R415),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-three",
            0,
        ) => Some(LiteralRun::R417),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-three",
            1,
        ) => Some(LiteralRun::R417),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-three",
            2,
        ) => Some(LiteralRun::R417),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-three",
            3,
        ) => Some(LiteralRun::R417),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-three",
            4,
        ) => Some(LiteralRun::R417),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-three",
            5,
        ) => Some(LiteralRun::R417),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-two",
            0,
        ) => Some(LiteralRun::R419),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-two",
            1,
        ) => Some(LiteralRun::R419),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-two",
            2,
        ) => Some(LiteralRun::R419),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-two",
            3,
        ) => Some(LiteralRun::R419),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-two",
            4,
        ) => Some(LiteralRun::R419),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-two",
            5,
        ) => Some(LiteralRun::R419),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose msrv --shard complete",
            0,
        ) => Some(LiteralRun::R361),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose msrv --shard complete",
            1,
        ) => Some(LiteralRun::R361),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose msrv --shard complete",
            2,
        ) => Some(LiteralRun::R361),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose msrv --shard complete",
            3,
        ) => Some(LiteralRun::R361),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose msrv --shard complete",
            4,
        ) => Some(LiteralRun::R361),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose msrv --shard complete",
            5,
        ) => Some(LiteralRun::R361),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose quality --shard complete",
            0,
        ) => Some(LiteralRun::R350),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose quality --shard complete",
            1,
        ) => Some(LiteralRun::R350),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose quality --shard complete",
            2,
        ) => Some(LiteralRun::R350),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose quality --shard complete",
            3,
        ) => Some(LiteralRun::R350),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose quality --shard complete",
            4,
        ) => Some(LiteralRun::R350),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose quality --shard complete",
            5,
        ) => Some(LiteralRun::R350),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose rehearsal-tool --shard complete",
            0,
        ) => Some(LiteralRun::R389),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose rehearsal-tool --shard complete",
            1,
        ) => Some(LiteralRun::R389),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose rehearsal-tool --shard complete",
            2,
        ) => Some(LiteralRun::R389),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose rehearsal-tool --shard complete",
            3,
        ) => Some(LiteralRun::R389),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose rehearsal-tool --shard complete",
            4,
        ) => Some(LiteralRun::R389),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind compiled --purpose rehearsal-tool --shard complete",
            5,
        ) => Some(LiteralRun::R389),
        ("./.release/tool/memcordon-ci ci import-cache-snapshot --kind registry-archives", 0) => {
            Some(LiteralRun::R335)
        }
        ("./.release/tool/memcordon-ci ci import-cache-snapshot --kind registry-archives", 1) => {
            Some(LiteralRun::R335)
        }
        ("./.release/tool/memcordon-ci ci import-cache-snapshot --kind registry-archives", 2) => {
            Some(LiteralRun::R335)
        }
        ("./.release/tool/memcordon-ci ci import-cache-snapshot --kind registry-archives", 3) => {
            Some(LiteralRun::R335)
        }
        ("./.release/tool/memcordon-ci ci import-cache-snapshot --kind registry-archives", 4) => {
            Some(LiteralRun::R335)
        }
        ("./.release/tool/memcordon-ci ci import-cache-snapshot --kind registry-archives", 5) => {
            Some(LiteralRun::R335)
        }
        ("./.release/tool/memcordon-ci ci import-cache-snapshot --kind registry-index", 0) => {
            Some(LiteralRun::R337)
        }
        ("./.release/tool/memcordon-ci ci import-cache-snapshot --kind registry-index", 1) => {
            Some(LiteralRun::R337)
        }
        ("./.release/tool/memcordon-ci ci import-cache-snapshot --kind registry-index", 2) => {
            Some(LiteralRun::R337)
        }
        ("./.release/tool/memcordon-ci ci import-cache-snapshot --kind registry-index", 3) => {
            Some(LiteralRun::R337)
        }
        ("./.release/tool/memcordon-ci ci import-cache-snapshot --kind registry-index", 4) => {
            Some(LiteralRun::R337)
        }
        ("./.release/tool/memcordon-ci ci import-cache-snapshot --kind registry-index", 5) => {
            Some(LiteralRun::R337)
        }
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete",
            0,
        ) => Some(LiteralRun::R373),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete",
            1,
        ) => Some(LiteralRun::R373),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete",
            2,
        ) => Some(LiteralRun::R373),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete",
            3,
        ) => Some(LiteralRun::R373),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete",
            4,
        ) => Some(LiteralRun::R373),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete",
            5,
        ) => Some(LiteralRun::R373),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete",
            0,
        ) => Some(LiteralRun::R375),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete",
            1,
        ) => Some(LiteralRun::R375),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete",
            2,
        ) => Some(LiteralRun::R375),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete",
            3,
        ) => Some(LiteralRun::R375),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete",
            4,
        ) => Some(LiteralRun::R375),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete",
            5,
        ) => Some(LiteralRun::R375),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete",
            0,
        ) => Some(LiteralRun::R446),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete",
            1,
        ) => Some(LiteralRun::R446),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete",
            2,
        ) => Some(LiteralRun::R446),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete",
            3,
        ) => Some(LiteralRun::R446),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete",
            4,
        ) => Some(LiteralRun::R446),
        (
            "./.release/tool/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete",
            5,
        ) => Some(LiteralRun::R446),
        ("./.release/tool/memcordon-ci ci miri-cache-context", 0) => Some(LiteralRun::R396),
        ("./.release/tool/memcordon-ci ci miri-cache-context", 1) => Some(LiteralRun::R396),
        ("./.release/tool/memcordon-ci ci miri-cache-context", 2) => Some(LiteralRun::R396),
        ("./.release/tool/memcordon-ci ci miri-cache-context", 3) => Some(LiteralRun::R396),
        ("./.release/tool/memcordon-ci ci miri-cache-context", 4) => Some(LiteralRun::R396),
        ("./.release/tool/memcordon-ci ci miri-cache-context", 5) => Some(LiteralRun::R396),
        (
            "./.release/tool/memcordon-ci ci prepare --profile fuzz --failure-mode collect-all",
            0,
        ) => Some(LiteralRun::R448),
        (
            "./.release/tool/memcordon-ci ci prepare --profile fuzz --failure-mode collect-all",
            1,
        ) => Some(LiteralRun::R448),
        (
            "./.release/tool/memcordon-ci ci prepare --profile fuzz --failure-mode collect-all",
            2,
        ) => Some(LiteralRun::R448),
        (
            "./.release/tool/memcordon-ci ci prepare --profile fuzz --failure-mode collect-all",
            3,
        ) => Some(LiteralRun::R448),
        (
            "./.release/tool/memcordon-ci ci prepare --profile fuzz --failure-mode collect-all",
            4,
        ) => Some(LiteralRun::R448),
        (
            "./.release/tool/memcordon-ci ci prepare --profile fuzz --failure-mode collect-all",
            5,
        ) => Some(LiteralRun::R448),
        (
            "./.release/tool/memcordon-ci ci prepare --profile fuzz --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R447),
        (
            "./.release/tool/memcordon-ci ci prepare --profile fuzz --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R447),
        (
            "./.release/tool/memcordon-ci ci prepare --profile fuzz --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R447),
        (
            "./.release/tool/memcordon-ci ci prepare --profile fuzz --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R447),
        (
            "./.release/tool/memcordon-ci ci prepare --profile fuzz --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R447),
        (
            "./.release/tool/memcordon-ci ci prepare --profile fuzz --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R447),
        ("./.release/tool/memcordon-ci ci prepare-miri-components", 0) => Some(LiteralRun::R395),
        ("./.release/tool/memcordon-ci ci prepare-miri-components", 1) => Some(LiteralRun::R395),
        ("./.release/tool/memcordon-ci ci prepare-miri-components", 2) => Some(LiteralRun::R395),
        ("./.release/tool/memcordon-ci ci prepare-miri-components", 3) => Some(LiteralRun::R395),
        ("./.release/tool/memcordon-ci ci prepare-miri-components", 4) => Some(LiteralRun::R395),
        ("./.release/tool/memcordon-ci ci prepare-miri-components", 5) => Some(LiteralRun::R395),
        ("./.release/tool/memcordon-ci ci prepare-miri-sysroot", 0) => Some(LiteralRun::R397),
        ("./.release/tool/memcordon-ci ci prepare-miri-sysroot", 1) => Some(LiteralRun::R397),
        ("./.release/tool/memcordon-ci ci prepare-miri-sysroot", 2) => Some(LiteralRun::R397),
        ("./.release/tool/memcordon-ci ci prepare-miri-sysroot", 3) => Some(LiteralRun::R397),
        ("./.release/tool/memcordon-ci ci prepare-miri-sysroot", 4) => Some(LiteralRun::R397),
        ("./.release/tool/memcordon-ci ci prepare-miri-sysroot", 5) => Some(LiteralRun::R397),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode compatible --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R464),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode compatible --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R464),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode compatible --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R464),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode compatible --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R464),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode compatible --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R464),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode compatible --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R464),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode discard --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R460),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode discard --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R460),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode discard --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R460),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode discard --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R460),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode discard --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R460),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode discard --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R460),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode exact --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R462),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode exact --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R462),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode exact --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R462),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode exact --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R462),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode exact --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R462),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode exact --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R462),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode compatible --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R457),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode compatible --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R457),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode compatible --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R457),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode compatible --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R457),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode compatible --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R457),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode compatible --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R457),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode discard --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R453),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode discard --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R453),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode discard --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R453),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode discard --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R453),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode discard --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R453),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode discard --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R453),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode exact --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R455),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode exact --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R455),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode exact --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R455),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode exact --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R455),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode exact --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R455),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode exact --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R455),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode compatible --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R458),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode compatible --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R458),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode compatible --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R458),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode compatible --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R458),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode compatible --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R458),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode compatible --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R458),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode discard --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R454),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode discard --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R454),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode discard --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R454),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode discard --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R454),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode discard --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R454),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode discard --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R454),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode exact --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R456),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode exact --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R456),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode exact --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R456),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode exact --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R456),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode exact --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R456),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode exact --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R456),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode compatible --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R463),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode compatible --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R463),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode compatible --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R463),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode compatible --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R463),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode compatible --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R463),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode compatible --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R463),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode discard --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R459),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode discard --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R459),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode discard --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R459),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode discard --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R459),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode discard --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R459),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode discard --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R459),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode exact --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R461),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode exact --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R461),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode exact --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R461),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode exact --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R461),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode exact --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R461),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode exact --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R461),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode compatible",
            0,
        ) => Some(LiteralRun::R413),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode compatible",
            1,
        ) => Some(LiteralRun::R413),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode compatible",
            2,
        ) => Some(LiteralRun::R413),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode compatible",
            3,
        ) => Some(LiteralRun::R413),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode compatible",
            4,
        ) => Some(LiteralRun::R413),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode compatible",
            5,
        ) => Some(LiteralRun::R413),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode discard",
            0,
        ) => Some(LiteralRun::R409),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode discard",
            1,
        ) => Some(LiteralRun::R409),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode discard",
            2,
        ) => Some(LiteralRun::R409),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode discard",
            3,
        ) => Some(LiteralRun::R409),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode discard",
            4,
        ) => Some(LiteralRun::R409),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode discard",
            5,
        ) => Some(LiteralRun::R409),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode exact",
            0,
        ) => Some(LiteralRun::R411),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode exact",
            1,
        ) => Some(LiteralRun::R411),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode exact",
            2,
        ) => Some(LiteralRun::R411),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode exact",
            3,
        ) => Some(LiteralRun::R411),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode exact",
            4,
        ) => Some(LiteralRun::R411),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode exact",
            5,
        ) => Some(LiteralRun::R411),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode compatible",
            0,
        ) => Some(LiteralRun::R406),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode compatible",
            1,
        ) => Some(LiteralRun::R406),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode compatible",
            2,
        ) => Some(LiteralRun::R406),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode compatible",
            3,
        ) => Some(LiteralRun::R406),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode compatible",
            4,
        ) => Some(LiteralRun::R406),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode compatible",
            5,
        ) => Some(LiteralRun::R406),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode discard",
            0,
        ) => Some(LiteralRun::R402),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode discard",
            1,
        ) => Some(LiteralRun::R402),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode discard",
            2,
        ) => Some(LiteralRun::R402),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode discard",
            3,
        ) => Some(LiteralRun::R402),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode discard",
            4,
        ) => Some(LiteralRun::R402),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode discard",
            5,
        ) => Some(LiteralRun::R402),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode exact",
            0,
        ) => Some(LiteralRun::R404),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode exact",
            1,
        ) => Some(LiteralRun::R404),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode exact",
            2,
        ) => Some(LiteralRun::R404),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode exact",
            3,
        ) => Some(LiteralRun::R404),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode exact",
            4,
        ) => Some(LiteralRun::R404),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode exact",
            5,
        ) => Some(LiteralRun::R404),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode compatible",
            0,
        ) => Some(LiteralRun::R407),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode compatible",
            1,
        ) => Some(LiteralRun::R407),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode compatible",
            2,
        ) => Some(LiteralRun::R407),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode compatible",
            3,
        ) => Some(LiteralRun::R407),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode compatible",
            4,
        ) => Some(LiteralRun::R407),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode compatible",
            5,
        ) => Some(LiteralRun::R407),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode discard",
            0,
        ) => Some(LiteralRun::R403),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode discard",
            1,
        ) => Some(LiteralRun::R403),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode discard",
            2,
        ) => Some(LiteralRun::R403),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode discard",
            3,
        ) => Some(LiteralRun::R403),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode discard",
            4,
        ) => Some(LiteralRun::R403),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode discard",
            5,
        ) => Some(LiteralRun::R403),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode exact",
            0,
        ) => Some(LiteralRun::R405),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode exact",
            1,
        ) => Some(LiteralRun::R405),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode exact",
            2,
        ) => Some(LiteralRun::R405),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode exact",
            3,
        ) => Some(LiteralRun::R405),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode exact",
            4,
        ) => Some(LiteralRun::R405),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode exact",
            5,
        ) => Some(LiteralRun::R405),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode compatible",
            0,
        ) => Some(LiteralRun::R412),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode compatible",
            1,
        ) => Some(LiteralRun::R412),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode compatible",
            2,
        ) => Some(LiteralRun::R412),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode compatible",
            3,
        ) => Some(LiteralRun::R412),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode compatible",
            4,
        ) => Some(LiteralRun::R412),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode compatible",
            5,
        ) => Some(LiteralRun::R412),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode discard",
            0,
        ) => Some(LiteralRun::R408),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode discard",
            1,
        ) => Some(LiteralRun::R408),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode discard",
            2,
        ) => Some(LiteralRun::R408),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode discard",
            3,
        ) => Some(LiteralRun::R408),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode discard",
            4,
        ) => Some(LiteralRun::R408),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode discard",
            5,
        ) => Some(LiteralRun::R408),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode exact",
            0,
        ) => Some(LiteralRun::R410),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode exact",
            1,
        ) => Some(LiteralRun::R410),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode exact",
            2,
        ) => Some(LiteralRun::R410),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode exact",
            3,
        ) => Some(LiteralRun::R410),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode exact",
            4,
        ) => Some(LiteralRun::R410),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode exact",
            5,
        ) => Some(LiteralRun::R410),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode compatible",
            0,
        ) => Some(LiteralRun::R359),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode compatible",
            1,
        ) => Some(LiteralRun::R359),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode compatible",
            2,
        ) => Some(LiteralRun::R359),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode compatible",
            3,
        ) => Some(LiteralRun::R359),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode compatible",
            4,
        ) => Some(LiteralRun::R359),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode compatible",
            5,
        ) => Some(LiteralRun::R359),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode discard",
            0,
        ) => Some(LiteralRun::R357),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode discard",
            1,
        ) => Some(LiteralRun::R357),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode discard",
            2,
        ) => Some(LiteralRun::R357),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode discard",
            3,
        ) => Some(LiteralRun::R357),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode discard",
            4,
        ) => Some(LiteralRun::R357),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode discard",
            5,
        ) => Some(LiteralRun::R357),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode exact",
            0,
        ) => Some(LiteralRun::R358),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode exact",
            1,
        ) => Some(LiteralRun::R358),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode exact",
            2,
        ) => Some(LiteralRun::R358),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode exact",
            3,
        ) => Some(LiteralRun::R358),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode exact",
            4,
        ) => Some(LiteralRun::R358),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode exact",
            5,
        ) => Some(LiteralRun::R358),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode compatible",
            0,
        ) => Some(LiteralRun::R348),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode compatible",
            1,
        ) => Some(LiteralRun::R348),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode compatible",
            2,
        ) => Some(LiteralRun::R348),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode compatible",
            3,
        ) => Some(LiteralRun::R348),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode compatible",
            4,
        ) => Some(LiteralRun::R348),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode compatible",
            5,
        ) => Some(LiteralRun::R348),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode discard",
            0,
        ) => Some(LiteralRun::R346),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode discard",
            1,
        ) => Some(LiteralRun::R346),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode discard",
            2,
        ) => Some(LiteralRun::R346),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode discard",
            3,
        ) => Some(LiteralRun::R346),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode discard",
            4,
        ) => Some(LiteralRun::R346),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode discard",
            5,
        ) => Some(LiteralRun::R346),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode exact",
            0,
        ) => Some(LiteralRun::R347),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode exact",
            1,
        ) => Some(LiteralRun::R347),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode exact",
            2,
        ) => Some(LiteralRun::R347),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode exact",
            3,
        ) => Some(LiteralRun::R347),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode exact",
            4,
        ) => Some(LiteralRun::R347),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode exact",
            5,
        ) => Some(LiteralRun::R347),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose rehearsal-tool --shard complete --mode compatible",
            0,
        ) => Some(LiteralRun::R387),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose rehearsal-tool --shard complete --mode compatible",
            1,
        ) => Some(LiteralRun::R387),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose rehearsal-tool --shard complete --mode compatible",
            2,
        ) => Some(LiteralRun::R387),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose rehearsal-tool --shard complete --mode compatible",
            3,
        ) => Some(LiteralRun::R387),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose rehearsal-tool --shard complete --mode compatible",
            4,
        ) => Some(LiteralRun::R387),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose rehearsal-tool --shard complete --mode compatible",
            5,
        ) => Some(LiteralRun::R387),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose rehearsal-tool --shard complete --mode discard",
            0,
        ) => Some(LiteralRun::R385),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose rehearsal-tool --shard complete --mode discard",
            1,
        ) => Some(LiteralRun::R385),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose rehearsal-tool --shard complete --mode discard",
            2,
        ) => Some(LiteralRun::R385),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose rehearsal-tool --shard complete --mode discard",
            3,
        ) => Some(LiteralRun::R385),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose rehearsal-tool --shard complete --mode discard",
            4,
        ) => Some(LiteralRun::R385),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose rehearsal-tool --shard complete --mode discard",
            5,
        ) => Some(LiteralRun::R385),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose rehearsal-tool --shard complete --mode exact",
            0,
        ) => Some(LiteralRun::R386),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose rehearsal-tool --shard complete --mode exact",
            1,
        ) => Some(LiteralRun::R386),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose rehearsal-tool --shard complete --mode exact",
            2,
        ) => Some(LiteralRun::R386),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose rehearsal-tool --shard complete --mode exact",
            3,
        ) => Some(LiteralRun::R386),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose rehearsal-tool --shard complete --mode exact",
            4,
        ) => Some(LiteralRun::R386),
        (
            "./.release/tool/memcordon-ci ci prepare-restored-cache --purpose rehearsal-tool --shard complete --mode exact",
            5,
        ) => Some(LiteralRun::R386),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            0,
        ) => Some(LiteralRun::R482),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            1,
        ) => Some(LiteralRun::R482),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            2,
        ) => Some(LiteralRun::R482),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            3,
        ) => Some(LiteralRun::R482),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            4,
        ) => Some(LiteralRun::R482),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            5,
        ) => Some(LiteralRun::R482),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            0,
        ) => Some(LiteralRun::R465),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            1,
        ) => Some(LiteralRun::R465),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            2,
        ) => Some(LiteralRun::R465),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            3,
        ) => Some(LiteralRun::R465),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            4,
        ) => Some(LiteralRun::R465),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            5,
        ) => Some(LiteralRun::R465),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            0,
        ) => Some(LiteralRun::R466),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            1,
        ) => Some(LiteralRun::R466),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            2,
        ) => Some(LiteralRun::R466),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            3,
        ) => Some(LiteralRun::R466),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            4,
        ) => Some(LiteralRun::R466),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            5,
        ) => Some(LiteralRun::R466),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            0,
        ) => Some(LiteralRun::R481),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            1,
        ) => Some(LiteralRun::R481),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            2,
        ) => Some(LiteralRun::R481),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            3,
        ) => Some(LiteralRun::R481),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            4,
        ) => Some(LiteralRun::R481),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            5,
        ) => Some(LiteralRun::R481),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-four",
            0,
        ) => Some(LiteralRun::R420),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-four",
            1,
        ) => Some(LiteralRun::R420),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-four",
            2,
        ) => Some(LiteralRun::R420),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-four",
            3,
        ) => Some(LiteralRun::R420),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-four",
            4,
        ) => Some(LiteralRun::R420),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-four",
            5,
        ) => Some(LiteralRun::R420),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-one",
            0,
        ) => Some(LiteralRun::R414),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-one",
            1,
        ) => Some(LiteralRun::R414),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-one",
            2,
        ) => Some(LiteralRun::R414),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-one",
            3,
        ) => Some(LiteralRun::R414),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-one",
            4,
        ) => Some(LiteralRun::R414),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-one",
            5,
        ) => Some(LiteralRun::R414),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-three",
            0,
        ) => Some(LiteralRun::R416),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-three",
            1,
        ) => Some(LiteralRun::R416),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-three",
            2,
        ) => Some(LiteralRun::R416),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-three",
            3,
        ) => Some(LiteralRun::R416),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-three",
            4,
        ) => Some(LiteralRun::R416),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-three",
            5,
        ) => Some(LiteralRun::R416),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-two",
            0,
        ) => Some(LiteralRun::R418),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-two",
            1,
        ) => Some(LiteralRun::R418),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-two",
            2,
        ) => Some(LiteralRun::R418),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-two",
            3,
        ) => Some(LiteralRun::R418),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-two",
            4,
        ) => Some(LiteralRun::R418),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-two",
            5,
        ) => Some(LiteralRun::R418),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose msrv --shard complete",
            0,
        ) => Some(LiteralRun::R360),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose msrv --shard complete",
            1,
        ) => Some(LiteralRun::R360),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose msrv --shard complete",
            2,
        ) => Some(LiteralRun::R360),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose msrv --shard complete",
            3,
        ) => Some(LiteralRun::R360),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose msrv --shard complete",
            4,
        ) => Some(LiteralRun::R360),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose msrv --shard complete",
            5,
        ) => Some(LiteralRun::R360),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose quality --shard complete",
            0,
        ) => Some(LiteralRun::R349),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose quality --shard complete",
            1,
        ) => Some(LiteralRun::R349),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose quality --shard complete",
            2,
        ) => Some(LiteralRun::R349),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose quality --shard complete",
            3,
        ) => Some(LiteralRun::R349),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose quality --shard complete",
            4,
        ) => Some(LiteralRun::R349),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose quality --shard complete",
            5,
        ) => Some(LiteralRun::R349),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose rehearsal-tool --shard complete",
            0,
        ) => Some(LiteralRun::R388),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose rehearsal-tool --shard complete",
            1,
        ) => Some(LiteralRun::R388),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose rehearsal-tool --shard complete",
            2,
        ) => Some(LiteralRun::R388),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose rehearsal-tool --shard complete",
            3,
        ) => Some(LiteralRun::R388),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose rehearsal-tool --shard complete",
            4,
        ) => Some(LiteralRun::R388),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind compiled --purpose rehearsal-tool --shard complete",
            5,
        ) => Some(LiteralRun::R388),
        ("./.release/tool/memcordon-ci ci seed-context --kind registry-archives", 0) => {
            Some(LiteralRun::R334)
        }
        ("./.release/tool/memcordon-ci ci seed-context --kind registry-archives", 1) => {
            Some(LiteralRun::R334)
        }
        ("./.release/tool/memcordon-ci ci seed-context --kind registry-archives", 2) => {
            Some(LiteralRun::R334)
        }
        ("./.release/tool/memcordon-ci ci seed-context --kind registry-archives", 3) => {
            Some(LiteralRun::R334)
        }
        ("./.release/tool/memcordon-ci ci seed-context --kind registry-archives", 4) => {
            Some(LiteralRun::R334)
        }
        ("./.release/tool/memcordon-ci ci seed-context --kind registry-archives", 5) => {
            Some(LiteralRun::R334)
        }
        ("./.release/tool/memcordon-ci ci seed-context --kind registry-index", 0) => {
            Some(LiteralRun::R336)
        }
        ("./.release/tool/memcordon-ci ci seed-context --kind registry-index", 1) => {
            Some(LiteralRun::R336)
        }
        ("./.release/tool/memcordon-ci ci seed-context --kind registry-index", 2) => {
            Some(LiteralRun::R336)
        }
        ("./.release/tool/memcordon-ci ci seed-context --kind registry-index", 3) => {
            Some(LiteralRun::R336)
        }
        ("./.release/tool/memcordon-ci ci seed-context --kind registry-index", 4) => {
            Some(LiteralRun::R336)
        }
        ("./.release/tool/memcordon-ci ci seed-context --kind registry-index", 5) => {
            Some(LiteralRun::R336)
        }
        (
            "./.release/tool/memcordon-ci ci seed-context --kind tool-build --purpose cargo-audit --shard complete",
            0,
        ) => Some(LiteralRun::R372),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind tool-build --purpose cargo-audit --shard complete",
            1,
        ) => Some(LiteralRun::R372),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind tool-build --purpose cargo-audit --shard complete",
            2,
        ) => Some(LiteralRun::R372),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind tool-build --purpose cargo-audit --shard complete",
            3,
        ) => Some(LiteralRun::R372),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind tool-build --purpose cargo-audit --shard complete",
            4,
        ) => Some(LiteralRun::R372),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind tool-build --purpose cargo-audit --shard complete",
            5,
        ) => Some(LiteralRun::R372),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind tool-build --purpose cargo-deny --shard complete",
            0,
        ) => Some(LiteralRun::R374),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind tool-build --purpose cargo-deny --shard complete",
            1,
        ) => Some(LiteralRun::R374),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind tool-build --purpose cargo-deny --shard complete",
            2,
        ) => Some(LiteralRun::R374),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind tool-build --purpose cargo-deny --shard complete",
            3,
        ) => Some(LiteralRun::R374),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind tool-build --purpose cargo-deny --shard complete",
            4,
        ) => Some(LiteralRun::R374),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind tool-build --purpose cargo-deny --shard complete",
            5,
        ) => Some(LiteralRun::R374),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind tool-build --purpose cargo-fuzz --shard complete",
            0,
        ) => Some(LiteralRun::R445),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind tool-build --purpose cargo-fuzz --shard complete",
            1,
        ) => Some(LiteralRun::R445),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind tool-build --purpose cargo-fuzz --shard complete",
            2,
        ) => Some(LiteralRun::R445),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind tool-build --purpose cargo-fuzz --shard complete",
            3,
        ) => Some(LiteralRun::R445),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind tool-build --purpose cargo-fuzz --shard complete",
            4,
        ) => Some(LiteralRun::R445),
        (
            "./.release/tool/memcordon-ci ci seed-context --kind tool-build --purpose cargo-fuzz --shard complete",
            5,
        ) => Some(LiteralRun::R445),
        (
            "./.release/tool/memcordon-ci release assemble --build-source .release/build-source.json --consumer-readiness --destination .release/assembled",
            0,
        ) => Some(LiteralRun::R540),
        (
            "./.release/tool/memcordon-ci release assemble --build-source .release/build-source.json --consumer-readiness --destination .release/assembled",
            1,
        ) => Some(LiteralRun::R540),
        (
            "./.release/tool/memcordon-ci release assemble --build-source .release/build-source.json --consumer-readiness --destination .release/assembled",
            2,
        ) => Some(LiteralRun::R540),
        (
            "./.release/tool/memcordon-ci release assemble --build-source .release/build-source.json --consumer-readiness --destination .release/assembled",
            3,
        ) => Some(LiteralRun::R540),
        (
            "./.release/tool/memcordon-ci release assemble --build-source .release/build-source.json --consumer-readiness --destination .release/assembled",
            4,
        ) => Some(LiteralRun::R540),
        (
            "./.release/tool/memcordon-ci release assemble --build-source .release/build-source.json --consumer-readiness --destination .release/assembled",
            5,
        ) => Some(LiteralRun::R540),
        (
            "./.release/tool/memcordon-ci release finalize-preparation --build-source .release/build-source.json --input .release/assembled --publisher-archive .release/tool/memcordon-publication-tool.tar.gz --destination .release/final",
            0,
        ) => Some(LiteralRun::R541),
        (
            "./.release/tool/memcordon-ci release finalize-preparation --build-source .release/build-source.json --input .release/assembled --publisher-archive .release/tool/memcordon-publication-tool.tar.gz --destination .release/final",
            1,
        ) => Some(LiteralRun::R541),
        (
            "./.release/tool/memcordon-ci release finalize-preparation --build-source .release/build-source.json --input .release/assembled --publisher-archive .release/tool/memcordon-publication-tool.tar.gz --destination .release/final",
            2,
        ) => Some(LiteralRun::R541),
        (
            "./.release/tool/memcordon-ci release finalize-preparation --build-source .release/build-source.json --input .release/assembled --publisher-archive .release/tool/memcordon-publication-tool.tar.gz --destination .release/final",
            3,
        ) => Some(LiteralRun::R541),
        (
            "./.release/tool/memcordon-ci release finalize-preparation --build-source .release/build-source.json --input .release/assembled --publisher-archive .release/tool/memcordon-publication-tool.tar.gz --destination .release/final",
            4,
        ) => Some(LiteralRun::R541),
        (
            "./.release/tool/memcordon-ci release finalize-preparation --build-source .release/build-source.json --input .release/assembled --publisher-archive .release/tool/memcordon-publication-tool.tar.gz --destination .release/final",
            5,
        ) => Some(LiteralRun::R541),
        (
            "./.release/tool/memcordon-ci release packages --build-source .release/build-source.json",
            0,
        ) => Some(LiteralRun::R344),
        (
            "./.release/tool/memcordon-ci release packages --build-source .release/build-source.json",
            1,
        ) => Some(LiteralRun::R344),
        (
            "./.release/tool/memcordon-ci release packages --build-source .release/build-source.json",
            2,
        ) => Some(LiteralRun::R344),
        (
            "./.release/tool/memcordon-ci release packages --build-source .release/build-source.json",
            3,
        ) => Some(LiteralRun::R344),
        (
            "./.release/tool/memcordon-ci release packages --build-source .release/build-source.json",
            4,
        ) => Some(LiteralRun::R344),
        (
            "./.release/tool/memcordon-ci release packages --build-source .release/build-source.json",
            5,
        ) => Some(LiteralRun::R344),
        ("./.release/tool/memcordon-ci release public-consumer", 0) => Some(LiteralRun::R552),
        ("./.release/tool/memcordon-ci release public-consumer", 1) => Some(LiteralRun::R552),
        ("./.release/tool/memcordon-ci release public-consumer", 2) => Some(LiteralRun::R552),
        ("./.release/tool/memcordon-ci release public-consumer", 3) => Some(LiteralRun::R552),
        ("./.release/tool/memcordon-ci release public-consumer", 4) => Some(LiteralRun::R552),
        ("./.release/tool/memcordon-ci release public-consumer", 5) => Some(LiteralRun::R552),
        ("./.release/tool/memcordon-ci release publish", 0) => Some(LiteralRun::R546),
        ("./.release/tool/memcordon-ci release publish", 1) => Some(LiteralRun::R546),
        ("./.release/tool/memcordon-ci release publish", 2) => Some(LiteralRun::R546),
        ("./.release/tool/memcordon-ci release publish", 3) => Some(LiteralRun::R546),
        ("./.release/tool/memcordon-ci release publish", 4) => Some(LiteralRun::R546),
        ("./.release/tool/memcordon-ci release publish", 5) => Some(LiteralRun::R546),
        ("./.release/tool/memcordon-ci release recovery-inputs", 0) => Some(LiteralRun::R545),
        ("./.release/tool/memcordon-ci release recovery-inputs", 1) => Some(LiteralRun::R545),
        ("./.release/tool/memcordon-ci release recovery-inputs", 2) => Some(LiteralRun::R545),
        ("./.release/tool/memcordon-ci release recovery-inputs", 3) => Some(LiteralRun::R545),
        ("./.release/tool/memcordon-ci release recovery-inputs", 4) => Some(LiteralRun::R545),
        ("./.release/tool/memcordon-ci release recovery-inputs", 5) => Some(LiteralRun::R545),
        (
            "./.release/tool/memcordon-ci release rehearsal-tool --executable target/ci/rehearsal-build/release/memcordon-release-rehearsal",
            0,
        ) => Some(LiteralRun::R391),
        (
            "./.release/tool/memcordon-ci release rehearsal-tool --executable target/ci/rehearsal-build/release/memcordon-release-rehearsal",
            1,
        ) => Some(LiteralRun::R391),
        (
            "./.release/tool/memcordon-ci release rehearsal-tool --executable target/ci/rehearsal-build/release/memcordon-release-rehearsal",
            2,
        ) => Some(LiteralRun::R391),
        (
            "./.release/tool/memcordon-ci release rehearsal-tool --executable target/ci/rehearsal-build/release/memcordon-release-rehearsal",
            3,
        ) => Some(LiteralRun::R391),
        (
            "./.release/tool/memcordon-ci release rehearsal-tool --executable target/ci/rehearsal-build/release/memcordon-release-rehearsal",
            4,
        ) => Some(LiteralRun::R391),
        (
            "./.release/tool/memcordon-ci release rehearsal-tool --executable target/ci/rehearsal-build/release/memcordon-release-rehearsal",
            5,
        ) => Some(LiteralRun::R391),
        ("./.release/tool/memcordon-ci release select-preparation", 0) => Some(LiteralRun::R544),
        ("./.release/tool/memcordon-ci release select-preparation", 1) => Some(LiteralRun::R544),
        ("./.release/tool/memcordon-ci release select-preparation", 2) => Some(LiteralRun::R544),
        ("./.release/tool/memcordon-ci release select-preparation", 3) => Some(LiteralRun::R544),
        ("./.release/tool/memcordon-ci release select-preparation", 4) => Some(LiteralRun::R544),
        ("./.release/tool/memcordon-ci release select-preparation", 5) => Some(LiteralRun::R544),
        (
            "./.release/tool/memcordon-ci release verify-source --build-source .release/build-source.json",
            0,
        ) => Some(LiteralRun::R343),
        (
            "./.release/tool/memcordon-ci release verify-source --build-source .release/build-source.json",
            1,
        ) => Some(LiteralRun::R343),
        (
            "./.release/tool/memcordon-ci release verify-source --build-source .release/build-source.json",
            2,
        ) => Some(LiteralRun::R343),
        (
            "./.release/tool/memcordon-ci release verify-source --build-source .release/build-source.json",
            3,
        ) => Some(LiteralRun::R343),
        (
            "./.release/tool/memcordon-ci release verify-source --build-source .release/build-source.json",
            4,
        ) => Some(LiteralRun::R343),
        (
            "./.release/tool/memcordon-ci release verify-source --build-source .release/build-source.json",
            5,
        ) => Some(LiteralRun::R343),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-four --failure-mode collect-all",
            0,
        ) => Some(LiteralRun::R488),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-four --failure-mode collect-all",
            1,
        ) => Some(LiteralRun::R488),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-four --failure-mode collect-all",
            2,
        ) => Some(LiteralRun::R488),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-four --failure-mode collect-all",
            3,
        ) => Some(LiteralRun::R488),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-four --failure-mode collect-all",
            4,
        ) => Some(LiteralRun::R488),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-four --failure-mode collect-all",
            5,
        ) => Some(LiteralRun::R488),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-four --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R487),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-four --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R487),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-four --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R487),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-four --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R487),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-four --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R487),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-four --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R487),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-one --failure-mode collect-all",
            0,
        ) => Some(LiteralRun::R470),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-one --failure-mode collect-all",
            1,
        ) => Some(LiteralRun::R470),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-one --failure-mode collect-all",
            2,
        ) => Some(LiteralRun::R470),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-one --failure-mode collect-all",
            3,
        ) => Some(LiteralRun::R470),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-one --failure-mode collect-all",
            4,
        ) => Some(LiteralRun::R470),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-one --failure-mode collect-all",
            5,
        ) => Some(LiteralRun::R470),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-one --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R469),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-one --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R469),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-one --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R469),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-one --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R469),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-one --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R469),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-one --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R469),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-three --failure-mode collect-all",
            0,
        ) => Some(LiteralRun::R472),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-three --failure-mode collect-all",
            1,
        ) => Some(LiteralRun::R472),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-three --failure-mode collect-all",
            2,
        ) => Some(LiteralRun::R472),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-three --failure-mode collect-all",
            3,
        ) => Some(LiteralRun::R472),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-three --failure-mode collect-all",
            4,
        ) => Some(LiteralRun::R472),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-three --failure-mode collect-all",
            5,
        ) => Some(LiteralRun::R472),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-three --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R471),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-three --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R471),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-three --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R471),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-three --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R471),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-three --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R471),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-three --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R471),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-two --failure-mode collect-all",
            0,
        ) => Some(LiteralRun::R486),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-two --failure-mode collect-all",
            1,
        ) => Some(LiteralRun::R486),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-two --failure-mode collect-all",
            2,
        ) => Some(LiteralRun::R486),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-two --failure-mode collect-all",
            3,
        ) => Some(LiteralRun::R486),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-two --failure-mode collect-all",
            4,
        ) => Some(LiteralRun::R486),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-two --failure-mode collect-all",
            5,
        ) => Some(LiteralRun::R486),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-two --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R485),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-two --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R485),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-two --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R485),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-two --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R485),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-two --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R485),
        (
            "./.release/tool/memcordon-ci suite fuzz-compile-quarter-two --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R485),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-four --failure-mode collect-all",
            0,
        ) => Some(LiteralRun::R496),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-four --failure-mode collect-all",
            1,
        ) => Some(LiteralRun::R496),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-four --failure-mode collect-all",
            2,
        ) => Some(LiteralRun::R496),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-four --failure-mode collect-all",
            3,
        ) => Some(LiteralRun::R496),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-four --failure-mode collect-all",
            4,
        ) => Some(LiteralRun::R496),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-four --failure-mode collect-all",
            5,
        ) => Some(LiteralRun::R496),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-four --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R495),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-four --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R495),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-four --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R495),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-four --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R495),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-four --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R495),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-four --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R495),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-one --failure-mode collect-all",
            0,
        ) => Some(LiteralRun::R478),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-one --failure-mode collect-all",
            1,
        ) => Some(LiteralRun::R478),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-one --failure-mode collect-all",
            2,
        ) => Some(LiteralRun::R478),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-one --failure-mode collect-all",
            3,
        ) => Some(LiteralRun::R478),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-one --failure-mode collect-all",
            4,
        ) => Some(LiteralRun::R478),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-one --failure-mode collect-all",
            5,
        ) => Some(LiteralRun::R478),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-one --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R477),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-one --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R477),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-one --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R477),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-one --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R477),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-one --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R477),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-one --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R477),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-three --failure-mode collect-all",
            0,
        ) => Some(LiteralRun::R480),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-three --failure-mode collect-all",
            1,
        ) => Some(LiteralRun::R480),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-three --failure-mode collect-all",
            2,
        ) => Some(LiteralRun::R480),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-three --failure-mode collect-all",
            3,
        ) => Some(LiteralRun::R480),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-three --failure-mode collect-all",
            4,
        ) => Some(LiteralRun::R480),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-three --failure-mode collect-all",
            5,
        ) => Some(LiteralRun::R480),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-three --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R479),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-three --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R479),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-three --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R479),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-three --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R479),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-three --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R479),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-three --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R479),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-two --failure-mode collect-all",
            0,
        ) => Some(LiteralRun::R494),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-two --failure-mode collect-all",
            1,
        ) => Some(LiteralRun::R494),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-two --failure-mode collect-all",
            2,
        ) => Some(LiteralRun::R494),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-two --failure-mode collect-all",
            3,
        ) => Some(LiteralRun::R494),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-two --failure-mode collect-all",
            4,
        ) => Some(LiteralRun::R494),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-two --failure-mode collect-all",
            5,
        ) => Some(LiteralRun::R494),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-two --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R493),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-two --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R493),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-two --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R493),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-two --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R493),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-two --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R493),
        (
            "./.release/tool/memcordon-ci suite fuzz-execute-quarter-two --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R493),
        ("./.release/tool/memcordon-ci suite miri-quarter-four --failure-mode collect-all", 0) => {
            Some(LiteralRun::R429)
        }
        ("./.release/tool/memcordon-ci suite miri-quarter-four --failure-mode collect-all", 1) => {
            Some(LiteralRun::R429)
        }
        ("./.release/tool/memcordon-ci suite miri-quarter-four --failure-mode collect-all", 2) => {
            Some(LiteralRun::R429)
        }
        ("./.release/tool/memcordon-ci suite miri-quarter-four --failure-mode collect-all", 3) => {
            Some(LiteralRun::R429)
        }
        ("./.release/tool/memcordon-ci suite miri-quarter-four --failure-mode collect-all", 4) => {
            Some(LiteralRun::R429)
        }
        ("./.release/tool/memcordon-ci suite miri-quarter-four --failure-mode collect-all", 5) => {
            Some(LiteralRun::R429)
        }
        (
            "./.release/tool/memcordon-ci suite miri-quarter-four --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R428),
        (
            "./.release/tool/memcordon-ci suite miri-quarter-four --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R428),
        (
            "./.release/tool/memcordon-ci suite miri-quarter-four --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R428),
        (
            "./.release/tool/memcordon-ci suite miri-quarter-four --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R428),
        (
            "./.release/tool/memcordon-ci suite miri-quarter-four --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R428),
        (
            "./.release/tool/memcordon-ci suite miri-quarter-four --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R428),
        ("./.release/tool/memcordon-ci suite miri-quarter-one --failure-mode collect-all", 0) => {
            Some(LiteralRun::R423)
        }
        ("./.release/tool/memcordon-ci suite miri-quarter-one --failure-mode collect-all", 1) => {
            Some(LiteralRun::R423)
        }
        ("./.release/tool/memcordon-ci suite miri-quarter-one --failure-mode collect-all", 2) => {
            Some(LiteralRun::R423)
        }
        ("./.release/tool/memcordon-ci suite miri-quarter-one --failure-mode collect-all", 3) => {
            Some(LiteralRun::R423)
        }
        ("./.release/tool/memcordon-ci suite miri-quarter-one --failure-mode collect-all", 4) => {
            Some(LiteralRun::R423)
        }
        ("./.release/tool/memcordon-ci suite miri-quarter-one --failure-mode collect-all", 5) => {
            Some(LiteralRun::R423)
        }
        (
            "./.release/tool/memcordon-ci suite miri-quarter-one --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R422),
        (
            "./.release/tool/memcordon-ci suite miri-quarter-one --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R422),
        (
            "./.release/tool/memcordon-ci suite miri-quarter-one --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R422),
        (
            "./.release/tool/memcordon-ci suite miri-quarter-one --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R422),
        (
            "./.release/tool/memcordon-ci suite miri-quarter-one --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R422),
        (
            "./.release/tool/memcordon-ci suite miri-quarter-one --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R422),
        ("./.release/tool/memcordon-ci suite miri-quarter-three --failure-mode collect-all", 0) => {
            Some(LiteralRun::R425)
        }
        ("./.release/tool/memcordon-ci suite miri-quarter-three --failure-mode collect-all", 1) => {
            Some(LiteralRun::R425)
        }
        ("./.release/tool/memcordon-ci suite miri-quarter-three --failure-mode collect-all", 2) => {
            Some(LiteralRun::R425)
        }
        ("./.release/tool/memcordon-ci suite miri-quarter-three --failure-mode collect-all", 3) => {
            Some(LiteralRun::R425)
        }
        ("./.release/tool/memcordon-ci suite miri-quarter-three --failure-mode collect-all", 4) => {
            Some(LiteralRun::R425)
        }
        ("./.release/tool/memcordon-ci suite miri-quarter-three --failure-mode collect-all", 5) => {
            Some(LiteralRun::R425)
        }
        (
            "./.release/tool/memcordon-ci suite miri-quarter-three --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R424),
        (
            "./.release/tool/memcordon-ci suite miri-quarter-three --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R424),
        (
            "./.release/tool/memcordon-ci suite miri-quarter-three --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R424),
        (
            "./.release/tool/memcordon-ci suite miri-quarter-three --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R424),
        (
            "./.release/tool/memcordon-ci suite miri-quarter-three --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R424),
        (
            "./.release/tool/memcordon-ci suite miri-quarter-three --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R424),
        ("./.release/tool/memcordon-ci suite miri-quarter-two --failure-mode collect-all", 0) => {
            Some(LiteralRun::R427)
        }
        ("./.release/tool/memcordon-ci suite miri-quarter-two --failure-mode collect-all", 1) => {
            Some(LiteralRun::R427)
        }
        ("./.release/tool/memcordon-ci suite miri-quarter-two --failure-mode collect-all", 2) => {
            Some(LiteralRun::R427)
        }
        ("./.release/tool/memcordon-ci suite miri-quarter-two --failure-mode collect-all", 3) => {
            Some(LiteralRun::R427)
        }
        ("./.release/tool/memcordon-ci suite miri-quarter-two --failure-mode collect-all", 4) => {
            Some(LiteralRun::R427)
        }
        ("./.release/tool/memcordon-ci suite miri-quarter-two --failure-mode collect-all", 5) => {
            Some(LiteralRun::R427)
        }
        (
            "./.release/tool/memcordon-ci suite miri-quarter-two --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R426),
        (
            "./.release/tool/memcordon-ci suite miri-quarter-two --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R426),
        (
            "./.release/tool/memcordon-ci suite miri-quarter-two --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R426),
        (
            "./.release/tool/memcordon-ci suite miri-quarter-two --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R426),
        (
            "./.release/tool/memcordon-ci suite miri-quarter-two --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R426),
        (
            "./.release/tool/memcordon-ci suite miri-quarter-two --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R426),
        ("./.release/tool/memcordon-ci suite msrv --failure-mode collect-all", 0) => {
            Some(LiteralRun::R363)
        }
        ("./.release/tool/memcordon-ci suite msrv --failure-mode collect-all", 1) => {
            Some(LiteralRun::R363)
        }
        ("./.release/tool/memcordon-ci suite msrv --failure-mode collect-all", 2) => {
            Some(LiteralRun::R363)
        }
        ("./.release/tool/memcordon-ci suite msrv --failure-mode collect-all", 3) => {
            Some(LiteralRun::R363)
        }
        ("./.release/tool/memcordon-ci suite msrv --failure-mode collect-all", 4) => {
            Some(LiteralRun::R363)
        }
        ("./.release/tool/memcordon-ci suite msrv --failure-mode collect-all", 5) => {
            Some(LiteralRun::R363)
        }
        ("./.release/tool/memcordon-ci suite msrv --failure-mode stop-after-failure", 0) => {
            Some(LiteralRun::R362)
        }
        ("./.release/tool/memcordon-ci suite msrv --failure-mode stop-after-failure", 1) => {
            Some(LiteralRun::R362)
        }
        ("./.release/tool/memcordon-ci suite msrv --failure-mode stop-after-failure", 2) => {
            Some(LiteralRun::R362)
        }
        ("./.release/tool/memcordon-ci suite msrv --failure-mode stop-after-failure", 3) => {
            Some(LiteralRun::R362)
        }
        ("./.release/tool/memcordon-ci suite msrv --failure-mode stop-after-failure", 4) => {
            Some(LiteralRun::R362)
        }
        ("./.release/tool/memcordon-ci suite msrv --failure-mode stop-after-failure", 5) => {
            Some(LiteralRun::R362)
        }
        ("./.release/tool/memcordon-ci suite quality-compile --failure-mode collect-all", 0) => {
            Some(LiteralRun::R352)
        }
        ("./.release/tool/memcordon-ci suite quality-compile --failure-mode collect-all", 1) => {
            Some(LiteralRun::R352)
        }
        ("./.release/tool/memcordon-ci suite quality-compile --failure-mode collect-all", 2) => {
            Some(LiteralRun::R352)
        }
        ("./.release/tool/memcordon-ci suite quality-compile --failure-mode collect-all", 3) => {
            Some(LiteralRun::R352)
        }
        ("./.release/tool/memcordon-ci suite quality-compile --failure-mode collect-all", 4) => {
            Some(LiteralRun::R352)
        }
        ("./.release/tool/memcordon-ci suite quality-compile --failure-mode collect-all", 5) => {
            Some(LiteralRun::R352)
        }
        (
            "./.release/tool/memcordon-ci suite quality-compile --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R351),
        (
            "./.release/tool/memcordon-ci suite quality-compile --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R351),
        (
            "./.release/tool/memcordon-ci suite quality-compile --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R351),
        (
            "./.release/tool/memcordon-ci suite quality-compile --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R351),
        (
            "./.release/tool/memcordon-ci suite quality-compile --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R351),
        (
            "./.release/tool/memcordon-ci suite quality-compile --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R351),
        ("./.release/tool/memcordon-ci suite supply-chain --failure-mode collect-all", 0) => {
            Some(LiteralRun::R377)
        }
        ("./.release/tool/memcordon-ci suite supply-chain --failure-mode collect-all", 1) => {
            Some(LiteralRun::R377)
        }
        ("./.release/tool/memcordon-ci suite supply-chain --failure-mode collect-all", 2) => {
            Some(LiteralRun::R377)
        }
        ("./.release/tool/memcordon-ci suite supply-chain --failure-mode collect-all", 3) => {
            Some(LiteralRun::R377)
        }
        ("./.release/tool/memcordon-ci suite supply-chain --failure-mode collect-all", 4) => {
            Some(LiteralRun::R377)
        }
        ("./.release/tool/memcordon-ci suite supply-chain --failure-mode collect-all", 5) => {
            Some(LiteralRun::R377)
        }
        (
            "./.release/tool/memcordon-ci suite supply-chain --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R376),
        (
            "./.release/tool/memcordon-ci suite supply-chain --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R376),
        (
            "./.release/tool/memcordon-ci suite supply-chain --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R376),
        (
            "./.release/tool/memcordon-ci suite supply-chain --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R376),
        (
            "./.release/tool/memcordon-ci suite supply-chain --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R376),
        (
            "./.release/tool/memcordon-ci suite supply-chain --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R376),
        (
            "./target/ci/release/consumer-readiness acquire --github-context --driver ./target/ci/release/memcordon-ci --identity .release/readiness-identity.json --destination .release/readiness-cell",
            0,
        ) => Some(LiteralRun::R553),
        (
            "./target/ci/release/consumer-readiness acquire --github-context --driver ./target/ci/release/memcordon-ci --identity .release/readiness-identity.json --destination .release/readiness-cell",
            1,
        ) => Some(LiteralRun::R554),
        (
            "./target/ci/release/consumer-readiness acquire --github-context --driver ./target/ci/release/memcordon-ci --identity .release/readiness-identity.json --destination .release/readiness-cell",
            2,
        ) => Some(LiteralRun::R533),
        (
            "./target/ci/release/consumer-readiness acquire --github-context --driver ./target/ci/release/memcordon-ci --identity .release/readiness-identity.json --destination .release/readiness-cell",
            3,
        ) => Some(LiteralRun::R555),
        (
            "./target/ci/release/consumer-readiness acquire --github-context --driver ./target/ci/release/memcordon-ci --identity .release/readiness-identity.json --destination .release/readiness-cell",
            4,
        ) => Some(LiteralRun::R556),
        (
            "./target/ci/release/consumer-readiness acquire --github-context --driver ./target/ci/release/memcordon-ci --identity .release/readiness-identity.json --destination .release/readiness-cell",
            5,
        ) => Some(LiteralRun::R557),
        (
            "./target/ci/release/consumer-readiness cleanup --github-context --driver ./target/ci/release/memcordon-ci --identity .release/readiness-identity.json --destination .release/readiness-cell",
            0,
        ) => Some(LiteralRun::R558),
        (
            "./target/ci/release/consumer-readiness cleanup --github-context --driver ./target/ci/release/memcordon-ci --identity .release/readiness-identity.json --destination .release/readiness-cell",
            1,
        ) => Some(LiteralRun::R559),
        (
            "./target/ci/release/consumer-readiness cleanup --github-context --driver ./target/ci/release/memcordon-ci --identity .release/readiness-identity.json --destination .release/readiness-cell",
            2,
        ) => Some(LiteralRun::R534),
        (
            "./target/ci/release/consumer-readiness cleanup --github-context --driver ./target/ci/release/memcordon-ci --identity .release/readiness-identity.json --destination .release/readiness-cell",
            3,
        ) => Some(LiteralRun::R560),
        (
            "./target/ci/release/consumer-readiness cleanup --github-context --driver ./target/ci/release/memcordon-ci --identity .release/readiness-identity.json --destination .release/readiness-cell",
            4,
        ) => Some(LiteralRun::R561),
        (
            "./target/ci/release/consumer-readiness cleanup --github-context --driver ./target/ci/release/memcordon-ci --identity .release/readiness-identity.json --destination .release/readiness-cell",
            5,
        ) => Some(LiteralRun::R562),
        (
            "./target/ci/release/consumer-readiness identity --github-context --build-source .release/build-source.json --output .release/native-readiness-identity.json",
            0,
        ) => Some(LiteralRun::R525),
        (
            "./target/ci/release/consumer-readiness identity --github-context --build-source .release/build-source.json --output .release/native-readiness-identity.json",
            1,
        ) => Some(LiteralRun::R525),
        (
            "./target/ci/release/consumer-readiness identity --github-context --build-source .release/build-source.json --output .release/native-readiness-identity.json",
            2,
        ) => Some(LiteralRun::R525),
        (
            "./target/ci/release/consumer-readiness identity --github-context --build-source .release/build-source.json --output .release/native-readiness-identity.json",
            3,
        ) => Some(LiteralRun::R563),
        (
            "./target/ci/release/consumer-readiness identity --github-context --build-source .release/build-source.json --output .release/native-readiness-identity.json",
            4,
        ) => Some(LiteralRun::R563),
        (
            "./target/ci/release/consumer-readiness identity --github-context --build-source .release/build-source.json --output .release/native-readiness-identity.json",
            5,
        ) => Some(LiteralRun::R564),
        (
            "./target/ci/release/consumer-readiness identity --github-context --build-source .release/build-source.json --output .release/readiness-identity.json",
            0,
        ) => Some(LiteralRun::R531),
        (
            "./target/ci/release/consumer-readiness identity --github-context --build-source .release/build-source.json --output .release/readiness-identity.json",
            1,
        ) => Some(LiteralRun::R531),
        (
            "./target/ci/release/consumer-readiness identity --github-context --build-source .release/build-source.json --output .release/readiness-identity.json",
            2,
        ) => Some(LiteralRun::R531),
        (
            "./target/ci/release/consumer-readiness identity --github-context --build-source .release/build-source.json --output .release/readiness-identity.json",
            3,
        ) => Some(LiteralRun::R565),
        (
            "./target/ci/release/consumer-readiness identity --github-context --build-source .release/build-source.json --output .release/readiness-identity.json",
            4,
        ) => Some(LiteralRun::R565),
        (
            "./target/ci/release/consumer-readiness identity --github-context --build-source .release/build-source.json --output .release/readiness-identity.json",
            5,
        ) => Some(LiteralRun::R566),
        (
            "./target/ci/release/consumer-readiness seal-producer --github-context --identity .release/readiness-identity.json --manifest ci/consumer-readiness-v2.toml --cell .release/readiness-cell/cell.json --output .release/readiness-cell/producer-manifest.json",
            0,
        ) => Some(LiteralRun::R535),
        (
            "./target/ci/release/consumer-readiness seal-producer --github-context --identity .release/readiness-identity.json --manifest ci/consumer-readiness-v2.toml --cell .release/readiness-cell/cell.json --output .release/readiness-cell/producer-manifest.json",
            1,
        ) => Some(LiteralRun::R535),
        (
            "./target/ci/release/consumer-readiness seal-producer --github-context --identity .release/readiness-identity.json --manifest ci/consumer-readiness-v2.toml --cell .release/readiness-cell/cell.json --output .release/readiness-cell/producer-manifest.json",
            2,
        ) => Some(LiteralRun::R535),
        (
            "./target/ci/release/consumer-readiness seal-producer --github-context --identity .release/readiness-identity.json --manifest ci/consumer-readiness-v2.toml --cell .release/readiness-cell/cell.json --output .release/readiness-cell/producer-manifest.json",
            3,
        ) => Some(LiteralRun::R567),
        (
            "./target/ci/release/consumer-readiness seal-producer --github-context --identity .release/readiness-identity.json --manifest ci/consumer-readiness-v2.toml --cell .release/readiness-cell/cell.json --output .release/readiness-cell/producer-manifest.json",
            4,
        ) => Some(LiteralRun::R567),
        (
            "./target/ci/release/consumer-readiness seal-producer --github-context --identity .release/readiness-identity.json --manifest ci/consumer-readiness-v2.toml --cell .release/readiness-cell/cell.json --output .release/readiness-cell/producer-manifest.json",
            5,
        ) => Some(LiteralRun::R568),
        ("./target/ci/release/memcordon-ci ci aggregate-macos", 0) => Some(LiteralRun::R569),
        ("./target/ci/release/memcordon-ci ci aggregate-macos", 1) => Some(LiteralRun::R570),
        ("./target/ci/release/memcordon-ci ci aggregate-macos", 2) => Some(LiteralRun::R263),
        ("./target/ci/release/memcordon-ci ci aggregate-macos", 3) => Some(LiteralRun::R263),
        ("./target/ci/release/memcordon-ci ci aggregate-macos", 4) => Some(LiteralRun::R569),
        ("./target/ci/release/memcordon-ci ci aggregate-macos", 5) => Some(LiteralRun::R570),
        ("./target/ci/release/memcordon-ci ci aggregate-stress", 0) => Some(LiteralRun::R571),
        ("./target/ci/release/memcordon-ci ci aggregate-stress", 1) => Some(LiteralRun::R572),
        ("./target/ci/release/memcordon-ci ci aggregate-stress", 2) => Some(LiteralRun::R232),
        ("./target/ci/release/memcordon-ci ci aggregate-stress", 3) => Some(LiteralRun::R232),
        ("./target/ci/release/memcordon-ci ci aggregate-stress", 4) => Some(LiteralRun::R571),
        ("./target/ci/release/memcordon-ci ci aggregate-stress", 5) => Some(LiteralRun::R572),
        ("./target/ci/release/memcordon-ci ci bootstrap-cache-context", 0) => {
            Some(LiteralRun::R573)
        }
        ("./target/ci/release/memcordon-ci ci bootstrap-cache-context", 1) => {
            Some(LiteralRun::R574)
        }
        ("./target/ci/release/memcordon-ci ci bootstrap-cache-context", 2) => Some(LiteralRun::R2),
        ("./target/ci/release/memcordon-ci ci bootstrap-cache-context", 3) => Some(LiteralRun::R2),
        ("./target/ci/release/memcordon-ci ci bootstrap-cache-context", 4) => {
            Some(LiteralRun::R573)
        }
        ("./target/ci/release/memcordon-ci ci bootstrap-cache-context", 5) => {
            Some(LiteralRun::R574)
        }
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose backend --shard complete",
            0,
        ) => Some(LiteralRun::R575),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose backend --shard complete",
            1,
        ) => Some(LiteralRun::R576),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose backend --shard complete",
            2,
        ) => Some(LiteralRun::R315),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose backend --shard complete",
            3,
        ) => Some(LiteralRun::R315),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose backend --shard complete",
            4,
        ) => Some(LiteralRun::R575),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose backend --shard complete",
            5,
        ) => Some(LiteralRun::R576),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose backend --shard complete --for-save",
            0,
        ) => Some(LiteralRun::R577),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose backend --shard complete --for-save",
            1,
        ) => Some(LiteralRun::R578),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose backend --shard complete --for-save",
            2,
        ) => Some(LiteralRun::R322),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose backend --shard complete --for-save",
            3,
        ) => Some(LiteralRun::R322),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose backend --shard complete --for-save",
            4,
        ) => Some(LiteralRun::R577),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose backend --shard complete --for-save",
            5,
        ) => Some(LiteralRun::R578),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-audit --shard complete",
            0,
        ) => Some(LiteralRun::R579),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-audit --shard complete",
            1,
        ) => Some(LiteralRun::R580),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-audit --shard complete",
            2,
        ) => Some(LiteralRun::R40),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-audit --shard complete",
            3,
        ) => Some(LiteralRun::R40),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-audit --shard complete",
            4,
        ) => Some(LiteralRun::R579),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-audit --shard complete",
            5,
        ) => Some(LiteralRun::R580),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-audit --shard complete --for-save",
            0,
        ) => Some(LiteralRun::R581),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-audit --shard complete --for-save",
            1,
        ) => Some(LiteralRun::R582),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-audit --shard complete --for-save",
            2,
        ) => Some(LiteralRun::R49),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-audit --shard complete --for-save",
            3,
        ) => Some(LiteralRun::R49),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-audit --shard complete --for-save",
            4,
        ) => Some(LiteralRun::R581),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-audit --shard complete --for-save",
            5,
        ) => Some(LiteralRun::R582),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-deny --shard complete",
            0,
        ) => Some(LiteralRun::R583),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-deny --shard complete",
            1,
        ) => Some(LiteralRun::R584),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-deny --shard complete",
            2,
        ) => Some(LiteralRun::R42),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-deny --shard complete",
            3,
        ) => Some(LiteralRun::R42),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-deny --shard complete",
            4,
        ) => Some(LiteralRun::R583),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-deny --shard complete",
            5,
        ) => Some(LiteralRun::R584),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-deny --shard complete --for-save",
            0,
        ) => Some(LiteralRun::R585),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-deny --shard complete --for-save",
            1,
        ) => Some(LiteralRun::R586),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-deny --shard complete --for-save",
            2,
        ) => Some(LiteralRun::R50),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-deny --shard complete --for-save",
            3,
        ) => Some(LiteralRun::R50),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-deny --shard complete --for-save",
            4,
        ) => Some(LiteralRun::R585),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-deny --shard complete --for-save",
            5,
        ) => Some(LiteralRun::R586),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete",
            0,
        ) => Some(LiteralRun::R587),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete",
            1,
        ) => Some(LiteralRun::R588),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete",
            2,
        ) => Some(LiteralRun::R140),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete",
            3,
        ) => Some(LiteralRun::R140),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete",
            4,
        ) => Some(LiteralRun::R587),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete",
            5,
        ) => Some(LiteralRun::R588),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete --for-save",
            0,
        ) => Some(LiteralRun::R589),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete --for-save",
            1,
        ) => Some(LiteralRun::R590),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete --for-save",
            2,
        ) => Some(LiteralRun::R199),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete --for-save",
            3,
        ) => Some(LiteralRun::R199),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete --for-save",
            4,
        ) => Some(LiteralRun::R589),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose cargo-fuzz --shard complete --for-save",
            5,
        ) => Some(LiteralRun::R590),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose consumer-readiness --shard candidate",
            0,
        ) => Some(LiteralRun::R591),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose consumer-readiness --shard candidate",
            1,
        ) => Some(LiteralRun::R592),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose consumer-readiness --shard candidate",
            2,
        ) => Some(LiteralRun::R532),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose consumer-readiness --shard candidate",
            3,
        ) => Some(LiteralRun::R532),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose consumer-readiness --shard candidate",
            4,
        ) => Some(LiteralRun::R591),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose consumer-readiness --shard candidate",
            5,
        ) => Some(LiteralRun::R592),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose consumer-readiness --shard public",
            0,
        ) => Some(LiteralRun::R593),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose consumer-readiness --shard public",
            1,
        ) => Some(LiteralRun::R594),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose consumer-readiness --shard public",
            2,
        ) => Some(LiteralRun::R548),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose consumer-readiness --shard public",
            3,
        ) => Some(LiteralRun::R548),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose consumer-readiness --shard public",
            4,
        ) => Some(LiteralRun::R593),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose consumer-readiness --shard public",
            5,
        ) => Some(LiteralRun::R594),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose deadline --shard complete",
            0,
        ) => Some(LiteralRun::R595),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose deadline --shard complete",
            1,
        ) => Some(LiteralRun::R596),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose deadline --shard complete",
            2,
        ) => Some(LiteralRun::R80),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose deadline --shard complete",
            3,
        ) => Some(LiteralRun::R80),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose deadline --shard complete",
            4,
        ) => Some(LiteralRun::R595),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose deadline --shard complete",
            5,
        ) => Some(LiteralRun::R596),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose deadline --shard complete --for-save",
            0,
        ) => Some(LiteralRun::R597),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose deadline --shard complete --for-save",
            1,
        ) => Some(LiteralRun::R598),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose deadline --shard complete --for-save",
            2,
        ) => Some(LiteralRun::R87),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose deadline --shard complete --for-save",
            3,
        ) => Some(LiteralRun::R87),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose deadline --shard complete --for-save",
            4,
        ) => Some(LiteralRun::R597),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose deadline --shard complete --for-save",
            5,
        ) => Some(LiteralRun::R598),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R599),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R600),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R150),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R150),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R599),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R600),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets --for-save",
            0,
        ) => Some(LiteralRun::R601),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets --for-save",
            1,
        ) => Some(LiteralRun::R602),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets --for-save",
            2,
        ) => Some(LiteralRun::R198),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets --for-save",
            3,
        ) => Some(LiteralRun::R198),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets --for-save",
            4,
        ) => Some(LiteralRun::R601),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-four --partition fuzz-targets --for-save",
            5,
        ) => Some(LiteralRun::R602),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R603),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R604),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R147),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R147),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R603),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R604),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets --for-save",
            0,
        ) => Some(LiteralRun::R605),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets --for-save",
            1,
        ) => Some(LiteralRun::R606),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets --for-save",
            2,
        ) => Some(LiteralRun::R195),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets --for-save",
            3,
        ) => Some(LiteralRun::R195),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets --for-save",
            4,
        ) => Some(LiteralRun::R605),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-one --partition fuzz-targets --for-save",
            5,
        ) => Some(LiteralRun::R606),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R607),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R608),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R149),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R149),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R607),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R608),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets --for-save",
            0,
        ) => Some(LiteralRun::R609),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets --for-save",
            1,
        ) => Some(LiteralRun::R610),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets --for-save",
            2,
        ) => Some(LiteralRun::R197),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets --for-save",
            3,
        ) => Some(LiteralRun::R197),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets --for-save",
            4,
        ) => Some(LiteralRun::R609),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-three --partition fuzz-targets --for-save",
            5,
        ) => Some(LiteralRun::R610),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R611),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R612),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R148),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R148),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R611),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R612),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets --for-save",
            0,
        ) => Some(LiteralRun::R613),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets --for-save",
            1,
        ) => Some(LiteralRun::R614),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets --for-save",
            2,
        ) => Some(LiteralRun::R196),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets --for-save",
            3,
        ) => Some(LiteralRun::R196),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets --for-save",
            4,
        ) => Some(LiteralRun::R613),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose fuzz --shard quarter-two --partition fuzz-targets --for-save",
            5,
        ) => Some(LiteralRun::R614),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard acceptance",
            0,
        ) => Some(LiteralRun::R615),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard acceptance",
            1,
        ) => Some(LiteralRun::R616),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard acceptance",
            2,
        ) => Some(LiteralRun::R253),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard acceptance",
            3,
        ) => Some(LiteralRun::R253),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard acceptance",
            4,
        ) => Some(LiteralRun::R615),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard acceptance",
            5,
        ) => Some(LiteralRun::R616),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard acceptance --for-save",
            0,
        ) => Some(LiteralRun::R617),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard acceptance --for-save",
            1,
        ) => Some(LiteralRun::R618),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard acceptance --for-save",
            2,
        ) => Some(LiteralRun::R260),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard acceptance --for-save",
            3,
        ) => Some(LiteralRun::R260),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard acceptance --for-save",
            4,
        ) => Some(LiteralRun::R617),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard acceptance --for-save",
            5,
        ) => Some(LiteralRun::R618),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard combined",
            0,
        ) => Some(LiteralRun::R619),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard combined",
            1,
        ) => Some(LiteralRun::R620),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard combined",
            2,
        ) => Some(LiteralRun::R233),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard combined",
            3,
        ) => Some(LiteralRun::R233),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard combined",
            4,
        ) => Some(LiteralRun::R619),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard combined",
            5,
        ) => Some(LiteralRun::R620),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard combined --for-save",
            0,
        ) => Some(LiteralRun::R621),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard combined --for-save",
            1,
        ) => Some(LiteralRun::R622),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard combined --for-save",
            2,
        ) => Some(LiteralRun::R240),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard combined --for-save",
            3,
        ) => Some(LiteralRun::R240),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard combined --for-save",
            4,
        ) => Some(LiteralRun::R621),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard combined --for-save",
            5,
        ) => Some(LiteralRun::R622),
        ("./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard native", 0) => {
            Some(LiteralRun::R623)
        }
        ("./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard native", 1) => {
            Some(LiteralRun::R624)
        }
        ("./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard native", 2) => {
            Some(LiteralRun::R243)
        }
        ("./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard native", 3) => {
            Some(LiteralRun::R243)
        }
        ("./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard native", 4) => {
            Some(LiteralRun::R623)
        }
        ("./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard native", 5) => {
            Some(LiteralRun::R624)
        }
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard native --for-save",
            0,
        ) => Some(LiteralRun::R625),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard native --for-save",
            1,
        ) => Some(LiteralRun::R626),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard native --for-save",
            2,
        ) => Some(LiteralRun::R250),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard native --for-save",
            3,
        ) => Some(LiteralRun::R250),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard native --for-save",
            4,
        ) => Some(LiteralRun::R625),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard native --for-save",
            5,
        ) => Some(LiteralRun::R626),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-four",
            0,
        ) => Some(LiteralRun::R627),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-four",
            1,
        ) => Some(LiteralRun::R628),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-four",
            2,
        ) => Some(LiteralRun::R98),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-four",
            3,
        ) => Some(LiteralRun::R98),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-four",
            4,
        ) => Some(LiteralRun::R627),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-four",
            5,
        ) => Some(LiteralRun::R628),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-four --for-save",
            0,
        ) => Some(LiteralRun::R629),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-four --for-save",
            1,
        ) => Some(LiteralRun::R630),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-four --for-save",
            2,
        ) => Some(LiteralRun::R130),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-four --for-save",
            3,
        ) => Some(LiteralRun::R130),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-four --for-save",
            4,
        ) => Some(LiteralRun::R629),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-four --for-save",
            5,
        ) => Some(LiteralRun::R630),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-one",
            0,
        ) => Some(LiteralRun::R631),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-one",
            1,
        ) => Some(LiteralRun::R632),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-one",
            2,
        ) => Some(LiteralRun::R95),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-one",
            3,
        ) => Some(LiteralRun::R95),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-one",
            4,
        ) => Some(LiteralRun::R631),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-one",
            5,
        ) => Some(LiteralRun::R632),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-one --for-save",
            0,
        ) => Some(LiteralRun::R633),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-one --for-save",
            1,
        ) => Some(LiteralRun::R634),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-one --for-save",
            2,
        ) => Some(LiteralRun::R127),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-one --for-save",
            3,
        ) => Some(LiteralRun::R127),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-one --for-save",
            4,
        ) => Some(LiteralRun::R633),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-one --for-save",
            5,
        ) => Some(LiteralRun::R634),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-three",
            0,
        ) => Some(LiteralRun::R635),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-three",
            1,
        ) => Some(LiteralRun::R636),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-three",
            2,
        ) => Some(LiteralRun::R96),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-three",
            3,
        ) => Some(LiteralRun::R96),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-three",
            4,
        ) => Some(LiteralRun::R635),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-three",
            5,
        ) => Some(LiteralRun::R636),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-three --for-save",
            0,
        ) => Some(LiteralRun::R637),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-three --for-save",
            1,
        ) => Some(LiteralRun::R638),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-three --for-save",
            2,
        ) => Some(LiteralRun::R128),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-three --for-save",
            3,
        ) => Some(LiteralRun::R128),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-three --for-save",
            4,
        ) => Some(LiteralRun::R637),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-three --for-save",
            5,
        ) => Some(LiteralRun::R638),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-two",
            0,
        ) => Some(LiteralRun::R639),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-two",
            1,
        ) => Some(LiteralRun::R640),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-two",
            2,
        ) => Some(LiteralRun::R97),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-two",
            3,
        ) => Some(LiteralRun::R97),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-two",
            4,
        ) => Some(LiteralRun::R639),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-two",
            5,
        ) => Some(LiteralRun::R640),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-two --for-save",
            0,
        ) => Some(LiteralRun::R641),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-two --for-save",
            1,
        ) => Some(LiteralRun::R642),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-two --for-save",
            2,
        ) => Some(LiteralRun::R129),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-two --for-save",
            3,
        ) => Some(LiteralRun::R129),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-two --for-save",
            4,
        ) => Some(LiteralRun::R641),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose miri --shard quarter-two --for-save",
            5,
        ) => Some(LiteralRun::R642),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose msrv --shard complete",
            0,
        ) => Some(LiteralRun::R643),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose msrv --shard complete",
            1,
        ) => Some(LiteralRun::R644),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose msrv --shard complete",
            2,
        ) => Some(LiteralRun::R27),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose msrv --shard complete",
            3,
        ) => Some(LiteralRun::R27),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose msrv --shard complete",
            4,
        ) => Some(LiteralRun::R643),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose msrv --shard complete",
            5,
        ) => Some(LiteralRun::R644),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose msrv --shard complete --for-save",
            0,
        ) => Some(LiteralRun::R645),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose msrv --shard complete --for-save",
            1,
        ) => Some(LiteralRun::R646),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose msrv --shard complete --for-save",
            2,
        ) => Some(LiteralRun::R35),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose msrv --shard complete --for-save",
            3,
        ) => Some(LiteralRun::R35),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose msrv --shard complete --for-save",
            4,
        ) => Some(LiteralRun::R645),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose msrv --shard complete --for-save",
            5,
        ) => Some(LiteralRun::R646),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-auxiliary --shard complete",
            0,
        ) => Some(LiteralRun::R647),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-auxiliary --shard complete",
            1,
        ) => Some(LiteralRun::R648),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-auxiliary --shard complete",
            2,
        ) => Some(LiteralRun::R60),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-auxiliary --shard complete",
            3,
        ) => Some(LiteralRun::R60),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-auxiliary --shard complete",
            4,
        ) => Some(LiteralRun::R647),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-auxiliary --shard complete",
            5,
        ) => Some(LiteralRun::R648),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-auxiliary --shard complete --for-save",
            0,
        ) => Some(LiteralRun::R649),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-auxiliary --shard complete --for-save",
            1,
        ) => Some(LiteralRun::R650),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-auxiliary --shard complete --for-save",
            2,
        ) => Some(LiteralRun::R75),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-auxiliary --shard complete --for-save",
            3,
        ) => Some(LiteralRun::R75),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-auxiliary --shard complete --for-save",
            4,
        ) => Some(LiteralRun::R649),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-auxiliary --shard complete --for-save",
            5,
        ) => Some(LiteralRun::R650),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-auxiliary --shard complete --partition auxiliary-profiles",
            0,
        ) => Some(LiteralRun::R651),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-auxiliary --shard complete --partition auxiliary-profiles",
            1,
        ) => Some(LiteralRun::R652),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-auxiliary --shard complete --partition auxiliary-profiles",
            2,
        ) => Some(LiteralRun::R66),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-auxiliary --shard complete --partition auxiliary-profiles",
            3,
        ) => Some(LiteralRun::R66),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-auxiliary --shard complete --partition auxiliary-profiles",
            4,
        ) => Some(LiteralRun::R651),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-auxiliary --shard complete --partition auxiliary-profiles",
            5,
        ) => Some(LiteralRun::R652),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-debug --shard complete --partition native-tests",
            0,
        ) => Some(LiteralRun::R653),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-debug --shard complete --partition native-tests",
            1,
        ) => Some(LiteralRun::R654),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-debug --shard complete --partition native-tests",
            2,
        ) => Some(LiteralRun::R56),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-debug --shard complete --partition native-tests",
            3,
        ) => Some(LiteralRun::R56),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-debug --shard complete --partition native-tests",
            4,
        ) => Some(LiteralRun::R653),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-debug --shard complete --partition native-tests",
            5,
        ) => Some(LiteralRun::R654),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-debug --shard complete --partition native-tests --for-save",
            0,
        ) => Some(LiteralRun::R655),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-debug --shard complete --partition native-tests --for-save",
            1,
        ) => Some(LiteralRun::R656),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-debug --shard complete --partition native-tests --for-save",
            2,
        ) => Some(LiteralRun::R74),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-debug --shard complete --partition native-tests --for-save",
            3,
        ) => Some(LiteralRun::R74),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-debug --shard complete --partition native-tests --for-save",
            4,
        ) => Some(LiteralRun::R655),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-debug --shard complete --partition native-tests --for-save",
            5,
        ) => Some(LiteralRun::R656),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition native-tests",
            0,
        ) => Some(LiteralRun::R657),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition native-tests",
            1,
        ) => Some(LiteralRun::R658),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition native-tests",
            2,
        ) => Some(LiteralRun::R505),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition native-tests",
            3,
        ) => Some(LiteralRun::R505),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition native-tests",
            4,
        ) => Some(LiteralRun::R657),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition native-tests",
            5,
        ) => Some(LiteralRun::R658),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition native-tests --for-save",
            0,
        ) => Some(LiteralRun::R659),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition native-tests --for-save",
            1,
        ) => Some(LiteralRun::R660),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition native-tests --for-save",
            2,
        ) => Some(LiteralRun::R519),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition native-tests --for-save",
            3,
        ) => Some(LiteralRun::R519),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition native-tests --for-save",
            4,
        ) => Some(LiteralRun::R659),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition native-tests --for-save",
            5,
        ) => Some(LiteralRun::R660),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition product",
            0,
        ) => Some(LiteralRun::R661),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition product",
            1,
        ) => Some(LiteralRun::R662),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition product",
            2,
        ) => Some(LiteralRun::R509),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition product",
            3,
        ) => Some(LiteralRun::R509),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition product",
            4,
        ) => Some(LiteralRun::R661),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition product",
            5,
        ) => Some(LiteralRun::R662),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition product --for-save",
            0,
        ) => Some(LiteralRun::R663),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition product --for-save",
            1,
        ) => Some(LiteralRun::R664),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition product --for-save",
            2,
        ) => Some(LiteralRun::R520),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition product --for-save",
            3,
        ) => Some(LiteralRun::R520),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition product --for-save",
            4,
        ) => Some(LiteralRun::R663),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose native-readiness --shard complete --partition product --for-save",
            5,
        ) => Some(LiteralRun::R664),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition native-tests",
            0,
        ) => Some(LiteralRun::R665),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition native-tests",
            1,
        ) => Some(LiteralRun::R666),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition native-tests",
            2,
        ) => Some(LiteralRun::R287),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition native-tests",
            3,
        ) => Some(LiteralRun::R287),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition native-tests",
            4,
        ) => Some(LiteralRun::R665),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition native-tests",
            5,
        ) => Some(LiteralRun::R666),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition native-tests --for-save",
            0,
        ) => Some(LiteralRun::R667),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition native-tests --for-save",
            1,
        ) => Some(LiteralRun::R668),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition native-tests --for-save",
            2,
        ) => Some(LiteralRun::R306),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition native-tests --for-save",
            3,
        ) => Some(LiteralRun::R306),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition native-tests --for-save",
            4,
        ) => Some(LiteralRun::R667),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition native-tests --for-save",
            5,
        ) => Some(LiteralRun::R668),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition private-native-tests",
            0,
        ) => Some(LiteralRun::R669),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition private-native-tests",
            1,
        ) => Some(LiteralRun::R670),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition private-native-tests",
            2,
        ) => Some(LiteralRun::R295),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition private-native-tests",
            3,
        ) => Some(LiteralRun::R295),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition private-native-tests",
            4,
        ) => Some(LiteralRun::R669),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition private-native-tests",
            5,
        ) => Some(LiteralRun::R670),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition private-native-tests --for-save",
            0,
        ) => Some(LiteralRun::R671),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition private-native-tests --for-save",
            1,
        ) => Some(LiteralRun::R672),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition private-native-tests --for-save",
            2,
        ) => Some(LiteralRun::R308),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition private-native-tests --for-save",
            3,
        ) => Some(LiteralRun::R308),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition private-native-tests --for-save",
            4,
        ) => Some(LiteralRun::R671),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition private-native-tests --for-save",
            5,
        ) => Some(LiteralRun::R672),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition product",
            0,
        ) => Some(LiteralRun::R673),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition product",
            1,
        ) => Some(LiteralRun::R674),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition product",
            2,
        ) => Some(LiteralRun::R291),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition product",
            3,
        ) => Some(LiteralRun::R291),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition product",
            4,
        ) => Some(LiteralRun::R673),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition product",
            5,
        ) => Some(LiteralRun::R674),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition product --for-save",
            0,
        ) => Some(LiteralRun::R675),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition product --for-save",
            1,
        ) => Some(LiteralRun::R676),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition product --for-save",
            2,
        ) => Some(LiteralRun::R307),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition product --for-save",
            3,
        ) => Some(LiteralRun::R307),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition product --for-save",
            4,
        ) => Some(LiteralRun::R675),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose private --shard complete --partition product --for-save",
            5,
        ) => Some(LiteralRun::R676),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose quality --shard complete",
            0,
        ) => Some(LiteralRun::R677),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose quality --shard complete",
            1,
        ) => Some(LiteralRun::R678),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose quality --shard complete",
            2,
        ) => Some(LiteralRun::R15),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose quality --shard complete",
            3,
        ) => Some(LiteralRun::R15),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose quality --shard complete",
            4,
        ) => Some(LiteralRun::R677),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose quality --shard complete",
            5,
        ) => Some(LiteralRun::R678),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose quality --shard complete --for-save",
            0,
        ) => Some(LiteralRun::R679),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose quality --shard complete --for-save",
            1,
        ) => Some(LiteralRun::R680),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose quality --shard complete --for-save",
            2,
        ) => Some(LiteralRun::R23),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose quality --shard complete --for-save",
            3,
        ) => Some(LiteralRun::R23),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose quality --shard complete --for-save",
            4,
        ) => Some(LiteralRun::R679),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose quality --shard complete --for-save",
            5,
        ) => Some(LiteralRun::R680),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress --shard complete",
            0,
        ) => Some(LiteralRun::R681),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress --shard complete",
            1,
        ) => Some(LiteralRun::R682),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress --shard complete",
            2,
        ) => Some(LiteralRun::R202),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress --shard complete",
            3,
        ) => Some(LiteralRun::R202),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress --shard complete",
            4,
        ) => Some(LiteralRun::R681),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress --shard complete",
            5,
        ) => Some(LiteralRun::R682),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress --shard complete --for-save",
            0,
        ) => Some(LiteralRun::R683),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress --shard complete --for-save",
            1,
        ) => Some(LiteralRun::R684),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress --shard complete --for-save",
            2,
        ) => Some(LiteralRun::R209),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress --shard complete --for-save",
            3,
        ) => Some(LiteralRun::R209),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress --shard complete --for-save",
            4,
        ) => Some(LiteralRun::R683),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress --shard complete --for-save",
            5,
        ) => Some(LiteralRun::R684),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress-lifecycle --shard complete",
            0,
        ) => Some(LiteralRun::R685),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress-lifecycle --shard complete",
            1,
        ) => Some(LiteralRun::R686),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress-lifecycle --shard complete",
            2,
        ) => Some(LiteralRun::R222),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress-lifecycle --shard complete",
            3,
        ) => Some(LiteralRun::R222),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress-lifecycle --shard complete",
            4,
        ) => Some(LiteralRun::R685),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress-lifecycle --shard complete",
            5,
        ) => Some(LiteralRun::R686),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress-lifecycle --shard complete --for-save",
            0,
        ) => Some(LiteralRun::R687),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress-lifecycle --shard complete --for-save",
            1,
        ) => Some(LiteralRun::R688),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress-lifecycle --shard complete --for-save",
            2,
        ) => Some(LiteralRun::R229),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress-lifecycle --shard complete --for-save",
            3,
        ) => Some(LiteralRun::R229),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress-lifecycle --shard complete --for-save",
            4,
        ) => Some(LiteralRun::R687),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress-lifecycle --shard complete --for-save",
            5,
        ) => Some(LiteralRun::R688),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress-packages --shard complete",
            0,
        ) => Some(LiteralRun::R689),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress-packages --shard complete",
            1,
        ) => Some(LiteralRun::R690),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress-packages --shard complete",
            2,
        ) => Some(LiteralRun::R212),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress-packages --shard complete",
            3,
        ) => Some(LiteralRun::R212),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress-packages --shard complete",
            4,
        ) => Some(LiteralRun::R689),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress-packages --shard complete",
            5,
        ) => Some(LiteralRun::R690),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress-packages --shard complete --for-save",
            0,
        ) => Some(LiteralRun::R691),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress-packages --shard complete --for-save",
            1,
        ) => Some(LiteralRun::R692),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress-packages --shard complete --for-save",
            2,
        ) => Some(LiteralRun::R219),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress-packages --shard complete --for-save",
            3,
        ) => Some(LiteralRun::R219),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress-packages --shard complete --for-save",
            4,
        ) => Some(LiteralRun::R691),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose stress-packages --shard complete --for-save",
            5,
        ) => Some(LiteralRun::R692),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose supply --shard complete",
            0,
        ) => Some(LiteralRun::R693),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose supply --shard complete",
            1,
        ) => Some(LiteralRun::R694),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose supply --shard complete",
            2,
        ) => Some(LiteralRun::R38),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose supply --shard complete",
            3,
        ) => Some(LiteralRun::R38),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose supply --shard complete",
            4,
        ) => Some(LiteralRun::R693),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose supply --shard complete",
            5,
        ) => Some(LiteralRun::R694),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition native-tests",
            0,
        ) => Some(LiteralRun::R695),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition native-tests",
            1,
        ) => Some(LiteralRun::R696),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition native-tests",
            2,
        ) => Some(LiteralRun::R265),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition native-tests",
            3,
        ) => Some(LiteralRun::R265),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition native-tests",
            4,
        ) => Some(LiteralRun::R695),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition native-tests",
            5,
        ) => Some(LiteralRun::R696),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition native-tests --for-save",
            0,
        ) => Some(LiteralRun::R697),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition native-tests --for-save",
            1,
        ) => Some(LiteralRun::R698),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition native-tests --for-save",
            2,
        ) => Some(LiteralRun::R278),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition native-tests --for-save",
            3,
        ) => Some(LiteralRun::R278),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition native-tests --for-save",
            4,
        ) => Some(LiteralRun::R697),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition native-tests --for-save",
            5,
        ) => Some(LiteralRun::R698),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition product",
            0,
        ) => Some(LiteralRun::R699),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition product",
            1,
        ) => Some(LiteralRun::R700),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition product",
            2,
        ) => Some(LiteralRun::R269),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition product",
            3,
        ) => Some(LiteralRun::R269),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition product",
            4,
        ) => Some(LiteralRun::R699),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition product",
            5,
        ) => Some(LiteralRun::R700),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition product --for-save",
            0,
        ) => Some(LiteralRun::R701),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition product --for-save",
            1,
        ) => Some(LiteralRun::R702),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition product --for-save",
            2,
        ) => Some(LiteralRun::R279),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition product --for-save",
            3,
        ) => Some(LiteralRun::R279),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition product --for-save",
            4,
        ) => Some(LiteralRun::R701),
        (
            "./target/ci/release/memcordon-ci ci cache-context --purpose windows-working --shard complete --partition product --for-save",
            5,
        ) => Some(LiteralRun::R702),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose backend --shard complete --stage build",
            0,
        ) => Some(LiteralRun::R703),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose backend --shard complete --stage build",
            1,
        ) => Some(LiteralRun::R704),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose backend --shard complete --stage build",
            2,
        ) => Some(LiteralRun::R323),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose backend --shard complete --stage build",
            3,
        ) => Some(LiteralRun::R323),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose backend --shard complete --stage build",
            4,
        ) => Some(LiteralRun::R703),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose backend --shard complete --stage build",
            5,
        ) => Some(LiteralRun::R704),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose deadline --shard complete --stage build",
            0,
        ) => Some(LiteralRun::R705),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose deadline --shard complete --stage build",
            1,
        ) => Some(LiteralRun::R706),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose deadline --shard complete --stage build",
            2,
        ) => Some(LiteralRun::R88),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose deadline --shard complete --stage build",
            3,
        ) => Some(LiteralRun::R88),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose deadline --shard complete --stage build",
            4,
        ) => Some(LiteralRun::R705),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose deadline --shard complete --stage build",
            5,
        ) => Some(LiteralRun::R706),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four --stage build",
            0,
        ) => Some(LiteralRun::R707),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four --stage build",
            1,
        ) => Some(LiteralRun::R708),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four --stage build",
            2,
        ) => Some(LiteralRun::R191),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four --stage build",
            3,
        ) => Some(LiteralRun::R191),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four --stage build",
            4,
        ) => Some(LiteralRun::R707),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four --stage build",
            5,
        ) => Some(LiteralRun::R708),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one --stage build",
            0,
        ) => Some(LiteralRun::R709),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one --stage build",
            1,
        ) => Some(LiteralRun::R710),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one --stage build",
            2,
        ) => Some(LiteralRun::R167),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one --stage build",
            3,
        ) => Some(LiteralRun::R167),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one --stage build",
            4,
        ) => Some(LiteralRun::R709),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one --stage build",
            5,
        ) => Some(LiteralRun::R710),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three --stage build",
            0,
        ) => Some(LiteralRun::R711),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three --stage build",
            1,
        ) => Some(LiteralRun::R712),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three --stage build",
            2,
        ) => Some(LiteralRun::R183),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three --stage build",
            3,
        ) => Some(LiteralRun::R183),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three --stage build",
            4,
        ) => Some(LiteralRun::R711),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three --stage build",
            5,
        ) => Some(LiteralRun::R712),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two --stage build",
            0,
        ) => Some(LiteralRun::R713),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two --stage build",
            1,
        ) => Some(LiteralRun::R714),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two --stage build",
            2,
        ) => Some(LiteralRun::R175),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two --stage build",
            3,
        ) => Some(LiteralRun::R175),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two --stage build",
            4,
        ) => Some(LiteralRun::R713),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two --stage build",
            5,
        ) => Some(LiteralRun::R714),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose macos --shard acceptance --stage build",
            0,
        ) => Some(LiteralRun::R715),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose macos --shard acceptance --stage build",
            1,
        ) => Some(LiteralRun::R716),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose macos --shard acceptance --stage build",
            2,
        ) => Some(LiteralRun::R261),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose macos --shard acceptance --stage build",
            3,
        ) => Some(LiteralRun::R261),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose macos --shard acceptance --stage build",
            4,
        ) => Some(LiteralRun::R715),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose macos --shard acceptance --stage build",
            5,
        ) => Some(LiteralRun::R716),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose macos --shard combined --stage build",
            0,
        ) => Some(LiteralRun::R717),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose macos --shard combined --stage build",
            1,
        ) => Some(LiteralRun::R718),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose macos --shard combined --stage build",
            2,
        ) => Some(LiteralRun::R241),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose macos --shard combined --stage build",
            3,
        ) => Some(LiteralRun::R241),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose macos --shard combined --stage build",
            4,
        ) => Some(LiteralRun::R717),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose macos --shard combined --stage build",
            5,
        ) => Some(LiteralRun::R718),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose macos --shard native --stage build",
            0,
        ) => Some(LiteralRun::R719),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose macos --shard native --stage build",
            1,
        ) => Some(LiteralRun::R720),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose macos --shard native --stage build",
            2,
        ) => Some(LiteralRun::R251),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose macos --shard native --stage build",
            3,
        ) => Some(LiteralRun::R251),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose macos --shard native --stage build",
            4,
        ) => Some(LiteralRun::R719),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose macos --shard native --stage build",
            5,
        ) => Some(LiteralRun::R720),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-four --stage build",
            0,
        ) => Some(LiteralRun::R721),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-four --stage build",
            1,
        ) => Some(LiteralRun::R722),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-four --stage build",
            2,
        ) => Some(LiteralRun::R137),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-four --stage build",
            3,
        ) => Some(LiteralRun::R137),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-four --stage build",
            4,
        ) => Some(LiteralRun::R721),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-four --stage build",
            5,
        ) => Some(LiteralRun::R722),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-one --stage build",
            0,
        ) => Some(LiteralRun::R723),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-one --stage build",
            1,
        ) => Some(LiteralRun::R724),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-one --stage build",
            2,
        ) => Some(LiteralRun::R131),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-one --stage build",
            3,
        ) => Some(LiteralRun::R131),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-one --stage build",
            4,
        ) => Some(LiteralRun::R723),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-one --stage build",
            5,
        ) => Some(LiteralRun::R724),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-three --stage build",
            0,
        ) => Some(LiteralRun::R725),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-three --stage build",
            1,
        ) => Some(LiteralRun::R726),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-three --stage build",
            2,
        ) => Some(LiteralRun::R133),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-three --stage build",
            3,
        ) => Some(LiteralRun::R133),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-three --stage build",
            4,
        ) => Some(LiteralRun::R725),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-three --stage build",
            5,
        ) => Some(LiteralRun::R726),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-two --stage build",
            0,
        ) => Some(LiteralRun::R727),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-two --stage build",
            1,
        ) => Some(LiteralRun::R728),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-two --stage build",
            2,
        ) => Some(LiteralRun::R135),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-two --stage build",
            3,
        ) => Some(LiteralRun::R135),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-two --stage build",
            4,
        ) => Some(LiteralRun::R727),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose miri --shard quarter-two --stage build",
            5,
        ) => Some(LiteralRun::R728),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose msrv --shard complete --stage build",
            0,
        ) => Some(LiteralRun::R729),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose msrv --shard complete --stage build",
            1,
        ) => Some(LiteralRun::R730),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose msrv --shard complete --stage build",
            2,
        ) => Some(LiteralRun::R36),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose msrv --shard complete --stage build",
            3,
        ) => Some(LiteralRun::R36),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose msrv --shard complete --stage build",
            4,
        ) => Some(LiteralRun::R729),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose msrv --shard complete --stage build",
            5,
        ) => Some(LiteralRun::R730),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles --stage build",
            0,
        ) => Some(LiteralRun::R731),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles --stage build",
            1,
        ) => Some(LiteralRun::R732),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles --stage build",
            2,
        ) => Some(LiteralRun::R76),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles --stage build",
            3,
        ) => Some(LiteralRun::R76),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles --stage build",
            4,
        ) => Some(LiteralRun::R731),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles --stage build",
            5,
        ) => Some(LiteralRun::R732),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-debug --partition native-tests --shard complete --stage build",
            0,
        ) => Some(LiteralRun::R733),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-debug --partition native-tests --shard complete --stage build",
            1,
        ) => Some(LiteralRun::R734),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-debug --partition native-tests --shard complete --stage build",
            2,
        ) => Some(LiteralRun::R70),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-debug --partition native-tests --shard complete --stage build",
            3,
        ) => Some(LiteralRun::R70),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-debug --partition native-tests --shard complete --stage build",
            4,
        ) => Some(LiteralRun::R733),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-debug --partition native-tests --shard complete --stage build",
            5,
        ) => Some(LiteralRun::R734),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-debug --shard complete --partition native-tests --stage build",
            0,
        ) => Some(LiteralRun::R735),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-debug --shard complete --partition native-tests --stage build",
            1,
        ) => Some(LiteralRun::R736),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-debug --shard complete --partition native-tests --stage build",
            2,
        ) => Some(LiteralRun::R78),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-debug --shard complete --partition native-tests --stage build",
            3,
        ) => Some(LiteralRun::R78),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-debug --shard complete --partition native-tests --stage build",
            4,
        ) => Some(LiteralRun::R735),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-debug --shard complete --partition native-tests --stage build",
            5,
        ) => Some(LiteralRun::R736),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition native-tests --stage build",
            0,
        ) => Some(LiteralRun::R737),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition native-tests --stage build",
            1,
        ) => Some(LiteralRun::R738),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition native-tests --stage build",
            2,
        ) => Some(LiteralRun::R521),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition native-tests --stage build",
            3,
        ) => Some(LiteralRun::R521),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition native-tests --stage build",
            4,
        ) => Some(LiteralRun::R737),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition native-tests --stage build",
            5,
        ) => Some(LiteralRun::R738),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition product --stage build",
            0,
        ) => Some(LiteralRun::R739),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition product --stage build",
            1,
        ) => Some(LiteralRun::R740),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition product --stage build",
            2,
        ) => Some(LiteralRun::R523),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition product --stage build",
            3,
        ) => Some(LiteralRun::R523),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition product --stage build",
            4,
        ) => Some(LiteralRun::R739),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition product --stage build",
            5,
        ) => Some(LiteralRun::R740),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose private --shard complete --partition native-tests --stage build",
            0,
        ) => Some(LiteralRun::R741),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose private --shard complete --partition native-tests --stage build",
            1,
        ) => Some(LiteralRun::R742),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose private --shard complete --partition native-tests --stage build",
            2,
        ) => Some(LiteralRun::R309),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose private --shard complete --partition native-tests --stage build",
            3,
        ) => Some(LiteralRun::R309),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose private --shard complete --partition native-tests --stage build",
            4,
        ) => Some(LiteralRun::R741),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose private --shard complete --partition native-tests --stage build",
            5,
        ) => Some(LiteralRun::R742),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose private --shard complete --partition private-native-tests --stage build",
            0,
        ) => Some(LiteralRun::R743),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose private --shard complete --partition private-native-tests --stage build",
            1,
        ) => Some(LiteralRun::R744),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose private --shard complete --partition private-native-tests --stage build",
            2,
        ) => Some(LiteralRun::R313),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose private --shard complete --partition private-native-tests --stage build",
            3,
        ) => Some(LiteralRun::R313),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose private --shard complete --partition private-native-tests --stage build",
            4,
        ) => Some(LiteralRun::R743),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose private --shard complete --partition private-native-tests --stage build",
            5,
        ) => Some(LiteralRun::R744),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose private --shard complete --partition product --stage build",
            0,
        ) => Some(LiteralRun::R745),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose private --shard complete --partition product --stage build",
            1,
        ) => Some(LiteralRun::R746),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose private --shard complete --partition product --stage build",
            2,
        ) => Some(LiteralRun::R311),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose private --shard complete --partition product --stage build",
            3,
        ) => Some(LiteralRun::R311),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose private --shard complete --partition product --stage build",
            4,
        ) => Some(LiteralRun::R745),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose private --shard complete --partition product --stage build",
            5,
        ) => Some(LiteralRun::R746),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose quality --shard complete --stage build",
            0,
        ) => Some(LiteralRun::R747),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose quality --shard complete --stage build",
            1,
        ) => Some(LiteralRun::R748),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose quality --shard complete --stage build",
            2,
        ) => Some(LiteralRun::R24),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose quality --shard complete --stage build",
            3,
        ) => Some(LiteralRun::R24),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose quality --shard complete --stage build",
            4,
        ) => Some(LiteralRun::R747),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose quality --shard complete --stage build",
            5,
        ) => Some(LiteralRun::R748),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose stress --shard complete --stage build",
            0,
        ) => Some(LiteralRun::R749),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose stress --shard complete --stage build",
            1,
        ) => Some(LiteralRun::R750),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose stress --shard complete --stage build",
            2,
        ) => Some(LiteralRun::R210),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose stress --shard complete --stage build",
            3,
        ) => Some(LiteralRun::R210),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose stress --shard complete --stage build",
            4,
        ) => Some(LiteralRun::R749),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose stress --shard complete --stage build",
            5,
        ) => Some(LiteralRun::R750),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose stress-lifecycle --shard complete --stage build",
            0,
        ) => Some(LiteralRun::R751),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose stress-lifecycle --shard complete --stage build",
            1,
        ) => Some(LiteralRun::R752),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose stress-lifecycle --shard complete --stage build",
            2,
        ) => Some(LiteralRun::R230),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose stress-lifecycle --shard complete --stage build",
            3,
        ) => Some(LiteralRun::R230),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose stress-lifecycle --shard complete --stage build",
            4,
        ) => Some(LiteralRun::R751),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose stress-lifecycle --shard complete --stage build",
            5,
        ) => Some(LiteralRun::R752),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose stress-packages --shard complete --stage build",
            0,
        ) => Some(LiteralRun::R753),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose stress-packages --shard complete --stage build",
            1,
        ) => Some(LiteralRun::R754),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose stress-packages --shard complete --stage build",
            2,
        ) => Some(LiteralRun::R220),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose stress-packages --shard complete --stage build",
            3,
        ) => Some(LiteralRun::R220),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose stress-packages --shard complete --stage build",
            4,
        ) => Some(LiteralRun::R753),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose stress-packages --shard complete --stage build",
            5,
        ) => Some(LiteralRun::R754),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose windows-working --shard complete --partition native-tests --stage build",
            0,
        ) => Some(LiteralRun::R755),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose windows-working --shard complete --partition native-tests --stage build",
            1,
        ) => Some(LiteralRun::R756),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose windows-working --shard complete --partition native-tests --stage build",
            2,
        ) => Some(LiteralRun::R280),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose windows-working --shard complete --partition native-tests --stage build",
            3,
        ) => Some(LiteralRun::R280),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose windows-working --shard complete --partition native-tests --stage build",
            4,
        ) => Some(LiteralRun::R755),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose windows-working --shard complete --partition native-tests --stage build",
            5,
        ) => Some(LiteralRun::R756),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose windows-working --shard complete --partition product --stage build",
            0,
        ) => Some(LiteralRun::R757),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose windows-working --shard complete --partition product --stage build",
            1,
        ) => Some(LiteralRun::R758),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose windows-working --shard complete --partition product --stage build",
            2,
        ) => Some(LiteralRun::R282),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose windows-working --shard complete --partition product --stage build",
            3,
        ) => Some(LiteralRun::R282),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose windows-working --shard complete --partition product --stage build",
            4,
        ) => Some(LiteralRun::R757),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind compiled --purpose windows-working --shard complete --partition product --stage build",
            5,
        ) => Some(LiteralRun::R758),
        ("./target/ci/release/memcordon-ci ci cache-snapshot --kind registry-archives", 0) => {
            Some(LiteralRun::R759)
        }
        ("./target/ci/release/memcordon-ci ci cache-snapshot --kind registry-archives", 1) => {
            Some(LiteralRun::R760)
        }
        ("./target/ci/release/memcordon-ci ci cache-snapshot --kind registry-archives", 2) => {
            Some(LiteralRun::R9)
        }
        ("./target/ci/release/memcordon-ci ci cache-snapshot --kind registry-archives", 3) => {
            Some(LiteralRun::R9)
        }
        ("./target/ci/release/memcordon-ci ci cache-snapshot --kind registry-archives", 4) => {
            Some(LiteralRun::R759)
        }
        ("./target/ci/release/memcordon-ci ci cache-snapshot --kind registry-archives", 5) => {
            Some(LiteralRun::R760)
        }
        ("./target/ci/release/memcordon-ci ci cache-snapshot --kind registry-index", 0) => {
            Some(LiteralRun::R761)
        }
        ("./target/ci/release/memcordon-ci ci cache-snapshot --kind registry-index", 1) => {
            Some(LiteralRun::R762)
        }
        ("./target/ci/release/memcordon-ci ci cache-snapshot --kind registry-index", 2) => {
            Some(LiteralRun::R11)
        }
        ("./target/ci/release/memcordon-ci ci cache-snapshot --kind registry-index", 3) => {
            Some(LiteralRun::R11)
        }
        ("./target/ci/release/memcordon-ci ci cache-snapshot --kind registry-index", 4) => {
            Some(LiteralRun::R761)
        }
        ("./target/ci/release/memcordon-ci ci cache-snapshot --kind registry-index", 5) => {
            Some(LiteralRun::R762)
        }
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-audit --shard complete --stage build",
            0,
        ) => Some(LiteralRun::R763),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-audit --shard complete --stage build",
            1,
        ) => Some(LiteralRun::R764),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-audit --shard complete --stage build",
            2,
        ) => Some(LiteralRun::R51),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-audit --shard complete --stage build",
            3,
        ) => Some(LiteralRun::R51),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-audit --shard complete --stage build",
            4,
        ) => Some(LiteralRun::R763),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-audit --shard complete --stage build",
            5,
        ) => Some(LiteralRun::R764),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-deny --shard complete --stage build",
            0,
        ) => Some(LiteralRun::R765),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-deny --shard complete --stage build",
            1,
        ) => Some(LiteralRun::R766),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-deny --shard complete --stage build",
            2,
        ) => Some(LiteralRun::R53),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-deny --shard complete --stage build",
            3,
        ) => Some(LiteralRun::R53),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-deny --shard complete --stage build",
            4,
        ) => Some(LiteralRun::R765),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-deny --shard complete --stage build",
            5,
        ) => Some(LiteralRun::R766),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete --stage build",
            0,
        ) => Some(LiteralRun::R767),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete --stage build",
            1,
        ) => Some(LiteralRun::R768),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete --stage build",
            2,
        ) => Some(LiteralRun::R200),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete --stage build",
            3,
        ) => Some(LiteralRun::R200),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete --stage build",
            4,
        ) => Some(LiteralRun::R767),
        (
            "./target/ci/release/memcordon-ci ci cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete --stage build",
            5,
        ) => Some(LiteralRun::R768),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose backend --shard complete",
            0,
        ) => Some(LiteralRun::R769),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose backend --shard complete",
            1,
        ) => Some(LiteralRun::R770),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose backend --shard complete",
            2,
        ) => Some(LiteralRun::R324),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose backend --shard complete",
            3,
        ) => Some(LiteralRun::R324),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose backend --shard complete",
            4,
        ) => Some(LiteralRun::R769),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose backend --shard complete",
            5,
        ) => Some(LiteralRun::R770),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose deadline --shard complete",
            0,
        ) => Some(LiteralRun::R771),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose deadline --shard complete",
            1,
        ) => Some(LiteralRun::R772),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose deadline --shard complete",
            2,
        ) => Some(LiteralRun::R89),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose deadline --shard complete",
            3,
        ) => Some(LiteralRun::R89),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose deadline --shard complete",
            4,
        ) => Some(LiteralRun::R771),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose deadline --shard complete",
            5,
        ) => Some(LiteralRun::R772),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            0,
        ) => Some(LiteralRun::R773),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            1,
        ) => Some(LiteralRun::R774),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            2,
        ) => Some(LiteralRun::R192),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            3,
        ) => Some(LiteralRun::R192),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            4,
        ) => Some(LiteralRun::R773),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            5,
        ) => Some(LiteralRun::R774),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            0,
        ) => Some(LiteralRun::R775),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            1,
        ) => Some(LiteralRun::R776),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            2,
        ) => Some(LiteralRun::R168),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            3,
        ) => Some(LiteralRun::R168),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            4,
        ) => Some(LiteralRun::R775),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            5,
        ) => Some(LiteralRun::R776),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            0,
        ) => Some(LiteralRun::R777),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            1,
        ) => Some(LiteralRun::R778),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            2,
        ) => Some(LiteralRun::R184),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            3,
        ) => Some(LiteralRun::R184),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            4,
        ) => Some(LiteralRun::R777),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            5,
        ) => Some(LiteralRun::R778),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            0,
        ) => Some(LiteralRun::R779),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            1,
        ) => Some(LiteralRun::R780),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            2,
        ) => Some(LiteralRun::R176),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            3,
        ) => Some(LiteralRun::R176),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            4,
        ) => Some(LiteralRun::R779),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            5,
        ) => Some(LiteralRun::R780),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose macos --shard acceptance",
            0,
        ) => Some(LiteralRun::R781),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose macos --shard acceptance",
            1,
        ) => Some(LiteralRun::R782),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose macos --shard acceptance",
            2,
        ) => Some(LiteralRun::R262),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose macos --shard acceptance",
            3,
        ) => Some(LiteralRun::R262),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose macos --shard acceptance",
            4,
        ) => Some(LiteralRun::R781),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose macos --shard acceptance",
            5,
        ) => Some(LiteralRun::R782),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose macos --shard combined",
            0,
        ) => Some(LiteralRun::R783),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose macos --shard combined",
            1,
        ) => Some(LiteralRun::R784),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose macos --shard combined",
            2,
        ) => Some(LiteralRun::R242),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose macos --shard combined",
            3,
        ) => Some(LiteralRun::R242),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose macos --shard combined",
            4,
        ) => Some(LiteralRun::R783),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose macos --shard combined",
            5,
        ) => Some(LiteralRun::R784),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose macos --shard native",
            0,
        ) => Some(LiteralRun::R785),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose macos --shard native",
            1,
        ) => Some(LiteralRun::R786),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose macos --shard native",
            2,
        ) => Some(LiteralRun::R252),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose macos --shard native",
            3,
        ) => Some(LiteralRun::R252),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose macos --shard native",
            4,
        ) => Some(LiteralRun::R785),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose macos --shard native",
            5,
        ) => Some(LiteralRun::R786),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-four",
            0,
        ) => Some(LiteralRun::R787),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-four",
            1,
        ) => Some(LiteralRun::R788),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-four",
            2,
        ) => Some(LiteralRun::R138),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-four",
            3,
        ) => Some(LiteralRun::R138),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-four",
            4,
        ) => Some(LiteralRun::R787),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-four",
            5,
        ) => Some(LiteralRun::R788),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-one",
            0,
        ) => Some(LiteralRun::R789),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-one",
            1,
        ) => Some(LiteralRun::R790),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-one",
            2,
        ) => Some(LiteralRun::R132),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-one",
            3,
        ) => Some(LiteralRun::R132),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-one",
            4,
        ) => Some(LiteralRun::R789),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-one",
            5,
        ) => Some(LiteralRun::R790),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-three",
            0,
        ) => Some(LiteralRun::R791),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-three",
            1,
        ) => Some(LiteralRun::R792),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-three",
            2,
        ) => Some(LiteralRun::R134),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-three",
            3,
        ) => Some(LiteralRun::R134),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-three",
            4,
        ) => Some(LiteralRun::R791),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-three",
            5,
        ) => Some(LiteralRun::R792),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-two",
            0,
        ) => Some(LiteralRun::R793),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-two",
            1,
        ) => Some(LiteralRun::R794),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-two",
            2,
        ) => Some(LiteralRun::R136),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-two",
            3,
        ) => Some(LiteralRun::R136),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-two",
            4,
        ) => Some(LiteralRun::R793),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose miri --shard quarter-two",
            5,
        ) => Some(LiteralRun::R794),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose msrv --shard complete",
            0,
        ) => Some(LiteralRun::R795),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose msrv --shard complete",
            1,
        ) => Some(LiteralRun::R796),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose msrv --shard complete",
            2,
        ) => Some(LiteralRun::R37),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose msrv --shard complete",
            3,
        ) => Some(LiteralRun::R37),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose msrv --shard complete",
            4,
        ) => Some(LiteralRun::R795),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose msrv --shard complete",
            5,
        ) => Some(LiteralRun::R796),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles",
            0,
        ) => Some(LiteralRun::R797),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles",
            1,
        ) => Some(LiteralRun::R798),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles",
            2,
        ) => Some(LiteralRun::R77),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles",
            3,
        ) => Some(LiteralRun::R77),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles",
            4,
        ) => Some(LiteralRun::R797),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles",
            5,
        ) => Some(LiteralRun::R798),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-debug --partition native-tests --shard complete",
            0,
        ) => Some(LiteralRun::R799),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-debug --partition native-tests --shard complete",
            1,
        ) => Some(LiteralRun::R800),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-debug --partition native-tests --shard complete",
            2,
        ) => Some(LiteralRun::R71),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-debug --partition native-tests --shard complete",
            3,
        ) => Some(LiteralRun::R71),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-debug --partition native-tests --shard complete",
            4,
        ) => Some(LiteralRun::R799),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-debug --partition native-tests --shard complete",
            5,
        ) => Some(LiteralRun::R800),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-debug --shard complete --partition native-tests",
            0,
        ) => Some(LiteralRun::R801),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-debug --shard complete --partition native-tests",
            1,
        ) => Some(LiteralRun::R802),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-debug --shard complete --partition native-tests",
            2,
        ) => Some(LiteralRun::R79),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-debug --shard complete --partition native-tests",
            3,
        ) => Some(LiteralRun::R79),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-debug --shard complete --partition native-tests",
            4,
        ) => Some(LiteralRun::R801),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-debug --shard complete --partition native-tests",
            5,
        ) => Some(LiteralRun::R802),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition native-tests",
            0,
        ) => Some(LiteralRun::R803),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition native-tests",
            1,
        ) => Some(LiteralRun::R804),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition native-tests",
            2,
        ) => Some(LiteralRun::R522),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition native-tests",
            3,
        ) => Some(LiteralRun::R522),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition native-tests",
            4,
        ) => Some(LiteralRun::R803),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition native-tests",
            5,
        ) => Some(LiteralRun::R804),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition product",
            0,
        ) => Some(LiteralRun::R805),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition product",
            1,
        ) => Some(LiteralRun::R806),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition product",
            2,
        ) => Some(LiteralRun::R524),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition product",
            3,
        ) => Some(LiteralRun::R524),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition product",
            4,
        ) => Some(LiteralRun::R805),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition product",
            5,
        ) => Some(LiteralRun::R806),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose private --shard complete --partition native-tests",
            0,
        ) => Some(LiteralRun::R807),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose private --shard complete --partition native-tests",
            1,
        ) => Some(LiteralRun::R808),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose private --shard complete --partition native-tests",
            2,
        ) => Some(LiteralRun::R310),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose private --shard complete --partition native-tests",
            3,
        ) => Some(LiteralRun::R310),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose private --shard complete --partition native-tests",
            4,
        ) => Some(LiteralRun::R807),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose private --shard complete --partition native-tests",
            5,
        ) => Some(LiteralRun::R808),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose private --shard complete --partition private-native-tests",
            0,
        ) => Some(LiteralRun::R809),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose private --shard complete --partition private-native-tests",
            1,
        ) => Some(LiteralRun::R810),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose private --shard complete --partition private-native-tests",
            2,
        ) => Some(LiteralRun::R314),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose private --shard complete --partition private-native-tests",
            3,
        ) => Some(LiteralRun::R314),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose private --shard complete --partition private-native-tests",
            4,
        ) => Some(LiteralRun::R809),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose private --shard complete --partition private-native-tests",
            5,
        ) => Some(LiteralRun::R810),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose private --shard complete --partition product",
            0,
        ) => Some(LiteralRun::R811),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose private --shard complete --partition product",
            1,
        ) => Some(LiteralRun::R812),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose private --shard complete --partition product",
            2,
        ) => Some(LiteralRun::R312),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose private --shard complete --partition product",
            3,
        ) => Some(LiteralRun::R312),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose private --shard complete --partition product",
            4,
        ) => Some(LiteralRun::R811),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose private --shard complete --partition product",
            5,
        ) => Some(LiteralRun::R812),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose quality --shard complete",
            0,
        ) => Some(LiteralRun::R813),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose quality --shard complete",
            1,
        ) => Some(LiteralRun::R814),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose quality --shard complete",
            2,
        ) => Some(LiteralRun::R25),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose quality --shard complete",
            3,
        ) => Some(LiteralRun::R25),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose quality --shard complete",
            4,
        ) => Some(LiteralRun::R813),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose quality --shard complete",
            5,
        ) => Some(LiteralRun::R814),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose stress --shard complete",
            0,
        ) => Some(LiteralRun::R815),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose stress --shard complete",
            1,
        ) => Some(LiteralRun::R816),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose stress --shard complete",
            2,
        ) => Some(LiteralRun::R211),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose stress --shard complete",
            3,
        ) => Some(LiteralRun::R211),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose stress --shard complete",
            4,
        ) => Some(LiteralRun::R815),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose stress --shard complete",
            5,
        ) => Some(LiteralRun::R816),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose stress-lifecycle --shard complete",
            0,
        ) => Some(LiteralRun::R817),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose stress-lifecycle --shard complete",
            1,
        ) => Some(LiteralRun::R818),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose stress-lifecycle --shard complete",
            2,
        ) => Some(LiteralRun::R231),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose stress-lifecycle --shard complete",
            3,
        ) => Some(LiteralRun::R231),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose stress-lifecycle --shard complete",
            4,
        ) => Some(LiteralRun::R817),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose stress-lifecycle --shard complete",
            5,
        ) => Some(LiteralRun::R818),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose stress-packages --shard complete",
            0,
        ) => Some(LiteralRun::R819),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose stress-packages --shard complete",
            1,
        ) => Some(LiteralRun::R820),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose stress-packages --shard complete",
            2,
        ) => Some(LiteralRun::R221),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose stress-packages --shard complete",
            3,
        ) => Some(LiteralRun::R221),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose stress-packages --shard complete",
            4,
        ) => Some(LiteralRun::R819),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose stress-packages --shard complete",
            5,
        ) => Some(LiteralRun::R820),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition native-tests",
            0,
        ) => Some(LiteralRun::R821),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition native-tests",
            1,
        ) => Some(LiteralRun::R822),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition native-tests",
            2,
        ) => Some(LiteralRun::R281),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition native-tests",
            3,
        ) => Some(LiteralRun::R281),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition native-tests",
            4,
        ) => Some(LiteralRun::R821),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition native-tests",
            5,
        ) => Some(LiteralRun::R822),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition product",
            0,
        ) => Some(LiteralRun::R823),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition product",
            1,
        ) => Some(LiteralRun::R824),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition product",
            2,
        ) => Some(LiteralRun::R283),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition product",
            3,
        ) => Some(LiteralRun::R283),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition product",
            4,
        ) => Some(LiteralRun::R823),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition product",
            5,
        ) => Some(LiteralRun::R824),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind registry-archives",
            0,
        ) => Some(LiteralRun::R825),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind registry-archives",
            1,
        ) => Some(LiteralRun::R826),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind registry-archives",
            2,
        ) => Some(LiteralRun::R10),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind registry-archives",
            3,
        ) => Some(LiteralRun::R10),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind registry-archives",
            4,
        ) => Some(LiteralRun::R825),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind registry-archives",
            5,
        ) => Some(LiteralRun::R826),
        ("./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind registry-index", 0) => {
            Some(LiteralRun::R827)
        }
        ("./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind registry-index", 1) => {
            Some(LiteralRun::R828)
        }
        ("./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind registry-index", 2) => {
            Some(LiteralRun::R12)
        }
        ("./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind registry-index", 3) => {
            Some(LiteralRun::R12)
        }
        ("./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind registry-index", 4) => {
            Some(LiteralRun::R827)
        }
        ("./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind registry-index", 5) => {
            Some(LiteralRun::R828)
        }
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete",
            0,
        ) => Some(LiteralRun::R829),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete",
            1,
        ) => Some(LiteralRun::R830),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete",
            2,
        ) => Some(LiteralRun::R52),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete",
            3,
        ) => Some(LiteralRun::R52),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete",
            4,
        ) => Some(LiteralRun::R829),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete",
            5,
        ) => Some(LiteralRun::R830),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete",
            0,
        ) => Some(LiteralRun::R831),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete",
            1,
        ) => Some(LiteralRun::R832),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete",
            2,
        ) => Some(LiteralRun::R54),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete",
            3,
        ) => Some(LiteralRun::R54),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete",
            4,
        ) => Some(LiteralRun::R831),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete",
            5,
        ) => Some(LiteralRun::R832),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete",
            0,
        ) => Some(LiteralRun::R833),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete",
            1,
        ) => Some(LiteralRun::R834),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete",
            2,
        ) => Some(LiteralRun::R201),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete",
            3,
        ) => Some(LiteralRun::R201),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete",
            4,
        ) => Some(LiteralRun::R833),
        (
            "./target/ci/release/memcordon-ci ci cleanup-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete",
            5,
        ) => Some(LiteralRun::R834),
        ("./target/ci/release/memcordon-ci ci download-cache-context --family fuzz", 0) => {
            Some(LiteralRun::R835)
        }
        ("./target/ci/release/memcordon-ci ci download-cache-context --family fuzz", 1) => {
            Some(LiteralRun::R836)
        }
        ("./target/ci/release/memcordon-ci ci download-cache-context --family fuzz", 2) => {
            Some(LiteralRun::R142)
        }
        ("./target/ci/release/memcordon-ci ci download-cache-context --family fuzz", 3) => {
            Some(LiteralRun::R142)
        }
        ("./target/ci/release/memcordon-ci ci download-cache-context --family fuzz", 4) => {
            Some(LiteralRun::R835)
        }
        ("./target/ci/release/memcordon-ci ci download-cache-context --family fuzz", 5) => {
            Some(LiteralRun::R836)
        }
        (
            "./target/ci/release/memcordon-ci ci download-cache-context --family tool-cargo-audit",
            0,
        ) => Some(LiteralRun::R837),
        (
            "./target/ci/release/memcordon-ci ci download-cache-context --family tool-cargo-audit",
            1,
        ) => Some(LiteralRun::R838),
        (
            "./target/ci/release/memcordon-ci ci download-cache-context --family tool-cargo-audit",
            2,
        ) => Some(LiteralRun::R39),
        (
            "./target/ci/release/memcordon-ci ci download-cache-context --family tool-cargo-audit",
            3,
        ) => Some(LiteralRun::R39),
        (
            "./target/ci/release/memcordon-ci ci download-cache-context --family tool-cargo-audit",
            4,
        ) => Some(LiteralRun::R837),
        (
            "./target/ci/release/memcordon-ci ci download-cache-context --family tool-cargo-audit",
            5,
        ) => Some(LiteralRun::R838),
        (
            "./target/ci/release/memcordon-ci ci download-cache-context --family tool-cargo-deny",
            0,
        ) => Some(LiteralRun::R839),
        (
            "./target/ci/release/memcordon-ci ci download-cache-context --family tool-cargo-deny",
            1,
        ) => Some(LiteralRun::R840),
        (
            "./target/ci/release/memcordon-ci ci download-cache-context --family tool-cargo-deny",
            2,
        ) => Some(LiteralRun::R41),
        (
            "./target/ci/release/memcordon-ci ci download-cache-context --family tool-cargo-deny",
            3,
        ) => Some(LiteralRun::R41),
        (
            "./target/ci/release/memcordon-ci ci download-cache-context --family tool-cargo-deny",
            4,
        ) => Some(LiteralRun::R839),
        (
            "./target/ci/release/memcordon-ci ci download-cache-context --family tool-cargo-deny",
            5,
        ) => Some(LiteralRun::R840),
        (
            "./target/ci/release/memcordon-ci ci download-cache-context --family tool-cargo-fuzz",
            0,
        ) => Some(LiteralRun::R841),
        (
            "./target/ci/release/memcordon-ci ci download-cache-context --family tool-cargo-fuzz",
            1,
        ) => Some(LiteralRun::R842),
        (
            "./target/ci/release/memcordon-ci ci download-cache-context --family tool-cargo-fuzz",
            2,
        ) => Some(LiteralRun::R139),
        (
            "./target/ci/release/memcordon-ci ci download-cache-context --family tool-cargo-fuzz",
            3,
        ) => Some(LiteralRun::R139),
        (
            "./target/ci/release/memcordon-ci ci download-cache-context --family tool-cargo-fuzz",
            4,
        ) => Some(LiteralRun::R841),
        (
            "./target/ci/release/memcordon-ci ci download-cache-context --family tool-cargo-fuzz",
            5,
        ) => Some(LiteralRun::R842),
        ("./target/ci/release/memcordon-ci ci download-cache-context --family workspace", 0) => {
            Some(LiteralRun::R843)
        }
        ("./target/ci/release/memcordon-ci ci download-cache-context --family workspace", 1) => {
            Some(LiteralRun::R844)
        }
        ("./target/ci/release/memcordon-ci ci download-cache-context --family workspace", 2) => {
            Some(LiteralRun::R3)
        }
        ("./target/ci/release/memcordon-ci ci download-cache-context --family workspace", 3) => {
            Some(LiteralRun::R3)
        }
        ("./target/ci/release/memcordon-ci ci download-cache-context --family workspace", 4) => {
            Some(LiteralRun::R843)
        }
        ("./target/ci/release/memcordon-ci ci download-cache-context --family workspace", 5) => {
            Some(LiteralRun::R844)
        }
        ("./target/ci/release/memcordon-ci ci fetch-downloads --family workspace", 0) => {
            Some(LiteralRun::R845)
        }
        ("./target/ci/release/memcordon-ci ci fetch-downloads --family workspace", 1) => {
            Some(LiteralRun::R846)
        }
        ("./target/ci/release/memcordon-ci ci fetch-downloads --family workspace", 2) => {
            Some(LiteralRun::R8)
        }
        ("./target/ci/release/memcordon-ci ci fetch-downloads --family workspace", 3) => {
            Some(LiteralRun::R8)
        }
        ("./target/ci/release/memcordon-ci ci fetch-downloads --family workspace", 4) => {
            Some(LiteralRun::R845)
        }
        ("./target/ci/release/memcordon-ci ci fetch-downloads --family workspace", 5) => {
            Some(LiteralRun::R846)
        }
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose backend --shard complete",
            0,
        ) => Some(LiteralRun::R847),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose backend --shard complete",
            1,
        ) => Some(LiteralRun::R848),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose backend --shard complete",
            2,
        ) => Some(LiteralRun::R320),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose backend --shard complete",
            3,
        ) => Some(LiteralRun::R320),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose backend --shard complete",
            4,
        ) => Some(LiteralRun::R847),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose backend --shard complete",
            5,
        ) => Some(LiteralRun::R848),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose deadline --shard complete",
            0,
        ) => Some(LiteralRun::R849),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose deadline --shard complete",
            1,
        ) => Some(LiteralRun::R850),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose deadline --shard complete",
            2,
        ) => Some(LiteralRun::R85),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose deadline --shard complete",
            3,
        ) => Some(LiteralRun::R85),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose deadline --shard complete",
            4,
        ) => Some(LiteralRun::R849),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose deadline --shard complete",
            5,
        ) => Some(LiteralRun::R850),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            0,
        ) => Some(LiteralRun::R851),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            1,
        ) => Some(LiteralRun::R852),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            2,
        ) => Some(LiteralRun::R188),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            3,
        ) => Some(LiteralRun::R188),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            4,
        ) => Some(LiteralRun::R851),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            5,
        ) => Some(LiteralRun::R852),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            0,
        ) => Some(LiteralRun::R853),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            1,
        ) => Some(LiteralRun::R854),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            2,
        ) => Some(LiteralRun::R164),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            3,
        ) => Some(LiteralRun::R164),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            4,
        ) => Some(LiteralRun::R853),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            5,
        ) => Some(LiteralRun::R854),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            0,
        ) => Some(LiteralRun::R855),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            1,
        ) => Some(LiteralRun::R856),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            2,
        ) => Some(LiteralRun::R180),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            3,
        ) => Some(LiteralRun::R180),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            4,
        ) => Some(LiteralRun::R855),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            5,
        ) => Some(LiteralRun::R856),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            0,
        ) => Some(LiteralRun::R857),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            1,
        ) => Some(LiteralRun::R858),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            2,
        ) => Some(LiteralRun::R172),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            3,
        ) => Some(LiteralRun::R172),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            4,
        ) => Some(LiteralRun::R857),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            5,
        ) => Some(LiteralRun::R858),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose macos --shard acceptance",
            0,
        ) => Some(LiteralRun::R859),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose macos --shard acceptance",
            1,
        ) => Some(LiteralRun::R860),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose macos --shard acceptance",
            2,
        ) => Some(LiteralRun::R258),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose macos --shard acceptance",
            3,
        ) => Some(LiteralRun::R258),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose macos --shard acceptance",
            4,
        ) => Some(LiteralRun::R859),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose macos --shard acceptance",
            5,
        ) => Some(LiteralRun::R860),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose macos --shard combined",
            0,
        ) => Some(LiteralRun::R861),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose macos --shard combined",
            1,
        ) => Some(LiteralRun::R862),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose macos --shard combined",
            2,
        ) => Some(LiteralRun::R238),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose macos --shard combined",
            3,
        ) => Some(LiteralRun::R238),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose macos --shard combined",
            4,
        ) => Some(LiteralRun::R861),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose macos --shard combined",
            5,
        ) => Some(LiteralRun::R862),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose macos --shard native",
            0,
        ) => Some(LiteralRun::R863),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose macos --shard native",
            1,
        ) => Some(LiteralRun::R864),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose macos --shard native",
            2,
        ) => Some(LiteralRun::R248),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose macos --shard native",
            3,
        ) => Some(LiteralRun::R248),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose macos --shard native",
            4,
        ) => Some(LiteralRun::R863),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose macos --shard native",
            5,
        ) => Some(LiteralRun::R864),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-four",
            0,
        ) => Some(LiteralRun::R865),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-four",
            1,
        ) => Some(LiteralRun::R866),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-four",
            2,
        ) => Some(LiteralRun::R118),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-four",
            3,
        ) => Some(LiteralRun::R118),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-four",
            4,
        ) => Some(LiteralRun::R865),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-four",
            5,
        ) => Some(LiteralRun::R866),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-one",
            0,
        ) => Some(LiteralRun::R867),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-one",
            1,
        ) => Some(LiteralRun::R868),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-one",
            2,
        ) => Some(LiteralRun::R112),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-one",
            3,
        ) => Some(LiteralRun::R112),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-one",
            4,
        ) => Some(LiteralRun::R867),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-one",
            5,
        ) => Some(LiteralRun::R868),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-three",
            0,
        ) => Some(LiteralRun::R869),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-three",
            1,
        ) => Some(LiteralRun::R870),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-three",
            2,
        ) => Some(LiteralRun::R114),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-three",
            3,
        ) => Some(LiteralRun::R114),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-three",
            4,
        ) => Some(LiteralRun::R869),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-three",
            5,
        ) => Some(LiteralRun::R870),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-two",
            0,
        ) => Some(LiteralRun::R871),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-two",
            1,
        ) => Some(LiteralRun::R872),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-two",
            2,
        ) => Some(LiteralRun::R116),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-two",
            3,
        ) => Some(LiteralRun::R116),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-two",
            4,
        ) => Some(LiteralRun::R871),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose miri --shard quarter-two",
            5,
        ) => Some(LiteralRun::R872),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose msrv --shard complete",
            0,
        ) => Some(LiteralRun::R873),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose msrv --shard complete",
            1,
        ) => Some(LiteralRun::R874),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose msrv --shard complete",
            2,
        ) => Some(LiteralRun::R32),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose msrv --shard complete",
            3,
        ) => Some(LiteralRun::R32),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose msrv --shard complete",
            4,
        ) => Some(LiteralRun::R873),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose msrv --shard complete",
            5,
        ) => Some(LiteralRun::R874),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles",
            0,
        ) => Some(LiteralRun::R875),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles",
            1,
        ) => Some(LiteralRun::R876),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles",
            2,
        ) => Some(LiteralRun::R68),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles",
            3,
        ) => Some(LiteralRun::R68),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles",
            4,
        ) => Some(LiteralRun::R875),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles",
            5,
        ) => Some(LiteralRun::R876),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-debug --partition native-tests --shard complete",
            0,
        ) => Some(LiteralRun::R877),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-debug --partition native-tests --shard complete",
            1,
        ) => Some(LiteralRun::R878),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-debug --partition native-tests --shard complete",
            2,
        ) => Some(LiteralRun::R65),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-debug --partition native-tests --shard complete",
            3,
        ) => Some(LiteralRun::R65),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-debug --partition native-tests --shard complete",
            4,
        ) => Some(LiteralRun::R877),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-debug --partition native-tests --shard complete",
            5,
        ) => Some(LiteralRun::R878),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition native-tests",
            0,
        ) => Some(LiteralRun::R879),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition native-tests",
            1,
        ) => Some(LiteralRun::R880),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition native-tests",
            2,
        ) => Some(LiteralRun::R514),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition native-tests",
            3,
        ) => Some(LiteralRun::R514),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition native-tests",
            4,
        ) => Some(LiteralRun::R879),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition native-tests",
            5,
        ) => Some(LiteralRun::R880),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition product",
            0,
        ) => Some(LiteralRun::R881),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition product",
            1,
        ) => Some(LiteralRun::R882),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition product",
            2,
        ) => Some(LiteralRun::R516),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition product",
            3,
        ) => Some(LiteralRun::R516),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition product",
            4,
        ) => Some(LiteralRun::R881),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose native-readiness --shard complete --partition product",
            5,
        ) => Some(LiteralRun::R882),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose private --shard complete --partition native-tests",
            0,
        ) => Some(LiteralRun::R883),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose private --shard complete --partition native-tests",
            1,
        ) => Some(LiteralRun::R884),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose private --shard complete --partition native-tests",
            2,
        ) => Some(LiteralRun::R300),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose private --shard complete --partition native-tests",
            3,
        ) => Some(LiteralRun::R300),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose private --shard complete --partition native-tests",
            4,
        ) => Some(LiteralRun::R883),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose private --shard complete --partition native-tests",
            5,
        ) => Some(LiteralRun::R884),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose private --shard complete --partition private-native-tests",
            0,
        ) => Some(LiteralRun::R885),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose private --shard complete --partition private-native-tests",
            1,
        ) => Some(LiteralRun::R886),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose private --shard complete --partition private-native-tests",
            2,
        ) => Some(LiteralRun::R304),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose private --shard complete --partition private-native-tests",
            3,
        ) => Some(LiteralRun::R304),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose private --shard complete --partition private-native-tests",
            4,
        ) => Some(LiteralRun::R885),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose private --shard complete --partition private-native-tests",
            5,
        ) => Some(LiteralRun::R886),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose private --shard complete --partition product",
            0,
        ) => Some(LiteralRun::R887),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose private --shard complete --partition product",
            1,
        ) => Some(LiteralRun::R888),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose private --shard complete --partition product",
            2,
        ) => Some(LiteralRun::R302),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose private --shard complete --partition product",
            3,
        ) => Some(LiteralRun::R302),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose private --shard complete --partition product",
            4,
        ) => Some(LiteralRun::R887),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose private --shard complete --partition product",
            5,
        ) => Some(LiteralRun::R888),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose quality --shard complete",
            0,
        ) => Some(LiteralRun::R889),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose quality --shard complete",
            1,
        ) => Some(LiteralRun::R890),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose quality --shard complete",
            2,
        ) => Some(LiteralRun::R20),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose quality --shard complete",
            3,
        ) => Some(LiteralRun::R20),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose quality --shard complete",
            4,
        ) => Some(LiteralRun::R889),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose quality --shard complete",
            5,
        ) => Some(LiteralRun::R890),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose stress --shard complete",
            0,
        ) => Some(LiteralRun::R891),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose stress --shard complete",
            1,
        ) => Some(LiteralRun::R892),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose stress --shard complete",
            2,
        ) => Some(LiteralRun::R207),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose stress --shard complete",
            3,
        ) => Some(LiteralRun::R207),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose stress --shard complete",
            4,
        ) => Some(LiteralRun::R891),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose stress --shard complete",
            5,
        ) => Some(LiteralRun::R892),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose stress-lifecycle --shard complete",
            0,
        ) => Some(LiteralRun::R893),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose stress-lifecycle --shard complete",
            1,
        ) => Some(LiteralRun::R894),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose stress-lifecycle --shard complete",
            2,
        ) => Some(LiteralRun::R227),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose stress-lifecycle --shard complete",
            3,
        ) => Some(LiteralRun::R227),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose stress-lifecycle --shard complete",
            4,
        ) => Some(LiteralRun::R893),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose stress-lifecycle --shard complete",
            5,
        ) => Some(LiteralRun::R894),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose stress-packages --shard complete",
            0,
        ) => Some(LiteralRun::R895),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose stress-packages --shard complete",
            1,
        ) => Some(LiteralRun::R896),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose stress-packages --shard complete",
            2,
        ) => Some(LiteralRun::R217),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose stress-packages --shard complete",
            3,
        ) => Some(LiteralRun::R217),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose stress-packages --shard complete",
            4,
        ) => Some(LiteralRun::R895),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose stress-packages --shard complete",
            5,
        ) => Some(LiteralRun::R896),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition native-tests",
            0,
        ) => Some(LiteralRun::R897),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition native-tests",
            1,
        ) => Some(LiteralRun::R898),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition native-tests",
            2,
        ) => Some(LiteralRun::R274),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition native-tests",
            3,
        ) => Some(LiteralRun::R274),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition native-tests",
            4,
        ) => Some(LiteralRun::R897),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition native-tests",
            5,
        ) => Some(LiteralRun::R898),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition product",
            0,
        ) => Some(LiteralRun::R899),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition product",
            1,
        ) => Some(LiteralRun::R900),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition product",
            2,
        ) => Some(LiteralRun::R276),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition product",
            3,
        ) => Some(LiteralRun::R276),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition product",
            4,
        ) => Some(LiteralRun::R899),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind compiled --purpose windows-working --shard complete --partition product",
            5,
        ) => Some(LiteralRun::R900),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind registry-archives",
            0,
        ) => Some(LiteralRun::R901),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind registry-archives",
            1,
        ) => Some(LiteralRun::R902),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind registry-archives",
            2,
        ) => Some(LiteralRun::R5),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind registry-archives",
            3,
        ) => Some(LiteralRun::R5),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind registry-archives",
            4,
        ) => Some(LiteralRun::R901),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind registry-archives",
            5,
        ) => Some(LiteralRun::R902),
        ("./target/ci/release/memcordon-ci ci import-cache-snapshot --kind registry-index", 0) => {
            Some(LiteralRun::R903)
        }
        ("./target/ci/release/memcordon-ci ci import-cache-snapshot --kind registry-index", 1) => {
            Some(LiteralRun::R904)
        }
        ("./target/ci/release/memcordon-ci ci import-cache-snapshot --kind registry-index", 2) => {
            Some(LiteralRun::R7)
        }
        ("./target/ci/release/memcordon-ci ci import-cache-snapshot --kind registry-index", 3) => {
            Some(LiteralRun::R7)
        }
        ("./target/ci/release/memcordon-ci ci import-cache-snapshot --kind registry-index", 4) => {
            Some(LiteralRun::R903)
        }
        ("./target/ci/release/memcordon-ci ci import-cache-snapshot --kind registry-index", 5) => {
            Some(LiteralRun::R904)
        }
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete",
            0,
        ) => Some(LiteralRun::R905),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete",
            1,
        ) => Some(LiteralRun::R906),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete",
            2,
        ) => Some(LiteralRun::R44),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete",
            3,
        ) => Some(LiteralRun::R44),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete",
            4,
        ) => Some(LiteralRun::R905),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-audit --shard complete",
            5,
        ) => Some(LiteralRun::R906),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete",
            0,
        ) => Some(LiteralRun::R907),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete",
            1,
        ) => Some(LiteralRun::R908),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete",
            2,
        ) => Some(LiteralRun::R46),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete",
            3,
        ) => Some(LiteralRun::R46),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete",
            4,
        ) => Some(LiteralRun::R907),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-deny --shard complete",
            5,
        ) => Some(LiteralRun::R908),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete",
            0,
        ) => Some(LiteralRun::R909),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete",
            1,
        ) => Some(LiteralRun::R910),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete",
            2,
        ) => Some(LiteralRun::R144),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete",
            3,
        ) => Some(LiteralRun::R144),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete",
            4,
        ) => Some(LiteralRun::R909),
        (
            "./target/ci/release/memcordon-ci ci import-cache-snapshot --kind tool-build --purpose cargo-fuzz --shard complete",
            5,
        ) => Some(LiteralRun::R910),
        ("./target/ci/release/memcordon-ci ci miri-cache-context", 0) => Some(LiteralRun::R911),
        ("./target/ci/release/memcordon-ci ci miri-cache-context", 1) => Some(LiteralRun::R912),
        ("./target/ci/release/memcordon-ci ci miri-cache-context", 2) => Some(LiteralRun::R93),
        ("./target/ci/release/memcordon-ci ci miri-cache-context", 3) => Some(LiteralRun::R93),
        ("./target/ci/release/memcordon-ci ci miri-cache-context", 4) => Some(LiteralRun::R911),
        ("./target/ci/release/memcordon-ci ci miri-cache-context", 5) => Some(LiteralRun::R912),
        ("./target/ci/release/memcordon-ci ci performance-plan", 0) => Some(LiteralRun::R913),
        ("./target/ci/release/memcordon-ci ci performance-plan", 1) => Some(LiteralRun::R914),
        ("./target/ci/release/memcordon-ci ci performance-plan", 2) => Some(LiteralRun::R91),
        ("./target/ci/release/memcordon-ci ci performance-plan", 3) => Some(LiteralRun::R91),
        ("./target/ci/release/memcordon-ci ci performance-plan", 4) => Some(LiteralRun::R913),
        ("./target/ci/release/memcordon-ci ci performance-plan", 5) => Some(LiteralRun::R914),
        (
            "./target/ci/release/memcordon-ci ci prepare --profile fuzz --failure-mode collect-all",
            0,
        ) => Some(LiteralRun::R915),
        (
            "./target/ci/release/memcordon-ci ci prepare --profile fuzz --failure-mode collect-all",
            1,
        ) => Some(LiteralRun::R916),
        (
            "./target/ci/release/memcordon-ci ci prepare --profile fuzz --failure-mode collect-all",
            2,
        ) => Some(LiteralRun::R146),
        (
            "./target/ci/release/memcordon-ci ci prepare --profile fuzz --failure-mode collect-all",
            3,
        ) => Some(LiteralRun::R146),
        (
            "./target/ci/release/memcordon-ci ci prepare --profile fuzz --failure-mode collect-all",
            4,
        ) => Some(LiteralRun::R915),
        (
            "./target/ci/release/memcordon-ci ci prepare --profile fuzz --failure-mode collect-all",
            5,
        ) => Some(LiteralRun::R916),
        (
            "./target/ci/release/memcordon-ci ci prepare --profile fuzz --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R917),
        (
            "./target/ci/release/memcordon-ci ci prepare --profile fuzz --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R918),
        (
            "./target/ci/release/memcordon-ci ci prepare --profile fuzz --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R145),
        (
            "./target/ci/release/memcordon-ci ci prepare --profile fuzz --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R145),
        (
            "./target/ci/release/memcordon-ci ci prepare --profile fuzz --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R917),
        (
            "./target/ci/release/memcordon-ci ci prepare --profile fuzz --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R918),
        ("./target/ci/release/memcordon-ci ci prepare-miri-components", 0) => {
            Some(LiteralRun::R919)
        }
        ("./target/ci/release/memcordon-ci ci prepare-miri-components", 1) => {
            Some(LiteralRun::R920)
        }
        ("./target/ci/release/memcordon-ci ci prepare-miri-components", 2) => Some(LiteralRun::R92),
        ("./target/ci/release/memcordon-ci ci prepare-miri-components", 3) => Some(LiteralRun::R92),
        ("./target/ci/release/memcordon-ci ci prepare-miri-components", 4) => {
            Some(LiteralRun::R919)
        }
        ("./target/ci/release/memcordon-ci ci prepare-miri-components", 5) => {
            Some(LiteralRun::R920)
        }
        ("./target/ci/release/memcordon-ci ci prepare-miri-sysroot", 0) => Some(LiteralRun::R921),
        ("./target/ci/release/memcordon-ci ci prepare-miri-sysroot", 1) => Some(LiteralRun::R922),
        ("./target/ci/release/memcordon-ci ci prepare-miri-sysroot", 2) => Some(LiteralRun::R94),
        ("./target/ci/release/memcordon-ci ci prepare-miri-sysroot", 3) => Some(LiteralRun::R94),
        ("./target/ci/release/memcordon-ci ci prepare-miri-sysroot", 4) => Some(LiteralRun::R921),
        ("./target/ci/release/memcordon-ci ci prepare-miri-sysroot", 5) => Some(LiteralRun::R922),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose backend --shard complete --mode compatible",
            0,
        ) => Some(LiteralRun::R923),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose backend --shard complete --mode compatible",
            1,
        ) => Some(LiteralRun::R924),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose backend --shard complete --mode compatible",
            2,
        ) => Some(LiteralRun::R318),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose backend --shard complete --mode compatible",
            3,
        ) => Some(LiteralRun::R318),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose backend --shard complete --mode compatible",
            4,
        ) => Some(LiteralRun::R923),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose backend --shard complete --mode compatible",
            5,
        ) => Some(LiteralRun::R924),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose backend --shard complete --mode discard",
            0,
        ) => Some(LiteralRun::R925),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose backend --shard complete --mode discard",
            1,
        ) => Some(LiteralRun::R926),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose backend --shard complete --mode discard",
            2,
        ) => Some(LiteralRun::R316),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose backend --shard complete --mode discard",
            3,
        ) => Some(LiteralRun::R316),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose backend --shard complete --mode discard",
            4,
        ) => Some(LiteralRun::R925),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose backend --shard complete --mode discard",
            5,
        ) => Some(LiteralRun::R926),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose backend --shard complete --mode exact",
            0,
        ) => Some(LiteralRun::R927),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose backend --shard complete --mode exact",
            1,
        ) => Some(LiteralRun::R928),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose backend --shard complete --mode exact",
            2,
        ) => Some(LiteralRun::R317),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose backend --shard complete --mode exact",
            3,
        ) => Some(LiteralRun::R317),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose backend --shard complete --mode exact",
            4,
        ) => Some(LiteralRun::R927),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose backend --shard complete --mode exact",
            5,
        ) => Some(LiteralRun::R928),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose deadline --shard complete --mode compatible",
            0,
        ) => Some(LiteralRun::R929),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose deadline --shard complete --mode compatible",
            1,
        ) => Some(LiteralRun::R930),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose deadline --shard complete --mode compatible",
            2,
        ) => Some(LiteralRun::R83),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose deadline --shard complete --mode compatible",
            3,
        ) => Some(LiteralRun::R83),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose deadline --shard complete --mode compatible",
            4,
        ) => Some(LiteralRun::R929),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose deadline --shard complete --mode compatible",
            5,
        ) => Some(LiteralRun::R930),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose deadline --shard complete --mode discard",
            0,
        ) => Some(LiteralRun::R931),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose deadline --shard complete --mode discard",
            1,
        ) => Some(LiteralRun::R932),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose deadline --shard complete --mode discard",
            2,
        ) => Some(LiteralRun::R81),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose deadline --shard complete --mode discard",
            3,
        ) => Some(LiteralRun::R81),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose deadline --shard complete --mode discard",
            4,
        ) => Some(LiteralRun::R931),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose deadline --shard complete --mode discard",
            5,
        ) => Some(LiteralRun::R932),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose deadline --shard complete --mode exact",
            0,
        ) => Some(LiteralRun::R933),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose deadline --shard complete --mode exact",
            1,
        ) => Some(LiteralRun::R934),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose deadline --shard complete --mode exact",
            2,
        ) => Some(LiteralRun::R82),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose deadline --shard complete --mode exact",
            3,
        ) => Some(LiteralRun::R82),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose deadline --shard complete --mode exact",
            4,
        ) => Some(LiteralRun::R933),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose deadline --shard complete --mode exact",
            5,
        ) => Some(LiteralRun::R934),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode compatible --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R935),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode compatible --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R936),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode compatible --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R162),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode compatible --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R162),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode compatible --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R935),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode compatible --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R936),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode discard --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R937),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode discard --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R938),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode discard --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R160),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode discard --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R160),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode discard --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R937),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode discard --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R938),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode exact --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R939),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode exact --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R940),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode exact --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R161),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode exact --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R161),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode exact --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R939),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-four --mode exact --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R940),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode compatible --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R941),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode compatible --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R942),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode compatible --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R153),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode compatible --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R153),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode compatible --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R941),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode compatible --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R942),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode discard --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R943),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode discard --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R944),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode discard --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R151),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode discard --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R151),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode discard --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R943),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode discard --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R944),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode exact --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R945),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode exact --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R946),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode exact --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R152),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode exact --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R152),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode exact --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R945),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-one --mode exact --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R946),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode compatible --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R947),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode compatible --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R948),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode compatible --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R159),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode compatible --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R159),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode compatible --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R947),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode compatible --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R948),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode discard --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R949),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode discard --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R950),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode discard --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R157),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode discard --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R157),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode discard --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R949),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode discard --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R950),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode exact --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R951),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode exact --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R952),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode exact --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R158),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode exact --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R158),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode exact --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R951),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-three --mode exact --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R952),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode compatible --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R953),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode compatible --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R954),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode compatible --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R156),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode compatible --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R156),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode compatible --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R953),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode compatible --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R954),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode discard --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R955),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode discard --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R956),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode discard --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R154),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode discard --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R154),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode discard --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R955),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode discard --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R956),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode exact --partition fuzz-targets",
            0,
        ) => Some(LiteralRun::R957),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode exact --partition fuzz-targets",
            1,
        ) => Some(LiteralRun::R958),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode exact --partition fuzz-targets",
            2,
        ) => Some(LiteralRun::R155),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode exact --partition fuzz-targets",
            3,
        ) => Some(LiteralRun::R155),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode exact --partition fuzz-targets",
            4,
        ) => Some(LiteralRun::R957),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose fuzz --shard quarter-two --mode exact --partition fuzz-targets",
            5,
        ) => Some(LiteralRun::R958),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard acceptance --mode compatible",
            0,
        ) => Some(LiteralRun::R959),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard acceptance --mode compatible",
            1,
        ) => Some(LiteralRun::R960),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard acceptance --mode compatible",
            2,
        ) => Some(LiteralRun::R256),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard acceptance --mode compatible",
            3,
        ) => Some(LiteralRun::R256),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard acceptance --mode compatible",
            4,
        ) => Some(LiteralRun::R959),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard acceptance --mode compatible",
            5,
        ) => Some(LiteralRun::R960),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard acceptance --mode discard",
            0,
        ) => Some(LiteralRun::R961),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard acceptance --mode discard",
            1,
        ) => Some(LiteralRun::R962),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard acceptance --mode discard",
            2,
        ) => Some(LiteralRun::R254),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard acceptance --mode discard",
            3,
        ) => Some(LiteralRun::R254),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard acceptance --mode discard",
            4,
        ) => Some(LiteralRun::R961),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard acceptance --mode discard",
            5,
        ) => Some(LiteralRun::R962),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard acceptance --mode exact",
            0,
        ) => Some(LiteralRun::R963),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard acceptance --mode exact",
            1,
        ) => Some(LiteralRun::R964),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard acceptance --mode exact",
            2,
        ) => Some(LiteralRun::R255),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard acceptance --mode exact",
            3,
        ) => Some(LiteralRun::R255),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard acceptance --mode exact",
            4,
        ) => Some(LiteralRun::R963),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard acceptance --mode exact",
            5,
        ) => Some(LiteralRun::R964),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard combined --mode compatible",
            0,
        ) => Some(LiteralRun::R965),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard combined --mode compatible",
            1,
        ) => Some(LiteralRun::R966),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard combined --mode compatible",
            2,
        ) => Some(LiteralRun::R236),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard combined --mode compatible",
            3,
        ) => Some(LiteralRun::R236),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard combined --mode compatible",
            4,
        ) => Some(LiteralRun::R965),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard combined --mode compatible",
            5,
        ) => Some(LiteralRun::R966),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard combined --mode discard",
            0,
        ) => Some(LiteralRun::R967),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard combined --mode discard",
            1,
        ) => Some(LiteralRun::R968),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard combined --mode discard",
            2,
        ) => Some(LiteralRun::R234),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard combined --mode discard",
            3,
        ) => Some(LiteralRun::R234),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard combined --mode discard",
            4,
        ) => Some(LiteralRun::R967),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard combined --mode discard",
            5,
        ) => Some(LiteralRun::R968),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard combined --mode exact",
            0,
        ) => Some(LiteralRun::R969),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard combined --mode exact",
            1,
        ) => Some(LiteralRun::R970),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard combined --mode exact",
            2,
        ) => Some(LiteralRun::R235),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard combined --mode exact",
            3,
        ) => Some(LiteralRun::R235),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard combined --mode exact",
            4,
        ) => Some(LiteralRun::R969),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard combined --mode exact",
            5,
        ) => Some(LiteralRun::R970),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard native --mode compatible",
            0,
        ) => Some(LiteralRun::R971),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard native --mode compatible",
            1,
        ) => Some(LiteralRun::R972),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard native --mode compatible",
            2,
        ) => Some(LiteralRun::R246),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard native --mode compatible",
            3,
        ) => Some(LiteralRun::R246),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard native --mode compatible",
            4,
        ) => Some(LiteralRun::R971),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard native --mode compatible",
            5,
        ) => Some(LiteralRun::R972),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard native --mode discard",
            0,
        ) => Some(LiteralRun::R973),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard native --mode discard",
            1,
        ) => Some(LiteralRun::R974),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard native --mode discard",
            2,
        ) => Some(LiteralRun::R244),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard native --mode discard",
            3,
        ) => Some(LiteralRun::R244),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard native --mode discard",
            4,
        ) => Some(LiteralRun::R973),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard native --mode discard",
            5,
        ) => Some(LiteralRun::R974),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard native --mode exact",
            0,
        ) => Some(LiteralRun::R975),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard native --mode exact",
            1,
        ) => Some(LiteralRun::R976),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard native --mode exact",
            2,
        ) => Some(LiteralRun::R245),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard native --mode exact",
            3,
        ) => Some(LiteralRun::R245),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard native --mode exact",
            4,
        ) => Some(LiteralRun::R975),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose macos --shard native --mode exact",
            5,
        ) => Some(LiteralRun::R976),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode compatible",
            0,
        ) => Some(LiteralRun::R977),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode compatible",
            1,
        ) => Some(LiteralRun::R978),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode compatible",
            2,
        ) => Some(LiteralRun::R110),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode compatible",
            3,
        ) => Some(LiteralRun::R110),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode compatible",
            4,
        ) => Some(LiteralRun::R977),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode compatible",
            5,
        ) => Some(LiteralRun::R978),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode discard",
            0,
        ) => Some(LiteralRun::R979),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode discard",
            1,
        ) => Some(LiteralRun::R980),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode discard",
            2,
        ) => Some(LiteralRun::R106),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode discard",
            3,
        ) => Some(LiteralRun::R106),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode discard",
            4,
        ) => Some(LiteralRun::R979),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode discard",
            5,
        ) => Some(LiteralRun::R980),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode exact",
            0,
        ) => Some(LiteralRun::R981),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode exact",
            1,
        ) => Some(LiteralRun::R982),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode exact",
            2,
        ) => Some(LiteralRun::R108),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode exact",
            3,
        ) => Some(LiteralRun::R108),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode exact",
            4,
        ) => Some(LiteralRun::R981),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-four --mode exact",
            5,
        ) => Some(LiteralRun::R982),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode compatible",
            0,
        ) => Some(LiteralRun::R983),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode compatible",
            1,
        ) => Some(LiteralRun::R984),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode compatible",
            2,
        ) => Some(LiteralRun::R103),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode compatible",
            3,
        ) => Some(LiteralRun::R103),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode compatible",
            4,
        ) => Some(LiteralRun::R983),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode compatible",
            5,
        ) => Some(LiteralRun::R984),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode discard",
            0,
        ) => Some(LiteralRun::R985),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode discard",
            1,
        ) => Some(LiteralRun::R986),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode discard",
            2,
        ) => Some(LiteralRun::R99),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode discard",
            3,
        ) => Some(LiteralRun::R99),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode discard",
            4,
        ) => Some(LiteralRun::R985),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode discard",
            5,
        ) => Some(LiteralRun::R986),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode exact",
            0,
        ) => Some(LiteralRun::R987),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode exact",
            1,
        ) => Some(LiteralRun::R988),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode exact",
            2,
        ) => Some(LiteralRun::R101),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode exact",
            3,
        ) => Some(LiteralRun::R101),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode exact",
            4,
        ) => Some(LiteralRun::R987),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-one --mode exact",
            5,
        ) => Some(LiteralRun::R988),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode compatible",
            0,
        ) => Some(LiteralRun::R989),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode compatible",
            1,
        ) => Some(LiteralRun::R990),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode compatible",
            2,
        ) => Some(LiteralRun::R104),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode compatible",
            3,
        ) => Some(LiteralRun::R104),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode compatible",
            4,
        ) => Some(LiteralRun::R989),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode compatible",
            5,
        ) => Some(LiteralRun::R990),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode discard",
            0,
        ) => Some(LiteralRun::R991),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode discard",
            1,
        ) => Some(LiteralRun::R992),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode discard",
            2,
        ) => Some(LiteralRun::R100),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode discard",
            3,
        ) => Some(LiteralRun::R100),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode discard",
            4,
        ) => Some(LiteralRun::R991),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode discard",
            5,
        ) => Some(LiteralRun::R992),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode exact",
            0,
        ) => Some(LiteralRun::R993),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode exact",
            1,
        ) => Some(LiteralRun::R994),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode exact",
            2,
        ) => Some(LiteralRun::R102),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode exact",
            3,
        ) => Some(LiteralRun::R102),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode exact",
            4,
        ) => Some(LiteralRun::R993),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-three --mode exact",
            5,
        ) => Some(LiteralRun::R994),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode compatible",
            0,
        ) => Some(LiteralRun::R995),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode compatible",
            1,
        ) => Some(LiteralRun::R996),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode compatible",
            2,
        ) => Some(LiteralRun::R109),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode compatible",
            3,
        ) => Some(LiteralRun::R109),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode compatible",
            4,
        ) => Some(LiteralRun::R995),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode compatible",
            5,
        ) => Some(LiteralRun::R996),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode discard",
            0,
        ) => Some(LiteralRun::R997),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode discard",
            1,
        ) => Some(LiteralRun::R998),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode discard",
            2,
        ) => Some(LiteralRun::R105),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode discard",
            3,
        ) => Some(LiteralRun::R105),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode discard",
            4,
        ) => Some(LiteralRun::R997),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode discard",
            5,
        ) => Some(LiteralRun::R998),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode exact",
            0,
        ) => Some(LiteralRun::R999),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode exact",
            1,
        ) => Some(LiteralRun::R1000),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode exact",
            2,
        ) => Some(LiteralRun::R107),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode exact",
            3,
        ) => Some(LiteralRun::R107),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode exact",
            4,
        ) => Some(LiteralRun::R999),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose miri --shard quarter-two --mode exact",
            5,
        ) => Some(LiteralRun::R1000),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode compatible",
            0,
        ) => Some(LiteralRun::R1001),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode compatible",
            1,
        ) => Some(LiteralRun::R1002),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode compatible",
            2,
        ) => Some(LiteralRun::R30),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode compatible",
            3,
        ) => Some(LiteralRun::R30),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode compatible",
            4,
        ) => Some(LiteralRun::R1001),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode compatible",
            5,
        ) => Some(LiteralRun::R1002),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode discard",
            0,
        ) => Some(LiteralRun::R1003),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode discard",
            1,
        ) => Some(LiteralRun::R1004),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode discard",
            2,
        ) => Some(LiteralRun::R28),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode discard",
            3,
        ) => Some(LiteralRun::R28),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode discard",
            4,
        ) => Some(LiteralRun::R1003),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode discard",
            5,
        ) => Some(LiteralRun::R1004),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode exact",
            0,
        ) => Some(LiteralRun::R1005),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode exact",
            1,
        ) => Some(LiteralRun::R1006),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode exact",
            2,
        ) => Some(LiteralRun::R29),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode exact",
            3,
        ) => Some(LiteralRun::R29),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode exact",
            4,
        ) => Some(LiteralRun::R1005),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose msrv --shard complete --mode exact",
            5,
        ) => Some(LiteralRun::R1006),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-auxiliary --shard complete --mode compatible",
            0,
        ) => Some(LiteralRun::R1007),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-auxiliary --shard complete --mode compatible",
            1,
        ) => Some(LiteralRun::R1008),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-auxiliary --shard complete --mode compatible",
            2,
        ) => Some(LiteralRun::R63),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-auxiliary --shard complete --mode compatible",
            3,
        ) => Some(LiteralRun::R63),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-auxiliary --shard complete --mode compatible",
            4,
        ) => Some(LiteralRun::R1007),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-auxiliary --shard complete --mode compatible",
            5,
        ) => Some(LiteralRun::R1008),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-auxiliary --shard complete --mode discard",
            0,
        ) => Some(LiteralRun::R1009),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-auxiliary --shard complete --mode discard",
            1,
        ) => Some(LiteralRun::R1010),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-auxiliary --shard complete --mode discard",
            2,
        ) => Some(LiteralRun::R61),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-auxiliary --shard complete --mode discard",
            3,
        ) => Some(LiteralRun::R61),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-auxiliary --shard complete --mode discard",
            4,
        ) => Some(LiteralRun::R1009),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-auxiliary --shard complete --mode discard",
            5,
        ) => Some(LiteralRun::R1010),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-auxiliary --shard complete --mode exact",
            0,
        ) => Some(LiteralRun::R1011),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-auxiliary --shard complete --mode exact",
            1,
        ) => Some(LiteralRun::R1012),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-auxiliary --shard complete --mode exact",
            2,
        ) => Some(LiteralRun::R62),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-auxiliary --shard complete --mode exact",
            3,
        ) => Some(LiteralRun::R62),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-auxiliary --shard complete --mode exact",
            4,
        ) => Some(LiteralRun::R1011),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-auxiliary --shard complete --mode exact",
            5,
        ) => Some(LiteralRun::R1012),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-debug --shard complete --mode compatible --partition native-tests",
            0,
        ) => Some(LiteralRun::R1013),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-debug --shard complete --mode compatible --partition native-tests",
            1,
        ) => Some(LiteralRun::R1014),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-debug --shard complete --mode compatible --partition native-tests",
            2,
        ) => Some(LiteralRun::R59),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-debug --shard complete --mode compatible --partition native-tests",
            3,
        ) => Some(LiteralRun::R59),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-debug --shard complete --mode compatible --partition native-tests",
            4,
        ) => Some(LiteralRun::R1013),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-debug --shard complete --mode compatible --partition native-tests",
            5,
        ) => Some(LiteralRun::R1014),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-debug --shard complete --mode discard --partition native-tests",
            0,
        ) => Some(LiteralRun::R1015),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-debug --shard complete --mode discard --partition native-tests",
            1,
        ) => Some(LiteralRun::R1016),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-debug --shard complete --mode discard --partition native-tests",
            2,
        ) => Some(LiteralRun::R57),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-debug --shard complete --mode discard --partition native-tests",
            3,
        ) => Some(LiteralRun::R57),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-debug --shard complete --mode discard --partition native-tests",
            4,
        ) => Some(LiteralRun::R1015),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-debug --shard complete --mode discard --partition native-tests",
            5,
        ) => Some(LiteralRun::R1016),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-debug --shard complete --mode exact --partition native-tests",
            0,
        ) => Some(LiteralRun::R1017),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-debug --shard complete --mode exact --partition native-tests",
            1,
        ) => Some(LiteralRun::R1018),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-debug --shard complete --mode exact --partition native-tests",
            2,
        ) => Some(LiteralRun::R58),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-debug --shard complete --mode exact --partition native-tests",
            3,
        ) => Some(LiteralRun::R58),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-debug --shard complete --mode exact --partition native-tests",
            4,
        ) => Some(LiteralRun::R1017),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-debug --shard complete --mode exact --partition native-tests",
            5,
        ) => Some(LiteralRun::R1018),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode compatible --partition native-tests",
            0,
        ) => Some(LiteralRun::R1019),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode compatible --partition native-tests",
            1,
        ) => Some(LiteralRun::R1020),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode compatible --partition native-tests",
            2,
        ) => Some(LiteralRun::R508),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode compatible --partition native-tests",
            3,
        ) => Some(LiteralRun::R508),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode compatible --partition native-tests",
            4,
        ) => Some(LiteralRun::R1019),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode compatible --partition native-tests",
            5,
        ) => Some(LiteralRun::R1020),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode compatible --partition product",
            0,
        ) => Some(LiteralRun::R1021),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode compatible --partition product",
            1,
        ) => Some(LiteralRun::R1022),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode compatible --partition product",
            2,
        ) => Some(LiteralRun::R512),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode compatible --partition product",
            3,
        ) => Some(LiteralRun::R512),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode compatible --partition product",
            4,
        ) => Some(LiteralRun::R1021),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode compatible --partition product",
            5,
        ) => Some(LiteralRun::R1022),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode discard --partition native-tests",
            0,
        ) => Some(LiteralRun::R1023),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode discard --partition native-tests",
            1,
        ) => Some(LiteralRun::R1024),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode discard --partition native-tests",
            2,
        ) => Some(LiteralRun::R506),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode discard --partition native-tests",
            3,
        ) => Some(LiteralRun::R506),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode discard --partition native-tests",
            4,
        ) => Some(LiteralRun::R1023),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode discard --partition native-tests",
            5,
        ) => Some(LiteralRun::R1024),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode discard --partition product",
            0,
        ) => Some(LiteralRun::R1025),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode discard --partition product",
            1,
        ) => Some(LiteralRun::R1026),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode discard --partition product",
            2,
        ) => Some(LiteralRun::R510),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode discard --partition product",
            3,
        ) => Some(LiteralRun::R510),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode discard --partition product",
            4,
        ) => Some(LiteralRun::R1025),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode discard --partition product",
            5,
        ) => Some(LiteralRun::R1026),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode exact --partition native-tests",
            0,
        ) => Some(LiteralRun::R1027),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode exact --partition native-tests",
            1,
        ) => Some(LiteralRun::R1028),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode exact --partition native-tests",
            2,
        ) => Some(LiteralRun::R507),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode exact --partition native-tests",
            3,
        ) => Some(LiteralRun::R507),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode exact --partition native-tests",
            4,
        ) => Some(LiteralRun::R1027),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode exact --partition native-tests",
            5,
        ) => Some(LiteralRun::R1028),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode exact --partition product",
            0,
        ) => Some(LiteralRun::R1029),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode exact --partition product",
            1,
        ) => Some(LiteralRun::R1030),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode exact --partition product",
            2,
        ) => Some(LiteralRun::R511),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode exact --partition product",
            3,
        ) => Some(LiteralRun::R511),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode exact --partition product",
            4,
        ) => Some(LiteralRun::R1029),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose native-readiness --shard complete --mode exact --partition product",
            5,
        ) => Some(LiteralRun::R1030),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode compatible --partition native-tests",
            0,
        ) => Some(LiteralRun::R1031),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode compatible --partition native-tests",
            1,
        ) => Some(LiteralRun::R1032),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode compatible --partition native-tests",
            2,
        ) => Some(LiteralRun::R290),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode compatible --partition native-tests",
            3,
        ) => Some(LiteralRun::R290),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode compatible --partition native-tests",
            4,
        ) => Some(LiteralRun::R1031),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode compatible --partition native-tests",
            5,
        ) => Some(LiteralRun::R1032),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode compatible --partition private-native-tests",
            0,
        ) => Some(LiteralRun::R1033),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode compatible --partition private-native-tests",
            1,
        ) => Some(LiteralRun::R1034),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode compatible --partition private-native-tests",
            2,
        ) => Some(LiteralRun::R298),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode compatible --partition private-native-tests",
            3,
        ) => Some(LiteralRun::R298),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode compatible --partition private-native-tests",
            4,
        ) => Some(LiteralRun::R1033),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode compatible --partition private-native-tests",
            5,
        ) => Some(LiteralRun::R1034),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode compatible --partition product",
            0,
        ) => Some(LiteralRun::R1035),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode compatible --partition product",
            1,
        ) => Some(LiteralRun::R1036),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode compatible --partition product",
            2,
        ) => Some(LiteralRun::R294),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode compatible --partition product",
            3,
        ) => Some(LiteralRun::R294),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode compatible --partition product",
            4,
        ) => Some(LiteralRun::R1035),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode compatible --partition product",
            5,
        ) => Some(LiteralRun::R1036),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode discard --partition native-tests",
            0,
        ) => Some(LiteralRun::R1037),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode discard --partition native-tests",
            1,
        ) => Some(LiteralRun::R1038),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode discard --partition native-tests",
            2,
        ) => Some(LiteralRun::R288),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode discard --partition native-tests",
            3,
        ) => Some(LiteralRun::R288),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode discard --partition native-tests",
            4,
        ) => Some(LiteralRun::R1037),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode discard --partition native-tests",
            5,
        ) => Some(LiteralRun::R1038),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode discard --partition private-native-tests",
            0,
        ) => Some(LiteralRun::R1039),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode discard --partition private-native-tests",
            1,
        ) => Some(LiteralRun::R1040),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode discard --partition private-native-tests",
            2,
        ) => Some(LiteralRun::R296),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode discard --partition private-native-tests",
            3,
        ) => Some(LiteralRun::R296),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode discard --partition private-native-tests",
            4,
        ) => Some(LiteralRun::R1039),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode discard --partition private-native-tests",
            5,
        ) => Some(LiteralRun::R1040),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode discard --partition product",
            0,
        ) => Some(LiteralRun::R1041),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode discard --partition product",
            1,
        ) => Some(LiteralRun::R1042),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode discard --partition product",
            2,
        ) => Some(LiteralRun::R292),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode discard --partition product",
            3,
        ) => Some(LiteralRun::R292),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode discard --partition product",
            4,
        ) => Some(LiteralRun::R1041),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode discard --partition product",
            5,
        ) => Some(LiteralRun::R1042),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode exact --partition native-tests",
            0,
        ) => Some(LiteralRun::R1043),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode exact --partition native-tests",
            1,
        ) => Some(LiteralRun::R1044),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode exact --partition native-tests",
            2,
        ) => Some(LiteralRun::R289),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode exact --partition native-tests",
            3,
        ) => Some(LiteralRun::R289),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode exact --partition native-tests",
            4,
        ) => Some(LiteralRun::R1043),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode exact --partition native-tests",
            5,
        ) => Some(LiteralRun::R1044),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode exact --partition private-native-tests",
            0,
        ) => Some(LiteralRun::R1045),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode exact --partition private-native-tests",
            1,
        ) => Some(LiteralRun::R1046),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode exact --partition private-native-tests",
            2,
        ) => Some(LiteralRun::R297),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode exact --partition private-native-tests",
            3,
        ) => Some(LiteralRun::R297),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode exact --partition private-native-tests",
            4,
        ) => Some(LiteralRun::R1045),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode exact --partition private-native-tests",
            5,
        ) => Some(LiteralRun::R1046),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode exact --partition product",
            0,
        ) => Some(LiteralRun::R1047),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode exact --partition product",
            1,
        ) => Some(LiteralRun::R1048),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode exact --partition product",
            2,
        ) => Some(LiteralRun::R293),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode exact --partition product",
            3,
        ) => Some(LiteralRun::R293),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode exact --partition product",
            4,
        ) => Some(LiteralRun::R1047),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose private --shard complete --mode exact --partition product",
            5,
        ) => Some(LiteralRun::R1048),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode compatible",
            0,
        ) => Some(LiteralRun::R1049),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode compatible",
            1,
        ) => Some(LiteralRun::R1050),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode compatible",
            2,
        ) => Some(LiteralRun::R18),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode compatible",
            3,
        ) => Some(LiteralRun::R18),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode compatible",
            4,
        ) => Some(LiteralRun::R1049),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode compatible",
            5,
        ) => Some(LiteralRun::R1050),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode discard",
            0,
        ) => Some(LiteralRun::R1051),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode discard",
            1,
        ) => Some(LiteralRun::R1052),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode discard",
            2,
        ) => Some(LiteralRun::R16),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode discard",
            3,
        ) => Some(LiteralRun::R16),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode discard",
            4,
        ) => Some(LiteralRun::R1051),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode discard",
            5,
        ) => Some(LiteralRun::R1052),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode exact",
            0,
        ) => Some(LiteralRun::R1053),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode exact",
            1,
        ) => Some(LiteralRun::R1054),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode exact",
            2,
        ) => Some(LiteralRun::R17),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode exact",
            3,
        ) => Some(LiteralRun::R17),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode exact",
            4,
        ) => Some(LiteralRun::R1053),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose quality --shard complete --mode exact",
            5,
        ) => Some(LiteralRun::R1054),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress --shard complete --mode compatible",
            0,
        ) => Some(LiteralRun::R1055),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress --shard complete --mode compatible",
            1,
        ) => Some(LiteralRun::R1056),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress --shard complete --mode compatible",
            2,
        ) => Some(LiteralRun::R205),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress --shard complete --mode compatible",
            3,
        ) => Some(LiteralRun::R205),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress --shard complete --mode compatible",
            4,
        ) => Some(LiteralRun::R1055),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress --shard complete --mode compatible",
            5,
        ) => Some(LiteralRun::R1056),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress --shard complete --mode discard",
            0,
        ) => Some(LiteralRun::R1057),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress --shard complete --mode discard",
            1,
        ) => Some(LiteralRun::R1058),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress --shard complete --mode discard",
            2,
        ) => Some(LiteralRun::R203),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress --shard complete --mode discard",
            3,
        ) => Some(LiteralRun::R203),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress --shard complete --mode discard",
            4,
        ) => Some(LiteralRun::R1057),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress --shard complete --mode discard",
            5,
        ) => Some(LiteralRun::R1058),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress --shard complete --mode exact",
            0,
        ) => Some(LiteralRun::R1059),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress --shard complete --mode exact",
            1,
        ) => Some(LiteralRun::R1060),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress --shard complete --mode exact",
            2,
        ) => Some(LiteralRun::R204),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress --shard complete --mode exact",
            3,
        ) => Some(LiteralRun::R204),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress --shard complete --mode exact",
            4,
        ) => Some(LiteralRun::R1059),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress --shard complete --mode exact",
            5,
        ) => Some(LiteralRun::R1060),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-lifecycle --shard complete --mode compatible",
            0,
        ) => Some(LiteralRun::R1061),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-lifecycle --shard complete --mode compatible",
            1,
        ) => Some(LiteralRun::R1062),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-lifecycle --shard complete --mode compatible",
            2,
        ) => Some(LiteralRun::R225),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-lifecycle --shard complete --mode compatible",
            3,
        ) => Some(LiteralRun::R225),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-lifecycle --shard complete --mode compatible",
            4,
        ) => Some(LiteralRun::R1061),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-lifecycle --shard complete --mode compatible",
            5,
        ) => Some(LiteralRun::R1062),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-lifecycle --shard complete --mode discard",
            0,
        ) => Some(LiteralRun::R1063),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-lifecycle --shard complete --mode discard",
            1,
        ) => Some(LiteralRun::R1064),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-lifecycle --shard complete --mode discard",
            2,
        ) => Some(LiteralRun::R223),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-lifecycle --shard complete --mode discard",
            3,
        ) => Some(LiteralRun::R223),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-lifecycle --shard complete --mode discard",
            4,
        ) => Some(LiteralRun::R1063),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-lifecycle --shard complete --mode discard",
            5,
        ) => Some(LiteralRun::R1064),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-lifecycle --shard complete --mode exact",
            0,
        ) => Some(LiteralRun::R1065),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-lifecycle --shard complete --mode exact",
            1,
        ) => Some(LiteralRun::R1066),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-lifecycle --shard complete --mode exact",
            2,
        ) => Some(LiteralRun::R224),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-lifecycle --shard complete --mode exact",
            3,
        ) => Some(LiteralRun::R224),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-lifecycle --shard complete --mode exact",
            4,
        ) => Some(LiteralRun::R1065),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-lifecycle --shard complete --mode exact",
            5,
        ) => Some(LiteralRun::R1066),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-packages --shard complete --mode compatible",
            0,
        ) => Some(LiteralRun::R1067),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-packages --shard complete --mode compatible",
            1,
        ) => Some(LiteralRun::R1068),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-packages --shard complete --mode compatible",
            2,
        ) => Some(LiteralRun::R215),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-packages --shard complete --mode compatible",
            3,
        ) => Some(LiteralRun::R215),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-packages --shard complete --mode compatible",
            4,
        ) => Some(LiteralRun::R1067),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-packages --shard complete --mode compatible",
            5,
        ) => Some(LiteralRun::R1068),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-packages --shard complete --mode discard",
            0,
        ) => Some(LiteralRun::R1069),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-packages --shard complete --mode discard",
            1,
        ) => Some(LiteralRun::R1070),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-packages --shard complete --mode discard",
            2,
        ) => Some(LiteralRun::R213),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-packages --shard complete --mode discard",
            3,
        ) => Some(LiteralRun::R213),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-packages --shard complete --mode discard",
            4,
        ) => Some(LiteralRun::R1069),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-packages --shard complete --mode discard",
            5,
        ) => Some(LiteralRun::R1070),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-packages --shard complete --mode exact",
            0,
        ) => Some(LiteralRun::R1071),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-packages --shard complete --mode exact",
            1,
        ) => Some(LiteralRun::R1072),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-packages --shard complete --mode exact",
            2,
        ) => Some(LiteralRun::R214),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-packages --shard complete --mode exact",
            3,
        ) => Some(LiteralRun::R214),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-packages --shard complete --mode exact",
            4,
        ) => Some(LiteralRun::R1071),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose stress-packages --shard complete --mode exact",
            5,
        ) => Some(LiteralRun::R1072),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode compatible --partition native-tests",
            0,
        ) => Some(LiteralRun::R1073),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode compatible --partition native-tests",
            1,
        ) => Some(LiteralRun::R1074),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode compatible --partition native-tests",
            2,
        ) => Some(LiteralRun::R268),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode compatible --partition native-tests",
            3,
        ) => Some(LiteralRun::R268),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode compatible --partition native-tests",
            4,
        ) => Some(LiteralRun::R1073),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode compatible --partition native-tests",
            5,
        ) => Some(LiteralRun::R1074),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode compatible --partition product",
            0,
        ) => Some(LiteralRun::R1075),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode compatible --partition product",
            1,
        ) => Some(LiteralRun::R1076),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode compatible --partition product",
            2,
        ) => Some(LiteralRun::R272),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode compatible --partition product",
            3,
        ) => Some(LiteralRun::R272),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode compatible --partition product",
            4,
        ) => Some(LiteralRun::R1075),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode compatible --partition product",
            5,
        ) => Some(LiteralRun::R1076),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode discard --partition native-tests",
            0,
        ) => Some(LiteralRun::R1077),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode discard --partition native-tests",
            1,
        ) => Some(LiteralRun::R1078),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode discard --partition native-tests",
            2,
        ) => Some(LiteralRun::R266),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode discard --partition native-tests",
            3,
        ) => Some(LiteralRun::R266),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode discard --partition native-tests",
            4,
        ) => Some(LiteralRun::R1077),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode discard --partition native-tests",
            5,
        ) => Some(LiteralRun::R1078),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode discard --partition product",
            0,
        ) => Some(LiteralRun::R1079),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode discard --partition product",
            1,
        ) => Some(LiteralRun::R1080),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode discard --partition product",
            2,
        ) => Some(LiteralRun::R270),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode discard --partition product",
            3,
        ) => Some(LiteralRun::R270),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode discard --partition product",
            4,
        ) => Some(LiteralRun::R1079),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode discard --partition product",
            5,
        ) => Some(LiteralRun::R1080),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode exact --partition native-tests",
            0,
        ) => Some(LiteralRun::R1081),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode exact --partition native-tests",
            1,
        ) => Some(LiteralRun::R1082),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode exact --partition native-tests",
            2,
        ) => Some(LiteralRun::R267),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode exact --partition native-tests",
            3,
        ) => Some(LiteralRun::R267),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode exact --partition native-tests",
            4,
        ) => Some(LiteralRun::R1081),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode exact --partition native-tests",
            5,
        ) => Some(LiteralRun::R1082),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode exact --partition product",
            0,
        ) => Some(LiteralRun::R1083),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode exact --partition product",
            1,
        ) => Some(LiteralRun::R1084),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode exact --partition product",
            2,
        ) => Some(LiteralRun::R271),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode exact --partition product",
            3,
        ) => Some(LiteralRun::R271),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode exact --partition product",
            4,
        ) => Some(LiteralRun::R1083),
        (
            "./target/ci/release/memcordon-ci ci prepare-restored-cache --purpose windows-working --shard complete --mode exact --partition product",
            5,
        ) => Some(LiteralRun::R1084),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose backend --shard complete",
            0,
        ) => Some(LiteralRun::R1085),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose backend --shard complete",
            1,
        ) => Some(LiteralRun::R1086),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose backend --shard complete",
            2,
        ) => Some(LiteralRun::R319),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose backend --shard complete",
            3,
        ) => Some(LiteralRun::R319),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose backend --shard complete",
            4,
        ) => Some(LiteralRun::R1085),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose backend --shard complete",
            5,
        ) => Some(LiteralRun::R1086),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose deadline --shard complete",
            0,
        ) => Some(LiteralRun::R1087),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose deadline --shard complete",
            1,
        ) => Some(LiteralRun::R1088),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose deadline --shard complete",
            2,
        ) => Some(LiteralRun::R84),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose deadline --shard complete",
            3,
        ) => Some(LiteralRun::R84),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose deadline --shard complete",
            4,
        ) => Some(LiteralRun::R1087),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose deadline --shard complete",
            5,
        ) => Some(LiteralRun::R1088),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            0,
        ) => Some(LiteralRun::R1089),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            1,
        ) => Some(LiteralRun::R1090),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            2,
        ) => Some(LiteralRun::R187),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            3,
        ) => Some(LiteralRun::R187),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            4,
        ) => Some(LiteralRun::R1089),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-four",
            5,
        ) => Some(LiteralRun::R1090),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            0,
        ) => Some(LiteralRun::R1091),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            1,
        ) => Some(LiteralRun::R1092),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            2,
        ) => Some(LiteralRun::R163),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            3,
        ) => Some(LiteralRun::R163),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            4,
        ) => Some(LiteralRun::R1091),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-one",
            5,
        ) => Some(LiteralRun::R1092),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            0,
        ) => Some(LiteralRun::R1093),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            1,
        ) => Some(LiteralRun::R1094),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            2,
        ) => Some(LiteralRun::R179),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            3,
        ) => Some(LiteralRun::R179),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            4,
        ) => Some(LiteralRun::R1093),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-three",
            5,
        ) => Some(LiteralRun::R1094),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            0,
        ) => Some(LiteralRun::R1095),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            1,
        ) => Some(LiteralRun::R1096),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            2,
        ) => Some(LiteralRun::R171),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            3,
        ) => Some(LiteralRun::R171),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            4,
        ) => Some(LiteralRun::R1095),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose fuzz --partition fuzz-targets --shard quarter-two",
            5,
        ) => Some(LiteralRun::R1096),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose macos --shard acceptance",
            0,
        ) => Some(LiteralRun::R1097),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose macos --shard acceptance",
            1,
        ) => Some(LiteralRun::R1098),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose macos --shard acceptance",
            2,
        ) => Some(LiteralRun::R257),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose macos --shard acceptance",
            3,
        ) => Some(LiteralRun::R257),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose macos --shard acceptance",
            4,
        ) => Some(LiteralRun::R1097),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose macos --shard acceptance",
            5,
        ) => Some(LiteralRun::R1098),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose macos --shard combined",
            0,
        ) => Some(LiteralRun::R1099),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose macos --shard combined",
            1,
        ) => Some(LiteralRun::R1100),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose macos --shard combined",
            2,
        ) => Some(LiteralRun::R237),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose macos --shard combined",
            3,
        ) => Some(LiteralRun::R237),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose macos --shard combined",
            4,
        ) => Some(LiteralRun::R1099),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose macos --shard combined",
            5,
        ) => Some(LiteralRun::R1100),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose macos --shard native",
            0,
        ) => Some(LiteralRun::R1101),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose macos --shard native",
            1,
        ) => Some(LiteralRun::R1102),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose macos --shard native",
            2,
        ) => Some(LiteralRun::R247),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose macos --shard native",
            3,
        ) => Some(LiteralRun::R247),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose macos --shard native",
            4,
        ) => Some(LiteralRun::R1101),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose macos --shard native",
            5,
        ) => Some(LiteralRun::R1102),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-four",
            0,
        ) => Some(LiteralRun::R1103),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-four",
            1,
        ) => Some(LiteralRun::R1104),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-four",
            2,
        ) => Some(LiteralRun::R117),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-four",
            3,
        ) => Some(LiteralRun::R117),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-four",
            4,
        ) => Some(LiteralRun::R1103),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-four",
            5,
        ) => Some(LiteralRun::R1104),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-one",
            0,
        ) => Some(LiteralRun::R1105),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-one",
            1,
        ) => Some(LiteralRun::R1106),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-one",
            2,
        ) => Some(LiteralRun::R111),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-one",
            3,
        ) => Some(LiteralRun::R111),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-one",
            4,
        ) => Some(LiteralRun::R1105),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-one",
            5,
        ) => Some(LiteralRun::R1106),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-three",
            0,
        ) => Some(LiteralRun::R1107),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-three",
            1,
        ) => Some(LiteralRun::R1108),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-three",
            2,
        ) => Some(LiteralRun::R113),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-three",
            3,
        ) => Some(LiteralRun::R113),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-three",
            4,
        ) => Some(LiteralRun::R1107),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-three",
            5,
        ) => Some(LiteralRun::R1108),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-two",
            0,
        ) => Some(LiteralRun::R1109),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-two",
            1,
        ) => Some(LiteralRun::R1110),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-two",
            2,
        ) => Some(LiteralRun::R115),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-two",
            3,
        ) => Some(LiteralRun::R115),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-two",
            4,
        ) => Some(LiteralRun::R1109),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose miri --shard quarter-two",
            5,
        ) => Some(LiteralRun::R1110),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose msrv --shard complete",
            0,
        ) => Some(LiteralRun::R1111),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose msrv --shard complete",
            1,
        ) => Some(LiteralRun::R1112),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose msrv --shard complete",
            2,
        ) => Some(LiteralRun::R31),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose msrv --shard complete",
            3,
        ) => Some(LiteralRun::R31),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose msrv --shard complete",
            4,
        ) => Some(LiteralRun::R1111),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose msrv --shard complete",
            5,
        ) => Some(LiteralRun::R1112),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles",
            0,
        ) => Some(LiteralRun::R1113),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles",
            1,
        ) => Some(LiteralRun::R1114),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles",
            2,
        ) => Some(LiteralRun::R67),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles",
            3,
        ) => Some(LiteralRun::R67),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles",
            4,
        ) => Some(LiteralRun::R1113),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose native-auxiliary --shard complete --partition auxiliary-profiles",
            5,
        ) => Some(LiteralRun::R1114),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose native-debug --partition native-tests --shard complete",
            0,
        ) => Some(LiteralRun::R1115),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose native-debug --partition native-tests --shard complete",
            1,
        ) => Some(LiteralRun::R1116),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose native-debug --partition native-tests --shard complete",
            2,
        ) => Some(LiteralRun::R64),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose native-debug --partition native-tests --shard complete",
            3,
        ) => Some(LiteralRun::R64),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose native-debug --partition native-tests --shard complete",
            4,
        ) => Some(LiteralRun::R1115),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose native-debug --partition native-tests --shard complete",
            5,
        ) => Some(LiteralRun::R1116),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose native-readiness --shard complete --partition native-tests",
            0,
        ) => Some(LiteralRun::R1117),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose native-readiness --shard complete --partition native-tests",
            1,
        ) => Some(LiteralRun::R1118),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose native-readiness --shard complete --partition native-tests",
            2,
        ) => Some(LiteralRun::R513),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose native-readiness --shard complete --partition native-tests",
            3,
        ) => Some(LiteralRun::R513),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose native-readiness --shard complete --partition native-tests",
            4,
        ) => Some(LiteralRun::R1117),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose native-readiness --shard complete --partition native-tests",
            5,
        ) => Some(LiteralRun::R1118),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose native-readiness --shard complete --partition product",
            0,
        ) => Some(LiteralRun::R1119),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose native-readiness --shard complete --partition product",
            1,
        ) => Some(LiteralRun::R1120),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose native-readiness --shard complete --partition product",
            2,
        ) => Some(LiteralRun::R515),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose native-readiness --shard complete --partition product",
            3,
        ) => Some(LiteralRun::R515),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose native-readiness --shard complete --partition product",
            4,
        ) => Some(LiteralRun::R1119),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose native-readiness --shard complete --partition product",
            5,
        ) => Some(LiteralRun::R1120),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose private --shard complete --partition native-tests",
            0,
        ) => Some(LiteralRun::R1121),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose private --shard complete --partition native-tests",
            1,
        ) => Some(LiteralRun::R1122),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose private --shard complete --partition native-tests",
            2,
        ) => Some(LiteralRun::R299),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose private --shard complete --partition native-tests",
            3,
        ) => Some(LiteralRun::R299),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose private --shard complete --partition native-tests",
            4,
        ) => Some(LiteralRun::R1121),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose private --shard complete --partition native-tests",
            5,
        ) => Some(LiteralRun::R1122),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose private --shard complete --partition private-native-tests",
            0,
        ) => Some(LiteralRun::R1123),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose private --shard complete --partition private-native-tests",
            1,
        ) => Some(LiteralRun::R1124),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose private --shard complete --partition private-native-tests",
            2,
        ) => Some(LiteralRun::R303),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose private --shard complete --partition private-native-tests",
            3,
        ) => Some(LiteralRun::R303),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose private --shard complete --partition private-native-tests",
            4,
        ) => Some(LiteralRun::R1123),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose private --shard complete --partition private-native-tests",
            5,
        ) => Some(LiteralRun::R1124),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose private --shard complete --partition product",
            0,
        ) => Some(LiteralRun::R1125),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose private --shard complete --partition product",
            1,
        ) => Some(LiteralRun::R1126),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose private --shard complete --partition product",
            2,
        ) => Some(LiteralRun::R301),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose private --shard complete --partition product",
            3,
        ) => Some(LiteralRun::R301),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose private --shard complete --partition product",
            4,
        ) => Some(LiteralRun::R1125),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose private --shard complete --partition product",
            5,
        ) => Some(LiteralRun::R1126),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose quality --shard complete",
            0,
        ) => Some(LiteralRun::R1127),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose quality --shard complete",
            1,
        ) => Some(LiteralRun::R1128),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose quality --shard complete",
            2,
        ) => Some(LiteralRun::R19),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose quality --shard complete",
            3,
        ) => Some(LiteralRun::R19),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose quality --shard complete",
            4,
        ) => Some(LiteralRun::R1127),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose quality --shard complete",
            5,
        ) => Some(LiteralRun::R1128),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose stress --shard complete",
            0,
        ) => Some(LiteralRun::R1129),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose stress --shard complete",
            1,
        ) => Some(LiteralRun::R1130),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose stress --shard complete",
            2,
        ) => Some(LiteralRun::R206),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose stress --shard complete",
            3,
        ) => Some(LiteralRun::R206),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose stress --shard complete",
            4,
        ) => Some(LiteralRun::R1129),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose stress --shard complete",
            5,
        ) => Some(LiteralRun::R1130),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose stress-lifecycle --shard complete",
            0,
        ) => Some(LiteralRun::R1131),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose stress-lifecycle --shard complete",
            1,
        ) => Some(LiteralRun::R1132),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose stress-lifecycle --shard complete",
            2,
        ) => Some(LiteralRun::R226),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose stress-lifecycle --shard complete",
            3,
        ) => Some(LiteralRun::R226),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose stress-lifecycle --shard complete",
            4,
        ) => Some(LiteralRun::R1131),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose stress-lifecycle --shard complete",
            5,
        ) => Some(LiteralRun::R1132),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose stress-packages --shard complete",
            0,
        ) => Some(LiteralRun::R1133),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose stress-packages --shard complete",
            1,
        ) => Some(LiteralRun::R1134),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose stress-packages --shard complete",
            2,
        ) => Some(LiteralRun::R216),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose stress-packages --shard complete",
            3,
        ) => Some(LiteralRun::R216),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose stress-packages --shard complete",
            4,
        ) => Some(LiteralRun::R1133),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose stress-packages --shard complete",
            5,
        ) => Some(LiteralRun::R1134),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose windows-working --shard complete --partition native-tests",
            0,
        ) => Some(LiteralRun::R1135),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose windows-working --shard complete --partition native-tests",
            1,
        ) => Some(LiteralRun::R1136),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose windows-working --shard complete --partition native-tests",
            2,
        ) => Some(LiteralRun::R273),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose windows-working --shard complete --partition native-tests",
            3,
        ) => Some(LiteralRun::R273),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose windows-working --shard complete --partition native-tests",
            4,
        ) => Some(LiteralRun::R1135),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose windows-working --shard complete --partition native-tests",
            5,
        ) => Some(LiteralRun::R1136),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose windows-working --shard complete --partition product",
            0,
        ) => Some(LiteralRun::R1137),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose windows-working --shard complete --partition product",
            1,
        ) => Some(LiteralRun::R1138),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose windows-working --shard complete --partition product",
            2,
        ) => Some(LiteralRun::R275),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose windows-working --shard complete --partition product",
            3,
        ) => Some(LiteralRun::R275),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose windows-working --shard complete --partition product",
            4,
        ) => Some(LiteralRun::R1137),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind compiled --purpose windows-working --shard complete --partition product",
            5,
        ) => Some(LiteralRun::R1138),
        ("./target/ci/release/memcordon-ci ci seed-context --kind registry-archives", 0) => {
            Some(LiteralRun::R1139)
        }
        ("./target/ci/release/memcordon-ci ci seed-context --kind registry-archives", 1) => {
            Some(LiteralRun::R1140)
        }
        ("./target/ci/release/memcordon-ci ci seed-context --kind registry-archives", 2) => {
            Some(LiteralRun::R4)
        }
        ("./target/ci/release/memcordon-ci ci seed-context --kind registry-archives", 3) => {
            Some(LiteralRun::R4)
        }
        ("./target/ci/release/memcordon-ci ci seed-context --kind registry-archives", 4) => {
            Some(LiteralRun::R1139)
        }
        ("./target/ci/release/memcordon-ci ci seed-context --kind registry-archives", 5) => {
            Some(LiteralRun::R1140)
        }
        ("./target/ci/release/memcordon-ci ci seed-context --kind registry-index", 0) => {
            Some(LiteralRun::R1141)
        }
        ("./target/ci/release/memcordon-ci ci seed-context --kind registry-index", 1) => {
            Some(LiteralRun::R1142)
        }
        ("./target/ci/release/memcordon-ci ci seed-context --kind registry-index", 2) => {
            Some(LiteralRun::R6)
        }
        ("./target/ci/release/memcordon-ci ci seed-context --kind registry-index", 3) => {
            Some(LiteralRun::R6)
        }
        ("./target/ci/release/memcordon-ci ci seed-context --kind registry-index", 4) => {
            Some(LiteralRun::R1141)
        }
        ("./target/ci/release/memcordon-ci ci seed-context --kind registry-index", 5) => {
            Some(LiteralRun::R1142)
        }
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind tool-build --purpose cargo-audit --shard complete",
            0,
        ) => Some(LiteralRun::R1143),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind tool-build --purpose cargo-audit --shard complete",
            1,
        ) => Some(LiteralRun::R1144),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind tool-build --purpose cargo-audit --shard complete",
            2,
        ) => Some(LiteralRun::R43),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind tool-build --purpose cargo-audit --shard complete",
            3,
        ) => Some(LiteralRun::R43),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind tool-build --purpose cargo-audit --shard complete",
            4,
        ) => Some(LiteralRun::R1143),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind tool-build --purpose cargo-audit --shard complete",
            5,
        ) => Some(LiteralRun::R1144),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind tool-build --purpose cargo-deny --shard complete",
            0,
        ) => Some(LiteralRun::R1145),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind tool-build --purpose cargo-deny --shard complete",
            1,
        ) => Some(LiteralRun::R1146),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind tool-build --purpose cargo-deny --shard complete",
            2,
        ) => Some(LiteralRun::R45),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind tool-build --purpose cargo-deny --shard complete",
            3,
        ) => Some(LiteralRun::R45),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind tool-build --purpose cargo-deny --shard complete",
            4,
        ) => Some(LiteralRun::R1145),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind tool-build --purpose cargo-deny --shard complete",
            5,
        ) => Some(LiteralRun::R1146),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind tool-build --purpose cargo-fuzz --shard complete",
            0,
        ) => Some(LiteralRun::R1147),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind tool-build --purpose cargo-fuzz --shard complete",
            1,
        ) => Some(LiteralRun::R1148),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind tool-build --purpose cargo-fuzz --shard complete",
            2,
        ) => Some(LiteralRun::R143),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind tool-build --purpose cargo-fuzz --shard complete",
            3,
        ) => Some(LiteralRun::R143),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind tool-build --purpose cargo-fuzz --shard complete",
            4,
        ) => Some(LiteralRun::R1147),
        (
            "./target/ci/release/memcordon-ci ci seed-context --kind tool-build --purpose cargo-fuzz --shard complete",
            5,
        ) => Some(LiteralRun::R1148),
        ("./target/ci/release/memcordon-ci ci workflow-scope", 0) => Some(LiteralRun::R1149),
        ("./target/ci/release/memcordon-ci ci workflow-scope", 1) => Some(LiteralRun::R1150),
        ("./target/ci/release/memcordon-ci ci workflow-scope", 2) => Some(LiteralRun::R90),
        ("./target/ci/release/memcordon-ci ci workflow-scope", 3) => Some(LiteralRun::R90),
        ("./target/ci/release/memcordon-ci ci workflow-scope", 4) => Some(LiteralRun::R1149),
        ("./target/ci/release/memcordon-ci ci workflow-scope", 5) => Some(LiteralRun::R1150),
        (
            "./target/ci/release/memcordon-ci consumer-readiness-loader-diagnostic --identity .release/native-readiness-identity.json --github-context --destination .release/support-loader-diagnostic",
            0,
        ) => Some(LiteralRun::R1151),
        (
            "./target/ci/release/memcordon-ci consumer-readiness-loader-diagnostic --identity .release/native-readiness-identity.json --github-context --destination .release/support-loader-diagnostic",
            1,
        ) => Some(LiteralRun::R1152),
        (
            "./target/ci/release/memcordon-ci consumer-readiness-loader-diagnostic --identity .release/native-readiness-identity.json --github-context --destination .release/support-loader-diagnostic",
            2,
        ) => Some(LiteralRun::R528),
        (
            "./target/ci/release/memcordon-ci consumer-readiness-loader-diagnostic --identity .release/native-readiness-identity.json --github-context --destination .release/support-loader-diagnostic",
            3,
        ) => Some(LiteralRun::R528),
        (
            "./target/ci/release/memcordon-ci consumer-readiness-loader-diagnostic --identity .release/native-readiness-identity.json --github-context --destination .release/support-loader-diagnostic",
            4,
        ) => Some(LiteralRun::R1151),
        (
            "./target/ci/release/memcordon-ci consumer-readiness-loader-diagnostic --identity .release/native-readiness-identity.json --github-context --destination .release/support-loader-diagnostic",
            5,
        ) => Some(LiteralRun::R1152),
        (
            "./target/ci/release/memcordon-ci consumer-readiness-loader-diagnostic --identity .release/native-readiness-identity.json --github-context --destination .release/support-loader-diagnostic --cleanup",
            0,
        ) => Some(LiteralRun::R1153),
        (
            "./target/ci/release/memcordon-ci consumer-readiness-loader-diagnostic --identity .release/native-readiness-identity.json --github-context --destination .release/support-loader-diagnostic --cleanup",
            1,
        ) => Some(LiteralRun::R1154),
        (
            "./target/ci/release/memcordon-ci consumer-readiness-loader-diagnostic --identity .release/native-readiness-identity.json --github-context --destination .release/support-loader-diagnostic --cleanup",
            2,
        ) => Some(LiteralRun::R529),
        (
            "./target/ci/release/memcordon-ci consumer-readiness-loader-diagnostic --identity .release/native-readiness-identity.json --github-context --destination .release/support-loader-diagnostic --cleanup",
            3,
        ) => Some(LiteralRun::R529),
        (
            "./target/ci/release/memcordon-ci consumer-readiness-loader-diagnostic --identity .release/native-readiness-identity.json --github-context --destination .release/support-loader-diagnostic --cleanup",
            4,
        ) => Some(LiteralRun::R1153),
        (
            "./target/ci/release/memcordon-ci consumer-readiness-loader-diagnostic --identity .release/native-readiness-identity.json --github-context --destination .release/support-loader-diagnostic --cleanup",
            5,
        ) => Some(LiteralRun::R1154),
        (
            "./target/ci/release/memcordon-ci consumer-readiness-native-components --identity .release/native-readiness-identity.json --github-context --destination .release/native-readiness",
            0,
        ) => Some(LiteralRun::R1155),
        (
            "./target/ci/release/memcordon-ci consumer-readiness-native-components --identity .release/native-readiness-identity.json --github-context --destination .release/native-readiness",
            1,
        ) => Some(LiteralRun::R1156),
        (
            "./target/ci/release/memcordon-ci consumer-readiness-native-components --identity .release/native-readiness-identity.json --github-context --destination .release/native-readiness",
            2,
        ) => Some(LiteralRun::R526),
        (
            "./target/ci/release/memcordon-ci consumer-readiness-native-components --identity .release/native-readiness-identity.json --github-context --destination .release/native-readiness",
            3,
        ) => Some(LiteralRun::R526),
        (
            "./target/ci/release/memcordon-ci consumer-readiness-native-components --identity .release/native-readiness-identity.json --github-context --destination .release/native-readiness",
            4,
        ) => Some(LiteralRun::R1155),
        (
            "./target/ci/release/memcordon-ci consumer-readiness-native-components --identity .release/native-readiness-identity.json --github-context --destination .release/native-readiness",
            5,
        ) => Some(LiteralRun::R1156),
        (
            "./target/ci/release/memcordon-ci consumer-readiness-native-components --identity .release/native-readiness-identity.json --github-context --destination .release/native-readiness --cleanup",
            0,
        ) => Some(LiteralRun::R1157),
        (
            "./target/ci/release/memcordon-ci consumer-readiness-native-components --identity .release/native-readiness-identity.json --github-context --destination .release/native-readiness --cleanup",
            1,
        ) => Some(LiteralRun::R1158),
        (
            "./target/ci/release/memcordon-ci consumer-readiness-native-components --identity .release/native-readiness-identity.json --github-context --destination .release/native-readiness --cleanup",
            2,
        ) => Some(LiteralRun::R527),
        (
            "./target/ci/release/memcordon-ci consumer-readiness-native-components --identity .release/native-readiness-identity.json --github-context --destination .release/native-readiness --cleanup",
            3,
        ) => Some(LiteralRun::R527),
        (
            "./target/ci/release/memcordon-ci consumer-readiness-native-components --identity .release/native-readiness-identity.json --github-context --destination .release/native-readiness --cleanup",
            4,
        ) => Some(LiteralRun::R1157),
        (
            "./target/ci/release/memcordon-ci consumer-readiness-native-components --identity .release/native-readiness-identity.json --github-context --destination .release/native-readiness --cleanup",
            5,
        ) => Some(LiteralRun::R1158),
        (
            "./target/ci/release/memcordon-ci release build-target --build-source .release/build-source.json --consumer-readiness",
            0,
        ) => Some(LiteralRun::R1159),
        (
            "./target/ci/release/memcordon-ci release build-target --build-source .release/build-source.json --consumer-readiness",
            1,
        ) => Some(LiteralRun::R1160),
        (
            "./target/ci/release/memcordon-ci release build-target --build-source .release/build-source.json --consumer-readiness",
            2,
        ) => Some(LiteralRun::R517),
        (
            "./target/ci/release/memcordon-ci release build-target --build-source .release/build-source.json --consumer-readiness",
            3,
        ) => Some(LiteralRun::R517),
        (
            "./target/ci/release/memcordon-ci release build-target --build-source .release/build-source.json --consumer-readiness",
            4,
        ) => Some(LiteralRun::R1159),
        (
            "./target/ci/release/memcordon-ci release build-target --build-source .release/build-source.json --consumer-readiness",
            5,
        ) => Some(LiteralRun::R1160),
        (
            "./target/ci/release/memcordon-ci release build-target --build-source .release/build-source.json --consumer-readiness --failure-mode collect-all",
            0,
        ) => Some(LiteralRun::R1161),
        (
            "./target/ci/release/memcordon-ci release build-target --build-source .release/build-source.json --consumer-readiness --failure-mode collect-all",
            1,
        ) => Some(LiteralRun::R1162),
        (
            "./target/ci/release/memcordon-ci release build-target --build-source .release/build-source.json --consumer-readiness --failure-mode collect-all",
            2,
        ) => Some(LiteralRun::R518),
        (
            "./target/ci/release/memcordon-ci release build-target --build-source .release/build-source.json --consumer-readiness --failure-mode collect-all",
            3,
        ) => Some(LiteralRun::R518),
        (
            "./target/ci/release/memcordon-ci release build-target --build-source .release/build-source.json --consumer-readiness --failure-mode collect-all",
            4,
        ) => Some(LiteralRun::R1161),
        (
            "./target/ci/release/memcordon-ci release build-target --build-source .release/build-source.json --consumer-readiness --failure-mode collect-all",
            5,
        ) => Some(LiteralRun::R1162),
        (
            "./target/ci/release/memcordon-ci release check-preparation --build-source .release/build-source.json --consumer-readiness",
            0,
        ) => Some(LiteralRun::R1163),
        (
            "./target/ci/release/memcordon-ci release check-preparation --build-source .release/build-source.json --consumer-readiness",
            1,
        ) => Some(LiteralRun::R1164),
        (
            "./target/ci/release/memcordon-ci release check-preparation --build-source .release/build-source.json --consumer-readiness",
            2,
        ) => Some(LiteralRun::R329),
        (
            "./target/ci/release/memcordon-ci release check-preparation --build-source .release/build-source.json --consumer-readiness",
            3,
        ) => Some(LiteralRun::R329),
        (
            "./target/ci/release/memcordon-ci release check-preparation --build-source .release/build-source.json --consumer-readiness",
            4,
        ) => Some(LiteralRun::R1163),
        (
            "./target/ci/release/memcordon-ci release check-preparation --build-source .release/build-source.json --consumer-readiness",
            5,
        ) => Some(LiteralRun::R1164),
        (
            "./target/ci/release/memcordon-ci release consumer-cache --channel cargo --profile readiness",
            0,
        ) => Some(LiteralRun::R1165),
        (
            "./target/ci/release/memcordon-ci release consumer-cache --channel cargo --profile readiness",
            1,
        ) => Some(LiteralRun::R1166),
        (
            "./target/ci/release/memcordon-ci release consumer-cache --channel cargo --profile readiness",
            2,
        ) => Some(LiteralRun::R536),
        (
            "./target/ci/release/memcordon-ci release consumer-cache --channel cargo --profile readiness",
            3,
        ) => Some(LiteralRun::R536),
        (
            "./target/ci/release/memcordon-ci release consumer-cache --channel cargo --profile readiness",
            4,
        ) => Some(LiteralRun::R1165),
        (
            "./target/ci/release/memcordon-ci release consumer-cache --channel cargo --profile readiness",
            5,
        ) => Some(LiteralRun::R1166),
        (
            "./target/ci/release/memcordon-ci release consumer-cache --channel native --profile readiness",
            0,
        ) => Some(LiteralRun::R1167),
        (
            "./target/ci/release/memcordon-ci release consumer-cache --channel native --profile readiness",
            1,
        ) => Some(LiteralRun::R1168),
        (
            "./target/ci/release/memcordon-ci release consumer-cache --channel native --profile readiness",
            2,
        ) => Some(LiteralRun::R537),
        (
            "./target/ci/release/memcordon-ci release consumer-cache --channel native --profile readiness",
            3,
        ) => Some(LiteralRun::R537),
        (
            "./target/ci/release/memcordon-ci release consumer-cache --channel native --profile readiness",
            4,
        ) => Some(LiteralRun::R1167),
        (
            "./target/ci/release/memcordon-ci release consumer-cache --channel native --profile readiness",
            5,
        ) => Some(LiteralRun::R1168),
        (
            "./target/ci/release/memcordon-ci release consumer-cache --target target/ci/windows-prepared/native-payload --packages target/ci/windows-prepared/cargo-payload --channel cargo --profile readiness",
            0,
        ) => Some(LiteralRun::R1169),
        (
            "./target/ci/release/memcordon-ci release consumer-cache --target target/ci/windows-prepared/native-payload --packages target/ci/windows-prepared/cargo-payload --channel cargo --profile readiness",
            1,
        ) => Some(LiteralRun::R1170),
        (
            "./target/ci/release/memcordon-ci release consumer-cache --target target/ci/windows-prepared/native-payload --packages target/ci/windows-prepared/cargo-payload --channel cargo --profile readiness",
            2,
        ) => Some(LiteralRun::R284),
        (
            "./target/ci/release/memcordon-ci release consumer-cache --target target/ci/windows-prepared/native-payload --packages target/ci/windows-prepared/cargo-payload --channel cargo --profile readiness",
            3,
        ) => Some(LiteralRun::R284),
        (
            "./target/ci/release/memcordon-ci release consumer-cache --target target/ci/windows-prepared/native-payload --packages target/ci/windows-prepared/cargo-payload --channel cargo --profile readiness",
            4,
        ) => Some(LiteralRun::R1169),
        (
            "./target/ci/release/memcordon-ci release consumer-cache --target target/ci/windows-prepared/native-payload --packages target/ci/windows-prepared/cargo-payload --channel cargo --profile readiness",
            5,
        ) => Some(LiteralRun::R1170),
        (
            "./target/ci/release/memcordon-ci release consumer-readiness-report --identity .release/readiness-identity.json --verifier ./target/ci/release/memcordon-readiness-verifier --scope candidate-before-publication --destination .release/readiness-report",
            0,
        ) => Some(LiteralRun::R1171),
        (
            "./target/ci/release/memcordon-ci release consumer-readiness-report --identity .release/readiness-identity.json --verifier ./target/ci/release/memcordon-readiness-verifier --scope candidate-before-publication --destination .release/readiness-report",
            1,
        ) => Some(LiteralRun::R1172),
        (
            "./target/ci/release/memcordon-ci release consumer-readiness-report --identity .release/readiness-identity.json --verifier ./target/ci/release/memcordon-readiness-verifier --scope candidate-before-publication --destination .release/readiness-report",
            2,
        ) => Some(LiteralRun::R550),
        (
            "./target/ci/release/memcordon-ci release consumer-readiness-report --identity .release/readiness-identity.json --verifier ./target/ci/release/memcordon-readiness-verifier --scope candidate-before-publication --destination .release/readiness-report",
            3,
        ) => Some(LiteralRun::R550),
        (
            "./target/ci/release/memcordon-ci release consumer-readiness-report --identity .release/readiness-identity.json --verifier ./target/ci/release/memcordon-readiness-verifier --scope candidate-before-publication --destination .release/readiness-report",
            4,
        ) => Some(LiteralRun::R1171),
        (
            "./target/ci/release/memcordon-ci release consumer-readiness-report --identity .release/readiness-identity.json --verifier ./target/ci/release/memcordon-readiness-verifier --scope candidate-before-publication --destination .release/readiness-report",
            5,
        ) => Some(LiteralRun::R1172),
        (
            "./target/ci/release/memcordon-ci release consumer-readiness-report --identity .release/readiness-identity.json --verifier ./target/ci/release/memcordon-readiness-verifier --scope complete-profile --destination .release/readiness-report",
            0,
        ) => Some(LiteralRun::R1173),
        (
            "./target/ci/release/memcordon-ci release consumer-readiness-report --identity .release/readiness-identity.json --verifier ./target/ci/release/memcordon-readiness-verifier --scope complete-profile --destination .release/readiness-report",
            1,
        ) => Some(LiteralRun::R1174),
        (
            "./target/ci/release/memcordon-ci release consumer-readiness-report --identity .release/readiness-identity.json --verifier ./target/ci/release/memcordon-readiness-verifier --scope complete-profile --destination .release/readiness-report",
            2,
        ) => Some(LiteralRun::R551),
        (
            "./target/ci/release/memcordon-ci release consumer-readiness-report --identity .release/readiness-identity.json --verifier ./target/ci/release/memcordon-readiness-verifier --scope complete-profile --destination .release/readiness-report",
            3,
        ) => Some(LiteralRun::R551),
        (
            "./target/ci/release/memcordon-ci release consumer-readiness-report --identity .release/readiness-identity.json --verifier ./target/ci/release/memcordon-readiness-verifier --scope complete-profile --destination .release/readiness-report",
            4,
        ) => Some(LiteralRun::R1173),
        (
            "./target/ci/release/memcordon-ci release consumer-readiness-report --identity .release/readiness-identity.json --verifier ./target/ci/release/memcordon-readiness-verifier --scope complete-profile --destination .release/readiness-report",
            5,
        ) => Some(LiteralRun::R1174),
        (
            "./target/ci/release/memcordon-ci release installed-consumers --channel cargo --destination .release/installed-results/cargo",
            0,
        ) => Some(LiteralRun::R1175),
        (
            "./target/ci/release/memcordon-ci release installed-consumers --channel cargo --destination .release/installed-results/cargo",
            1,
        ) => Some(LiteralRun::R1176),
        (
            "./target/ci/release/memcordon-ci release installed-consumers --channel cargo --destination .release/installed-results/cargo",
            2,
        ) => Some(LiteralRun::R539),
        (
            "./target/ci/release/memcordon-ci release installed-consumers --channel cargo --destination .release/installed-results/cargo",
            3,
        ) => Some(LiteralRun::R539),
        (
            "./target/ci/release/memcordon-ci release installed-consumers --channel cargo --destination .release/installed-results/cargo",
            4,
        ) => Some(LiteralRun::R1175),
        (
            "./target/ci/release/memcordon-ci release installed-consumers --channel cargo --destination .release/installed-results/cargo",
            5,
        ) => Some(LiteralRun::R1176),
        (
            "./target/ci/release/memcordon-ci release installed-consumers --channel native --destination .release/installed-results/native",
            0,
        ) => Some(LiteralRun::R1177),
        (
            "./target/ci/release/memcordon-ci release installed-consumers --channel native --destination .release/installed-results/native",
            1,
        ) => Some(LiteralRun::R1178),
        (
            "./target/ci/release/memcordon-ci release installed-consumers --channel native --destination .release/installed-results/native",
            2,
        ) => Some(LiteralRun::R538),
        (
            "./target/ci/release/memcordon-ci release installed-consumers --channel native --destination .release/installed-results/native",
            3,
        ) => Some(LiteralRun::R538),
        (
            "./target/ci/release/memcordon-ci release installed-consumers --channel native --destination .release/installed-results/native",
            4,
        ) => Some(LiteralRun::R1177),
        (
            "./target/ci/release/memcordon-ci release installed-consumers --channel native --destination .release/installed-results/native",
            5,
        ) => Some(LiteralRun::R1178),
        ("./target/ci/release/memcordon-ci release publication-tool", 0) => Some(LiteralRun::R1179),
        ("./target/ci/release/memcordon-ci release publication-tool", 1) => Some(LiteralRun::R1180),
        ("./target/ci/release/memcordon-ci release publication-tool", 2) => Some(LiteralRun::R330),
        ("./target/ci/release/memcordon-ci release publication-tool", 3) => Some(LiteralRun::R330),
        ("./target/ci/release/memcordon-ci release publication-tool", 4) => Some(LiteralRun::R1179),
        ("./target/ci/release/memcordon-ci release publication-tool", 5) => Some(LiteralRun::R1180),
        ("./target/ci/release/memcordon-ci release select-preparation", 0) => {
            Some(LiteralRun::R1181)
        }
        ("./target/ci/release/memcordon-ci release select-preparation", 1) => {
            Some(LiteralRun::R1182)
        }
        ("./target/ci/release/memcordon-ci release select-preparation", 2) => {
            Some(LiteralRun::R328)
        }
        ("./target/ci/release/memcordon-ci release select-preparation", 3) => {
            Some(LiteralRun::R328)
        }
        ("./target/ci/release/memcordon-ci release select-preparation", 4) => {
            Some(LiteralRun::R1181)
        }
        ("./target/ci/release/memcordon-ci release select-preparation", 5) => {
            Some(LiteralRun::R1182)
        }
        (
            "./target/ci/release/memcordon-ci release working-windows-consumer --channel cargo --destination target/ci/windows-installed/cargo",
            0,
        ) => Some(LiteralRun::R1183),
        (
            "./target/ci/release/memcordon-ci release working-windows-consumer --channel cargo --destination target/ci/windows-installed/cargo",
            1,
        ) => Some(LiteralRun::R1184),
        (
            "./target/ci/release/memcordon-ci release working-windows-consumer --channel cargo --destination target/ci/windows-installed/cargo",
            2,
        ) => Some(LiteralRun::R286),
        (
            "./target/ci/release/memcordon-ci release working-windows-consumer --channel cargo --destination target/ci/windows-installed/cargo",
            3,
        ) => Some(LiteralRun::R286),
        (
            "./target/ci/release/memcordon-ci release working-windows-consumer --channel cargo --destination target/ci/windows-installed/cargo",
            4,
        ) => Some(LiteralRun::R1183),
        (
            "./target/ci/release/memcordon-ci release working-windows-consumer --channel cargo --destination target/ci/windows-installed/cargo",
            5,
        ) => Some(LiteralRun::R1184),
        (
            "./target/ci/release/memcordon-ci release working-windows-consumer --channel native --destination target/ci/windows-installed/native",
            0,
        ) => Some(LiteralRun::R1185),
        (
            "./target/ci/release/memcordon-ci release working-windows-consumer --channel native --destination target/ci/windows-installed/native",
            1,
        ) => Some(LiteralRun::R1186),
        (
            "./target/ci/release/memcordon-ci release working-windows-consumer --channel native --destination target/ci/windows-installed/native",
            2,
        ) => Some(LiteralRun::R285),
        (
            "./target/ci/release/memcordon-ci release working-windows-consumer --channel native --destination target/ci/windows-installed/native",
            3,
        ) => Some(LiteralRun::R285),
        (
            "./target/ci/release/memcordon-ci release working-windows-consumer --channel native --destination target/ci/windows-installed/native",
            4,
        ) => Some(LiteralRun::R1185),
        (
            "./target/ci/release/memcordon-ci release working-windows-consumer --channel native --destination target/ci/windows-installed/native",
            5,
        ) => Some(LiteralRun::R1186),
        ("./target/ci/release/memcordon-ci release working-windows-prepare", 0) => {
            Some(LiteralRun::R1187)
        }
        ("./target/ci/release/memcordon-ci release working-windows-prepare", 1) => {
            Some(LiteralRun::R1188)
        }
        ("./target/ci/release/memcordon-ci release working-windows-prepare", 2) => {
            Some(LiteralRun::R277)
        }
        ("./target/ci/release/memcordon-ci release working-windows-prepare", 3) => {
            Some(LiteralRun::R277)
        }
        ("./target/ci/release/memcordon-ci release working-windows-prepare", 4) => {
            Some(LiteralRun::R1187)
        }
        ("./target/ci/release/memcordon-ci release working-windows-prepare", 5) => {
            Some(LiteralRun::R1188)
        }
        ("./target/ci/release/memcordon-ci suite backend-linux-cgroup", 0) => {
            Some(LiteralRun::R1189)
        }
        ("./target/ci/release/memcordon-ci suite backend-linux-cgroup", 1) => {
            Some(LiteralRun::R1190)
        }
        ("./target/ci/release/memcordon-ci suite backend-linux-cgroup", 2) => {
            Some(LiteralRun::R321)
        }
        ("./target/ci/release/memcordon-ci suite backend-linux-cgroup", 3) => {
            Some(LiteralRun::R321)
        }
        ("./target/ci/release/memcordon-ci suite backend-linux-cgroup", 4) => {
            Some(LiteralRun::R1189)
        }
        ("./target/ci/release/memcordon-ci suite backend-linux-cgroup", 5) => {
            Some(LiteralRun::R1190)
        }
        ("./target/ci/release/memcordon-ci suite backend-linux-private", 0) => {
            Some(LiteralRun::R1191)
        }
        ("./target/ci/release/memcordon-ci suite backend-linux-private", 1) => {
            Some(LiteralRun::R1192)
        }
        ("./target/ci/release/memcordon-ci suite backend-linux-private", 2) => {
            Some(LiteralRun::R305)
        }
        ("./target/ci/release/memcordon-ci suite backend-linux-private", 3) => {
            Some(LiteralRun::R305)
        }
        ("./target/ci/release/memcordon-ci suite backend-linux-private", 4) => {
            Some(LiteralRun::R1191)
        }
        ("./target/ci/release/memcordon-ci suite backend-linux-private", 5) => {
            Some(LiteralRun::R1192)
        }
        ("./target/ci/release/memcordon-ci suite backend-macos-watchdog", 0) => {
            Some(LiteralRun::R1193)
        }
        ("./target/ci/release/memcordon-ci suite backend-macos-watchdog", 1) => {
            Some(LiteralRun::R1194)
        }
        ("./target/ci/release/memcordon-ci suite backend-macos-watchdog", 2) => {
            Some(LiteralRun::R239)
        }
        ("./target/ci/release/memcordon-ci suite backend-macos-watchdog", 3) => {
            Some(LiteralRun::R239)
        }
        ("./target/ci/release/memcordon-ci suite backend-macos-watchdog", 4) => {
            Some(LiteralRun::R1193)
        }
        ("./target/ci/release/memcordon-ci suite backend-macos-watchdog", 5) => {
            Some(LiteralRun::R1194)
        }
        ("./target/ci/release/memcordon-ci suite backend-windows-job", 0) => {
            Some(LiteralRun::R1195)
        }
        ("./target/ci/release/memcordon-ci suite backend-windows-job", 1) => {
            Some(LiteralRun::R1196)
        }
        ("./target/ci/release/memcordon-ci suite backend-windows-job", 2) => Some(LiteralRun::R325),
        ("./target/ci/release/memcordon-ci suite backend-windows-job", 3) => Some(LiteralRun::R325),
        ("./target/ci/release/memcordon-ci suite backend-windows-job", 4) => {
            Some(LiteralRun::R1195)
        }
        ("./target/ci/release/memcordon-ci suite backend-windows-job", 5) => {
            Some(LiteralRun::R1196)
        }
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-four --failure-mode collect-all",
            0,
        ) => Some(LiteralRun::R1197),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-four --failure-mode collect-all",
            1,
        ) => Some(LiteralRun::R1198),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-four --failure-mode collect-all",
            2,
        ) => Some(LiteralRun::R190),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-four --failure-mode collect-all",
            3,
        ) => Some(LiteralRun::R190),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-four --failure-mode collect-all",
            4,
        ) => Some(LiteralRun::R1197),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-four --failure-mode collect-all",
            5,
        ) => Some(LiteralRun::R1198),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-four --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R1199),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-four --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R1200),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-four --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R189),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-four --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R189),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-four --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R1199),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-four --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R1200),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-one --failure-mode collect-all",
            0,
        ) => Some(LiteralRun::R1201),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-one --failure-mode collect-all",
            1,
        ) => Some(LiteralRun::R1202),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-one --failure-mode collect-all",
            2,
        ) => Some(LiteralRun::R166),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-one --failure-mode collect-all",
            3,
        ) => Some(LiteralRun::R166),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-one --failure-mode collect-all",
            4,
        ) => Some(LiteralRun::R1201),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-one --failure-mode collect-all",
            5,
        ) => Some(LiteralRun::R1202),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-one --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R1203),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-one --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R1204),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-one --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R165),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-one --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R165),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-one --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R1203),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-one --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R1204),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-three --failure-mode collect-all",
            0,
        ) => Some(LiteralRun::R1205),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-three --failure-mode collect-all",
            1,
        ) => Some(LiteralRun::R1206),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-three --failure-mode collect-all",
            2,
        ) => Some(LiteralRun::R182),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-three --failure-mode collect-all",
            3,
        ) => Some(LiteralRun::R182),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-three --failure-mode collect-all",
            4,
        ) => Some(LiteralRun::R1205),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-three --failure-mode collect-all",
            5,
        ) => Some(LiteralRun::R1206),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-three --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R1207),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-three --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R1208),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-three --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R181),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-three --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R181),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-three --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R1207),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-three --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R1208),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-two --failure-mode collect-all",
            0,
        ) => Some(LiteralRun::R1209),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-two --failure-mode collect-all",
            1,
        ) => Some(LiteralRun::R1210),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-two --failure-mode collect-all",
            2,
        ) => Some(LiteralRun::R174),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-two --failure-mode collect-all",
            3,
        ) => Some(LiteralRun::R174),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-two --failure-mode collect-all",
            4,
        ) => Some(LiteralRun::R1209),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-two --failure-mode collect-all",
            5,
        ) => Some(LiteralRun::R1210),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-two --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R1211),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-two --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R1212),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-two --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R173),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-two --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R173),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-two --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R1211),
        (
            "./target/ci/release/memcordon-ci suite fuzz-compile-quarter-two --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R1212),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-four --failure-mode collect-all",
            0,
        ) => Some(LiteralRun::R1213),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-four --failure-mode collect-all",
            1,
        ) => Some(LiteralRun::R1214),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-four --failure-mode collect-all",
            2,
        ) => Some(LiteralRun::R194),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-four --failure-mode collect-all",
            3,
        ) => Some(LiteralRun::R194),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-four --failure-mode collect-all",
            4,
        ) => Some(LiteralRun::R1213),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-four --failure-mode collect-all",
            5,
        ) => Some(LiteralRun::R1214),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-four --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R1215),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-four --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R1216),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-four --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R193),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-four --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R193),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-four --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R1215),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-four --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R1216),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-one --failure-mode collect-all",
            0,
        ) => Some(LiteralRun::R1217),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-one --failure-mode collect-all",
            1,
        ) => Some(LiteralRun::R1218),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-one --failure-mode collect-all",
            2,
        ) => Some(LiteralRun::R170),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-one --failure-mode collect-all",
            3,
        ) => Some(LiteralRun::R170),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-one --failure-mode collect-all",
            4,
        ) => Some(LiteralRun::R1217),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-one --failure-mode collect-all",
            5,
        ) => Some(LiteralRun::R1218),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-one --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R1219),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-one --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R1220),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-one --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R169),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-one --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R169),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-one --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R1219),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-one --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R1220),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-three --failure-mode collect-all",
            0,
        ) => Some(LiteralRun::R1221),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-three --failure-mode collect-all",
            1,
        ) => Some(LiteralRun::R1222),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-three --failure-mode collect-all",
            2,
        ) => Some(LiteralRun::R186),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-three --failure-mode collect-all",
            3,
        ) => Some(LiteralRun::R186),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-three --failure-mode collect-all",
            4,
        ) => Some(LiteralRun::R1221),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-three --failure-mode collect-all",
            5,
        ) => Some(LiteralRun::R1222),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-three --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R1223),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-three --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R1224),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-three --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R185),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-three --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R185),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-three --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R1223),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-three --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R1224),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-two --failure-mode collect-all",
            0,
        ) => Some(LiteralRun::R1225),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-two --failure-mode collect-all",
            1,
        ) => Some(LiteralRun::R1226),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-two --failure-mode collect-all",
            2,
        ) => Some(LiteralRun::R178),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-two --failure-mode collect-all",
            3,
        ) => Some(LiteralRun::R178),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-two --failure-mode collect-all",
            4,
        ) => Some(LiteralRun::R1225),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-two --failure-mode collect-all",
            5,
        ) => Some(LiteralRun::R1226),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-two --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R1227),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-two --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R1228),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-two --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R177),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-two --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R177),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-two --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R1227),
        (
            "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-two --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R1228),
        ("./target/ci/release/memcordon-ci suite macos-deadline", 0) => Some(LiteralRun::R1229),
        ("./target/ci/release/memcordon-ci suite macos-deadline", 1) => Some(LiteralRun::R1230),
        ("./target/ci/release/memcordon-ci suite macos-deadline", 2) => Some(LiteralRun::R86),
        ("./target/ci/release/memcordon-ci suite macos-deadline", 3) => Some(LiteralRun::R86),
        ("./target/ci/release/memcordon-ci suite macos-deadline", 4) => Some(LiteralRun::R1229),
        ("./target/ci/release/memcordon-ci suite macos-deadline", 5) => Some(LiteralRun::R1230),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-four --failure-mode collect-all",
            0,
        ) => Some(LiteralRun::R1231),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-four --failure-mode collect-all",
            1,
        ) => Some(LiteralRun::R1232),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-four --failure-mode collect-all",
            2,
        ) => Some(LiteralRun::R126),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-four --failure-mode collect-all",
            3,
        ) => Some(LiteralRun::R126),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-four --failure-mode collect-all",
            4,
        ) => Some(LiteralRun::R1231),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-four --failure-mode collect-all",
            5,
        ) => Some(LiteralRun::R1232),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-four --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R1233),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-four --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R1234),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-four --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R125),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-four --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R125),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-four --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R1233),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-four --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R1234),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-one --failure-mode collect-all",
            0,
        ) => Some(LiteralRun::R1235),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-one --failure-mode collect-all",
            1,
        ) => Some(LiteralRun::R1236),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-one --failure-mode collect-all",
            2,
        ) => Some(LiteralRun::R120),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-one --failure-mode collect-all",
            3,
        ) => Some(LiteralRun::R120),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-one --failure-mode collect-all",
            4,
        ) => Some(LiteralRun::R1235),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-one --failure-mode collect-all",
            5,
        ) => Some(LiteralRun::R1236),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-one --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R1237),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-one --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R1238),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-one --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R119),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-one --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R119),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-one --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R1237),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-one --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R1238),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-three --failure-mode collect-all",
            0,
        ) => Some(LiteralRun::R1239),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-three --failure-mode collect-all",
            1,
        ) => Some(LiteralRun::R1240),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-three --failure-mode collect-all",
            2,
        ) => Some(LiteralRun::R122),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-three --failure-mode collect-all",
            3,
        ) => Some(LiteralRun::R122),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-three --failure-mode collect-all",
            4,
        ) => Some(LiteralRun::R1239),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-three --failure-mode collect-all",
            5,
        ) => Some(LiteralRun::R1240),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-three --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R1241),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-three --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R1242),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-three --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R121),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-three --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R121),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-three --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R1241),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-three --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R1242),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-two --failure-mode collect-all",
            0,
        ) => Some(LiteralRun::R1243),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-two --failure-mode collect-all",
            1,
        ) => Some(LiteralRun::R1244),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-two --failure-mode collect-all",
            2,
        ) => Some(LiteralRun::R124),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-two --failure-mode collect-all",
            3,
        ) => Some(LiteralRun::R124),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-two --failure-mode collect-all",
            4,
        ) => Some(LiteralRun::R1243),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-two --failure-mode collect-all",
            5,
        ) => Some(LiteralRun::R1244),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-two --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R1245),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-two --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R1246),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-two --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R123),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-two --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R123),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-two --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R1245),
        (
            "./target/ci/release/memcordon-ci suite miri-quarter-two --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R1246),
        ("./target/ci/release/memcordon-ci suite msrv --failure-mode collect-all", 0) => {
            Some(LiteralRun::R1247)
        }
        ("./target/ci/release/memcordon-ci suite msrv --failure-mode collect-all", 1) => {
            Some(LiteralRun::R1248)
        }
        ("./target/ci/release/memcordon-ci suite msrv --failure-mode collect-all", 2) => {
            Some(LiteralRun::R34)
        }
        ("./target/ci/release/memcordon-ci suite msrv --failure-mode collect-all", 3) => {
            Some(LiteralRun::R34)
        }
        ("./target/ci/release/memcordon-ci suite msrv --failure-mode collect-all", 4) => {
            Some(LiteralRun::R1247)
        }
        ("./target/ci/release/memcordon-ci suite msrv --failure-mode collect-all", 5) => {
            Some(LiteralRun::R1248)
        }
        ("./target/ci/release/memcordon-ci suite msrv --failure-mode stop-after-failure", 0) => {
            Some(LiteralRun::R1249)
        }
        ("./target/ci/release/memcordon-ci suite msrv --failure-mode stop-after-failure", 1) => {
            Some(LiteralRun::R1250)
        }
        ("./target/ci/release/memcordon-ci suite msrv --failure-mode stop-after-failure", 2) => {
            Some(LiteralRun::R33)
        }
        ("./target/ci/release/memcordon-ci suite msrv --failure-mode stop-after-failure", 3) => {
            Some(LiteralRun::R33)
        }
        ("./target/ci/release/memcordon-ci suite msrv --failure-mode stop-after-failure", 4) => {
            Some(LiteralRun::R1249)
        }
        ("./target/ci/release/memcordon-ci suite msrv --failure-mode stop-after-failure", 5) => {
            Some(LiteralRun::R1250)
        }
        ("./target/ci/release/memcordon-ci suite native-compile", 0) => Some(LiteralRun::R1251),
        ("./target/ci/release/memcordon-ci suite native-compile", 1) => Some(LiteralRun::R1252),
        ("./target/ci/release/memcordon-ci suite native-compile", 2) => Some(LiteralRun::R69),
        ("./target/ci/release/memcordon-ci suite native-compile", 3) => Some(LiteralRun::R69),
        ("./target/ci/release/memcordon-ci suite native-compile", 4) => Some(LiteralRun::R1251),
        ("./target/ci/release/memcordon-ci suite native-compile", 5) => Some(LiteralRun::R1252),
        ("./target/ci/release/memcordon-ci suite native-execute", 0) => Some(LiteralRun::R1253),
        ("./target/ci/release/memcordon-ci suite native-execute", 1) => Some(LiteralRun::R1254),
        ("./target/ci/release/memcordon-ci suite native-execute", 2) => Some(LiteralRun::R72),
        ("./target/ci/release/memcordon-ci suite native-execute", 3) => Some(LiteralRun::R72),
        ("./target/ci/release/memcordon-ci suite native-execute", 4) => Some(LiteralRun::R1253),
        ("./target/ci/release/memcordon-ci suite native-execute", 5) => Some(LiteralRun::R1254),
        ("./target/ci/release/memcordon-ci suite native-execute --failure-mode collect-all", 0) => {
            Some(LiteralRun::R1255)
        }
        ("./target/ci/release/memcordon-ci suite native-execute --failure-mode collect-all", 1) => {
            Some(LiteralRun::R1256)
        }
        ("./target/ci/release/memcordon-ci suite native-execute --failure-mode collect-all", 2) => {
            Some(LiteralRun::R73)
        }
        ("./target/ci/release/memcordon-ci suite native-execute --failure-mode collect-all", 3) => {
            Some(LiteralRun::R73)
        }
        ("./target/ci/release/memcordon-ci suite native-execute --failure-mode collect-all", 4) => {
            Some(LiteralRun::R1255)
        }
        ("./target/ci/release/memcordon-ci suite native-execute --failure-mode collect-all", 5) => {
            Some(LiteralRun::R1256)
        }
        ("./target/ci/release/memcordon-ci suite policy", 0) => Some(LiteralRun::R1257),
        ("./target/ci/release/memcordon-ci suite policy", 1) => Some(LiteralRun::R1258),
        ("./target/ci/release/memcordon-ci suite policy", 2) => Some(LiteralRun::R13),
        ("./target/ci/release/memcordon-ci suite policy", 3) => Some(LiteralRun::R13),
        ("./target/ci/release/memcordon-ci suite policy", 4) => Some(LiteralRun::R1257),
        ("./target/ci/release/memcordon-ci suite policy", 5) => Some(LiteralRun::R1258),
        ("./target/ci/release/memcordon-ci suite quality --failure-mode collect-all", 0) => {
            Some(LiteralRun::R1259)
        }
        ("./target/ci/release/memcordon-ci suite quality --failure-mode collect-all", 1) => {
            Some(LiteralRun::R1260)
        }
        ("./target/ci/release/memcordon-ci suite quality --failure-mode collect-all", 2) => {
            Some(LiteralRun::R22)
        }
        ("./target/ci/release/memcordon-ci suite quality --failure-mode collect-all", 3) => {
            Some(LiteralRun::R22)
        }
        ("./target/ci/release/memcordon-ci suite quality --failure-mode collect-all", 4) => {
            Some(LiteralRun::R1259)
        }
        ("./target/ci/release/memcordon-ci suite quality --failure-mode collect-all", 5) => {
            Some(LiteralRun::R1260)
        }
        ("./target/ci/release/memcordon-ci suite quality --failure-mode stop-after-failure", 0) => {
            Some(LiteralRun::R1261)
        }
        ("./target/ci/release/memcordon-ci suite quality --failure-mode stop-after-failure", 1) => {
            Some(LiteralRun::R1262)
        }
        ("./target/ci/release/memcordon-ci suite quality --failure-mode stop-after-failure", 2) => {
            Some(LiteralRun::R21)
        }
        ("./target/ci/release/memcordon-ci suite quality --failure-mode stop-after-failure", 3) => {
            Some(LiteralRun::R21)
        }
        ("./target/ci/release/memcordon-ci suite quality --failure-mode stop-after-failure", 4) => {
            Some(LiteralRun::R1261)
        }
        ("./target/ci/release/memcordon-ci suite quality --failure-mode stop-after-failure", 5) => {
            Some(LiteralRun::R1262)
        }
        ("./target/ci/release/memcordon-ci suite release-macos-acceptance", 0) => {
            Some(LiteralRun::R1263)
        }
        ("./target/ci/release/memcordon-ci suite release-macos-acceptance", 1) => {
            Some(LiteralRun::R1264)
        }
        ("./target/ci/release/memcordon-ci suite release-macos-acceptance", 2) => {
            Some(LiteralRun::R259)
        }
        ("./target/ci/release/memcordon-ci suite release-macos-acceptance", 3) => {
            Some(LiteralRun::R259)
        }
        ("./target/ci/release/memcordon-ci suite release-macos-acceptance", 4) => {
            Some(LiteralRun::R1263)
        }
        ("./target/ci/release/memcordon-ci suite release-macos-acceptance", 5) => {
            Some(LiteralRun::R1264)
        }
        ("./target/ci/release/memcordon-ci suite release-macos-native", 0) => {
            Some(LiteralRun::R1265)
        }
        ("./target/ci/release/memcordon-ci suite release-macos-native", 1) => {
            Some(LiteralRun::R1266)
        }
        ("./target/ci/release/memcordon-ci suite release-macos-native", 2) => {
            Some(LiteralRun::R249)
        }
        ("./target/ci/release/memcordon-ci suite release-macos-native", 3) => {
            Some(LiteralRun::R249)
        }
        ("./target/ci/release/memcordon-ci suite release-macos-native", 4) => {
            Some(LiteralRun::R1265)
        }
        ("./target/ci/release/memcordon-ci suite release-macos-native", 5) => {
            Some(LiteralRun::R1266)
        }
        ("./target/ci/release/memcordon-ci suite stress", 0) => Some(LiteralRun::R1267),
        ("./target/ci/release/memcordon-ci suite stress", 1) => Some(LiteralRun::R1268),
        ("./target/ci/release/memcordon-ci suite stress", 2) => Some(LiteralRun::R208),
        ("./target/ci/release/memcordon-ci suite stress", 3) => Some(LiteralRun::R208),
        ("./target/ci/release/memcordon-ci suite stress", 4) => Some(LiteralRun::R1267),
        ("./target/ci/release/memcordon-ci suite stress", 5) => Some(LiteralRun::R1268),
        ("./target/ci/release/memcordon-ci suite stress-lifecycle", 0) => Some(LiteralRun::R1269),
        ("./target/ci/release/memcordon-ci suite stress-lifecycle", 1) => Some(LiteralRun::R1270),
        ("./target/ci/release/memcordon-ci suite stress-lifecycle", 2) => Some(LiteralRun::R228),
        ("./target/ci/release/memcordon-ci suite stress-lifecycle", 3) => Some(LiteralRun::R228),
        ("./target/ci/release/memcordon-ci suite stress-lifecycle", 4) => Some(LiteralRun::R1269),
        ("./target/ci/release/memcordon-ci suite stress-lifecycle", 5) => Some(LiteralRun::R1270),
        ("./target/ci/release/memcordon-ci suite stress-packages", 0) => Some(LiteralRun::R1271),
        ("./target/ci/release/memcordon-ci suite stress-packages", 1) => Some(LiteralRun::R1272),
        ("./target/ci/release/memcordon-ci suite stress-packages", 2) => Some(LiteralRun::R218),
        ("./target/ci/release/memcordon-ci suite stress-packages", 3) => Some(LiteralRun::R218),
        ("./target/ci/release/memcordon-ci suite stress-packages", 4) => Some(LiteralRun::R1271),
        ("./target/ci/release/memcordon-ci suite stress-packages", 5) => Some(LiteralRun::R1272),
        ("./target/ci/release/memcordon-ci suite supply-chain --failure-mode collect-all", 0) => {
            Some(LiteralRun::R1273)
        }
        ("./target/ci/release/memcordon-ci suite supply-chain --failure-mode collect-all", 1) => {
            Some(LiteralRun::R1274)
        }
        ("./target/ci/release/memcordon-ci suite supply-chain --failure-mode collect-all", 2) => {
            Some(LiteralRun::R48)
        }
        ("./target/ci/release/memcordon-ci suite supply-chain --failure-mode collect-all", 3) => {
            Some(LiteralRun::R48)
        }
        ("./target/ci/release/memcordon-ci suite supply-chain --failure-mode collect-all", 4) => {
            Some(LiteralRun::R1273)
        }
        ("./target/ci/release/memcordon-ci suite supply-chain --failure-mode collect-all", 5) => {
            Some(LiteralRun::R1274)
        }
        (
            "./target/ci/release/memcordon-ci suite supply-chain --failure-mode stop-after-failure",
            0,
        ) => Some(LiteralRun::R1275),
        (
            "./target/ci/release/memcordon-ci suite supply-chain --failure-mode stop-after-failure",
            1,
        ) => Some(LiteralRun::R1276),
        (
            "./target/ci/release/memcordon-ci suite supply-chain --failure-mode stop-after-failure",
            2,
        ) => Some(LiteralRun::R47),
        (
            "./target/ci/release/memcordon-ci suite supply-chain --failure-mode stop-after-failure",
            3,
        ) => Some(LiteralRun::R47),
        (
            "./target/ci/release/memcordon-ci suite supply-chain --failure-mode stop-after-failure",
            4,
        ) => Some(LiteralRun::R1275),
        (
            "./target/ci/release/memcordon-ci suite supply-chain --failure-mode stop-after-failure",
            5,
        ) => Some(LiteralRun::R1276),
        ("git config --global core.autocrlf false", 0) => Some(LiteralRun::R264),
        ("git config --global core.autocrlf false", 1) => Some(LiteralRun::R264),
        ("git config --global core.autocrlf false", 2) => Some(LiteralRun::R264),
        ("git config --global core.autocrlf false", 3) => Some(LiteralRun::R264),
        ("git config --global core.autocrlf false", 4) => Some(LiteralRun::R264),
        ("git config --global core.autocrlf false", 5) => Some(LiteralRun::R264),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-ci --bin consumer-readiness",
            0,
        ) => Some(LiteralRun::R530),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-ci --bin consumer-readiness",
            1,
        ) => Some(LiteralRun::R530),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-ci --bin consumer-readiness",
            2,
        ) => Some(LiteralRun::R1277),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-ci --bin consumer-readiness",
            3,
        ) => Some(LiteralRun::R530),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-ci --bin consumer-readiness",
            4,
        ) => Some(LiteralRun::R530),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-ci --bin consumer-readiness",
            5,
        ) => Some(LiteralRun::R530),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-ci --bin memcordon-ci",
            0,
        ) => Some(LiteralRun::R1),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-ci --bin memcordon-ci",
            1,
        ) => Some(LiteralRun::R1),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-ci --bin memcordon-ci",
            2,
        ) => Some(LiteralRun::R1278),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-ci --bin memcordon-ci",
            3,
        ) => Some(LiteralRun::R1),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-ci --bin memcordon-ci",
            4,
        ) => Some(LiteralRun::R1),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-ci --bin memcordon-ci",
            5,
        ) => Some(LiteralRun::R1),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-ci --bin memcordon-ci --bin consumer-readiness",
            0,
        ) => Some(LiteralRun::R504),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-ci --bin memcordon-ci --bin consumer-readiness",
            1,
        ) => Some(LiteralRun::R504),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-ci --bin memcordon-ci --bin consumer-readiness",
            2,
        ) => Some(LiteralRun::R1279),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-ci --bin memcordon-ci --bin consumer-readiness",
            3,
        ) => Some(LiteralRun::R504),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-ci --bin memcordon-ci --bin consumer-readiness",
            4,
        ) => Some(LiteralRun::R504),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-ci --bin memcordon-ci --bin consumer-readiness",
            5,
        ) => Some(LiteralRun::R504),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-readiness-verifier",
            0,
        ) => Some(LiteralRun::R549),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-readiness-verifier",
            1,
        ) => Some(LiteralRun::R549),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-readiness-verifier",
            2,
        ) => Some(LiteralRun::R1280),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-readiness-verifier",
            3,
        ) => Some(LiteralRun::R549),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-readiness-verifier",
            4,
        ) => Some(LiteralRun::R549),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-readiness-verifier",
            5,
        ) => Some(LiteralRun::R549),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci/native -p memcordon --features test-fixtures --bin memcordon-test-fixture",
            0,
        ) => Some(LiteralRun::R547),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci/native -p memcordon --features test-fixtures --bin memcordon-test-fixture",
            1,
        ) => Some(LiteralRun::R547),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci/native -p memcordon --features test-fixtures --bin memcordon-test-fixture",
            2,
        ) => Some(LiteralRun::R547),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci/native -p memcordon --features test-fixtures --bin memcordon-test-fixture",
            3,
        ) => Some(LiteralRun::R547),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci/native -p memcordon --features test-fixtures --bin memcordon-test-fixture",
            4,
        ) => Some(LiteralRun::R547),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci/native -p memcordon --features test-fixtures --bin memcordon-test-fixture",
            5,
        ) => Some(LiteralRun::R547),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci/rehearsal-build -p memcordon-ci --bin memcordon-release-rehearsal",
            0,
        ) => Some(LiteralRun::R390),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci/rehearsal-build -p memcordon-ci --bin memcordon-release-rehearsal",
            1,
        ) => Some(LiteralRun::R390),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci/rehearsal-build -p memcordon-ci --bin memcordon-release-rehearsal",
            2,
        ) => Some(LiteralRun::R390),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci/rehearsal-build -p memcordon-ci --bin memcordon-release-rehearsal",
            3,
        ) => Some(LiteralRun::R390),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci/rehearsal-build -p memcordon-ci --bin memcordon-release-rehearsal",
            4,
        ) => Some(LiteralRun::R390),
        (
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci/rehearsal-build -p memcordon-ci --bin memcordon-release-rehearsal",
            5,
        ) => Some(LiteralRun::R390),
        (
            "rustup run 1.97.1 cargo clean --locked --package memcordon-ci --target-dir target",
            0,
        ) => Some(LiteralRun::R55),
        (
            "rustup run 1.97.1 cargo clean --locked --package memcordon-ci --target-dir target",
            1,
        ) => Some(LiteralRun::R55),
        (
            "rustup run 1.97.1 cargo clean --locked --package memcordon-ci --target-dir target",
            2,
        ) => Some(LiteralRun::R55),
        (
            "rustup run 1.97.1 cargo clean --locked --package memcordon-ci --target-dir target",
            3,
        ) => Some(LiteralRun::R55),
        (
            "rustup run 1.97.1 cargo clean --locked --package memcordon-ci --target-dir target",
            4,
        ) => Some(LiteralRun::R55),
        (
            "rustup run 1.97.1 cargo clean --locked --package memcordon-ci --target-dir target",
            5,
        ) => Some(LiteralRun::R55),
        ("rustup run 1.97.1 cargo fmt --all -- --check", 0) => Some(LiteralRun::R327),
        ("rustup run 1.97.1 cargo fmt --all -- --check", 1) => Some(LiteralRun::R327),
        ("rustup run 1.97.1 cargo fmt --all -- --check", 2) => Some(LiteralRun::R327),
        ("rustup run 1.97.1 cargo fmt --all -- --check", 3) => Some(LiteralRun::R327),
        ("rustup run 1.97.1 cargo fmt --all -- --check", 4) => Some(LiteralRun::R327),
        ("rustup run 1.97.1 cargo fmt --all -- --check", 5) => Some(LiteralRun::R327),
        ("rustup toolchain install 1.85.0 --profile minimal", 0) => Some(LiteralRun::R26),
        ("rustup toolchain install 1.85.0 --profile minimal", 1) => Some(LiteralRun::R26),
        ("rustup toolchain install 1.85.0 --profile minimal", 2) => Some(LiteralRun::R26),
        ("rustup toolchain install 1.85.0 --profile minimal", 3) => Some(LiteralRun::R26),
        ("rustup toolchain install 1.85.0 --profile minimal", 4) => Some(LiteralRun::R26),
        ("rustup toolchain install 1.85.0 --profile minimal", 5) => Some(LiteralRun::R26),
        ("rustup toolchain install 1.97.1 --profile minimal", 0) => Some(LiteralRun::R0),
        ("rustup toolchain install 1.97.1 --profile minimal", 1) => Some(LiteralRun::R0),
        ("rustup toolchain install 1.97.1 --profile minimal", 2) => Some(LiteralRun::R0),
        ("rustup toolchain install 1.97.1 --profile minimal", 3) => Some(LiteralRun::R0),
        ("rustup toolchain install 1.97.1 --profile minimal", 4) => Some(LiteralRun::R0),
        ("rustup toolchain install 1.97.1 --profile minimal", 5) => Some(LiteralRun::R0),
        (
            "rustup toolchain install 1.97.1 --profile minimal --component clippy --component rustfmt",
            0,
        ) => Some(LiteralRun::R14),
        (
            "rustup toolchain install 1.97.1 --profile minimal --component clippy --component rustfmt",
            1,
        ) => Some(LiteralRun::R14),
        (
            "rustup toolchain install 1.97.1 --profile minimal --component clippy --component rustfmt",
            2,
        ) => Some(LiteralRun::R14),
        (
            "rustup toolchain install 1.97.1 --profile minimal --component clippy --component rustfmt",
            3,
        ) => Some(LiteralRun::R14),
        (
            "rustup toolchain install 1.97.1 --profile minimal --component clippy --component rustfmt",
            4,
        ) => Some(LiteralRun::R14),
        (
            "rustup toolchain install 1.97.1 --profile minimal --component clippy --component rustfmt",
            5,
        ) => Some(LiteralRun::R14),
        ("rustup toolchain install 1.97.1 --profile minimal --component rustfmt", 0) => {
            Some(LiteralRun::R326)
        }
        ("rustup toolchain install 1.97.1 --profile minimal --component rustfmt", 1) => {
            Some(LiteralRun::R326)
        }
        ("rustup toolchain install 1.97.1 --profile minimal --component rustfmt", 2) => {
            Some(LiteralRun::R326)
        }
        ("rustup toolchain install 1.97.1 --profile minimal --component rustfmt", 3) => {
            Some(LiteralRun::R326)
        }
        ("rustup toolchain install 1.97.1 --profile minimal --component rustfmt", 4) => {
            Some(LiteralRun::R326)
        }
        ("rustup toolchain install 1.97.1 --profile minimal --component rustfmt", 5) => {
            Some(LiteralRun::R326)
        }
        ("rustup toolchain install nightly-2026-07-31 --profile minimal", 0) => {
            Some(LiteralRun::R141)
        }
        ("rustup toolchain install nightly-2026-07-31 --profile minimal", 1) => {
            Some(LiteralRun::R141)
        }
        ("rustup toolchain install nightly-2026-07-31 --profile minimal", 2) => {
            Some(LiteralRun::R141)
        }
        ("rustup toolchain install nightly-2026-07-31 --profile minimal", 3) => {
            Some(LiteralRun::R141)
        }
        ("rustup toolchain install nightly-2026-07-31 --profile minimal", 4) => {
            Some(LiteralRun::R141)
        }
        ("rustup toolchain install nightly-2026-07-31 --profile minimal", 5) => {
            Some(LiteralRun::R141)
        }
        (
            "tar -xzf .release/rehearsal-tool/memcordon-release-rehearsal.tar.gz -C .release/rehearsal-tool",
            0,
        ) => Some(LiteralRun::R542),
        (
            "tar -xzf .release/rehearsal-tool/memcordon-release-rehearsal.tar.gz -C .release/rehearsal-tool",
            1,
        ) => Some(LiteralRun::R542),
        (
            "tar -xzf .release/rehearsal-tool/memcordon-release-rehearsal.tar.gz -C .release/rehearsal-tool",
            2,
        ) => Some(LiteralRun::R542),
        (
            "tar -xzf .release/rehearsal-tool/memcordon-release-rehearsal.tar.gz -C .release/rehearsal-tool",
            3,
        ) => Some(LiteralRun::R542),
        (
            "tar -xzf .release/rehearsal-tool/memcordon-release-rehearsal.tar.gz -C .release/rehearsal-tool",
            4,
        ) => Some(LiteralRun::R542),
        (
            "tar -xzf .release/rehearsal-tool/memcordon-release-rehearsal.tar.gz -C .release/rehearsal-tool",
            5,
        ) => Some(LiteralRun::R542),
        ("tar -xzf .release/tool/memcordon-publication-tool.tar.gz -C .release/tool", 0) => {
            Some(LiteralRun::R331)
        }
        ("tar -xzf .release/tool/memcordon-publication-tool.tar.gz -C .release/tool", 1) => {
            Some(LiteralRun::R331)
        }
        ("tar -xzf .release/tool/memcordon-publication-tool.tar.gz -C .release/tool", 2) => {
            Some(LiteralRun::R331)
        }
        ("tar -xzf .release/tool/memcordon-publication-tool.tar.gz -C .release/tool", 3) => {
            Some(LiteralRun::R331)
        }
        ("tar -xzf .release/tool/memcordon-publication-tool.tar.gz -C .release/tool", 4) => {
            Some(LiteralRun::R331)
        }
        ("tar -xzf .release/tool/memcordon-publication-tool.tar.gz -C .release/tool", 5) => {
            Some(LiteralRun::R331)
        }

        _ => None,
    }
}
