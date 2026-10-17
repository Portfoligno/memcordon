use super::LiteralRun;
pub(super) fn phase(command: &str, compile: bool) -> Option<LiteralRun> {
    match (command, compile) {
        (
            "./target/ci-runtime/current/memcordon-ci release build-target --build-source .release/build-source.json --consumer-readiness",
            true,
        ) => Some(LiteralRun::R1713),
        (
            "./target/ci-runtime/current/memcordon-ci release build-target --build-source .release/build-source.json --consumer-readiness",
            false,
        ) => Some(LiteralRun::R1714),
        (
            "./target/ci-runtime/current/memcordon-ci release build-target --build-source .release/build-source.json --consumer-readiness --failure-mode collect-all",
            true,
        ) => Some(LiteralRun::R1715),
        (
            "./target/ci-runtime/current/memcordon-ci release build-target --build-source .release/build-source.json --consumer-readiness --failure-mode collect-all",
            false,
        ) => Some(LiteralRun::R1716),
        (
            "./target/ci-runtime/current/memcordon-ci.exe release build-target --build-source .release/build-source.json --consumer-readiness",
            true,
        ) => Some(LiteralRun::R1717),
        (
            "./target/ci-runtime/current/memcordon-ci.exe release build-target --build-source .release/build-source.json --consumer-readiness",
            false,
        ) => Some(LiteralRun::R1718),
        (
            "./target/ci-runtime/current/memcordon-ci.exe release build-target --build-source .release/build-source.json --consumer-readiness --failure-mode collect-all",
            true,
        ) => Some(LiteralRun::R1719),
        (
            "./target/ci-runtime/current/memcordon-ci.exe release build-target --build-source .release/build-source.json --consumer-readiness --failure-mode collect-all",
            false,
        ) => Some(LiteralRun::R1720),
        (
            "./target/ci/release/memcordon-ci release build-target --build-source .release/build-source.json --consumer-readiness",
            true,
        ) => Some(LiteralRun::R1721),
        (
            "./target/ci/release/memcordon-ci release build-target --build-source .release/build-source.json --consumer-readiness",
            false,
        ) => Some(LiteralRun::R1722),
        (
            "./target/ci/release/memcordon-ci release build-target --build-source .release/build-source.json --consumer-readiness --failure-mode collect-all",
            true,
        ) => Some(LiteralRun::R1723),
        (
            "./target/ci/release/memcordon-ci release build-target --build-source .release/build-source.json --consumer-readiness --failure-mode collect-all",
            false,
        ) => Some(LiteralRun::R1724),
        _ => None,
    }
}
