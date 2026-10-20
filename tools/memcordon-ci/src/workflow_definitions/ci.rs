//! Preserved operational graph; adapters are authored in `adapters.rs`.
//! Each bounded container has a separate frame, including on native test threads.
// Sequential heap insertion avoids giant aggregate stack frames on native test threads.
#![allow(clippy::vec_init_then_push)]
use super::{LiteralRun, literal, number, text};
use serde_yaml::Value;
pub(super) fn definition() -> Value {
    node_0()
}
fn node_0() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("CI"));
    values.insert(text("on"), node_1());
    values.insert(text("permissions"), node_12());
    values.insert(text("concurrency"), node_13());
    values.insert(text("jobs"), node_14());
    Value::Mapping(values)
}

fn node_1() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("push"), node_2());
    values.insert(text("pull_request"), node_4());
    values.insert(text("merge_group"), node_6());
    values.insert(text("workflow_dispatch"), node_8());
    Value::Mapping(values)
}

fn node_2() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("branches"), node_3());
    Value::Mapping(values)
}

fn node_3() -> Value {
    let mut values = Vec::new();
    values.push(text("**"));
    Value::Sequence(values)
}

fn node_4() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("branches"), node_5());
    Value::Mapping(values)
}

fn node_5() -> Value {
    let mut values = Vec::new();
    values.push(text("**"));
    Value::Sequence(values)
}

fn node_6() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("types"), node_7());
    Value::Mapping(values)
}

fn node_7() -> Value {
    let mut values = Vec::new();
    values.push(text("checks_requested"));
    Value::Sequence(values)
}

fn node_8() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("inputs"), node_9());
    Value::Mapping(values)
}

fn node_9() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("failure-mode"), node_10());
    Value::Mapping(values)
}

fn node_10() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("description"),
        text("Stop after failure, or collect independent failures in supported suites."),
    );
    values.insert(text("type"), text("choice"));
    values.insert(text("default"), text("stop-after-failure"));
    values.insert(text("options"), node_11());
    Value::Mapping(values)
}

fn node_11() -> Value {
    let mut values = Vec::new();
    values.push(text("stop-after-failure"));
    values.push(text("collect-all"));
    Value::Sequence(values)
}

fn node_12() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("contents"), text("read"));
    Value::Mapping(values)
}

fn node_13() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("group"),
        text("ci-${{ github.workflow }}-${{ github.event_name }}-${{ github.ref }}"),
    );
    values.insert(text("cancel-in-progress"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_14() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("policy"), node_15());
    values.insert(text("quality"), node_54());
    values.insert(text("msrv"), node_113());
    values.insert(text("supply-chain"), node_173());
    values.insert(text("native"), node_266());
    values.insert(text("macos-deadline"), node_362());
    Value::Mapping(values)
}

fn node_15() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("github.event_name != 'push'"));
    values.insert(text("name"), text("policy"));
    values.insert(text("runs-on"), text("ubuntu-24.04"));
    values.insert(text("timeout-minutes"), number("98"));
    values.insert(text("steps"), node_16());
    Value::Mapping(values)
}

fn node_16() -> Value {
    let mut values = Vec::new();
    values.push(node_17());
    values.push(node_19());
    values.push(node_21());
    values.push(node_22());
    values.push(node_23());
    values.push(node_24());
    values.push(node_26());
    values.push(node_27());
    values.push(node_29());
    values.push(node_30());
    values.push(node_32());
    values.push(node_33());
    values.push(node_34());
    values.push(node_36());
    values.push(node_37());
    values.push(node_38());
    values.push(node_39());
    values.push(node_41());
    values.push(node_42());
    values.push(node_44());
    values.push(node_46());
    values.push(node_47());
    values.push(node_48());
    values.push(node_50());
    values.push(node_52());
    values.push(node_53());
    Value::Sequence(values)
}

fn node_17() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Check out repository"));
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_18());
    Value::Mapping(values)
}

fn node_18() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_19() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Restore Cargo sources"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"), text("hashFiles('Cargo.lock') != ''"));
    values.insert(text("id"), text("policy-deps"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_20());
    Value::Mapping(values)
}

fn node_20() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("~/.cargo/registry/cache\n~/.cargo/git/db\n"),
    );
    values.insert(text("key"),text("mc-download-bootstrap-v5-${{ runner.os }}-${{ hashFiles('Cargo.lock', 'Cargo.toml', '.cargo/**', 'ci/toolchains.toml') }}"));
    values.insert(
        text("restore-keys"),
        text("mc-download-bootstrap-v5-${{ runner.os }}-"),
    );
    Value::Mapping(values)
}

fn node_21() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Install pinned Rust"));
    values.insert(text("run"), literal(LiteralRun::R0));
    Value::Mapping(values)
}

fn node_22() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Build ordinary CI driver"));
    values.insert(text("id"), text("driver-build"));
    values.insert(text("run"), literal(LiteralRun::R1));
    Value::Mapping(values)
}

fn node_23() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("bootstrap-home"));
    values.insert(
        text("if"),
        text("always() && steps.driver-build.outcome == 'success'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R2));
    Value::Mapping(values)
}

fn node_24() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save Cargo sources"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.driver-build.outcome == 'success' && steps.bootstrap-home.outcome == 'success' && steps.bootstrap-home.outputs.bootstrap-home-matches == 'true' && steps.policy-deps.outputs.cache-primary-key != '' && steps.policy-deps.outputs.cache-hit != 'true'"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_25());
    Value::Mapping(values)
}

fn node_25() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("~/.cargo/registry/cache\n~/.cargo/git/db\n"),
    );
    values.insert(
        text("key"),
        text("${{ steps.policy-deps.outputs.cache-primary-key }}"),
    );
    Value::Mapping(values)
}

fn node_26() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-context"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_27() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-downloads"));
    values.insert(
        text("if"),
        text("steps.workspace-download-context.outputs.source-key != ''"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_28());
    Value::Mapping(values)
}

fn node_28() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.workspace-download-context.outputs.source-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.workspace-download-context.outputs.source-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-download-context.outputs.source-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_29() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R4));
    Value::Mapping(values)
}

fn node_30() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore"));
    values.insert(text("if"),text("steps.archive-seed-context.outputs.seed-lookup-key != '' && steps.workspace-downloads.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_31());
    Value::Mapping(values)
}

fn node_31() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.archive-seed-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.archive-seed-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.archive-seed-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_32() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore-import"));
    values.insert(text("if"),text("steps.archive-seed-restore.outcome == 'success' && steps.archive-seed-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R5));
    Value::Mapping(values)
}

fn node_33() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R6));
    Value::Mapping(values)
}

fn node_34() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-restore"));
    values.insert(
        text("if"),
        text("steps.index-snapshot-context.outputs.seed-lookup-key != ''"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_35());
    Value::Mapping(values)
}

fn node_35() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.index-snapshot-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.index-snapshot-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.index-snapshot-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_36() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-restore-import"));
    values.insert(text("if"),text("steps.index-snapshot-restore.outcome == 'success' && steps.index-snapshot-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R7));
    Value::Mapping(values)
}

fn node_37() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(text("run"), literal(LiteralRun::R8));
    Value::Mapping(values)
}

fn node_38() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save-context"));
    values.insert(text("if"),text("always() && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-context.outputs.source-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_39() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.workspace-download-context.outputs.source-key != '' && steps.workspace-download-context.outputs.source-paths != '' && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-save-context.outcome == 'success' && steps.workspace-download-save-context.outputs.source-key == steps.workspace-download-context.outputs.source-key && steps.workspace-download-save-context.outputs.source-key == steps.workspace-fetch.outputs.workspace-downloads-key && !(steps.workspace-downloads.outcome == 'success' && steps.workspace-downloads.outputs.cache-hit == 'true') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && steps.workspace-download-context.outputs.source-paths != ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_40());
    Value::Mapping(values)
}

fn node_40() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-download-context.outputs.source-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-download-context.outputs.source-paths }}"),
    );
    Value::Mapping(values)
}

fn node_41() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R9));
    Value::Mapping(values)
}

fn node_42() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-probe"));
    values.insert(text("if"),text("always() && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_43());
    Value::Mapping(values)
}

fn node_43() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_44() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility && steps.archive-seed-snapshot.outputs.snapshot-key != '' && steps.archive-seed-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_45());
    Value::Mapping(values)
}

fn node_45() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_46() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.archive-seed-snapshot.outcome == 'success' || steps.archive-seed-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R10));
    Value::Mapping(values)
}

fn node_47() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R11));
    Value::Mapping(values)
}

fn node_48() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-probe"));
    values.insert(text("if"),text("always() && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_49());
    Value::Mapping(values)
}

fn node_49() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.index-snapshot-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.index-snapshot-snapshot.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_50() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility && steps.index-snapshot-snapshot.outputs.snapshot-key != '' && steps.index-snapshot-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_51());
    Value::Mapping(values)
}

fn node_51() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.index-snapshot-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.index-snapshot-snapshot.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_52() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.index-snapshot-snapshot.outcome == 'success' || steps.index-snapshot-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R12));
    Value::Mapping(values)
}

fn node_53() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Run repository policy"));
    values.insert(text("id"), text("suite-policy"));
    values.insert(text("run"), literal(LiteralRun::R13));
    Value::Mapping(values)
}

fn node_54() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("github.event_name != 'push'"));
    values.insert(text("name"), text("quality"));
    values.insert(text("runs-on"), text("ubuntu-24.04"));
    values.insert(text("timeout-minutes"), number("196"));
    values.insert(text("steps"), node_55());
    Value::Mapping(values)
}

fn node_55() -> Value {
    let mut values = Vec::new();
    values.push(node_56());
    values.push(node_58());
    values.push(node_60());
    values.push(node_61());
    values.push(node_62());
    values.push(node_63());
    values.push(node_65());
    values.push(node_66());
    values.push(node_68());
    values.push(node_69());
    values.push(node_71());
    values.push(node_72());
    values.push(node_73());
    values.push(node_75());
    values.push(node_76());
    values.push(node_77());
    values.push(node_78());
    values.push(node_80());
    values.push(node_82());
    values.push(node_83());
    values.push(node_84());
    values.push(node_86());
    values.push(node_88());
    values.push(node_89());
    values.push(node_90());
    values.push(node_92());
    values.push(node_93());
    values.push(node_95());
    values.push(node_96());
    values.push(node_97());
    values.push(node_98());
    values.push(node_99());
    values.push(node_101());
    values.push(node_102());
    values.push(node_103());
    values.push(node_104());
    values.push(node_105());
    values.push(node_107());
    values.push(node_108());
    values.push(node_110());
    values.push(node_112());
    Value::Sequence(values)
}

fn node_56() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Check out repository"));
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_57());
    Value::Mapping(values)
}

fn node_57() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_58() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Restore Cargo sources"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"), text("hashFiles('Cargo.lock') != ''"));
    values.insert(text("id"), text("quality-deps"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_59());
    Value::Mapping(values)
}

fn node_59() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("~/.cargo/registry/cache\n~/.cargo/git/db\n"),
    );
    values.insert(text("key"),text("mc-download-bootstrap-v5-${{ runner.os }}-${{ hashFiles('Cargo.lock', 'Cargo.toml', '.cargo/**', 'ci/toolchains.toml') }}"));
    values.insert(
        text("restore-keys"),
        text("mc-download-bootstrap-v5-${{ runner.os }}-"),
    );
    Value::Mapping(values)
}

fn node_60() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Install quality Rust"));
    values.insert(text("run"), literal(LiteralRun::R14));
    Value::Mapping(values)
}

fn node_61() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Build ordinary CI driver"));
    values.insert(text("id"), text("driver-build"));
    values.insert(text("run"), literal(LiteralRun::R1));
    Value::Mapping(values)
}

fn node_62() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("bootstrap-home"));
    values.insert(
        text("if"),
        text("always() && steps.driver-build.outcome == 'success'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R2));
    Value::Mapping(values)
}

fn node_63() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save Cargo sources"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.driver-build.outcome == 'success' && steps.bootstrap-home.outcome == 'success' && steps.bootstrap-home.outputs.bootstrap-home-matches == 'true' && steps.quality-deps.outputs.cache-primary-key != '' && steps.quality-deps.outputs.cache-hit != 'true'"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_64());
    Value::Mapping(values)
}

fn node_64() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("~/.cargo/registry/cache\n~/.cargo/git/db\n"),
    );
    values.insert(
        text("key"),
        text("${{ steps.quality-deps.outputs.cache-primary-key }}"),
    );
    Value::Mapping(values)
}

fn node_65() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-context"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_66() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-downloads"));
    values.insert(
        text("if"),
        text("steps.workspace-download-context.outputs.source-key != ''"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_67());
    Value::Mapping(values)
}

fn node_67() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.workspace-download-context.outputs.source-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.workspace-download-context.outputs.source-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-download-context.outputs.source-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_68() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R4));
    Value::Mapping(values)
}

fn node_69() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore"));
    values.insert(text("if"),text("steps.archive-seed-context.outputs.seed-lookup-key != '' && steps.workspace-downloads.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_70());
    Value::Mapping(values)
}

fn node_70() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.archive-seed-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.archive-seed-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.archive-seed-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_71() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore-import"));
    values.insert(text("if"),text("steps.archive-seed-restore.outcome == 'success' && steps.archive-seed-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R5));
    Value::Mapping(values)
}

fn node_72() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R6));
    Value::Mapping(values)
}

fn node_73() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-restore"));
    values.insert(
        text("if"),
        text("steps.index-snapshot-context.outputs.seed-lookup-key != ''"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_74());
    Value::Mapping(values)
}

fn node_74() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.index-snapshot-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.index-snapshot-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.index-snapshot-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_75() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-restore-import"));
    values.insert(text("if"),text("steps.index-snapshot-restore.outcome == 'success' && steps.index-snapshot-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R7));
    Value::Mapping(values)
}

fn node_76() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(text("run"), literal(LiteralRun::R8));
    Value::Mapping(values)
}

fn node_77() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R9));
    Value::Mapping(values)
}

fn node_78() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-probe"));
    values.insert(text("if"),text("always() && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_79());
    Value::Mapping(values)
}

fn node_79() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_80() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility && steps.archive-seed-snapshot.outputs.snapshot-key != '' && steps.archive-seed-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_81());
    Value::Mapping(values)
}

fn node_81() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_82() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.archive-seed-snapshot.outcome == 'success' || steps.archive-seed-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R10));
    Value::Mapping(values)
}

fn node_83() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R11));
    Value::Mapping(values)
}

fn node_84() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-probe"));
    values.insert(text("if"),text("always() && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_85());
    Value::Mapping(values)
}

fn node_85() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.index-snapshot-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.index-snapshot-snapshot.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_86() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility && steps.index-snapshot-snapshot.outputs.snapshot-key != '' && steps.index-snapshot-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_87());
    Value::Mapping(values)
}

fn node_87() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.index-snapshot-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.index-snapshot-snapshot.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_88() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.index-snapshot-snapshot.outcome == 'success' || steps.index-snapshot-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R12));
    Value::Mapping(values)
}

fn node_89() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save-context"));
    values.insert(text("if"),text("always() && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-context.outputs.source-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_90() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save complete workspace downloads"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.workspace-download-context.outputs.source-key != '' && steps.workspace-download-context.outputs.source-paths != '' && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-save-context.outcome == 'success' && steps.workspace-download-save-context.outputs.source-key == steps.workspace-download-context.outputs.source-key && steps.workspace-download-save-context.outputs.source-key == steps.workspace-fetch.outputs.workspace-downloads-key && !(steps.workspace-downloads.outcome == 'success' && steps.workspace-downloads.outputs.cache-hit == 'true') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && steps.workspace-download-context.outputs.source-paths != ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_91());
    Value::Mapping(values)
}

fn node_91() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.workspace-download-context.outputs.source-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.workspace-download-context.outputs.source-key }}"),
    );
    Value::Mapping(values)
}

fn node_92() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("quality-context"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R15));
    Value::Mapping(values)
}

fn node_93() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("quality-compiled"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("if"),
        text("steps.quality-context.outputs.compiled-cache-usable == 'true'"),
    );
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_94());
    Value::Mapping(values)
}

fn node_94() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.quality-context.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.quality-context.outputs.product-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.quality-context.outputs.product-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_95() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize quality-compiled discard restore"),
    );
    values.insert(text("id"), text("sanitize-quality-complete-recipe-discard"));
    values.insert(
        text("if"),
        text("steps.quality-compiled.outcome == 'failure'"),
    );
    values.insert(text("run"), literal(LiteralRun::R16));
    Value::Mapping(values)
}

fn node_96() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize quality-compiled exact restore"),
    );
    values.insert(text("id"), text("sanitize-quality-complete-recipe-exact"));
    values.insert(text("if"),text("steps.quality-compiled.outcome == 'success' && steps.quality-compiled.outputs.cache-hit == 'true'"));
    values.insert(text("run"), literal(LiteralRun::R17));
    Value::Mapping(values)
}

fn node_97() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize quality-compiled compatible restore"),
    );
    values.insert(
        text("id"),
        text("sanitize-quality-complete-recipe-compatible"),
    );
    values.insert(text("if"),text("steps.quality-compiled.outcome == 'success' && steps.quality-compiled.outputs.cache-matched-key != '' && steps.quality-compiled.outputs.cache-hit != 'true'"));
    values.insert(text("run"), literal(LiteralRun::R18));
    Value::Mapping(values)
}

fn node_98() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("quality-compiled-partial-context"));
    values.insert(text("if"),text("steps.quality-context.outputs.product-key != '' && steps.quality-compiled.outcome != 'failure' && steps.quality-compiled.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R19));
    Value::Mapping(values)
}

fn node_99() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("quality-compiled-partial-restore"));
    values.insert(text("if"),text("steps.quality-compiled-partial-context.outputs.seed-lookup-key != '' && steps.quality-context.outputs.product-key != '' && steps.quality-compiled.outcome != 'failure' && steps.quality-compiled.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_100());
    Value::Mapping(values)
}

fn node_100() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.quality-compiled-partial-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.quality-compiled-partial-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.quality-compiled-partial-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_101() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("quality-compiled-partial-import"));
    values.insert(text("if"),text("steps.quality-compiled-partial-restore.outcome == 'success' && steps.quality-compiled-partial-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R20));
    Value::Mapping(values)
}

fn node_102() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Run quality suite"));
    values.insert(text("id"), text("quality-run"));
    values.insert(
        text("if"),
        text("github.event_name != 'workflow_dispatch' || inputs.failure-mode != 'collect-all'"),
    );
    values.insert(text("run"), literal(LiteralRun::R21));
    Value::Mapping(values)
}

fn node_103() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Run quality suite"));
    values.insert(text("id"), text("quality-run-diagnostic"));
    values.insert(
        text("if"),
        text("github.event_name == 'workflow_dispatch' && inputs.failure-mode == 'collect-all'"),
    );
    values.insert(text("run"), literal(LiteralRun::R22));
    Value::Mapping(values)
}

fn node_104() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("quality-compiled-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-quality-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-quality-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-quality-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-quality-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-quality-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-quality-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.quality-run.outcome == 'skipped' || steps.quality-run.outputs.cache-quiescent == 'true') && (steps.quality-run-diagnostic.outcome == 'skipped' || steps.quality-run-diagnostic.outputs.cache-quiescent == 'true') && steps.quality-context.outputs.compiled-cache-usable == 'true' && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.quality-compiled-partial-import.outcome == 'skipped' || steps.quality-compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R23));
    Value::Mapping(values)
}

fn node_105() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-quality-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-quality-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-quality-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-quality-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-quality-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-quality-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.quality-run.outcome == 'skipped' || steps.quality-run.outputs.cache-quiescent == 'true') && (steps.quality-run-diagnostic.outcome == 'skipped' || steps.quality-run-diagnostic.outputs.cache-quiescent == 'true') && steps.quality-context.outputs.product-key != '' && steps.quality-compiled-save-context.outcome == 'success' && steps.quality-compiled-save-context.outputs.product-key == steps.quality-context.outputs.product-key && steps.quality-compiled-save-context.outputs.payload-ready == 'true' && (steps.quality-run.outputs.compiled-recipe-complete == 'true' || steps.quality-run-diagnostic.outputs.compiled-recipe-complete == 'true') && !(steps.quality-compiled.outcome == 'success' && steps.quality-compiled.outputs.cache-hit == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.quality-compiled-partial-import.outcome == 'skipped' || steps.quality-compiled-partial-import.outputs.cache-quiescent == 'true') && steps.quality-context.outputs.product-paths != '' && steps.quality-context.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_106());
    Value::Mapping(values)
}

fn node_106() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.quality-context.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.quality-context.outputs.product-key }}"),
    );
    Value::Mapping(values)
}

fn node_107() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("quality-compiled-partial"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.quality-context.outputs.product-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-quality-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-quality-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-quality-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-quality-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-quality-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-quality-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.quality-run.outcome == 'skipped' || steps.quality-run.outputs.cache-quiescent == 'true') && (steps.quality-run-diagnostic.outcome == 'skipped' || steps.quality-run-diagnostic.outputs.cache-quiescent == 'true') && !((steps.quality-run.outputs.compiled-recipe-complete == 'true' || steps.quality-run-diagnostic.outputs.compiled-recipe-complete == 'true') && steps.quality-compiled-save-context.outputs.payload-ready == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.quality-compiled-partial-import.outcome == 'skipped' || steps.quality-compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R24));
    Value::Mapping(values)
}

fn node_108() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("quality-compiled-partial-probe"));
    values.insert(text("if"),text("always() && steps.quality-compiled-partial.outputs.snapshot-ready == 'true' && steps.quality-compiled-partial.outputs.input-key == steps.quality-context.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_109());
    Value::Mapping(values)
}

fn node_109() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.quality-compiled-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.quality-compiled-partial.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_110() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("quality-compiled-partial-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.quality-compiled-partial.outputs.snapshot-ready == 'true' && steps.quality-compiled-partial.outputs.input-key == steps.quality-context.outputs.product-key && steps.quality-compiled-partial.outputs.snapshot-key != '' && steps.quality-compiled-partial-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_111());
    Value::Mapping(values)
}

fn node_111() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.quality-compiled-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.quality-compiled-partial.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_112() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("quality-compiled-partial-cleanup"));
    values.insert(text("if"),text("always() && (steps.quality-compiled-partial.outcome == 'success' || steps.quality-compiled-partial.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R25));
    Value::Mapping(values)
}

fn node_113() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("github.event_name != 'push'"));
    values.insert(text("name"), text("MSRV 1.85.0"));
    values.insert(text("runs-on"), text("ubuntu-24.04"));
    values.insert(text("timeout-minutes"), number("196"));
    values.insert(text("steps"), node_114());
    Value::Mapping(values)
}

fn node_114() -> Value {
    let mut values = Vec::new();
    values.push(node_115());
    values.push(node_117());
    values.push(node_119());
    values.push(node_120());
    values.push(node_121());
    values.push(node_122());
    values.push(node_123());
    values.push(node_125());
    values.push(node_126());
    values.push(node_128());
    values.push(node_129());
    values.push(node_131());
    values.push(node_132());
    values.push(node_133());
    values.push(node_135());
    values.push(node_136());
    values.push(node_137());
    values.push(node_138());
    values.push(node_140());
    values.push(node_142());
    values.push(node_143());
    values.push(node_144());
    values.push(node_146());
    values.push(node_148());
    values.push(node_149());
    values.push(node_150());
    values.push(node_152());
    values.push(node_153());
    values.push(node_155());
    values.push(node_156());
    values.push(node_157());
    values.push(node_158());
    values.push(node_159());
    values.push(node_161());
    values.push(node_162());
    values.push(node_163());
    values.push(node_164());
    values.push(node_165());
    values.push(node_167());
    values.push(node_168());
    values.push(node_170());
    values.push(node_172());
    Value::Sequence(values)
}

fn node_115() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Check out repository"));
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_116());
    Value::Mapping(values)
}

fn node_116() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_117() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Restore Cargo sources"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"), text("hashFiles('Cargo.lock') != ''"));
    values.insert(text("id"), text("msrv-deps"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_118());
    Value::Mapping(values)
}

fn node_118() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("~/.cargo/registry/cache\n~/.cargo/git/db\n"),
    );
    values.insert(text("key"),text("mc-download-bootstrap-v5-${{ runner.os }}-${{ hashFiles('Cargo.lock', 'Cargo.toml', '.cargo/**', 'ci/toolchains.toml') }}"));
    values.insert(
        text("restore-keys"),
        text("mc-download-bootstrap-v5-${{ runner.os }}-"),
    );
    Value::Mapping(values)
}

fn node_119() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Install CI driver Rust"));
    values.insert(text("run"), literal(LiteralRun::R0));
    Value::Mapping(values)
}

fn node_120() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Install declared MSRV"));
    values.insert(text("run"), literal(LiteralRun::R26));
    Value::Mapping(values)
}

fn node_121() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Build ordinary CI driver"));
    values.insert(text("id"), text("driver-build"));
    values.insert(text("run"), literal(LiteralRun::R1));
    Value::Mapping(values)
}

fn node_122() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("bootstrap-home"));
    values.insert(
        text("if"),
        text("always() && steps.driver-build.outcome == 'success'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R2));
    Value::Mapping(values)
}

fn node_123() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save Cargo sources"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.driver-build.outcome == 'success' && steps.bootstrap-home.outcome == 'success' && steps.bootstrap-home.outputs.bootstrap-home-matches == 'true' && steps.msrv-deps.outputs.cache-primary-key != '' && steps.msrv-deps.outputs.cache-hit != 'true'"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_124());
    Value::Mapping(values)
}

fn node_124() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("~/.cargo/registry/cache\n~/.cargo/git/db\n"),
    );
    values.insert(
        text("key"),
        text("${{ steps.msrv-deps.outputs.cache-primary-key }}"),
    );
    Value::Mapping(values)
}

fn node_125() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-context"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_126() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-downloads"));
    values.insert(
        text("if"),
        text("steps.workspace-download-context.outputs.source-key != ''"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_127());
    Value::Mapping(values)
}

fn node_127() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.workspace-download-context.outputs.source-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.workspace-download-context.outputs.source-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-download-context.outputs.source-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_128() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R4));
    Value::Mapping(values)
}

fn node_129() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore"));
    values.insert(text("if"),text("steps.archive-seed-context.outputs.seed-lookup-key != '' && steps.workspace-downloads.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_130());
    Value::Mapping(values)
}

fn node_130() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.archive-seed-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.archive-seed-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.archive-seed-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_131() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore-import"));
    values.insert(text("if"),text("steps.archive-seed-restore.outcome == 'success' && steps.archive-seed-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R5));
    Value::Mapping(values)
}

fn node_132() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R6));
    Value::Mapping(values)
}

fn node_133() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-restore"));
    values.insert(
        text("if"),
        text("steps.index-snapshot-context.outputs.seed-lookup-key != ''"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_134());
    Value::Mapping(values)
}

fn node_134() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.index-snapshot-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.index-snapshot-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.index-snapshot-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_135() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-restore-import"));
    values.insert(text("if"),text("steps.index-snapshot-restore.outcome == 'success' && steps.index-snapshot-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R7));
    Value::Mapping(values)
}

fn node_136() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(text("run"), literal(LiteralRun::R8));
    Value::Mapping(values)
}

fn node_137() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R9));
    Value::Mapping(values)
}

fn node_138() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-probe"));
    values.insert(text("if"),text("always() && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_139());
    Value::Mapping(values)
}

fn node_139() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_140() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility && steps.archive-seed-snapshot.outputs.snapshot-key != '' && steps.archive-seed-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_141());
    Value::Mapping(values)
}

fn node_141() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_142() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.archive-seed-snapshot.outcome == 'success' || steps.archive-seed-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R10));
    Value::Mapping(values)
}

fn node_143() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R11));
    Value::Mapping(values)
}

fn node_144() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-probe"));
    values.insert(text("if"),text("always() && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_145());
    Value::Mapping(values)
}

fn node_145() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.index-snapshot-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.index-snapshot-snapshot.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_146() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility && steps.index-snapshot-snapshot.outputs.snapshot-key != '' && steps.index-snapshot-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_147());
    Value::Mapping(values)
}

fn node_147() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.index-snapshot-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.index-snapshot-snapshot.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_148() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.index-snapshot-snapshot.outcome == 'success' || steps.index-snapshot-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R12));
    Value::Mapping(values)
}

fn node_149() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save-context"));
    values.insert(text("if"),text("always() && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-context.outputs.source-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_150() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save complete workspace downloads"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.workspace-download-context.outputs.source-key != '' && steps.workspace-download-context.outputs.source-paths != '' && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-save-context.outcome == 'success' && steps.workspace-download-save-context.outputs.source-key == steps.workspace-download-context.outputs.source-key && steps.workspace-download-save-context.outputs.source-key == steps.workspace-fetch.outputs.workspace-downloads-key && !(steps.workspace-downloads.outcome == 'success' && steps.workspace-downloads.outputs.cache-hit == 'true') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && steps.workspace-download-context.outputs.source-paths != ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_151());
    Value::Mapping(values)
}

fn node_151() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.workspace-download-context.outputs.source-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.workspace-download-context.outputs.source-key }}"),
    );
    Value::Mapping(values)
}

fn node_152() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("msrv-context"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R27));
    Value::Mapping(values)
}

fn node_153() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("msrv-compiled"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("if"),
        text("steps.msrv-context.outputs.compiled-cache-usable == 'true'"),
    );
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_154());
    Value::Mapping(values)
}

fn node_154() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.msrv-context.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.msrv-context.outputs.product-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.msrv-context.outputs.product-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_155() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize msrv-compiled discard restore"));
    values.insert(text("id"), text("sanitize-msrv-complete-recipe-discard"));
    values.insert(text("if"), text("steps.msrv-compiled.outcome == 'failure'"));
    values.insert(text("run"), literal(LiteralRun::R28));
    Value::Mapping(values)
}

fn node_156() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize msrv-compiled exact restore"));
    values.insert(text("id"), text("sanitize-msrv-complete-recipe-exact"));
    values.insert(text("if"),text("steps.msrv-compiled.outcome == 'success' && steps.msrv-compiled.outputs.cache-hit == 'true'"));
    values.insert(text("run"), literal(LiteralRun::R29));
    Value::Mapping(values)
}

fn node_157() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize msrv-compiled compatible restore"),
    );
    values.insert(text("id"), text("sanitize-msrv-complete-recipe-compatible"));
    values.insert(text("if"),text("steps.msrv-compiled.outcome == 'success' && steps.msrv-compiled.outputs.cache-matched-key != '' && steps.msrv-compiled.outputs.cache-hit != 'true'"));
    values.insert(text("run"), literal(LiteralRun::R30));
    Value::Mapping(values)
}

fn node_158() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("msrv-compiled-partial-context"));
    values.insert(text("if"),text("steps.msrv-context.outputs.product-key != '' && steps.msrv-compiled.outcome != 'failure' && steps.msrv-compiled.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R31));
    Value::Mapping(values)
}

fn node_159() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("msrv-compiled-partial-restore"));
    values.insert(text("if"),text("steps.msrv-compiled-partial-context.outputs.seed-lookup-key != '' && steps.msrv-context.outputs.product-key != '' && steps.msrv-compiled.outcome != 'failure' && steps.msrv-compiled.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_160());
    Value::Mapping(values)
}

fn node_160() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.msrv-compiled-partial-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.msrv-compiled-partial-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.msrv-compiled-partial-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_161() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("msrv-compiled-partial-import"));
    values.insert(text("if"),text("steps.msrv-compiled-partial-restore.outcome == 'success' && steps.msrv-compiled-partial-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R32));
    Value::Mapping(values)
}

fn node_162() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Run MSRV suite"));
    values.insert(text("id"), text("msrv-run"));
    values.insert(
        text("if"),
        text("github.event_name != 'workflow_dispatch' || inputs.failure-mode != 'collect-all'"),
    );
    values.insert(text("run"), literal(LiteralRun::R33));
    Value::Mapping(values)
}

fn node_163() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Run MSRV suite"));
    values.insert(text("id"), text("msrv-run-diagnostic"));
    values.insert(
        text("if"),
        text("github.event_name == 'workflow_dispatch' && inputs.failure-mode == 'collect-all'"),
    );
    values.insert(text("run"), literal(LiteralRun::R34));
    Value::Mapping(values)
}

fn node_164() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("msrv-compiled-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-msrv-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-msrv-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-msrv-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-msrv-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-msrv-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-msrv-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.msrv-run.outcome == 'skipped' || steps.msrv-run.outputs.cache-quiescent == 'true') && (steps.msrv-run-diagnostic.outcome == 'skipped' || steps.msrv-run-diagnostic.outputs.cache-quiescent == 'true') && steps.msrv-context.outputs.compiled-cache-usable == 'true' && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.msrv-compiled-partial-import.outcome == 'skipped' || steps.msrv-compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R35));
    Value::Mapping(values)
}

fn node_165() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-msrv-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-msrv-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-msrv-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-msrv-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-msrv-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-msrv-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.msrv-run.outcome == 'skipped' || steps.msrv-run.outputs.cache-quiescent == 'true') && (steps.msrv-run-diagnostic.outcome == 'skipped' || steps.msrv-run-diagnostic.outputs.cache-quiescent == 'true') && steps.msrv-context.outputs.product-key != '' && steps.msrv-compiled-save-context.outcome == 'success' && steps.msrv-compiled-save-context.outputs.product-key == steps.msrv-context.outputs.product-key && steps.msrv-compiled-save-context.outputs.payload-ready == 'true' && (steps.msrv-run.outputs.compiled-recipe-complete == 'true' || steps.msrv-run-diagnostic.outputs.compiled-recipe-complete == 'true') && !(steps.msrv-compiled.outcome == 'success' && steps.msrv-compiled.outputs.cache-hit == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.msrv-compiled-partial-import.outcome == 'skipped' || steps.msrv-compiled-partial-import.outputs.cache-quiescent == 'true') && steps.msrv-context.outputs.product-paths != '' && steps.msrv-context.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_166());
    Value::Mapping(values)
}

fn node_166() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.msrv-context.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.msrv-context.outputs.product-key }}"),
    );
    Value::Mapping(values)
}

fn node_167() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("msrv-compiled-partial"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.msrv-context.outputs.product-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-msrv-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-msrv-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-msrv-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-msrv-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-msrv-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-msrv-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.msrv-run.outcome == 'skipped' || steps.msrv-run.outputs.cache-quiescent == 'true') && (steps.msrv-run-diagnostic.outcome == 'skipped' || steps.msrv-run-diagnostic.outputs.cache-quiescent == 'true') && !((steps.msrv-run.outputs.compiled-recipe-complete == 'true' || steps.msrv-run-diagnostic.outputs.compiled-recipe-complete == 'true') && steps.msrv-compiled-save-context.outputs.payload-ready == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.msrv-compiled-partial-import.outcome == 'skipped' || steps.msrv-compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R36));
    Value::Mapping(values)
}

fn node_168() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("msrv-compiled-partial-probe"));
    values.insert(text("if"),text("always() && steps.msrv-compiled-partial.outputs.snapshot-ready == 'true' && steps.msrv-compiled-partial.outputs.input-key == steps.msrv-context.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_169());
    Value::Mapping(values)
}

fn node_169() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.msrv-compiled-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.msrv-compiled-partial.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_170() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("msrv-compiled-partial-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.msrv-compiled-partial.outputs.snapshot-ready == 'true' && steps.msrv-compiled-partial.outputs.input-key == steps.msrv-context.outputs.product-key && steps.msrv-compiled-partial.outputs.snapshot-key != '' && steps.msrv-compiled-partial-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_171());
    Value::Mapping(values)
}

fn node_171() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.msrv-compiled-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.msrv-compiled-partial.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_172() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("msrv-compiled-partial-cleanup"));
    values.insert(text("if"),text("always() && (steps.msrv-compiled-partial.outcome == 'success' || steps.msrv-compiled-partial.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R37));
    Value::Mapping(values)
}

fn node_173() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("github.event_name != 'push'"));
    values.insert(text("name"), text("supply chain"));
    values.insert(text("runs-on"), text("ubuntu-24.04"));
    values.insert(text("timeout-minutes"), number("135"));
    values.insert(text("steps"), node_174());
    Value::Mapping(values)
}

fn node_174() -> Value {
    let mut values = Vec::new();
    values.push(node_175());
    values.push(node_177());
    values.push(node_179());
    values.push(node_180());
    values.push(node_181());
    values.push(node_182());
    values.push(node_184());
    values.push(node_185());
    values.push(node_187());
    values.push(node_188());
    values.push(node_190());
    values.push(node_191());
    values.push(node_192());
    values.push(node_194());
    values.push(node_195());
    values.push(node_196());
    values.push(node_197());
    values.push(node_199());
    values.push(node_200());
    values.push(node_201());
    values.push(node_202());
    values.push(node_204());
    values.push(node_206());
    values.push(node_208());
    values.push(node_209());
    values.push(node_210());
    values.push(node_212());
    values.push(node_214());
    values.push(node_216());
    values.push(node_217());
    values.push(node_219());
    values.push(node_220());
    values.push(node_221());
    values.push(node_223());
    values.push(node_224());
    values.push(node_225());
    values.push(node_226());
    values.push(node_227());
    values.push(node_228());
    values.push(node_230());
    values.push(node_232());
    values.push(node_234());
    values.push(node_235());
    values.push(node_236());
    values.push(node_238());
    values.push(node_240());
    values.push(node_242());
    values.push(node_243());
    values.push(node_245());
    values.push(node_247());
    values.push(node_248());
    values.push(node_249());
    values.push(node_251());
    values.push(node_253());
    values.push(node_254());
    values.push(node_255());
    values.push(node_257());
    values.push(node_259());
    values.push(node_260());
    values.push(node_261());
    values.push(node_263());
    values.push(node_265());
    Value::Sequence(values)
}

fn node_175() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Check out repository"));
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_176());
    Value::Mapping(values)
}

fn node_176() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_177() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Restore Cargo sources"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"), text("hashFiles('Cargo.lock') != ''"));
    values.insert(text("id"), text("supply-deps"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_178());
    Value::Mapping(values)
}

fn node_178() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("~/.cargo/registry/cache\n~/.cargo/git/db\n"),
    );
    values.insert(text("key"),text("mc-download-bootstrap-v5-${{ runner.os }}-${{ hashFiles('Cargo.lock', 'Cargo.toml', '.cargo/**', 'ci/toolchains.toml') }}"));
    values.insert(
        text("restore-keys"),
        text("mc-download-bootstrap-v5-${{ runner.os }}-"),
    );
    Value::Mapping(values)
}

fn node_179() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Install pinned Rust"));
    values.insert(text("run"), literal(LiteralRun::R0));
    Value::Mapping(values)
}

fn node_180() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Build ordinary CI driver"));
    values.insert(text("id"), text("driver-build"));
    values.insert(text("run"), literal(LiteralRun::R1));
    Value::Mapping(values)
}

fn node_181() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("bootstrap-home"));
    values.insert(
        text("if"),
        text("always() && steps.driver-build.outcome == 'success'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R2));
    Value::Mapping(values)
}

fn node_182() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save Cargo sources"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.driver-build.outcome == 'success' && steps.bootstrap-home.outcome == 'success' && steps.bootstrap-home.outputs.bootstrap-home-matches == 'true' && steps.supply-deps.outputs.cache-primary-key != '' && steps.supply-deps.outputs.cache-hit != 'true'"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_183());
    Value::Mapping(values)
}

fn node_183() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("~/.cargo/registry/cache\n~/.cargo/git/db\n"),
    );
    values.insert(
        text("key"),
        text("${{ steps.supply-deps.outputs.cache-primary-key }}"),
    );
    Value::Mapping(values)
}

fn node_184() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-context"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_185() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-downloads"));
    values.insert(
        text("if"),
        text("steps.workspace-download-context.outputs.source-key != ''"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_186());
    Value::Mapping(values)
}

fn node_186() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.workspace-download-context.outputs.source-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.workspace-download-context.outputs.source-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-download-context.outputs.source-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_187() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-context"));
    values.insert(text("run"), literal(LiteralRun::R4));
    Value::Mapping(values)
}

fn node_188() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore"));
    values.insert(text("if"),text("steps.archive-seed-context.outputs.seed-lookup-key != '' && steps.workspace-downloads.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_189());
    Value::Mapping(values)
}

fn node_189() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.archive-seed-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.archive-seed-context.outputs.seed-restore-prefix }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.archive-seed-context.outputs.seed-import-path }}"),
    );
    Value::Mapping(values)
}

fn node_190() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("steps.archive-seed-restore.outcome == 'success' && steps.archive-seed-restore.outputs.cache-matched-key != ''"));
    values.insert(
        text("id"),
        text("import-registry-archives-sources-complete-recipe"),
    );
    values.insert(text("run"), literal(LiteralRun::R5));
    Value::Mapping(values)
}

fn node_191() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-context"));
    values.insert(text("run"), literal(LiteralRun::R6));
    Value::Mapping(values)
}

fn node_192() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-restore"));
    values.insert(
        text("if"),
        text("steps.index-snapshot-context.outputs.seed-lookup-key != ''"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_193());
    Value::Mapping(values)
}

fn node_193() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.index-snapshot-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.index-snapshot-context.outputs.seed-restore-prefix }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.index-snapshot-context.outputs.seed-import-path }}"),
    );
    Value::Mapping(values)
}

fn node_194() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("steps.index-snapshot-restore.outcome == 'success' && steps.index-snapshot-restore.outputs.cache-matched-key != ''"));
    values.insert(
        text("id"),
        text("import-registry-index-sources-complete-recipe"),
    );
    values.insert(text("run"), literal(LiteralRun::R7));
    Value::Mapping(values)
}

fn node_195() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(text("run"), literal(LiteralRun::R8));
    Value::Mapping(values)
}

fn node_196() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save-context"));
    values.insert(text("if"),text("always() && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-context.outputs.source-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_197() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save complete workspace downloads"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.workspace-download-context.outputs.source-key != '' && steps.workspace-download-context.outputs.source-paths != '' && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-save-context.outcome == 'success' && steps.workspace-download-save-context.outputs.source-key == steps.workspace-download-context.outputs.source-key && steps.workspace-download-save-context.outputs.source-key == steps.workspace-fetch.outputs.workspace-downloads-key && !(steps.workspace-downloads.outcome == 'success' && steps.workspace-downloads.outputs.cache-hit == 'true') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && steps.workspace-download-context.outputs.source-paths != ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_198());
    Value::Mapping(values)
}

fn node_198() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.workspace-download-context.outputs.source-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.workspace-download-context.outputs.source-key }}"),
    );
    Value::Mapping(values)
}

fn node_199() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("supply-context"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R38));
    Value::Mapping(values)
}

fn node_200() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-audit-download-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R39));
    Value::Mapping(values)
}

fn node_201() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-audit"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R40));
    Value::Mapping(values)
}

fn node_202() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-audit-downloads"));
    values.insert(
        text("if"),
        text("steps.cache-cargo-audit-download-context.outputs.source-key != ''"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_203());
    Value::Mapping(values)
}

fn node_203() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.cache-cargo-audit-download-context.outputs.source-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.cache-cargo-audit-download-context.outputs.source-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.cache-cargo-audit-download-context.outputs.source-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_204() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-audit-binary"));
    values.insert(
        text("if"),
        text("steps.cache-cargo-audit.outputs.tool-key != ''"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_205());
    Value::Mapping(values)
}

fn node_205() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.cache-cargo-audit.outputs.tool-path }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.cache-cargo-audit.outputs.tool-key }}"),
    );
    Value::Mapping(values)
}

fn node_206() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-audit-build"));
    values.insert(
        text("if"),
        text("steps.cache-cargo-audit.outputs.tool-build-key != ''"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_207());
    Value::Mapping(values)
}

fn node_207() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.cache-cargo-audit.outputs.tool-build-path }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.cache-cargo-audit.outputs.tool-build-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.cache-cargo-audit.outputs.tool-build-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_208() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-deny-download-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R41));
    Value::Mapping(values)
}

fn node_209() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-deny"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R42));
    Value::Mapping(values)
}

fn node_210() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-deny-downloads"));
    values.insert(
        text("if"),
        text("steps.cache-cargo-deny-download-context.outputs.source-key != ''"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_211());
    Value::Mapping(values)
}

fn node_211() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.cache-cargo-deny-download-context.outputs.source-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.cache-cargo-deny-download-context.outputs.source-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.cache-cargo-deny-download-context.outputs.source-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_212() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-deny-binary"));
    values.insert(
        text("if"),
        text("steps.cache-cargo-deny.outputs.tool-key != ''"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_213());
    Value::Mapping(values)
}

fn node_213() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.cache-cargo-deny.outputs.tool-path }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.cache-cargo-deny.outputs.tool-key }}"),
    );
    Value::Mapping(values)
}

fn node_214() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-deny-build"));
    values.insert(
        text("if"),
        text("steps.cache-cargo-deny.outputs.tool-build-key != ''"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_215());
    Value::Mapping(values)
}

fn node_215() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.cache-cargo-deny.outputs.tool-build-path }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.cache-cargo-deny.outputs.tool-build-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.cache-cargo-deny.outputs.tool-build-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_216() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-audit-build-partial-context"));
    values.insert(text("if"),text("steps.cache-cargo-audit.outputs.tool-build-key != '' && steps.cache-cargo-audit-build.outcome != 'failure' && steps.cache-cargo-audit-build.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R43));
    Value::Mapping(values)
}

fn node_217() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-audit-build-partial-restore"));
    values.insert(text("if"),text("steps.cache-cargo-audit-build-partial-context.outputs.seed-lookup-key != '' && steps.cache-cargo-audit.outputs.tool-build-key != '' && steps.cache-cargo-audit-build.outcome != 'failure' && steps.cache-cargo-audit-build.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_218());
    Value::Mapping(values)
}

fn node_218() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.cache-cargo-audit-build-partial-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.cache-cargo-audit-build-partial-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.cache-cargo-audit-build-partial-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_219() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-audit-build-partial-import"));
    values.insert(text("if"),text("steps.cache-cargo-audit-build-partial-restore.outcome == 'success' && steps.cache-cargo-audit-build-partial-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R44));
    Value::Mapping(values)
}

fn node_220() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-deny-build-partial-context"));
    values.insert(text("if"),text("steps.cache-cargo-deny.outputs.tool-build-key != '' && steps.cache-cargo-deny-build.outcome != 'failure' && steps.cache-cargo-deny-build.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R45));
    Value::Mapping(values)
}

fn node_221() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-deny-build-partial-restore"));
    values.insert(text("if"),text("steps.cache-cargo-deny-build-partial-context.outputs.seed-lookup-key != '' && steps.cache-cargo-deny.outputs.tool-build-key != '' && steps.cache-cargo-deny-build.outcome != 'failure' && steps.cache-cargo-deny-build.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_222());
    Value::Mapping(values)
}

fn node_222() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.cache-cargo-deny-build-partial-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.cache-cargo-deny-build-partial-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.cache-cargo-deny-build-partial-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_223() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-deny-build-partial-import"));
    values.insert(text("if"),text("steps.cache-cargo-deny-build-partial-restore.outcome == 'success' && steps.cache-cargo-deny-build-partial-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R46));
    Value::Mapping(values)
}

fn node_224() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Run supply-chain suite"));
    values.insert(text("id"), text("supply-run"));
    values.insert(
        text("if"),
        text("github.event_name != 'workflow_dispatch' || inputs.failure-mode != 'collect-all'"),
    );
    values.insert(text("run"), literal(LiteralRun::R47));
    Value::Mapping(values)
}

fn node_225() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Run supply-chain suite"));
    values.insert(text("id"), text("supply-run-diagnostic"));
    values.insert(
        text("if"),
        text("github.event_name == 'workflow_dispatch' && inputs.failure-mode == 'collect-all'"),
    );
    values.insert(text("run"), literal(LiteralRun::R48));
    Value::Mapping(values)
}

fn node_226() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-audit-download-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.supply-run.outcome == 'skipped' || steps.supply-run.outputs.cache-quiescent == 'true') && (steps.supply-run-diagnostic.outcome == 'skipped' || steps.supply-run-diagnostic.outputs.cache-quiescent == 'true') && (steps.cache-cargo-audit-build-partial-import.outcome == 'skipped' || steps.cache-cargo-audit-build-partial-import.outputs.cache-quiescent == 'true') && (steps.cache-cargo-deny-build-partial-import.outcome == 'skipped' || steps.cache-cargo-deny-build-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R39));
    Value::Mapping(values)
}

fn node_227() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-audit-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.supply-run.outcome == 'skipped' || steps.supply-run.outputs.cache-quiescent == 'true') && (steps.supply-run-diagnostic.outcome == 'skipped' || steps.supply-run-diagnostic.outputs.cache-quiescent == 'true') && (steps.cache-cargo-audit-build-partial-import.outcome == 'skipped' || steps.cache-cargo-audit-build-partial-import.outputs.cache-quiescent == 'true') && (steps.cache-cargo-deny-build-partial-import.outcome == 'skipped' || steps.cache-cargo-deny-build-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R49));
    Value::Mapping(values)
}

fn node_228() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save cache-cargo-audit-binary"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.supply-run.outcome == 'skipped' || steps.supply-run.outputs.cache-quiescent == 'true') && (steps.supply-run-diagnostic.outcome == 'skipped' || steps.supply-run-diagnostic.outputs.cache-quiescent == 'true') && steps.cache-cargo-audit.outputs.tool-key != '' && steps.cache-cargo-audit-save-context.outcome == 'success' && steps.cache-cargo-audit-save-context.outputs.tool-key == steps.cache-cargo-audit.outputs.tool-key && (steps.supply-run.outputs.tool-cargo-audit-ready == 'true' || steps.supply-run-diagnostic.outputs.tool-cargo-audit-ready == 'true') && !(steps.cache-cargo-audit-binary.outcome == 'success' && steps.cache-cargo-audit-binary.outputs.cache-hit == 'true') && (steps.cache-cargo-audit-build-partial-import.outcome == 'skipped' || steps.cache-cargo-audit-build-partial-import.outputs.cache-quiescent == 'true') && (steps.cache-cargo-deny-build-partial-import.outcome == 'skipped' || steps.cache-cargo-deny-build-partial-import.outputs.cache-quiescent == 'true') && steps.cache-cargo-audit.outputs.tool-path != ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_229());
    Value::Mapping(values)
}

fn node_229() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.cache-cargo-audit.outputs.tool-path }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.cache-cargo-audit.outputs.tool-key }}"),
    );
    Value::Mapping(values)
}

fn node_230() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save cargo-audit downloads"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.supply-run.outcome == 'skipped' || steps.supply-run.outputs.cache-quiescent == 'true') && (steps.supply-run-diagnostic.outcome == 'skipped' || steps.supply-run-diagnostic.outputs.cache-quiescent == 'true') && steps.cache-cargo-audit-download-context.outputs.source-key != '' && steps.cache-cargo-audit-download-save-context.outcome == 'success' && steps.cache-cargo-audit-download-save-context.outputs.source-key == steps.cache-cargo-audit-download-context.outputs.source-key && ((steps.supply-run.outputs.download-cargo-audit-populated == 'true' && steps.cache-cargo-audit-download-save-context.outputs.source-key == steps.supply-run.outputs.download-cargo-audit-key) || (steps.supply-run-diagnostic.outputs.download-cargo-audit-populated == 'true' && steps.cache-cargo-audit-download-save-context.outputs.source-key == steps.supply-run-diagnostic.outputs.download-cargo-audit-key)) && !(steps.cache-cargo-audit-downloads.outcome == 'success' && steps.cache-cargo-audit-downloads.outputs.cache-hit == 'true') && (steps.cache-cargo-audit-build-partial-import.outcome == 'skipped' || steps.cache-cargo-audit-build-partial-import.outputs.cache-quiescent == 'true') && (steps.cache-cargo-deny-build-partial-import.outcome == 'skipped' || steps.cache-cargo-deny-build-partial-import.outputs.cache-quiescent == 'true') && steps.cache-cargo-audit-download-context.outputs.source-paths != ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_231());
    Value::Mapping(values)
}

fn node_231() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.cache-cargo-audit-download-context.outputs.source-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.cache-cargo-audit-download-context.outputs.source-key }}"),
    );
    Value::Mapping(values)
}

fn node_232() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save cache-cargo-audit-build"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.supply-run.outcome == 'skipped' || steps.supply-run.outputs.cache-quiescent == 'true') && (steps.supply-run-diagnostic.outcome == 'skipped' || steps.supply-run-diagnostic.outputs.cache-quiescent == 'true') && steps.cache-cargo-audit.outputs.tool-build-key != '' && steps.cache-cargo-audit-save-context.outcome == 'success' && steps.cache-cargo-audit-save-context.outputs.tool-build-key == steps.cache-cargo-audit.outputs.tool-build-key && steps.cache-cargo-audit-save-context.outputs.payload-ready == 'true' && (steps.supply-run.outputs.tool-cargo-audit-build-complete == 'true' || steps.supply-run-diagnostic.outputs.tool-cargo-audit-build-complete == 'true') && !(steps.cache-cargo-audit-build.outcome == 'success' && steps.cache-cargo-audit-build.outputs.cache-hit == 'true') && (steps.cache-cargo-audit-build-partial-import.outcome == 'skipped' || steps.cache-cargo-audit-build-partial-import.outputs.cache-quiescent == 'true') && (steps.cache-cargo-deny-build-partial-import.outcome == 'skipped' || steps.cache-cargo-deny-build-partial-import.outputs.cache-quiescent == 'true') && steps.cache-cargo-audit.outputs.tool-build-path != '' && steps.cache-cargo-audit.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_233());
    Value::Mapping(values)
}

fn node_233() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.cache-cargo-audit.outputs.tool-build-path }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.cache-cargo-audit.outputs.tool-build-key }}"),
    );
    Value::Mapping(values)
}

fn node_234() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-deny-download-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.supply-run.outcome == 'skipped' || steps.supply-run.outputs.cache-quiescent == 'true') && (steps.supply-run-diagnostic.outcome == 'skipped' || steps.supply-run-diagnostic.outputs.cache-quiescent == 'true') && (steps.cache-cargo-audit-build-partial-import.outcome == 'skipped' || steps.cache-cargo-audit-build-partial-import.outputs.cache-quiescent == 'true') && (steps.cache-cargo-deny-build-partial-import.outcome == 'skipped' || steps.cache-cargo-deny-build-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R41));
    Value::Mapping(values)
}

fn node_235() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-deny-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.supply-run.outcome == 'skipped' || steps.supply-run.outputs.cache-quiescent == 'true') && (steps.supply-run-diagnostic.outcome == 'skipped' || steps.supply-run-diagnostic.outputs.cache-quiescent == 'true') && (steps.cache-cargo-audit-build-partial-import.outcome == 'skipped' || steps.cache-cargo-audit-build-partial-import.outputs.cache-quiescent == 'true') && (steps.cache-cargo-deny-build-partial-import.outcome == 'skipped' || steps.cache-cargo-deny-build-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R50));
    Value::Mapping(values)
}

fn node_236() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save cache-cargo-deny-binary"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.supply-run.outcome == 'skipped' || steps.supply-run.outputs.cache-quiescent == 'true') && (steps.supply-run-diagnostic.outcome == 'skipped' || steps.supply-run-diagnostic.outputs.cache-quiescent == 'true') && steps.cache-cargo-deny.outputs.tool-key != '' && steps.cache-cargo-deny-save-context.outcome == 'success' && steps.cache-cargo-deny-save-context.outputs.tool-key == steps.cache-cargo-deny.outputs.tool-key && (steps.supply-run.outputs.tool-cargo-deny-ready == 'true' || steps.supply-run-diagnostic.outputs.tool-cargo-deny-ready == 'true') && !(steps.cache-cargo-deny-binary.outcome == 'success' && steps.cache-cargo-deny-binary.outputs.cache-hit == 'true') && (steps.cache-cargo-audit-build-partial-import.outcome == 'skipped' || steps.cache-cargo-audit-build-partial-import.outputs.cache-quiescent == 'true') && (steps.cache-cargo-deny-build-partial-import.outcome == 'skipped' || steps.cache-cargo-deny-build-partial-import.outputs.cache-quiescent == 'true') && steps.cache-cargo-deny.outputs.tool-path != ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_237());
    Value::Mapping(values)
}

fn node_237() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.cache-cargo-deny.outputs.tool-path }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.cache-cargo-deny.outputs.tool-key }}"),
    );
    Value::Mapping(values)
}

fn node_238() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save cargo-deny downloads"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.supply-run.outcome == 'skipped' || steps.supply-run.outputs.cache-quiescent == 'true') && (steps.supply-run-diagnostic.outcome == 'skipped' || steps.supply-run-diagnostic.outputs.cache-quiescent == 'true') && steps.cache-cargo-deny-download-context.outputs.source-key != '' && steps.cache-cargo-deny-download-save-context.outcome == 'success' && steps.cache-cargo-deny-download-save-context.outputs.source-key == steps.cache-cargo-deny-download-context.outputs.source-key && ((steps.supply-run.outputs.download-cargo-deny-populated == 'true' && steps.cache-cargo-deny-download-save-context.outputs.source-key == steps.supply-run.outputs.download-cargo-deny-key) || (steps.supply-run-diagnostic.outputs.download-cargo-deny-populated == 'true' && steps.cache-cargo-deny-download-save-context.outputs.source-key == steps.supply-run-diagnostic.outputs.download-cargo-deny-key)) && !(steps.cache-cargo-deny-downloads.outcome == 'success' && steps.cache-cargo-deny-downloads.outputs.cache-hit == 'true') && (steps.cache-cargo-audit-build-partial-import.outcome == 'skipped' || steps.cache-cargo-audit-build-partial-import.outputs.cache-quiescent == 'true') && (steps.cache-cargo-deny-build-partial-import.outcome == 'skipped' || steps.cache-cargo-deny-build-partial-import.outputs.cache-quiescent == 'true') && steps.cache-cargo-deny-download-context.outputs.source-paths != ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_239());
    Value::Mapping(values)
}

fn node_239() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.cache-cargo-deny-download-context.outputs.source-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.cache-cargo-deny-download-context.outputs.source-key }}"),
    );
    Value::Mapping(values)
}

fn node_240() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save cache-cargo-deny-build"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.supply-run.outcome == 'skipped' || steps.supply-run.outputs.cache-quiescent == 'true') && (steps.supply-run-diagnostic.outcome == 'skipped' || steps.supply-run-diagnostic.outputs.cache-quiescent == 'true') && steps.cache-cargo-deny.outputs.tool-build-key != '' && steps.cache-cargo-deny-save-context.outcome == 'success' && steps.cache-cargo-deny-save-context.outputs.tool-build-key == steps.cache-cargo-deny.outputs.tool-build-key && steps.cache-cargo-deny-save-context.outputs.payload-ready == 'true' && (steps.supply-run.outputs.tool-cargo-deny-build-complete == 'true' || steps.supply-run-diagnostic.outputs.tool-cargo-deny-build-complete == 'true') && !(steps.cache-cargo-deny-build.outcome == 'success' && steps.cache-cargo-deny-build.outputs.cache-hit == 'true') && (steps.cache-cargo-audit-build-partial-import.outcome == 'skipped' || steps.cache-cargo-audit-build-partial-import.outputs.cache-quiescent == 'true') && (steps.cache-cargo-deny-build-partial-import.outcome == 'skipped' || steps.cache-cargo-deny-build-partial-import.outputs.cache-quiescent == 'true') && steps.cache-cargo-deny.outputs.tool-build-path != '' && steps.cache-cargo-deny.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_241());
    Value::Mapping(values)
}

fn node_241() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.cache-cargo-deny.outputs.tool-build-path }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.cache-cargo-deny.outputs.tool-build-key }}"),
    );
    Value::Mapping(values)
}

fn node_242() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.supply-run.outcome == 'skipped' || steps.supply-run.outputs.cache-quiescent == 'true') && (steps.supply-run-diagnostic.outcome == 'skipped' || steps.supply-run-diagnostic.outputs.cache-quiescent == 'true') && (steps.cache-cargo-audit-build-partial-import.outcome == 'skipped' || steps.cache-cargo-audit-build-partial-import.outputs.cache-quiescent == 'true') && (steps.cache-cargo-deny-build-partial-import.outcome == 'skipped' || steps.cache-cargo-deny-build-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("run"), literal(LiteralRun::R9));
    Value::Mapping(values)
}

fn node_243() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-probe"));
    values.insert(text("if"),text("always() && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_244());
    Value::Mapping(values)
}

fn node_244() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_245() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save observed registry-archives"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility && steps.archive-seed-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_246());
    Value::Mapping(values)
}

fn node_246() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_247() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (steps.archive-seed-snapshot.outcome == 'success' || steps.archive-seed-snapshot.outcome == 'failure')"));
    values.insert(text("run"), literal(LiteralRun::R10));
    Value::Mapping(values)
}

fn node_248() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.supply-run.outcome == 'skipped' || steps.supply-run.outputs.cache-quiescent == 'true') && (steps.supply-run-diagnostic.outcome == 'skipped' || steps.supply-run-diagnostic.outputs.cache-quiescent == 'true') && (steps.cache-cargo-audit-build-partial-import.outcome == 'skipped' || steps.cache-cargo-audit-build-partial-import.outputs.cache-quiescent == 'true') && (steps.cache-cargo-deny-build-partial-import.outcome == 'skipped' || steps.cache-cargo-deny-build-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("run"), literal(LiteralRun::R11));
    Value::Mapping(values)
}

fn node_249() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-probe"));
    values.insert(text("if"),text("always() && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_250());
    Value::Mapping(values)
}

fn node_250() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.index-snapshot-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.index-snapshot-snapshot.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_251() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save observed registry-index"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility && steps.index-snapshot-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_252());
    Value::Mapping(values)
}

fn node_252() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.index-snapshot-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.index-snapshot-snapshot.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_253() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (steps.index-snapshot-snapshot.outcome == 'success' || steps.index-snapshot-snapshot.outcome == 'failure')"));
    values.insert(text("run"), literal(LiteralRun::R12));
    Value::Mapping(values)
}

fn node_254() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-audit-build-partial"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.cache-cargo-audit.outputs.tool-build-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.supply-run.outcome == 'skipped' || steps.supply-run.outputs.cache-quiescent == 'true') && (steps.supply-run-diagnostic.outcome == 'skipped' || steps.supply-run-diagnostic.outputs.cache-quiescent == 'true') && !((steps.supply-run.outputs.tool-cargo-audit-build-complete == 'true' || steps.supply-run-diagnostic.outputs.tool-cargo-audit-build-complete == 'true') && steps.cache-cargo-audit-save-context.outputs.payload-ready == 'true') && (steps.cache-cargo-audit-build-partial-import.outcome == 'skipped' || steps.cache-cargo-audit-build-partial-import.outputs.cache-quiescent == 'true') && (steps.cache-cargo-deny-build-partial-import.outcome == 'skipped' || steps.cache-cargo-deny-build-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R51));
    Value::Mapping(values)
}

fn node_255() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-audit-build-partial-probe"));
    values.insert(text("if"),text("always() && steps.cache-cargo-audit-build-partial.outputs.snapshot-ready == 'true' && steps.cache-cargo-audit-build-partial.outputs.input-key == steps.cache-cargo-audit.outputs.tool-build-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_256());
    Value::Mapping(values)
}

fn node_256() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.cache-cargo-audit-build-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.cache-cargo-audit-build-partial.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_257() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-audit-build-partial-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.cache-cargo-audit-build-partial.outputs.snapshot-ready == 'true' && steps.cache-cargo-audit-build-partial.outputs.input-key == steps.cache-cargo-audit.outputs.tool-build-key && steps.cache-cargo-audit-build-partial.outputs.snapshot-key != '' && steps.cache-cargo-audit-build-partial-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_258());
    Value::Mapping(values)
}

fn node_258() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.cache-cargo-audit-build-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.cache-cargo-audit-build-partial.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_259() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-audit-build-partial-cleanup"));
    values.insert(text("if"),text("always() && (steps.cache-cargo-audit-build-partial.outcome == 'success' || steps.cache-cargo-audit-build-partial.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R52));
    Value::Mapping(values)
}

fn node_260() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-deny-build-partial"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.cache-cargo-deny.outputs.tool-build-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.cache-cargo-audit-build-partial-import.outcome == 'skipped' || steps.cache-cargo-audit-build-partial-import.outputs.cache-quiescent == 'true') && (steps.supply-run.outcome == 'skipped' || steps.supply-run.outputs.cache-quiescent == 'true') && (steps.supply-run-diagnostic.outcome == 'skipped' || steps.supply-run-diagnostic.outputs.cache-quiescent == 'true') && !((steps.supply-run.outputs.tool-cargo-deny-build-complete == 'true' || steps.supply-run-diagnostic.outputs.tool-cargo-deny-build-complete == 'true') && steps.cache-cargo-deny-save-context.outputs.payload-ready == 'true') && (steps.cache-cargo-deny-build-partial-import.outcome == 'skipped' || steps.cache-cargo-deny-build-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R53));
    Value::Mapping(values)
}

fn node_261() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-deny-build-partial-probe"));
    values.insert(text("if"),text("always() && steps.cache-cargo-deny-build-partial.outputs.snapshot-ready == 'true' && steps.cache-cargo-deny-build-partial.outputs.input-key == steps.cache-cargo-deny.outputs.tool-build-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_262());
    Value::Mapping(values)
}

fn node_262() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.cache-cargo-deny-build-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.cache-cargo-deny-build-partial.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_263() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-deny-build-partial-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.cache-cargo-deny-build-partial.outputs.snapshot-ready == 'true' && steps.cache-cargo-deny-build-partial.outputs.input-key == steps.cache-cargo-deny.outputs.tool-build-key && steps.cache-cargo-deny-build-partial.outputs.snapshot-key != '' && steps.cache-cargo-deny-build-partial-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_264());
    Value::Mapping(values)
}

fn node_264() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.cache-cargo-deny-build-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.cache-cargo-deny-build-partial.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_265() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-deny-build-partial-cleanup"));
    values.insert(text("if"),text("always() && (steps.cache-cargo-deny-build-partial.outcome == 'success' || steps.cache-cargo-deny-build-partial.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R54));
    Value::Mapping(values)
}

fn node_266() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("github.event.deleted != true"));
    values.insert(text("name"), text("native / ${{ matrix.id }}"));
    values.insert(text("strategy"), node_267());
    values.insert(text("runs-on"), text("${{ matrix.runner }}"));
    values.insert(text("timeout-minutes"), number("139"));
    values.insert(text("steps"), node_276());
    Value::Mapping(values)
}

fn node_267() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("fail-fast"), Value::Bool(false));
    values.insert(text("matrix"), node_268());
    Value::Mapping(values)
}

fn node_268() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("include"), node_269());
    Value::Mapping(values)
}

fn node_269() -> Value {
    let mut values = Vec::new();
    values.push(node_270());
    values.push(node_271());
    values.push(node_272());
    values.push(node_273());
    values.push(node_274());
    values.push(node_275());
    Value::Sequence(values)
}

fn node_270() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("linux-x64"));
    values.insert(text("runner"), text("ubuntu-24.04"));
    Value::Mapping(values)
}

fn node_271() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("linux-arm64"));
    values.insert(text("runner"), text("ubuntu-24.04-arm"));
    Value::Mapping(values)
}

fn node_272() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("macos-arm64"));
    values.insert(text("runner"), text("macos-15"));
    Value::Mapping(values)
}

fn node_273() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("macos-x64"));
    values.insert(text("runner"), text("macos-15-intel"));
    Value::Mapping(values)
}

fn node_274() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("windows-x64"));
    values.insert(text("runner"), text("windows-2025"));
    Value::Mapping(values)
}

fn node_275() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("windows-arm64"));
    values.insert(text("runner"), text("windows-11-arm"));
    Value::Mapping(values)
}

fn node_276() -> Value {
    let mut values = Vec::new();
    values.push(node_277());
    values.push(node_279());
    values.push(node_281());
    values.push(node_282());
    values.push(node_283());
    values.push(node_284());
    values.push(node_285());
    values.push(node_287());
    values.push(node_288());
    values.push(node_290());
    values.push(node_291());
    values.push(node_293());
    values.push(node_294());
    values.push(node_295());
    values.push(node_297());
    values.push(node_298());
    values.push(node_299());
    values.push(node_300());
    values.push(node_302());
    values.push(node_303());
    values.push(node_305());
    values.push(node_306());
    values.push(node_307());
    values.push(node_308());
    values.push(node_309());
    values.push(node_311());
    values.push(node_312());
    values.push(node_313());
    values.push(node_314());
    values.push(node_315());
    values.push(node_317());
    values.push(node_318());
    values.push(node_319());
    values.push(node_320());
    values.push(node_322());
    values.push(node_323());
    values.push(node_324());
    values.push(node_325());
    values.push(node_327());
    values.push(node_329());
    values.push(node_330());
    values.push(node_331());
    values.push(node_332());
    values.push(node_333());
    values.push(node_334());
    values.push(node_336());
    values.push(node_338());
    values.push(node_339());
    values.push(node_341());
    values.push(node_343());
    values.push(node_344());
    values.push(node_345());
    values.push(node_347());
    values.push(node_349());
    values.push(node_350());
    values.push(node_351());
    values.push(node_353());
    values.push(node_355());
    values.push(node_356());
    values.push(node_357());
    values.push(node_359());
    values.push(node_361());
    Value::Sequence(values)
}

fn node_277() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Check out repository"));
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_278());
    Value::Mapping(values)
}

fn node_278() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_279() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Restore Cargo sources"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"), text("hashFiles('Cargo.lock') != ''"));
    values.insert(text("id"), text("native-deps"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_280());
    Value::Mapping(values)
}

fn node_280() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("~/.cargo/registry/cache\n~/.cargo/git/db\n"),
    );
    values.insert(text("key"),text("mc-download-bootstrap-v5-${{ runner.os }}-${{ hashFiles('Cargo.lock', 'Cargo.toml', '.cargo/**', 'ci/toolchains.toml') }}"));
    values.insert(
        text("restore-keys"),
        text("mc-download-bootstrap-v5-${{ runner.os }}-"),
    );
    Value::Mapping(values)
}

fn node_281() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Install pinned Rust"));
    values.insert(text("run"), literal(LiteralRun::R0));
    Value::Mapping(values)
}

fn node_282() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Initialize genuine auxiliary Cargo target"),
    );
    values.insert(text("run"), literal(LiteralRun::R55));
    Value::Mapping(values)
}

fn node_283() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Build ordinary CI driver"));
    values.insert(text("id"), text("driver-build"));
    values.insert(text("run"), literal(LiteralRun::R1));
    Value::Mapping(values)
}

fn node_284() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("bootstrap-home"));
    values.insert(
        text("if"),
        text("always() && steps.driver-build.outcome == 'success'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R2));
    Value::Mapping(values)
}

fn node_285() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save Cargo sources"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.driver-build.outcome == 'success' && steps.bootstrap-home.outcome == 'success' && steps.bootstrap-home.outputs.bootstrap-home-matches == 'true' && steps.native-deps.outputs.cache-primary-key != '' && steps.native-deps.outputs.cache-hit != 'true'"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_286());
    Value::Mapping(values)
}

fn node_286() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("~/.cargo/registry/cache\n~/.cargo/git/db\n"),
    );
    values.insert(
        text("key"),
        text("${{ steps.native-deps.outputs.cache-primary-key }}"),
    );
    Value::Mapping(values)
}

fn node_287() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-context"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_288() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-downloads"));
    values.insert(
        text("if"),
        text("steps.workspace-download-context.outputs.source-key != ''"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_289());
    Value::Mapping(values)
}

fn node_289() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.workspace-download-context.outputs.source-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.workspace-download-context.outputs.source-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-download-context.outputs.source-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_290() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-context"));
    values.insert(text("run"), literal(LiteralRun::R4));
    Value::Mapping(values)
}

fn node_291() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore"));
    values.insert(text("if"),text("steps.archive-seed-context.outputs.seed-lookup-key != '' && steps.workspace-downloads.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_292());
    Value::Mapping(values)
}

fn node_292() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.archive-seed-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.archive-seed-context.outputs.seed-restore-prefix }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.archive-seed-context.outputs.seed-import-path }}"),
    );
    Value::Mapping(values)
}

fn node_293() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("steps.archive-seed-restore.outcome == 'success' && steps.archive-seed-restore.outputs.cache-matched-key != ''"));
    values.insert(
        text("id"),
        text("import-registry-archives-sources-complete-recipe"),
    );
    values.insert(text("run"), literal(LiteralRun::R5));
    Value::Mapping(values)
}

fn node_294() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-context"));
    values.insert(text("run"), literal(LiteralRun::R6));
    Value::Mapping(values)
}

fn node_295() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-restore"));
    values.insert(
        text("if"),
        text("steps.index-snapshot-context.outputs.seed-lookup-key != ''"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_296());
    Value::Mapping(values)
}

fn node_296() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.index-snapshot-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.index-snapshot-context.outputs.seed-restore-prefix }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.index-snapshot-context.outputs.seed-import-path }}"),
    );
    Value::Mapping(values)
}

fn node_297() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("steps.index-snapshot-restore.outcome == 'success' && steps.index-snapshot-restore.outputs.cache-matched-key != ''"));
    values.insert(
        text("id"),
        text("import-registry-index-sources-complete-recipe"),
    );
    values.insert(text("run"), literal(LiteralRun::R7));
    Value::Mapping(values)
}

fn node_298() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(text("run"), literal(LiteralRun::R8));
    Value::Mapping(values)
}

fn node_299() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save-context"));
    values.insert(text("if"),text("always() && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-context.outputs.source-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_300() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save complete workspace downloads"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.workspace-download-context.outputs.source-key != '' && steps.workspace-download-context.outputs.source-paths != '' && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-save-context.outcome == 'success' && steps.workspace-download-save-context.outputs.source-key == steps.workspace-download-context.outputs.source-key && steps.workspace-download-save-context.outputs.source-key == steps.workspace-fetch.outputs.workspace-downloads-key && !(steps.workspace-downloads.outcome == 'success' && steps.workspace-downloads.outputs.cache-hit == 'true') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && steps.workspace-download-context.outputs.source-paths != ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_301());
    Value::Mapping(values)
}

fn node_301() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.workspace-download-context.outputs.source-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.workspace-download-context.outputs.source-key }}"),
    );
    Value::Mapping(values)
}

fn node_302() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-context"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R56));
    Value::Mapping(values)
}

fn node_303() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("if"),
        text("steps.compiled-context.outputs.compiled-cache-usable == 'true'"),
    );
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_304());
    Value::Mapping(values)
}

fn node_304() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.compiled-context.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.compiled-context.outputs.product-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.compiled-context.outputs.product-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_305() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize compiled discard restore"));
    values.insert(
        text("id"),
        text("sanitize-native-debug-complete-native-tests-discard"),
    );
    values.insert(text("if"), text("steps.compiled.outcome == 'failure'"));
    values.insert(text("run"), literal(LiteralRun::R57));
    Value::Mapping(values)
}

fn node_306() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize compiled exact restore"));
    values.insert(
        text("id"),
        text("sanitize-native-debug-complete-native-tests-exact"),
    );
    values.insert(
        text("if"),
        text("steps.compiled.outcome == 'success' && steps.compiled.outputs.cache-hit == 'true'"),
    );
    values.insert(text("run"), literal(LiteralRun::R58));
    Value::Mapping(values)
}

fn node_307() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize compiled compatible restore"));
    values.insert(
        text("id"),
        text("sanitize-native-debug-complete-native-tests-compatible"),
    );
    values.insert(text("if"),text("steps.compiled.outcome == 'success' && steps.compiled.outputs.cache-matched-key != '' && steps.compiled.outputs.cache-hit != 'true'"));
    values.insert(text("run"), literal(LiteralRun::R59));
    Value::Mapping(values)
}

fn node_308() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("auxiliary-context"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R60));
    Value::Mapping(values)
}

fn node_309() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("auxiliary-compiled"));
    values.insert(
        text("if"),
        text("steps.auxiliary-context.outputs.compiled-cache-usable == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_310());
    Value::Mapping(values)
}

fn node_310() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.auxiliary-context.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.auxiliary-context.outputs.product-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.auxiliary-context.outputs.product-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_311() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("if"),
        text("steps.auxiliary-compiled.outcome == 'failure'"),
    );
    values.insert(
        text("id"),
        text("sanitize-native-auxiliary-complete-recipe-discard"),
    );
    values.insert(text("run"), literal(LiteralRun::R61));
    Value::Mapping(values)
}

fn node_312() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("steps.auxiliary-compiled.outcome == 'success' && steps.auxiliary-compiled.outputs.cache-hit == 'true'"));
    values.insert(
        text("id"),
        text("sanitize-native-auxiliary-complete-recipe-exact"),
    );
    values.insert(text("run"), literal(LiteralRun::R62));
    Value::Mapping(values)
}

fn node_313() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("steps.auxiliary-compiled.outcome == 'success' && steps.auxiliary-compiled.outputs.cache-matched-key != '' && steps.auxiliary-compiled.outputs.cache-hit != 'true'"));
    values.insert(
        text("id"),
        text("sanitize-native-auxiliary-complete-recipe-compatible"),
    );
    values.insert(text("run"), literal(LiteralRun::R63));
    Value::Mapping(values)
}

fn node_314() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("native-seed-context"));
    values.insert(text("if"),text("steps.compiled-context.outputs.product-key != '' && steps.compiled.outputs.cache-matched-key == ''"));
    values.insert(text("run"), literal(LiteralRun::R64));
    Value::Mapping(values)
}

fn node_315() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("native-seed"));
    values.insert(
        text("if"),
        text("steps.native-seed-context.outputs.seed-lookup-key != ''"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_316());
    Value::Mapping(values)
}

fn node_316() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.native-seed-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.native-seed-context.outputs.seed-restore-prefix }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.native-seed-context.outputs.seed-import-path }}"),
    );
    Value::Mapping(values)
}

fn node_317() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("steps.native-seed.outcome == 'success' && steps.native-seed.outputs.cache-matched-key != ''"));
    values.insert(
        text("id"),
        text("import-compiled-native-debug-complete-native-tests"),
    );
    values.insert(text("run"), literal(LiteralRun::R65));
    Value::Mapping(values)
}

fn node_318() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("auxiliary-compiled-partial-input-context"));
    values.insert(
        text("if"),
        text("steps.auxiliary-context.outputs.product-key != ''"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R66));
    Value::Mapping(values)
}

fn node_319() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("auxiliary-compiled-partial-context"));
    values.insert(text("if"),text("steps.auxiliary-compiled-partial-input-context.outputs.product-key != '' && steps.auxiliary-compiled.outcome != 'failure' && steps.auxiliary-compiled.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R67));
    Value::Mapping(values)
}

fn node_320() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("auxiliary-compiled-partial-restore"));
    values.insert(text("if"),text("steps.auxiliary-compiled-partial-context.outputs.seed-lookup-key != '' && steps.auxiliary-compiled-partial-input-context.outputs.product-key != '' && steps.auxiliary-compiled.outcome != 'failure' && steps.auxiliary-compiled.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_321());
    Value::Mapping(values)
}

fn node_321() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.auxiliary-compiled-partial-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.auxiliary-compiled-partial-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.auxiliary-compiled-partial-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_322() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("auxiliary-compiled-partial-import"));
    values.insert(text("if"),text("steps.auxiliary-compiled-partial-restore.outcome == 'success' && steps.auxiliary-compiled-partial-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R68));
    Value::Mapping(values)
}

fn node_323() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("native-compile"));
    values.insert(text("run"), literal(LiteralRun::R69));
    Value::Mapping(values)
}

fn node_324() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("native-build-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-native-debug-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-native-debug-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-native-debug-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-native-debug-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-native-debug-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-native-debug-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-native-auxiliary-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-native-auxiliary-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-native-auxiliary-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-native-auxiliary-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-native-auxiliary-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-native-auxiliary-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-native-debug-complete-native-tests.outcome == 'skipped' || steps.import-compiled-native-debug-complete-native-tests.outputs.cache-quiescent == 'true') && (steps.native-compile.outcome == 'skipped' || steps.native-compile.outputs.cache-quiescent == 'true') && (steps.auxiliary-compiled-partial-import.outcome == 'skipped' || steps.auxiliary-compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("run"), literal(LiteralRun::R70));
    Value::Mapping(values)
}

fn node_325() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("native-build-probe"));
    values.insert(text("if"),text("always() && steps.native-build-snapshot.outputs.snapshot-ready == 'true' && steps.native-build-snapshot.outputs.input-key == steps.compiled-context.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_326());
    Value::Mapping(values)
}

fn node_326() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.native-build-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.native-build-snapshot.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_327() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Retain settled native compilation"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.native-build-snapshot.outputs.snapshot-ready == 'true' && steps.native-build-snapshot.outputs.input-key == steps.compiled-context.outputs.product-key && steps.native-build-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_328());
    Value::Mapping(values)
}

fn node_328() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.native-build-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.native-build-snapshot.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_329() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (steps.native-build-snapshot.outcome == 'success' || steps.native-build-snapshot.outcome == 'failure')"));
    values.insert(text("run"), literal(LiteralRun::R71));
    Value::Mapping(values)
}

fn node_330() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Run native suite"));
    values.insert(text("id"), text("native-run"));
    values.insert(
        text("if"),
        text("github.event_name != 'workflow_dispatch' || inputs.failure-mode != 'collect-all'"),
    );
    values.insert(text("run"), literal(LiteralRun::R72));
    Value::Mapping(values)
}

fn node_331() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Collect all native diagnostic failures"));
    values.insert(text("id"), text("native-diagnostic"));
    values.insert(
        text("if"),
        text("github.event_name == 'workflow_dispatch' && inputs.failure-mode == 'collect-all'"),
    );
    values.insert(text("run"), literal(LiteralRun::R73));
    Value::Mapping(values)
}

fn node_332() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-native-debug-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-native-debug-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-native-debug-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-native-debug-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-native-debug-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-native-debug-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-native-auxiliary-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-native-auxiliary-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-native-auxiliary-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-native-auxiliary-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-native-auxiliary-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-native-auxiliary-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-native-debug-complete-native-tests.outcome == 'skipped' || steps.import-compiled-native-debug-complete-native-tests.outputs.cache-quiescent == 'true') && (steps.native-compile.outcome == 'skipped' || steps.native-compile.outputs.cache-quiescent == 'true') && (steps.native-run.outcome == 'skipped' || steps.native-run.outputs.cache-quiescent == 'true') && (steps.native-diagnostic.outcome == 'skipped' || steps.native-diagnostic.outputs.cache-quiescent == 'true') && steps.compiled-context.outputs.compiled-cache-usable == 'true' && (steps.auxiliary-compiled-partial-import.outcome == 'skipped' || steps.auxiliary-compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R74));
    Value::Mapping(values)
}

fn node_333() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("auxiliary-save-context"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-native-debug-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-native-debug-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-native-debug-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-native-debug-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-native-debug-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-native-debug-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-native-auxiliary-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-native-auxiliary-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-native-auxiliary-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-native-auxiliary-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-native-auxiliary-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-native-auxiliary-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-native-debug-complete-native-tests.outcome == 'skipped' || steps.import-compiled-native-debug-complete-native-tests.outputs.cache-quiescent == 'true') && (steps.native-compile.outcome == 'skipped' || steps.native-compile.outputs.cache-quiescent == 'true') && (steps.native-run.outcome == 'skipped' || steps.native-run.outputs.cache-quiescent == 'true') && (steps.native-diagnostic.outcome == 'skipped' || steps.native-diagnostic.outputs.cache-quiescent == 'true') && (steps.auxiliary-compiled-partial-import.outcome == 'skipped' || steps.auxiliary-compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R75));
    Value::Mapping(values)
}

fn node_334() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save settled auxiliary compilation"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-native-debug-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-native-debug-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-native-debug-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-native-debug-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-native-debug-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-native-debug-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-native-auxiliary-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-native-auxiliary-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-native-auxiliary-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-native-auxiliary-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-native-auxiliary-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-native-auxiliary-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-native-debug-complete-native-tests.outcome == 'skipped' || steps.import-compiled-native-debug-complete-native-tests.outputs.cache-quiescent == 'true') && (steps.native-compile.outcome == 'skipped' || steps.native-compile.outputs.cache-quiescent == 'true') && (steps.native-run.outcome == 'skipped' || steps.native-run.outputs.cache-quiescent == 'true') && (steps.native-diagnostic.outcome == 'skipped' || steps.native-diagnostic.outputs.cache-quiescent == 'true') && steps.auxiliary-context.outputs.product-key != '' && steps.auxiliary-save-context.outcome == 'success' && steps.auxiliary-save-context.outputs.product-key == steps.auxiliary-context.outputs.product-key && steps.auxiliary-save-context.outputs.payload-ready == 'true' && (steps.native-run.outputs.compiled-recipe-complete == 'true' || steps.native-diagnostic.outputs.compiled-recipe-complete == 'true') && !(steps.auxiliary-compiled.outcome == 'success' && steps.auxiliary-compiled.outputs.cache-hit == 'true') && (steps.auxiliary-compiled-partial-import.outcome == 'skipped' || steps.auxiliary-compiled-partial-import.outputs.cache-quiescent == 'true') && steps.auxiliary-context.outputs.product-paths != '' && steps.auxiliary-context.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_335());
    Value::Mapping(values)
}

fn node_335() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.auxiliary-context.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.auxiliary-context.outputs.product-key }}"),
    );
    Value::Mapping(values)
}

fn node_336() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-native-debug-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-native-debug-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-native-debug-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-native-debug-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-native-debug-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-native-debug-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-native-auxiliary-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-native-auxiliary-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-native-auxiliary-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-native-auxiliary-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-native-auxiliary-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-native-auxiliary-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-native-debug-complete-native-tests.outcome == 'skipped' || steps.import-compiled-native-debug-complete-native-tests.outputs.cache-quiescent == 'true') && (steps.native-compile.outcome == 'skipped' || steps.native-compile.outputs.cache-quiescent == 'true') && (steps.native-run.outcome == 'skipped' || steps.native-run.outputs.cache-quiescent == 'true') && (steps.native-diagnostic.outcome == 'skipped' || steps.native-diagnostic.outputs.cache-quiescent == 'true') && steps.compiled-context.outputs.product-key != '' && steps.compiled-save-context.outcome == 'success' && steps.compiled-save-context.outputs.product-key == steps.compiled-context.outputs.product-key && steps.compiled-save-context.outputs.payload-ready == 'true' && ((steps.native-compile.outputs.compiled-native-complete == 'true') && (steps.native-run.outcome == 'skipped' || steps.native-run.outputs.compiled-native-complete == 'true') && (steps.native-diagnostic.outcome == 'skipped' || steps.native-diagnostic.outputs.compiled-native-complete == 'true')) && !(steps.compiled.outcome == 'success' && steps.compiled.outputs.cache-hit == 'true') && (steps.auxiliary-compiled-partial-import.outcome == 'skipped' || steps.auxiliary-compiled-partial-import.outputs.cache-quiescent == 'true') && steps.compiled-context.outputs.product-paths != '' && steps.compiled-context.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_337());
    Value::Mapping(values)
}

fn node_337() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.compiled-context.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.compiled-context.outputs.product-key }}"),
    );
    Value::Mapping(values)
}

fn node_338() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-native-debug-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-native-debug-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-native-debug-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-native-debug-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-native-debug-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-native-debug-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-native-auxiliary-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-native-auxiliary-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-native-auxiliary-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-native-auxiliary-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-native-auxiliary-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-native-auxiliary-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-native-debug-complete-native-tests.outcome == 'skipped' || steps.import-compiled-native-debug-complete-native-tests.outputs.cache-quiescent == 'true') && (steps.native-compile.outcome == 'skipped' || steps.native-compile.outputs.cache-quiescent == 'true') && (steps.native-run.outcome == 'skipped' || steps.native-run.outputs.cache-quiescent == 'true') && (steps.native-diagnostic.outcome == 'skipped' || steps.native-diagnostic.outputs.cache-quiescent == 'true') && (steps.auxiliary-compiled-partial-import.outcome == 'skipped' || steps.auxiliary-compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("run"), literal(LiteralRun::R9));
    Value::Mapping(values)
}

fn node_339() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-probe"));
    values.insert(text("if"),text("always() && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_340());
    Value::Mapping(values)
}

fn node_340() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_341() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save observed registry-archives"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility && steps.archive-seed-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_342());
    Value::Mapping(values)
}

fn node_342() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_343() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (steps.archive-seed-snapshot.outcome == 'success' || steps.archive-seed-snapshot.outcome == 'failure')"));
    values.insert(text("run"), literal(LiteralRun::R10));
    Value::Mapping(values)
}

fn node_344() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-native-debug-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-native-debug-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-native-debug-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-native-debug-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-native-debug-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-native-debug-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-native-auxiliary-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-native-auxiliary-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-native-auxiliary-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-native-auxiliary-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-native-auxiliary-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-native-auxiliary-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-native-debug-complete-native-tests.outcome == 'skipped' || steps.import-compiled-native-debug-complete-native-tests.outputs.cache-quiescent == 'true') && (steps.native-compile.outcome == 'skipped' || steps.native-compile.outputs.cache-quiescent == 'true') && (steps.native-run.outcome == 'skipped' || steps.native-run.outputs.cache-quiescent == 'true') && (steps.native-diagnostic.outcome == 'skipped' || steps.native-diagnostic.outputs.cache-quiescent == 'true') && (steps.auxiliary-compiled-partial-import.outcome == 'skipped' || steps.auxiliary-compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("run"), literal(LiteralRun::R11));
    Value::Mapping(values)
}

fn node_345() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-probe"));
    values.insert(text("if"),text("always() && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_346());
    Value::Mapping(values)
}

fn node_346() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.index-snapshot-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.index-snapshot-snapshot.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_347() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save observed registry-index"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility && steps.index-snapshot-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_348());
    Value::Mapping(values)
}

fn node_348() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.index-snapshot-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.index-snapshot-snapshot.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_349() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (steps.index-snapshot-snapshot.outcome == 'success' || steps.index-snapshot-snapshot.outcome == 'failure')"));
    values.insert(text("run"), literal(LiteralRun::R12));
    Value::Mapping(values)
}

fn node_350() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("auxiliary-compiled-partial"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.auxiliary-compiled-partial-input-context.outputs.product-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-native-debug-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-native-debug-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-native-debug-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-native-debug-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-native-debug-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-native-debug-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-native-auxiliary-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-native-auxiliary-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-native-auxiliary-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-native-auxiliary-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-native-auxiliary-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-native-auxiliary-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-native-debug-complete-native-tests.outcome == 'skipped' || steps.import-compiled-native-debug-complete-native-tests.outputs.cache-quiescent == 'true') && (steps.native-compile.outcome == 'skipped' || steps.native-compile.outputs.cache-quiescent == 'true') && (steps.native-run.outcome == 'skipped' || steps.native-run.outputs.cache-quiescent == 'true') && (steps.native-diagnostic.outcome == 'skipped' || steps.native-diagnostic.outputs.cache-quiescent == 'true') && !((steps.native-run.outputs.compiled-recipe-complete == 'true' || steps.native-diagnostic.outputs.compiled-recipe-complete == 'true') && steps.auxiliary-save-context.outputs.payload-ready == 'true') && (steps.auxiliary-compiled-partial-import.outcome == 'skipped' || steps.auxiliary-compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R76));
    Value::Mapping(values)
}

fn node_351() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("auxiliary-compiled-partial-probe"));
    values.insert(text("if"),text("always() && steps.auxiliary-compiled-partial.outputs.snapshot-ready == 'true' && steps.auxiliary-compiled-partial.outputs.input-key == steps.auxiliary-compiled-partial-input-context.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_352());
    Value::Mapping(values)
}

fn node_352() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.auxiliary-compiled-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.auxiliary-compiled-partial.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_353() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("auxiliary-compiled-partial-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.auxiliary-compiled-partial.outputs.snapshot-ready == 'true' && steps.auxiliary-compiled-partial.outputs.input-key == steps.auxiliary-compiled-partial-input-context.outputs.product-key && steps.auxiliary-compiled-partial.outputs.snapshot-key != '' && steps.auxiliary-compiled-partial-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_354());
    Value::Mapping(values)
}

fn node_354() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.auxiliary-compiled-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.auxiliary-compiled-partial.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_355() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("auxiliary-compiled-partial-cleanup"));
    values.insert(text("if"),text("always() && (steps.auxiliary-compiled-partial.outcome == 'success' || steps.auxiliary-compiled-partial.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R77));
    Value::Mapping(values)
}

fn node_356() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.compiled-context.outputs.product-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-native-debug-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-native-debug-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-native-debug-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-native-debug-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-native-debug-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-native-debug-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-native-auxiliary-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-native-auxiliary-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-native-auxiliary-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-native-auxiliary-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-native-auxiliary-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-native-auxiliary-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-native-debug-complete-native-tests.outcome == 'skipped' || steps.import-compiled-native-debug-complete-native-tests.outputs.cache-quiescent == 'true') && (steps.auxiliary-compiled-partial-import.outcome == 'skipped' || steps.auxiliary-compiled-partial-import.outputs.cache-quiescent == 'true') && (steps.native-compile.outcome == 'skipped' || steps.native-compile.outputs.cache-quiescent == 'true') && (steps.native-run.outcome == 'skipped' || steps.native-run.outputs.cache-quiescent == 'true') && (steps.native-diagnostic.outcome == 'skipped' || steps.native-diagnostic.outputs.cache-quiescent == 'true') && !(((steps.native-compile.outputs.compiled-native-complete == 'true') && (steps.native-run.outcome == 'skipped' || steps.native-run.outputs.compiled-native-complete == 'true') && (steps.native-diagnostic.outcome == 'skipped' || steps.native-diagnostic.outputs.compiled-native-complete == 'true')) && steps.compiled-save-context.outputs.payload-ready == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R78));
    Value::Mapping(values)
}

fn node_357() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-probe"));
    values.insert(text("if"),text("always() && steps.compiled-partial.outputs.snapshot-ready == 'true' && steps.compiled-partial.outputs.input-key == steps.compiled-context.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_358());
    Value::Mapping(values)
}

fn node_358() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.compiled-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.compiled-partial.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_359() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.compiled-partial.outputs.snapshot-ready == 'true' && steps.compiled-partial.outputs.input-key == steps.compiled-context.outputs.product-key && steps.compiled-partial.outputs.snapshot-key != '' && steps.compiled-partial-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_360());
    Value::Mapping(values)
}

fn node_360() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.compiled-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.compiled-partial.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_361() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-cleanup"));
    values.insert(text("if"),text("always() && (steps.compiled-partial.outcome == 'success' || steps.compiled-partial.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R79));
    Value::Mapping(values)
}

fn node_362() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("github.event_name != 'push'"));
    values.insert(text("name"), text("macOS deadline / ${{ matrix.id }}"));
    values.insert(text("strategy"), node_363());
    values.insert(text("runs-on"), text("${{ matrix.runner }}"));
    values.insert(text("timeout-minutes"), number("143"));
    values.insert(text("steps"), node_368());
    Value::Mapping(values)
}

fn node_363() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("fail-fast"), Value::Bool(false));
    values.insert(text("matrix"), node_364());
    Value::Mapping(values)
}

fn node_364() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("include"), node_365());
    Value::Mapping(values)
}

fn node_365() -> Value {
    let mut values = Vec::new();
    values.push(node_366());
    values.push(node_367());
    Value::Sequence(values)
}

fn node_366() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("arm64"));
    values.insert(text("runner"), text("macos-15"));
    Value::Mapping(values)
}

fn node_367() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("x64"));
    values.insert(text("runner"), text("macos-15-intel"));
    Value::Mapping(values)
}

fn node_368() -> Value {
    let mut values = Vec::new();
    values.push(node_369());
    values.push(node_371());
    values.push(node_373());
    values.push(node_374());
    values.push(node_375());
    values.push(node_376());
    values.push(node_378());
    values.push(node_379());
    values.push(node_381());
    values.push(node_382());
    values.push(node_384());
    values.push(node_385());
    values.push(node_386());
    values.push(node_388());
    values.push(node_389());
    values.push(node_390());
    values.push(node_391());
    values.push(node_393());
    values.push(node_394());
    values.push(node_396());
    values.push(node_398());
    values.push(node_399());
    values.push(node_400());
    values.push(node_402());
    values.push(node_404());
    values.push(node_405());
    values.push(node_406());
    values.push(node_408());
    values.push(node_409());
    values.push(node_410());
    values.push(node_411());
    values.push(node_412());
    values.push(node_414());
    values.push(node_415());
    values.push(node_416());
    values.push(node_417());
    values.push(node_419());
    values.push(node_421());
    values.push(node_422());
    values.push(node_424());
    values.push(node_426());
    Value::Sequence(values)
}

fn node_369() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_370());
    Value::Mapping(values)
}

fn node_370() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_371() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("deadline-deps"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"), text("hashFiles('Cargo.lock') != ''"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_372());
    Value::Mapping(values)
}

fn node_372() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("~/.cargo/registry/cache\n~/.cargo/git/db\n"),
    );
    values.insert(text("key"),text("mc-download-bootstrap-v5-${{ runner.os }}-${{ hashFiles('Cargo.lock', 'Cargo.toml', '.cargo/**', 'ci/toolchains.toml') }}"));
    values.insert(
        text("restore-keys"),
        text("mc-download-bootstrap-v5-${{ runner.os }}-"),
    );
    Value::Mapping(values)
}

fn node_373() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R0));
    Value::Mapping(values)
}

fn node_374() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Build ordinary CI driver"));
    values.insert(text("id"), text("driver-build"));
    values.insert(text("run"), literal(LiteralRun::R1));
    Value::Mapping(values)
}

fn node_375() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("bootstrap-home"));
    values.insert(
        text("if"),
        text("always() && steps.driver-build.outcome == 'success'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R2));
    Value::Mapping(values)
}

fn node_376() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.driver-build.outcome == 'success' && steps.bootstrap-home.outcome == 'success' && steps.bootstrap-home.outputs.bootstrap-home-matches == 'true' && steps.deadline-deps.outputs.cache-primary-key != '' && steps.deadline-deps.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_377());
    Value::Mapping(values)
}

fn node_377() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("~/.cargo/registry/cache\n~/.cargo/git/db\n"),
    );
    values.insert(
        text("key"),
        text("${{ steps.deadline-deps.outputs.cache-primary-key }}"),
    );
    Value::Mapping(values)
}

fn node_378() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-context"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_379() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-downloads"));
    values.insert(
        text("if"),
        text("steps.workspace-download-context.outputs.source-key != ''"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_380());
    Value::Mapping(values)
}

fn node_380() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.workspace-download-context.outputs.source-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.workspace-download-context.outputs.source-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-download-context.outputs.source-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_381() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R4));
    Value::Mapping(values)
}

fn node_382() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore"));
    values.insert(text("if"),text("steps.archive-seed-context.outputs.seed-lookup-key != '' && steps.workspace-downloads.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_383());
    Value::Mapping(values)
}

fn node_383() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.archive-seed-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.archive-seed-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.archive-seed-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_384() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore-import"));
    values.insert(text("if"),text("steps.archive-seed-restore.outcome == 'success' && steps.archive-seed-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R5));
    Value::Mapping(values)
}

fn node_385() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R6));
    Value::Mapping(values)
}

fn node_386() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-restore"));
    values.insert(
        text("if"),
        text("steps.index-snapshot-context.outputs.seed-lookup-key != ''"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_387());
    Value::Mapping(values)
}

fn node_387() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.index-snapshot-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.index-snapshot-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.index-snapshot-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_388() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-restore-import"));
    values.insert(text("if"),text("steps.index-snapshot-restore.outcome == 'success' && steps.index-snapshot-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R7));
    Value::Mapping(values)
}

fn node_389() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(text("run"), literal(LiteralRun::R8));
    Value::Mapping(values)
}

fn node_390() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save-context"));
    values.insert(text("if"),text("always() && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-context.outputs.source-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_391() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.workspace-download-context.outputs.source-key != '' && steps.workspace-download-context.outputs.source-paths != '' && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-save-context.outcome == 'success' && steps.workspace-download-save-context.outputs.source-key == steps.workspace-download-context.outputs.source-key && steps.workspace-download-save-context.outputs.source-key == steps.workspace-fetch.outputs.workspace-downloads-key && !(steps.workspace-downloads.outcome == 'success' && steps.workspace-downloads.outputs.cache-hit == 'true') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && steps.workspace-download-context.outputs.source-paths != ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_392());
    Value::Mapping(values)
}

fn node_392() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-download-context.outputs.source-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-download-context.outputs.source-paths }}"),
    );
    Value::Mapping(values)
}

fn node_393() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R9));
    Value::Mapping(values)
}

fn node_394() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-probe"));
    values.insert(text("if"),text("always() && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_395());
    Value::Mapping(values)
}

fn node_395() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_396() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility && steps.archive-seed-snapshot.outputs.snapshot-key != '' && steps.archive-seed-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_397());
    Value::Mapping(values)
}

fn node_397() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_398() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.archive-seed-snapshot.outcome == 'success' || steps.archive-seed-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R10));
    Value::Mapping(values)
}

fn node_399() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R11));
    Value::Mapping(values)
}

fn node_400() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-probe"));
    values.insert(text("if"),text("always() && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_401());
    Value::Mapping(values)
}

fn node_401() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.index-snapshot-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.index-snapshot-snapshot.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_402() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility && steps.index-snapshot-snapshot.outputs.snapshot-key != '' && steps.index-snapshot-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_403());
    Value::Mapping(values)
}

fn node_403() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.index-snapshot-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.index-snapshot-snapshot.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_404() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.index-snapshot-snapshot.outcome == 'success' || steps.index-snapshot-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R12));
    Value::Mapping(values)
}

fn node_405() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("deadline-context"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R80));
    Value::Mapping(values)
}

fn node_406() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("deadline-compiled"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("if"),
        text("steps.deadline-context.outputs.compiled-cache-usable == 'true'"),
    );
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_407());
    Value::Mapping(values)
}

fn node_407() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.deadline-context.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.deadline-context.outputs.product-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.deadline-context.outputs.product-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_408() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize deadline-compiled discard restore"),
    );
    values.insert(
        text("id"),
        text("sanitize-deadline-complete-recipe-discard"),
    );
    values.insert(
        text("if"),
        text("steps.deadline-compiled.outcome == 'failure'"),
    );
    values.insert(text("run"), literal(LiteralRun::R81));
    Value::Mapping(values)
}

fn node_409() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize deadline-compiled exact restore"),
    );
    values.insert(text("id"), text("sanitize-deadline-complete-recipe-exact"));
    values.insert(text("if"),text("steps.deadline-compiled.outcome == 'success' && steps.deadline-compiled.outputs.cache-hit == 'true'"));
    values.insert(text("run"), literal(LiteralRun::R82));
    Value::Mapping(values)
}

fn node_410() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize deadline-compiled compatible restore"),
    );
    values.insert(
        text("id"),
        text("sanitize-deadline-complete-recipe-compatible"),
    );
    values.insert(text("if"),text("steps.deadline-compiled.outcome == 'success' && steps.deadline-compiled.outputs.cache-matched-key != '' && steps.deadline-compiled.outputs.cache-hit != 'true'"));
    values.insert(text("run"), literal(LiteralRun::R83));
    Value::Mapping(values)
}

fn node_411() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("deadline-compiled-partial-context"));
    values.insert(text("if"),text("steps.deadline-context.outputs.product-key != '' && steps.deadline-compiled.outcome != 'failure' && steps.deadline-compiled.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R84));
    Value::Mapping(values)
}

fn node_412() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("deadline-compiled-partial-restore"));
    values.insert(text("if"),text("steps.deadline-compiled-partial-context.outputs.seed-lookup-key != '' && steps.deadline-context.outputs.product-key != '' && steps.deadline-compiled.outcome != 'failure' && steps.deadline-compiled.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_413());
    Value::Mapping(values)
}

fn node_413() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.deadline-compiled-partial-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.deadline-compiled-partial-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.deadline-compiled-partial-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_414() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("deadline-compiled-partial-import"));
    values.insert(text("if"),text("steps.deadline-compiled-partial-restore.outcome == 'success' && steps.deadline-compiled-partial-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R85));
    Value::Mapping(values)
}

fn node_415() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("deadline-run"));
    values.insert(text("run"), literal(LiteralRun::R86));
    Value::Mapping(values)
}

fn node_416() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("deadline-compiled-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-deadline-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-deadline-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-deadline-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-deadline-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-deadline-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-deadline-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.deadline-run.outcome == 'skipped' || steps.deadline-run.outputs.cache-quiescent == 'true') && steps.deadline-context.outputs.compiled-cache-usable == 'true' && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.deadline-compiled-partial-import.outcome == 'skipped' || steps.deadline-compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R87));
    Value::Mapping(values)
}

fn node_417() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-deadline-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-deadline-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-deadline-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-deadline-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-deadline-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-deadline-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.deadline-run.outcome == 'skipped' || steps.deadline-run.outputs.cache-quiescent == 'true') && steps.deadline-context.outputs.product-key != '' && steps.deadline-compiled-save-context.outcome == 'success' && steps.deadline-compiled-save-context.outputs.product-key == steps.deadline-context.outputs.product-key && steps.deadline-compiled-save-context.outputs.payload-ready == 'true' && (steps.deadline-run.outputs.compiled-recipe-complete == 'true') && !(steps.deadline-compiled.outcome == 'success' && steps.deadline-compiled.outputs.cache-hit == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.deadline-compiled-partial-import.outcome == 'skipped' || steps.deadline-compiled-partial-import.outputs.cache-quiescent == 'true') && steps.deadline-context.outputs.product-paths != '' && steps.deadline-context.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_418());
    Value::Mapping(values)
}

fn node_418() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.deadline-context.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.deadline-context.outputs.product-key }}"),
    );
    Value::Mapping(values)
}

fn node_419() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("always()"));
    values.insert(text("uses"), text("./.github/actions/upload-artifact"));
    values.insert(text("with"), node_420());
    Value::Mapping(values)
}

fn node_420() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("macos-deadline-${{ matrix.id }}"));
    values.insert(text("path"), text("target/ci/deadline-evidence"));
    values.insert(text("if-no-files-found"), text("error"));
    values.insert(text("retention-days"), number("14"));
    Value::Mapping(values)
}

fn node_421() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("deadline-compiled-partial"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.deadline-context.outputs.product-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-deadline-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-deadline-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-deadline-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-deadline-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-deadline-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-deadline-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.deadline-run.outcome == 'skipped' || steps.deadline-run.outputs.cache-quiescent == 'true') && !((steps.deadline-run.outputs.compiled-recipe-complete == 'true') && steps.deadline-compiled-save-context.outputs.payload-ready == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.deadline-compiled-partial-import.outcome == 'skipped' || steps.deadline-compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R88));
    Value::Mapping(values)
}

fn node_422() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("deadline-compiled-partial-probe"));
    values.insert(text("if"),text("always() && steps.deadline-compiled-partial.outputs.snapshot-ready == 'true' && steps.deadline-compiled-partial.outputs.input-key == steps.deadline-context.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_423());
    Value::Mapping(values)
}

fn node_423() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.deadline-compiled-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.deadline-compiled-partial.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_424() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("deadline-compiled-partial-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.deadline-compiled-partial.outputs.snapshot-ready == 'true' && steps.deadline-compiled-partial.outputs.input-key == steps.deadline-context.outputs.product-key && steps.deadline-compiled-partial.outputs.snapshot-key != '' && steps.deadline-compiled-partial-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_425());
    Value::Mapping(values)
}

fn node_425() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.deadline-compiled-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.deadline-compiled-partial.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_426() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("deadline-compiled-partial-cleanup"));
    values.insert(text("if"),text("always() && (steps.deadline-compiled-partial.outcome == 'success' || steps.deadline-compiled-partial.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R89));
    Value::Mapping(values)
}
