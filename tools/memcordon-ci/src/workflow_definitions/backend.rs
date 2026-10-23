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
    values.insert(text("name"), text("Native backend tests"));
    values.insert(text("on"), node_1());
    values.insert(text("permissions"), node_2());
    values.insert(text("concurrency"), node_3());
    values.insert(text("jobs"), node_4());
    Value::Mapping(values)
}

fn node_1() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("push"), Value::Null);
    values.insert(text("workflow_dispatch"), Value::Null);
    Value::Mapping(values)
}

fn node_2() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("contents"), text("read"));
    Value::Mapping(values)
}

fn node_3() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("group"),
        text("backend-certification-${{ github.event_name }}-${{ github.ref }}"),
    );
    values.insert(
        text("cancel-in-progress"),
        text("${{ github.event_name == 'push' && startsWith(github.ref, 'refs/heads/') }}"),
    );
    Value::Mapping(values)
}

fn node_4() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("macos-performance-plan"), node_5());
    values.insert(text("macos-combined"), node_14());
    values.insert(text("macos-native"), node_79());
    values.insert(text("macos-acceptance"), node_144());
    values.insert(text("macos-assessment"), node_209());
    values.insert(text("windows-payload-x64"), node_221());
    values.insert(text("windows-payload-arm64"), node_305());
    values.insert(text("windows-installed-x64"), node_389());
    values.insert(text("windows-installed-arm64"), node_440());
    values.insert(text("private-linux"), node_491());
    values.insert(text("standard-linux"), node_594());
    values.insert(text("standard-windows"), node_652());
    values.insert(text("standard-windows-arm64"), node_710());
    Value::Mapping(values)
}

fn node_5() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("github.event.deleted != true"));
    values.insert(text("runs-on"), text("ubuntu-24.04"));
    values.insert(text("timeout-minutes"), number("20"));
    values.insert(text("outputs"), node_6());
    values.insert(text("steps"), node_7());
    Value::Mapping(values)
}

fn node_6() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("split"), text("${{ steps.plan.outputs.macos-split }}"));
    values.insert(
        text("standalone-common"),
        text("${{ steps.scope.outputs.standalone-common }}"),
    );
    Value::Mapping(values)
}

fn node_7() -> Value {
    let mut values = Vec::new();
    values.push(node_8());
    values.push(node_10());
    values.push(node_11());
    values.push(node_12());
    values.push(node_13());
    Value::Sequence(values)
}

fn node_8() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_9());
    Value::Mapping(values)
}

fn node_9() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_10() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R0));
    Value::Mapping(values)
}

fn node_11() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R1));
    Value::Mapping(values)
}

fn node_12() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("scope"));
    values.insert(text("run"), literal(LiteralRun::R90));
    Value::Mapping(values)
}

fn node_13() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("plan"));
    values.insert(
        text("if"),
        text("steps.scope.outputs.standalone-common == 'true'"),
    );
    values.insert(text("run"), literal(LiteralRun::R91));
    Value::Mapping(values)
}

fn node_14() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("needs"), text("macos-performance-plan"));
    values.insert(text("if"),text("needs.macos-performance-plan.outputs.standalone-common == 'true' && needs.macos-performance-plan.outputs.split == 'false'"));
    values.insert(text("strategy"), node_15());
    values.insert(text("runs-on"), text("${{ matrix.runner }}"));
    values.insert(text("timeout-minutes"), number("181"));
    values.insert(text("steps"), node_20());
    Value::Mapping(values)
}

fn node_15() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("fail-fast"), Value::Bool(false));
    values.insert(text("matrix"), node_16());
    Value::Mapping(values)
}

fn node_16() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("include"), node_17());
    Value::Mapping(values)
}

fn node_17() -> Value {
    let mut values = Vec::new();
    values.push(node_18());
    values.push(node_19());
    Value::Sequence(values)
}

fn node_18() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("macos-x64"));
    values.insert(text("runner"), text("macos-15-intel"));
    Value::Mapping(values)
}

fn node_19() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("macos-arm64"));
    values.insert(text("runner"), text("macos-15"));
    Value::Mapping(values)
}

fn node_20() -> Value {
    let mut values = Vec::new();
    values.push(node_21());
    values.push(node_23());
    values.push(node_25());
    values.push(node_26());
    values.push(node_27());
    values.push(node_28());
    values.push(node_30());
    values.push(node_31());
    values.push(node_33());
    values.push(node_34());
    values.push(node_36());
    values.push(node_37());
    values.push(node_38());
    values.push(node_40());
    values.push(node_41());
    values.push(node_42());
    values.push(node_43());
    values.push(node_45());
    values.push(node_47());
    values.push(node_48());
    values.push(node_49());
    values.push(node_51());
    values.push(node_53());
    values.push(node_54());
    values.push(node_55());
    values.push(node_57());
    values.push(node_58());
    values.push(node_60());
    values.push(node_61());
    values.push(node_62());
    values.push(node_63());
    values.push(node_64());
    values.push(node_66());
    values.push(node_67());
    values.push(node_68());
    values.push(node_70());
    values.push(node_71());
    values.push(node_73());
    values.push(node_74());
    values.push(node_76());
    values.push(node_78());
    Value::Sequence(values)
}

fn node_21() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_22());
    Value::Mapping(values)
}

fn node_22() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_23() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("deps"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"), text("hashFiles('Cargo.lock') != ''"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_24());
    Value::Mapping(values)
}

fn node_24() -> Value {
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

fn node_25() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R0));
    Value::Mapping(values)
}

fn node_26() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R1));
    values.insert(text("id"), text("driver-build"));
    Value::Mapping(values)
}

fn node_27() -> Value {
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

fn node_28() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.driver-build.outcome == 'success' && steps.bootstrap-home.outcome == 'success' && steps.bootstrap-home.outputs.bootstrap-home-matches == 'true' && steps.deps.outputs.cache-primary-key != '' && steps.deps.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_29());
    Value::Mapping(values)
}

fn node_29() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("~/.cargo/registry/cache\n~/.cargo/git/db\n"),
    );
    values.insert(
        text("key"),
        text("${{ steps.deps.outputs.cache-primary-key }}"),
    );
    Value::Mapping(values)
}

fn node_30() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-context"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_31() -> Value {
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
    values.insert(text("with"), node_32());
    Value::Mapping(values)
}

fn node_32() -> Value {
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

fn node_33() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R4));
    Value::Mapping(values)
}

fn node_34() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore"));
    values.insert(text("if"),text("steps.archive-seed-context.outputs.seed-lookup-key != '' && steps.workspace-downloads.outputs.cache-hit != 'true'"));
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

fn node_36() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore-import"));
    values.insert(text("if"),text("steps.archive-seed-restore.outcome == 'success' && steps.archive-seed-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R5));
    Value::Mapping(values)
}

fn node_37() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R6));
    Value::Mapping(values)
}

fn node_38() -> Value {
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
    values.insert(text("with"), node_39());
    Value::Mapping(values)
}

fn node_39() -> Value {
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

fn node_40() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-restore-import"));
    values.insert(text("if"),text("steps.index-snapshot-restore.outcome == 'success' && steps.index-snapshot-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R7));
    Value::Mapping(values)
}

fn node_41() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(text("run"), literal(LiteralRun::R8));
    Value::Mapping(values)
}

fn node_42() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R9));
    Value::Mapping(values)
}

fn node_43() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-probe"));
    values.insert(text("if"),text("always() && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_44());
    Value::Mapping(values)
}

fn node_44() -> Value {
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

fn node_45() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility && steps.archive-seed-snapshot.outputs.snapshot-key != '' && steps.archive-seed-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_46());
    Value::Mapping(values)
}

fn node_46() -> Value {
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

fn node_47() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.archive-seed-snapshot.outcome == 'success' || steps.archive-seed-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R10));
    Value::Mapping(values)
}

fn node_48() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R11));
    Value::Mapping(values)
}

fn node_49() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-probe"));
    values.insert(text("if"),text("always() && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_50());
    Value::Mapping(values)
}

fn node_50() -> Value {
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

fn node_51() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility && steps.index-snapshot-snapshot.outputs.snapshot-key != '' && steps.index-snapshot-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_52());
    Value::Mapping(values)
}

fn node_52() -> Value {
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

fn node_53() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.index-snapshot-snapshot.outcome == 'success' || steps.index-snapshot-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R12));
    Value::Mapping(values)
}

fn node_54() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save-context"));
    values.insert(text("if"),text("always() && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-context.outputs.source-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_55() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save complete workspace downloads"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.workspace-download-context.outputs.source-key != '' && steps.workspace-download-context.outputs.source-paths != '' && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-save-context.outcome == 'success' && steps.workspace-download-save-context.outputs.source-key == steps.workspace-download-context.outputs.source-key && steps.workspace-download-save-context.outputs.source-key == steps.workspace-fetch.outputs.workspace-downloads-key && !(steps.workspace-downloads.outcome == 'success' && steps.workspace-downloads.outputs.cache-hit == 'true') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && steps.workspace-download-context.outputs.source-paths != ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_56());
    Value::Mapping(values)
}

fn node_56() -> Value {
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

fn node_57() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("context"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R233));
    Value::Mapping(values)
}

fn node_58() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("if"),
        text("steps.context.outputs.compiled-cache-usable == 'true'"),
    );
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
        text("${{ steps.context.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.context.outputs.product-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.context.outputs.product-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_60() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize compiled discard restore"));
    values.insert(text("id"), text("sanitize-macos-combined-recipe-discard"));
    values.insert(text("if"), text("steps.compiled.outcome == 'failure'"));
    values.insert(text("run"), literal(LiteralRun::R234));
    Value::Mapping(values)
}

fn node_61() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize compiled exact restore"));
    values.insert(text("id"), text("sanitize-macos-combined-recipe-exact"));
    values.insert(
        text("if"),
        text("steps.compiled.outcome == 'success' && steps.compiled.outputs.cache-hit == 'true'"),
    );
    values.insert(text("run"), literal(LiteralRun::R235));
    Value::Mapping(values)
}

fn node_62() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize compiled compatible restore"));
    values.insert(
        text("id"),
        text("sanitize-macos-combined-recipe-compatible"),
    );
    values.insert(text("if"),text("steps.compiled.outcome == 'success' && steps.compiled.outputs.cache-matched-key != '' && steps.compiled.outputs.cache-hit != 'true'"));
    values.insert(text("run"), literal(LiteralRun::R236));
    Value::Mapping(values)
}

fn node_63() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-context"));
    values.insert(text("if"),text("steps.context.outputs.product-key != '' && steps.compiled.outcome != 'failure' && steps.compiled.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R237));
    Value::Mapping(values)
}

fn node_64() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-restore"));
    values.insert(text("if"),text("steps.compiled-partial-context.outputs.seed-lookup-key != '' && steps.context.outputs.product-key != '' && steps.compiled.outcome != 'failure' && steps.compiled.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_65());
    Value::Mapping(values)
}

fn node_65() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.compiled-partial-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.compiled-partial-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.compiled-partial-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_66() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-import"));
    values.insert(text("if"),text("steps.compiled-partial-restore.outcome == 'success' && steps.compiled-partial-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R238));
    Value::Mapping(values)
}

fn node_67() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("native"));
    values.insert(text("run"), literal(LiteralRun::R239));
    Value::Mapping(values)
}

fn node_68() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("always()"));
    values.insert(text("uses"), text("./.github/actions/upload-artifact"));
    values.insert(text("with"), node_69());
    Value::Mapping(values)
}

fn node_69() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("macos-combined-${{ matrix.id }}"));
    values.insert(text("path"), text("target/ci/reports"));
    values.insert(text("if-no-files-found"), text("error"));
    values.insert(text("include-hidden-files"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_70() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-macos-combined-recipe-discard.outcome == 'skipped' || steps.sanitize-macos-combined-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-macos-combined-recipe-exact.outcome == 'skipped' || steps.sanitize-macos-combined-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-macos-combined-recipe-compatible.outcome == 'skipped' || steps.sanitize-macos-combined-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.native.outcome == 'skipped' || steps.native.outputs.cache-quiescent == 'true') && steps.context.outputs.compiled-cache-usable == 'true' && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.compiled-partial-import.outcome == 'skipped' || steps.compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R240));
    Value::Mapping(values)
}

fn node_71() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-macos-combined-recipe-discard.outcome == 'skipped' || steps.sanitize-macos-combined-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-macos-combined-recipe-exact.outcome == 'skipped' || steps.sanitize-macos-combined-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-macos-combined-recipe-compatible.outcome == 'skipped' || steps.sanitize-macos-combined-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.native.outcome == 'skipped' || steps.native.outputs.cache-quiescent == 'true') && steps.context.outputs.product-key != '' && steps.compiled-save-context.outcome == 'success' && steps.compiled-save-context.outputs.product-key == steps.context.outputs.product-key && steps.compiled-save-context.outputs.payload-ready == 'true' && (steps.native.outputs.compiled-recipe-complete == 'true') && !(steps.compiled.outcome == 'success' && steps.compiled.outputs.cache-hit == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.compiled-partial-import.outcome == 'skipped' || steps.compiled-partial-import.outputs.cache-quiescent == 'true') && steps.context.outputs.product-paths != '' && steps.context.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_72());
    Value::Mapping(values)
}

fn node_72() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.context.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.context.outputs.product-key }}"),
    );
    Value::Mapping(values)
}

fn node_73() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.context.outputs.product-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-macos-combined-recipe-discard.outcome == 'skipped' || steps.sanitize-macos-combined-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-macos-combined-recipe-exact.outcome == 'skipped' || steps.sanitize-macos-combined-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-macos-combined-recipe-compatible.outcome == 'skipped' || steps.sanitize-macos-combined-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.native.outcome == 'skipped' || steps.native.outputs.cache-quiescent == 'true') && !((steps.native.outputs.compiled-recipe-complete == 'true') && steps.compiled-save-context.outputs.payload-ready == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.compiled-partial-import.outcome == 'skipped' || steps.compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R241));
    Value::Mapping(values)
}

fn node_74() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-probe"));
    values.insert(text("if"),text("always() && steps.compiled-partial.outputs.snapshot-ready == 'true' && steps.compiled-partial.outputs.input-key == steps.context.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_75());
    Value::Mapping(values)
}

fn node_75() -> Value {
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

fn node_76() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.compiled-partial.outputs.snapshot-ready == 'true' && steps.compiled-partial.outputs.input-key == steps.context.outputs.product-key && steps.compiled-partial.outputs.snapshot-key != '' && steps.compiled-partial-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_77());
    Value::Mapping(values)
}

fn node_77() -> Value {
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

fn node_78() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-cleanup"));
    values.insert(text("if"),text("always() && (steps.compiled-partial.outcome == 'success' || steps.compiled-partial.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R242));
    Value::Mapping(values)
}

fn node_79() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("needs"), text("macos-performance-plan"));
    values.insert(text("if"),text("needs.macos-performance-plan.outputs.standalone-common == 'true' && needs.macos-performance-plan.outputs.split == 'true'"));
    values.insert(text("strategy"), node_80());
    values.insert(text("runs-on"), text("${{ matrix.runner }}"));
    values.insert(text("timeout-minutes"), number("181"));
    values.insert(text("steps"), node_85());
    Value::Mapping(values)
}

fn node_80() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("fail-fast"), Value::Bool(false));
    values.insert(text("matrix"), node_81());
    Value::Mapping(values)
}

fn node_81() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("include"), node_82());
    Value::Mapping(values)
}

fn node_82() -> Value {
    let mut values = Vec::new();
    values.push(node_83());
    values.push(node_84());
    Value::Sequence(values)
}

fn node_83() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("macos-x64"));
    values.insert(text("runner"), text("macos-15-intel"));
    Value::Mapping(values)
}

fn node_84() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("macos-arm64"));
    values.insert(text("runner"), text("macos-15"));
    Value::Mapping(values)
}

fn node_85() -> Value {
    let mut values = Vec::new();
    values.push(node_86());
    values.push(node_88());
    values.push(node_90());
    values.push(node_91());
    values.push(node_92());
    values.push(node_93());
    values.push(node_95());
    values.push(node_96());
    values.push(node_98());
    values.push(node_99());
    values.push(node_101());
    values.push(node_102());
    values.push(node_103());
    values.push(node_105());
    values.push(node_106());
    values.push(node_107());
    values.push(node_108());
    values.push(node_110());
    values.push(node_112());
    values.push(node_113());
    values.push(node_114());
    values.push(node_116());
    values.push(node_118());
    values.push(node_119());
    values.push(node_120());
    values.push(node_122());
    values.push(node_123());
    values.push(node_125());
    values.push(node_126());
    values.push(node_127());
    values.push(node_128());
    values.push(node_129());
    values.push(node_131());
    values.push(node_132());
    values.push(node_133());
    values.push(node_135());
    values.push(node_136());
    values.push(node_138());
    values.push(node_139());
    values.push(node_141());
    values.push(node_143());
    Value::Sequence(values)
}

fn node_86() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_87());
    Value::Mapping(values)
}

fn node_87() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_88() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("deps"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"), text("hashFiles('Cargo.lock') != ''"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_89());
    Value::Mapping(values)
}

fn node_89() -> Value {
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

fn node_90() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R0));
    Value::Mapping(values)
}

fn node_91() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R1));
    values.insert(text("id"), text("driver-build"));
    Value::Mapping(values)
}

fn node_92() -> Value {
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

fn node_93() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.driver-build.outcome == 'success' && steps.bootstrap-home.outcome == 'success' && steps.bootstrap-home.outputs.bootstrap-home-matches == 'true' && steps.deps.outputs.cache-primary-key != '' && steps.deps.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_94());
    Value::Mapping(values)
}

fn node_94() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("~/.cargo/registry/cache\n~/.cargo/git/db\n"),
    );
    values.insert(
        text("key"),
        text("${{ steps.deps.outputs.cache-primary-key }}"),
    );
    Value::Mapping(values)
}

fn node_95() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-context"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_96() -> Value {
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
    values.insert(text("with"), node_97());
    Value::Mapping(values)
}

fn node_97() -> Value {
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

fn node_98() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R4));
    Value::Mapping(values)
}

fn node_99() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore"));
    values.insert(text("if"),text("steps.archive-seed-context.outputs.seed-lookup-key != '' && steps.workspace-downloads.outputs.cache-hit != 'true'"));
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

fn node_101() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore-import"));
    values.insert(text("if"),text("steps.archive-seed-restore.outcome == 'success' && steps.archive-seed-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R5));
    Value::Mapping(values)
}

fn node_102() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R6));
    Value::Mapping(values)
}

fn node_103() -> Value {
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
    values.insert(text("with"), node_104());
    Value::Mapping(values)
}

fn node_104() -> Value {
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

fn node_105() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-restore-import"));
    values.insert(text("if"),text("steps.index-snapshot-restore.outcome == 'success' && steps.index-snapshot-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R7));
    Value::Mapping(values)
}

fn node_106() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(text("run"), literal(LiteralRun::R8));
    Value::Mapping(values)
}

fn node_107() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R9));
    Value::Mapping(values)
}

fn node_108() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-probe"));
    values.insert(text("if"),text("always() && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility"));
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
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_110() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility && steps.archive-seed-snapshot.outputs.snapshot-key != '' && steps.archive-seed-probe.outputs.cache-hit != 'true'"));
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
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_112() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.archive-seed-snapshot.outcome == 'success' || steps.archive-seed-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R10));
    Value::Mapping(values)
}

fn node_113() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R11));
    Value::Mapping(values)
}

fn node_114() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-probe"));
    values.insert(text("if"),text("always() && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_115());
    Value::Mapping(values)
}

fn node_115() -> Value {
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

fn node_116() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility && steps.index-snapshot-snapshot.outputs.snapshot-key != '' && steps.index-snapshot-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_117());
    Value::Mapping(values)
}

fn node_117() -> Value {
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

fn node_118() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.index-snapshot-snapshot.outcome == 'success' || steps.index-snapshot-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R12));
    Value::Mapping(values)
}

fn node_119() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save-context"));
    values.insert(text("if"),text("always() && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-context.outputs.source-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_120() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save complete workspace downloads"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.workspace-download-context.outputs.source-key != '' && steps.workspace-download-context.outputs.source-paths != '' && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-save-context.outcome == 'success' && steps.workspace-download-save-context.outputs.source-key == steps.workspace-download-context.outputs.source-key && steps.workspace-download-save-context.outputs.source-key == steps.workspace-fetch.outputs.workspace-downloads-key && !(steps.workspace-downloads.outcome == 'success' && steps.workspace-downloads.outputs.cache-hit == 'true') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && steps.workspace-download-context.outputs.source-paths != ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_121());
    Value::Mapping(values)
}

fn node_121() -> Value {
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

fn node_122() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("context"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R243));
    Value::Mapping(values)
}

fn node_123() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("if"),
        text("steps.context.outputs.compiled-cache-usable == 'true'"),
    );
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_124());
    Value::Mapping(values)
}

fn node_124() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.context.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.context.outputs.product-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.context.outputs.product-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_125() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize compiled discard restore"));
    values.insert(text("id"), text("sanitize-macos-native-recipe-discard"));
    values.insert(text("if"), text("steps.compiled.outcome == 'failure'"));
    values.insert(text("run"), literal(LiteralRun::R244));
    Value::Mapping(values)
}

fn node_126() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize compiled exact restore"));
    values.insert(text("id"), text("sanitize-macos-native-recipe-exact"));
    values.insert(
        text("if"),
        text("steps.compiled.outcome == 'success' && steps.compiled.outputs.cache-hit == 'true'"),
    );
    values.insert(text("run"), literal(LiteralRun::R245));
    Value::Mapping(values)
}

fn node_127() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize compiled compatible restore"));
    values.insert(text("id"), text("sanitize-macos-native-recipe-compatible"));
    values.insert(text("if"),text("steps.compiled.outcome == 'success' && steps.compiled.outputs.cache-matched-key != '' && steps.compiled.outputs.cache-hit != 'true'"));
    values.insert(text("run"), literal(LiteralRun::R246));
    Value::Mapping(values)
}

fn node_128() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-context"));
    values.insert(text("if"),text("steps.context.outputs.product-key != '' && steps.compiled.outcome != 'failure' && steps.compiled.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R247));
    Value::Mapping(values)
}

fn node_129() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-restore"));
    values.insert(text("if"),text("steps.compiled-partial-context.outputs.seed-lookup-key != '' && steps.context.outputs.product-key != '' && steps.compiled.outcome != 'failure' && steps.compiled.outputs.cache-matched-key == ''"));
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
        text("${{ steps.compiled-partial-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.compiled-partial-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.compiled-partial-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_131() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-import"));
    values.insert(text("if"),text("steps.compiled-partial-restore.outcome == 'success' && steps.compiled-partial-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R248));
    Value::Mapping(values)
}

fn node_132() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("native"));
    values.insert(text("run"), literal(LiteralRun::R249));
    Value::Mapping(values)
}

fn node_133() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("always()"));
    values.insert(text("uses"), text("./.github/actions/upload-artifact"));
    values.insert(text("with"), node_134());
    Value::Mapping(values)
}

fn node_134() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("macos-native-${{ matrix.id }}"));
    values.insert(text("path"), text("target/ci/reports"));
    values.insert(text("if-no-files-found"), text("error"));
    values.insert(text("include-hidden-files"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_135() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-macos-native-recipe-discard.outcome == 'skipped' || steps.sanitize-macos-native-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-macos-native-recipe-exact.outcome == 'skipped' || steps.sanitize-macos-native-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-macos-native-recipe-compatible.outcome == 'skipped' || steps.sanitize-macos-native-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.native.outcome == 'skipped' || steps.native.outputs.cache-quiescent == 'true') && steps.context.outputs.compiled-cache-usable == 'true' && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.compiled-partial-import.outcome == 'skipped' || steps.compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R250));
    Value::Mapping(values)
}

fn node_136() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-macos-native-recipe-discard.outcome == 'skipped' || steps.sanitize-macos-native-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-macos-native-recipe-exact.outcome == 'skipped' || steps.sanitize-macos-native-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-macos-native-recipe-compatible.outcome == 'skipped' || steps.sanitize-macos-native-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.native.outcome == 'skipped' || steps.native.outputs.cache-quiescent == 'true') && steps.context.outputs.product-key != '' && steps.compiled-save-context.outcome == 'success' && steps.compiled-save-context.outputs.product-key == steps.context.outputs.product-key && steps.compiled-save-context.outputs.payload-ready == 'true' && (steps.native.outputs.compiled-recipe-complete == 'true') && !(steps.compiled.outcome == 'success' && steps.compiled.outputs.cache-hit == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.compiled-partial-import.outcome == 'skipped' || steps.compiled-partial-import.outputs.cache-quiescent == 'true') && steps.context.outputs.product-paths != '' && steps.context.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_137());
    Value::Mapping(values)
}

fn node_137() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.context.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.context.outputs.product-key }}"),
    );
    Value::Mapping(values)
}

fn node_138() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.context.outputs.product-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-macos-native-recipe-discard.outcome == 'skipped' || steps.sanitize-macos-native-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-macos-native-recipe-exact.outcome == 'skipped' || steps.sanitize-macos-native-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-macos-native-recipe-compatible.outcome == 'skipped' || steps.sanitize-macos-native-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.native.outcome == 'skipped' || steps.native.outputs.cache-quiescent == 'true') && !((steps.native.outputs.compiled-recipe-complete == 'true') && steps.compiled-save-context.outputs.payload-ready == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.compiled-partial-import.outcome == 'skipped' || steps.compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R251));
    Value::Mapping(values)
}

fn node_139() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-probe"));
    values.insert(text("if"),text("always() && steps.compiled-partial.outputs.snapshot-ready == 'true' && steps.compiled-partial.outputs.input-key == steps.context.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_140());
    Value::Mapping(values)
}

fn node_140() -> Value {
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

fn node_141() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.compiled-partial.outputs.snapshot-ready == 'true' && steps.compiled-partial.outputs.input-key == steps.context.outputs.product-key && steps.compiled-partial.outputs.snapshot-key != '' && steps.compiled-partial-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_142());
    Value::Mapping(values)
}

fn node_142() -> Value {
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

fn node_143() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-cleanup"));
    values.insert(text("if"),text("always() && (steps.compiled-partial.outcome == 'success' || steps.compiled-partial.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R252));
    Value::Mapping(values)
}

fn node_144() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("needs"), text("macos-performance-plan"));
    values.insert(text("if"),text("needs.macos-performance-plan.outputs.standalone-common == 'true' && needs.macos-performance-plan.outputs.split == 'true'"));
    values.insert(text("strategy"), node_145());
    values.insert(text("runs-on"), text("${{ matrix.runner }}"));
    values.insert(text("timeout-minutes"), number("181"));
    values.insert(text("steps"), node_150());
    Value::Mapping(values)
}

fn node_145() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("fail-fast"), Value::Bool(false));
    values.insert(text("matrix"), node_146());
    Value::Mapping(values)
}

fn node_146() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("include"), node_147());
    Value::Mapping(values)
}

fn node_147() -> Value {
    let mut values = Vec::new();
    values.push(node_148());
    values.push(node_149());
    Value::Sequence(values)
}

fn node_148() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("macos-x64"));
    values.insert(text("runner"), text("macos-15-intel"));
    Value::Mapping(values)
}

fn node_149() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("macos-arm64"));
    values.insert(text("runner"), text("macos-15"));
    Value::Mapping(values)
}

fn node_150() -> Value {
    let mut values = Vec::new();
    values.push(node_151());
    values.push(node_153());
    values.push(node_155());
    values.push(node_156());
    values.push(node_157());
    values.push(node_158());
    values.push(node_160());
    values.push(node_161());
    values.push(node_163());
    values.push(node_164());
    values.push(node_166());
    values.push(node_167());
    values.push(node_168());
    values.push(node_170());
    values.push(node_171());
    values.push(node_172());
    values.push(node_173());
    values.push(node_175());
    values.push(node_177());
    values.push(node_178());
    values.push(node_179());
    values.push(node_181());
    values.push(node_183());
    values.push(node_184());
    values.push(node_185());
    values.push(node_187());
    values.push(node_188());
    values.push(node_190());
    values.push(node_191());
    values.push(node_192());
    values.push(node_193());
    values.push(node_194());
    values.push(node_196());
    values.push(node_197());
    values.push(node_198());
    values.push(node_200());
    values.push(node_201());
    values.push(node_203());
    values.push(node_204());
    values.push(node_206());
    values.push(node_208());
    Value::Sequence(values)
}

fn node_151() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_152());
    Value::Mapping(values)
}

fn node_152() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_153() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("deps"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"), text("hashFiles('Cargo.lock') != ''"));
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
        text("~/.cargo/registry/cache\n~/.cargo/git/db\n"),
    );
    values.insert(text("key"),text("mc-download-bootstrap-v5-${{ runner.os }}-${{ hashFiles('Cargo.lock', 'Cargo.toml', '.cargo/**', 'ci/toolchains.toml') }}"));
    values.insert(
        text("restore-keys"),
        text("mc-download-bootstrap-v5-${{ runner.os }}-"),
    );
    Value::Mapping(values)
}

fn node_155() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R0));
    Value::Mapping(values)
}

fn node_156() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R1));
    values.insert(text("id"), text("driver-build"));
    Value::Mapping(values)
}

fn node_157() -> Value {
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

fn node_158() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.driver-build.outcome == 'success' && steps.bootstrap-home.outcome == 'success' && steps.bootstrap-home.outputs.bootstrap-home-matches == 'true' && steps.deps.outputs.cache-primary-key != '' && steps.deps.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_159());
    Value::Mapping(values)
}

fn node_159() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("~/.cargo/registry/cache\n~/.cargo/git/db\n"),
    );
    values.insert(
        text("key"),
        text("${{ steps.deps.outputs.cache-primary-key }}"),
    );
    Value::Mapping(values)
}

fn node_160() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-context"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_161() -> Value {
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
    values.insert(text("with"), node_162());
    Value::Mapping(values)
}

fn node_162() -> Value {
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

fn node_163() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R4));
    Value::Mapping(values)
}

fn node_164() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore"));
    values.insert(text("if"),text("steps.archive-seed-context.outputs.seed-lookup-key != '' && steps.workspace-downloads.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_165());
    Value::Mapping(values)
}

fn node_165() -> Value {
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

fn node_166() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore-import"));
    values.insert(text("if"),text("steps.archive-seed-restore.outcome == 'success' && steps.archive-seed-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R5));
    Value::Mapping(values)
}

fn node_167() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R6));
    Value::Mapping(values)
}

fn node_168() -> Value {
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
    values.insert(text("with"), node_169());
    Value::Mapping(values)
}

fn node_169() -> Value {
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

fn node_170() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-restore-import"));
    values.insert(text("if"),text("steps.index-snapshot-restore.outcome == 'success' && steps.index-snapshot-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R7));
    Value::Mapping(values)
}

fn node_171() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(text("run"), literal(LiteralRun::R8));
    Value::Mapping(values)
}

fn node_172() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R9));
    Value::Mapping(values)
}

fn node_173() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-probe"));
    values.insert(text("if"),text("always() && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_174());
    Value::Mapping(values)
}

fn node_174() -> Value {
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

fn node_175() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility && steps.archive-seed-snapshot.outputs.snapshot-key != '' && steps.archive-seed-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_176());
    Value::Mapping(values)
}

fn node_176() -> Value {
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

fn node_177() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.archive-seed-snapshot.outcome == 'success' || steps.archive-seed-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R10));
    Value::Mapping(values)
}

fn node_178() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R11));
    Value::Mapping(values)
}

fn node_179() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-probe"));
    values.insert(text("if"),text("always() && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_180());
    Value::Mapping(values)
}

fn node_180() -> Value {
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

fn node_181() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility && steps.index-snapshot-snapshot.outputs.snapshot-key != '' && steps.index-snapshot-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_182());
    Value::Mapping(values)
}

fn node_182() -> Value {
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

fn node_183() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.index-snapshot-snapshot.outcome == 'success' || steps.index-snapshot-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R12));
    Value::Mapping(values)
}

fn node_184() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save-context"));
    values.insert(text("if"),text("always() && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-context.outputs.source-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_185() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save complete workspace downloads"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.workspace-download-context.outputs.source-key != '' && steps.workspace-download-context.outputs.source-paths != '' && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-save-context.outcome == 'success' && steps.workspace-download-save-context.outputs.source-key == steps.workspace-download-context.outputs.source-key && steps.workspace-download-save-context.outputs.source-key == steps.workspace-fetch.outputs.workspace-downloads-key && !(steps.workspace-downloads.outcome == 'success' && steps.workspace-downloads.outputs.cache-hit == 'true') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && steps.workspace-download-context.outputs.source-paths != ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
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
    Value::Mapping(values)
}

fn node_187() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("context"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R253));
    Value::Mapping(values)
}

fn node_188() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("if"),
        text("steps.context.outputs.compiled-cache-usable == 'true'"),
    );
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
        text("path"),
        text("${{ steps.context.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.context.outputs.product-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.context.outputs.product-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_190() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize compiled discard restore"));
    values.insert(text("id"), text("sanitize-macos-acceptance-recipe-discard"));
    values.insert(text("if"), text("steps.compiled.outcome == 'failure'"));
    values.insert(text("run"), literal(LiteralRun::R254));
    Value::Mapping(values)
}

fn node_191() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize compiled exact restore"));
    values.insert(text("id"), text("sanitize-macos-acceptance-recipe-exact"));
    values.insert(
        text("if"),
        text("steps.compiled.outcome == 'success' && steps.compiled.outputs.cache-hit == 'true'"),
    );
    values.insert(text("run"), literal(LiteralRun::R255));
    Value::Mapping(values)
}

fn node_192() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize compiled compatible restore"));
    values.insert(
        text("id"),
        text("sanitize-macos-acceptance-recipe-compatible"),
    );
    values.insert(text("if"),text("steps.compiled.outcome == 'success' && steps.compiled.outputs.cache-matched-key != '' && steps.compiled.outputs.cache-hit != 'true'"));
    values.insert(text("run"), literal(LiteralRun::R256));
    Value::Mapping(values)
}

fn node_193() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-context"));
    values.insert(text("if"),text("steps.context.outputs.product-key != '' && steps.compiled.outcome != 'failure' && steps.compiled.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R257));
    Value::Mapping(values)
}

fn node_194() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-restore"));
    values.insert(text("if"),text("steps.compiled-partial-context.outputs.seed-lookup-key != '' && steps.context.outputs.product-key != '' && steps.compiled.outcome != 'failure' && steps.compiled.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_195());
    Value::Mapping(values)
}

fn node_195() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.compiled-partial-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.compiled-partial-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.compiled-partial-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_196() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-import"));
    values.insert(text("if"),text("steps.compiled-partial-restore.outcome == 'success' && steps.compiled-partial-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R258));
    Value::Mapping(values)
}

fn node_197() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("native"));
    values.insert(text("run"), literal(LiteralRun::R259));
    Value::Mapping(values)
}

fn node_198() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("always()"));
    values.insert(text("uses"), text("./.github/actions/upload-artifact"));
    values.insert(text("with"), node_199());
    Value::Mapping(values)
}

fn node_199() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("macos-acceptance-${{ matrix.id }}"));
    values.insert(text("path"), text("target/ci/reports"));
    values.insert(text("if-no-files-found"), text("error"));
    values.insert(text("include-hidden-files"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_200() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-macos-acceptance-recipe-discard.outcome == 'skipped' || steps.sanitize-macos-acceptance-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-macos-acceptance-recipe-exact.outcome == 'skipped' || steps.sanitize-macos-acceptance-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-macos-acceptance-recipe-compatible.outcome == 'skipped' || steps.sanitize-macos-acceptance-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.native.outcome == 'skipped' || steps.native.outputs.cache-quiescent == 'true') && steps.context.outputs.compiled-cache-usable == 'true' && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.compiled-partial-import.outcome == 'skipped' || steps.compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R260));
    Value::Mapping(values)
}

fn node_201() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-macos-acceptance-recipe-discard.outcome == 'skipped' || steps.sanitize-macos-acceptance-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-macos-acceptance-recipe-exact.outcome == 'skipped' || steps.sanitize-macos-acceptance-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-macos-acceptance-recipe-compatible.outcome == 'skipped' || steps.sanitize-macos-acceptance-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.native.outcome == 'skipped' || steps.native.outputs.cache-quiescent == 'true') && steps.context.outputs.product-key != '' && steps.compiled-save-context.outcome == 'success' && steps.compiled-save-context.outputs.product-key == steps.context.outputs.product-key && steps.compiled-save-context.outputs.payload-ready == 'true' && (steps.native.outputs.compiled-recipe-complete == 'true') && !(steps.compiled.outcome == 'success' && steps.compiled.outputs.cache-hit == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.compiled-partial-import.outcome == 'skipped' || steps.compiled-partial-import.outputs.cache-quiescent == 'true') && steps.context.outputs.product-paths != '' && steps.context.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_202());
    Value::Mapping(values)
}

fn node_202() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.context.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.context.outputs.product-key }}"),
    );
    Value::Mapping(values)
}

fn node_203() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.context.outputs.product-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-macos-acceptance-recipe-discard.outcome == 'skipped' || steps.sanitize-macos-acceptance-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-macos-acceptance-recipe-exact.outcome == 'skipped' || steps.sanitize-macos-acceptance-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-macos-acceptance-recipe-compatible.outcome == 'skipped' || steps.sanitize-macos-acceptance-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.native.outcome == 'skipped' || steps.native.outputs.cache-quiescent == 'true') && !((steps.native.outputs.compiled-recipe-complete == 'true') && steps.compiled-save-context.outputs.payload-ready == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.compiled-partial-import.outcome == 'skipped' || steps.compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R261));
    Value::Mapping(values)
}

fn node_204() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-probe"));
    values.insert(text("if"),text("always() && steps.compiled-partial.outputs.snapshot-ready == 'true' && steps.compiled-partial.outputs.input-key == steps.context.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
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

fn node_206() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.compiled-partial.outputs.snapshot-ready == 'true' && steps.compiled-partial.outputs.input-key == steps.context.outputs.product-key && steps.compiled-partial.outputs.snapshot-key != '' && steps.compiled-partial-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_207());
    Value::Mapping(values)
}

fn node_207() -> Value {
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

fn node_208() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-cleanup"));
    values.insert(text("if"),text("always() && (steps.compiled-partial.outcome == 'success' || steps.compiled-partial.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R262));
    Value::Mapping(values)
}

fn node_209() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("!cancelled() && github.event.deleted != true && needs.macos-performance-plan.result == 'success' && needs.macos-performance-plan.outputs.standalone-common == 'true'"));
    values.insert(text("needs"), node_210());
    values.insert(text("runs-on"), text("ubuntu-24.04"));
    values.insert(text("timeout-minutes"), number("20"));
    values.insert(text("steps"), node_211());
    Value::Mapping(values)
}

fn node_210() -> Value {
    let mut values = Vec::new();
    values.push(text("macos-performance-plan"));
    values.push(text("macos-combined"));
    values.push(text("macos-native"));
    values.push(text("macos-acceptance"));
    Value::Sequence(values)
}

fn node_211() -> Value {
    let mut values = Vec::new();
    values.push(node_212());
    values.push(node_214());
    values.push(node_216());
    values.push(node_217());
    values.push(node_218());
    values.push(node_219());
    Value::Sequence(values)
}

fn node_212() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_213());
    Value::Mapping(values)
}

fn node_213() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_214() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"),
    );
    values.insert(text("with"), node_215());
    Value::Mapping(values)
}

fn node_215() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("pattern"), text("macos-*"));
    values.insert(text("path"), text("target/ci/macos-artifacts"));
    values.insert(text("digest-mismatch"), text("error"));
    Value::Mapping(values)
}

fn node_216() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R0));
    Value::Mapping(values)
}

fn node_217() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R1));
    Value::Mapping(values)
}

fn node_218() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R263));
    Value::Mapping(values)
}

fn node_219() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("always()"));
    values.insert(text("uses"), text("./.github/actions/upload-artifact"));
    values.insert(text("with"), node_220());
    Value::Mapping(values)
}

fn node_220() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("macos-assessment"));
    values.insert(
        text("path"),
        text("target/ci/reports/macos-assessment.json"),
    );
    values.insert(text("if-no-files-found"), text("error"));
    values.insert(text("include-hidden-files"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_221() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("github.event.deleted != true"));
    values.insert(text("runs-on"), text("windows-2025"));
    values.insert(text("timeout-minutes"), number("211"));
    values.insert(text("strategy"), node_222());
    values.insert(text("steps"), node_226());
    Value::Mapping(values)
}

fn node_222() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("fail-fast"), Value::Bool(false));
    values.insert(text("matrix"), node_223());
    Value::Mapping(values)
}

fn node_223() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("include"), node_224());
    Value::Mapping(values)
}

fn node_224() -> Value {
    let mut values = Vec::new();
    values.push(node_225());
    Value::Sequence(values)
}

fn node_225() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("x64"));
    Value::Mapping(values)
}

fn node_226() -> Value {
    let mut values = Vec::new();
    values.push(node_227());
    values.push(node_228());
    values.push(node_230());
    values.push(node_232());
    values.push(node_233());
    values.push(node_234());
    values.push(node_235());
    values.push(node_237());
    values.push(node_238());
    values.push(node_240());
    values.push(node_241());
    values.push(node_243());
    values.push(node_244());
    values.push(node_245());
    values.push(node_247());
    values.push(node_248());
    values.push(node_249());
    values.push(node_250());
    values.push(node_252());
    values.push(node_254());
    values.push(node_255());
    values.push(node_256());
    values.push(node_258());
    values.push(node_260());
    values.push(node_261());
    values.push(node_262());
    values.push(node_264());
    values.push(node_265());
    values.push(node_267());
    values.push(node_268());
    values.push(node_269());
    values.push(node_270());
    values.push(node_271());
    values.push(node_273());
    values.push(node_274());
    values.push(node_275());
    values.push(node_276());
    values.push(node_277());
    values.push(node_279());
    values.push(node_280());
    values.push(node_281());
    values.push(node_283());
    values.push(node_284());
    values.push(node_285());
    values.push(node_287());
    values.push(node_288());
    values.push(node_290());
    values.push(node_291());
    values.push(node_293());
    values.push(node_294());
    values.push(node_296());
    values.push(node_298());
    values.push(node_299());
    values.push(node_300());
    values.push(node_302());
    values.push(node_304());
    Value::Sequence(values)
}

fn node_227() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Configure checkout line endings"));
    values.insert(text("run"), literal(LiteralRun::R264));
    Value::Mapping(values)
}

fn node_228() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_229());
    Value::Mapping(values)
}

fn node_229() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_230() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("sources"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"), text("hashFiles('Cargo.lock') != ''"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_231());
    Value::Mapping(values)
}

fn node_231() -> Value {
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

fn node_232() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R0));
    Value::Mapping(values)
}

fn node_233() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R1));
    values.insert(text("id"), text("driver-build"));
    Value::Mapping(values)
}

fn node_234() -> Value {
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

fn node_235() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.driver-build.outcome == 'success' && steps.bootstrap-home.outcome == 'success' && steps.bootstrap-home.outputs.bootstrap-home-matches == 'true' && steps.sources.outputs.cache-primary-key != '' && steps.sources.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_236());
    Value::Mapping(values)
}

fn node_236() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("~/.cargo/registry/cache\n~/.cargo/git/db\n"),
    );
    values.insert(
        text("key"),
        text("${{ steps.sources.outputs.cache-primary-key }}"),
    );
    Value::Mapping(values)
}

fn node_237() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-context"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_238() -> Value {
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
    values.insert(text("with"), node_239());
    Value::Mapping(values)
}

fn node_239() -> Value {
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

fn node_240() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R4));
    Value::Mapping(values)
}

fn node_241() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore"));
    values.insert(text("if"),text("steps.archive-seed-context.outputs.seed-lookup-key != '' && steps.workspace-downloads.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_242());
    Value::Mapping(values)
}

fn node_242() -> Value {
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

fn node_243() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore-import"));
    values.insert(text("if"),text("steps.archive-seed-restore.outcome == 'success' && steps.archive-seed-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R5));
    Value::Mapping(values)
}

fn node_244() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R6));
    Value::Mapping(values)
}

fn node_245() -> Value {
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
    values.insert(text("with"), node_246());
    Value::Mapping(values)
}

fn node_246() -> Value {
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

fn node_247() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-restore-import"));
    values.insert(text("if"),text("steps.index-snapshot-restore.outcome == 'success' && steps.index-snapshot-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R7));
    Value::Mapping(values)
}

fn node_248() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(text("run"), literal(LiteralRun::R8));
    Value::Mapping(values)
}

fn node_249() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R9));
    Value::Mapping(values)
}

fn node_250() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-probe"));
    values.insert(text("if"),text("always() && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_251());
    Value::Mapping(values)
}

fn node_251() -> Value {
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

fn node_252() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility && steps.archive-seed-snapshot.outputs.snapshot-key != '' && steps.archive-seed-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_253());
    Value::Mapping(values)
}

fn node_253() -> Value {
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

fn node_254() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.archive-seed-snapshot.outcome == 'success' || steps.archive-seed-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R10));
    Value::Mapping(values)
}

fn node_255() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R11));
    Value::Mapping(values)
}

fn node_256() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-probe"));
    values.insert(text("if"),text("always() && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_257());
    Value::Mapping(values)
}

fn node_257() -> Value {
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

fn node_258() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility && steps.index-snapshot-snapshot.outputs.snapshot-key != '' && steps.index-snapshot-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_259());
    Value::Mapping(values)
}

fn node_259() -> Value {
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

fn node_260() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.index-snapshot-snapshot.outcome == 'success' || steps.index-snapshot-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R12));
    Value::Mapping(values)
}

fn node_261() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save-context"));
    values.insert(text("if"),text("always() && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-context.outputs.source-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_262() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save complete workspace downloads"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.workspace-download-context.outputs.source-key != '' && steps.workspace-download-context.outputs.source-paths != '' && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-save-context.outcome == 'success' && steps.workspace-download-save-context.outputs.source-key == steps.workspace-download-context.outputs.source-key && steps.workspace-download-save-context.outputs.source-key == steps.workspace-fetch.outputs.workspace-downloads-key && !(steps.workspace-downloads.outcome == 'success' && steps.workspace-downloads.outputs.cache-hit == 'true') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && steps.workspace-download-context.outputs.source-paths != ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_263());
    Value::Mapping(values)
}

fn node_263() -> Value {
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

fn node_264() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("context"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R265));
    Value::Mapping(values)
}

fn node_265() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("if"),
        text("steps.context.outputs.compiled-cache-usable == 'true'"),
    );
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_266());
    Value::Mapping(values)
}

fn node_266() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.context.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.context.outputs.product-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.context.outputs.product-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_267() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize products discard restore"));
    values.insert(
        text("id"),
        text("sanitize-windows-working-complete-native-tests-discard"),
    );
    values.insert(text("if"), text("steps.products.outcome == 'failure'"));
    values.insert(text("run"), literal(LiteralRun::R266));
    Value::Mapping(values)
}

fn node_268() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize products exact restore"));
    values.insert(
        text("id"),
        text("sanitize-windows-working-complete-native-tests-exact"),
    );
    values.insert(
        text("if"),
        text("steps.products.outcome == 'success' && steps.products.outputs.cache-hit == 'true'"),
    );
    values.insert(text("run"), literal(LiteralRun::R267));
    Value::Mapping(values)
}

fn node_269() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize products compatible restore"));
    values.insert(
        text("id"),
        text("sanitize-windows-working-complete-native-tests-compatible"),
    );
    values.insert(text("if"),text("steps.products.outcome == 'success' && steps.products.outputs.cache-matched-key != '' && steps.products.outputs.cache-hit != 'true'"));
    values.insert(text("run"), literal(LiteralRun::R268));
    Value::Mapping(values)
}

fn node_270() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("context-product"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R269));
    Value::Mapping(values)
}

fn node_271() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-product"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("if"),
        text("steps.context-product.outputs.compiled-cache-usable == 'true'"),
    );
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_272());
    Value::Mapping(values)
}

fn node_272() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.context-product.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.context-product.outputs.product-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.context-product.outputs.product-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_273() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize products discard restore"));
    values.insert(
        text("id"),
        text("sanitize-windows-working-complete-product-discard"),
    );
    values.insert(
        text("if"),
        text("steps.products-product.outcome == 'failure'"),
    );
    values.insert(text("run"), literal(LiteralRun::R270));
    Value::Mapping(values)
}

fn node_274() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize products exact restore"));
    values.insert(
        text("id"),
        text("sanitize-windows-working-complete-product-exact"),
    );
    values.insert(text("if"),text("steps.products-product.outcome == 'success' && steps.products-product.outputs.cache-hit == 'true'"));
    values.insert(text("run"), literal(LiteralRun::R271));
    Value::Mapping(values)
}

fn node_275() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize products compatible restore"));
    values.insert(
        text("id"),
        text("sanitize-windows-working-complete-product-compatible"),
    );
    values.insert(text("if"),text("steps.products-product.outcome == 'success' && steps.products-product.outputs.cache-matched-key != '' && steps.products-product.outputs.cache-hit != 'true'"));
    values.insert(text("run"), literal(LiteralRun::R272));
    Value::Mapping(values)
}

fn node_276() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-partial-context"));
    values.insert(text("if"),text("steps.context.outputs.product-key != '' && steps.products.outcome != 'failure' && steps.products.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R273));
    Value::Mapping(values)
}

fn node_277() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-partial-restore"));
    values.insert(text("if"),text("steps.products-partial-context.outputs.seed-lookup-key != '' && steps.context.outputs.product-key != '' && steps.products.outcome != 'failure' && steps.products.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_278());
    Value::Mapping(values)
}

fn node_278() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.products-partial-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.products-partial-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.products-partial-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_279() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-partial-import"));
    values.insert(text("if"),text("steps.products-partial-restore.outcome == 'success' && steps.products-partial-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R274));
    Value::Mapping(values)
}

fn node_280() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-product-partial-context"));
    values.insert(text("if"),text("steps.context-product.outputs.product-key != '' && steps.products-product.outcome != 'failure' && steps.products-product.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R275));
    Value::Mapping(values)
}

fn node_281() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-product-partial-restore"));
    values.insert(text("if"),text("steps.products-product-partial-context.outputs.seed-lookup-key != '' && steps.context-product.outputs.product-key != '' && steps.products-product.outcome != 'failure' && steps.products-product.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_282());
    Value::Mapping(values)
}

fn node_282() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.products-product-partial-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.products-product-partial-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.products-product-partial-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_283() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-product-partial-import"));
    values.insert(text("if"),text("steps.products-product-partial-restore.outcome == 'success' && steps.products-product-partial-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R276));
    Value::Mapping(values)
}

fn node_284() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("build"));
    values.insert(text("run"), literal(LiteralRun::R277));
    Value::Mapping(values)
}

fn node_285() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("uses"), text("./.github/actions/upload-artifact"));
    values.insert(text("with"), node_286());
    Value::Mapping(values)
}

fn node_286() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("windows-prepared-${{ matrix.id }}"));
    values.insert(text("path"), text("target/ci/windows-prepared"));
    values.insert(text("if-no-files-found"), text("error"));
    Value::Mapping(values)
}

fn node_287() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-discard.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-exact.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-compatible.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-compatible.outputs.cache-quiescent == 'true') && (steps.build.outcome == 'skipped' || steps.build.outputs.cache-quiescent == 'true') && steps.context.outputs.compiled-cache-usable == 'true' && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.products-partial-import.outcome == 'skipped' || steps.products-partial-import.outputs.cache-quiescent == 'true') && (steps.products-product-partial-import.outcome == 'skipped' || steps.products-product-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R278));
    Value::Mapping(values)
}

fn node_288() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-discard.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-exact.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-compatible.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-compatible.outputs.cache-quiescent == 'true') && (steps.build.outcome == 'skipped' || steps.build.outputs.cache-quiescent == 'true') && steps.context.outputs.product-key != '' && steps.products-save-context.outcome == 'success' && steps.products-save-context.outputs.product-key == steps.context.outputs.product-key && steps.products-save-context.outputs.payload-ready == 'true' && ((steps.build.outputs.compiled-native-complete == 'true') && (steps.build.outcome == 'skipped' || steps.build.outputs.compiled-native-complete == 'true')) && !(steps.products.outcome == 'success' && steps.products.outputs.cache-hit == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.products-partial-import.outcome == 'skipped' || steps.products-partial-import.outputs.cache-quiescent == 'true') && (steps.products-product-partial-import.outcome == 'skipped' || steps.products-product-partial-import.outputs.cache-quiescent == 'true') && steps.context.outputs.product-paths != '' && steps.context.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_289());
    Value::Mapping(values)
}

fn node_289() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.context.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.context.outputs.product-key }}"),
    );
    Value::Mapping(values)
}

fn node_290() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-save-context-product"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-discard.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-exact.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-compatible.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-compatible.outputs.cache-quiescent == 'true') && (steps.build.outcome == 'skipped' || steps.build.outputs.cache-quiescent == 'true') && steps.context-product.outputs.compiled-cache-usable == 'true' && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.products-partial-import.outcome == 'skipped' || steps.products-partial-import.outputs.cache-quiescent == 'true') && (steps.products-product-partial-import.outcome == 'skipped' || steps.products-product-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R279));
    Value::Mapping(values)
}

fn node_291() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-discard.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-exact.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-compatible.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-compatible.outputs.cache-quiescent == 'true') && (steps.build.outcome == 'skipped' || steps.build.outputs.cache-quiescent == 'true') && steps.context-product.outputs.product-key != '' && steps.products-save-context-product.outcome == 'success' && steps.products-save-context-product.outputs.product-key == steps.context-product.outputs.product-key && steps.products-save-context-product.outputs.payload-ready == 'true' && (steps.build.outputs.compiled-product-complete == 'true') && !(steps.products-product.outcome == 'success' && steps.products-product.outputs.cache-hit == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.products-partial-import.outcome == 'skipped' || steps.products-partial-import.outputs.cache-quiescent == 'true') && (steps.products-product-partial-import.outcome == 'skipped' || steps.products-product-partial-import.outputs.cache-quiescent == 'true') && steps.context-product.outputs.product-paths != '' && steps.context-product.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_292());
    Value::Mapping(values)
}

fn node_292() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.context-product.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.context-product.outputs.product-key }}"),
    );
    Value::Mapping(values)
}

fn node_293() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-partial"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.context.outputs.product-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-discard.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-exact.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-compatible.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-compatible.outputs.cache-quiescent == 'true') && (steps.build.outcome == 'skipped' || steps.build.outputs.cache-quiescent == 'true') && !(((steps.build.outputs.compiled-native-complete == 'true') && (steps.build.outcome == 'skipped' || steps.build.outputs.compiled-native-complete == 'true')) && steps.products-save-context.outputs.payload-ready == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.products-partial-import.outcome == 'skipped' || steps.products-partial-import.outputs.cache-quiescent == 'true') && (steps.products-product-partial-import.outcome == 'skipped' || steps.products-product-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R280));
    Value::Mapping(values)
}

fn node_294() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-partial-probe"));
    values.insert(text("if"),text("always() && steps.products-partial.outputs.snapshot-ready == 'true' && steps.products-partial.outputs.input-key == steps.context.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_295());
    Value::Mapping(values)
}

fn node_295() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.products-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.products-partial.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_296() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-partial-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.products-partial.outputs.snapshot-ready == 'true' && steps.products-partial.outputs.input-key == steps.context.outputs.product-key && steps.products-partial.outputs.snapshot-key != '' && steps.products-partial-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_297());
    Value::Mapping(values)
}

fn node_297() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.products-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.products-partial.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_298() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-partial-cleanup"));
    values.insert(text("if"),text("always() && (steps.products-partial.outcome == 'success' || steps.products-partial.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R281));
    Value::Mapping(values)
}

fn node_299() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-product-partial"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.context-product.outputs.product-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-discard.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-exact.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-compatible.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-compatible.outputs.cache-quiescent == 'true') && (steps.products-partial-import.outcome == 'skipped' || steps.products-partial-import.outputs.cache-quiescent == 'true') && (steps.build.outcome == 'skipped' || steps.build.outputs.cache-quiescent == 'true') && !((steps.build.outputs.compiled-product-complete == 'true') && steps.products-save-context-product.outputs.payload-ready == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.products-product-partial-import.outcome == 'skipped' || steps.products-product-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R282));
    Value::Mapping(values)
}

fn node_300() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-product-partial-probe"));
    values.insert(text("if"),text("always() && steps.products-product-partial.outputs.snapshot-ready == 'true' && steps.products-product-partial.outputs.input-key == steps.context-product.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_301());
    Value::Mapping(values)
}

fn node_301() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.products-product-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.products-product-partial.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_302() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-product-partial-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.products-product-partial.outputs.snapshot-ready == 'true' && steps.products-product-partial.outputs.input-key == steps.context-product.outputs.product-key && steps.products-product-partial.outputs.snapshot-key != '' && steps.products-product-partial-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_303());
    Value::Mapping(values)
}

fn node_303() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.products-product-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.products-product-partial.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_304() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-product-partial-cleanup"));
    values.insert(text("if"),text("always() && (steps.products-product-partial.outcome == 'success' || steps.products-product-partial.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R283));
    Value::Mapping(values)
}

fn node_305() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("github.event.deleted != true"));
    values.insert(text("runs-on"), text("windows-11-arm"));
    values.insert(text("timeout-minutes"), number("211"));
    values.insert(text("strategy"), node_306());
    values.insert(text("steps"), node_310());
    Value::Mapping(values)
}

fn node_306() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("fail-fast"), Value::Bool(false));
    values.insert(text("matrix"), node_307());
    Value::Mapping(values)
}

fn node_307() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("include"), node_308());
    Value::Mapping(values)
}

fn node_308() -> Value {
    let mut values = Vec::new();
    values.push(node_309());
    Value::Sequence(values)
}

fn node_309() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("arm64"));
    Value::Mapping(values)
}

fn node_310() -> Value {
    let mut values = Vec::new();
    values.push(node_311());
    values.push(node_312());
    values.push(node_314());
    values.push(node_316());
    values.push(node_317());
    values.push(node_318());
    values.push(node_319());
    values.push(node_321());
    values.push(node_322());
    values.push(node_324());
    values.push(node_325());
    values.push(node_327());
    values.push(node_328());
    values.push(node_329());
    values.push(node_331());
    values.push(node_332());
    values.push(node_333());
    values.push(node_334());
    values.push(node_336());
    values.push(node_338());
    values.push(node_339());
    values.push(node_340());
    values.push(node_342());
    values.push(node_344());
    values.push(node_345());
    values.push(node_346());
    values.push(node_348());
    values.push(node_349());
    values.push(node_351());
    values.push(node_352());
    values.push(node_353());
    values.push(node_354());
    values.push(node_355());
    values.push(node_357());
    values.push(node_358());
    values.push(node_359());
    values.push(node_360());
    values.push(node_361());
    values.push(node_363());
    values.push(node_364());
    values.push(node_365());
    values.push(node_367());
    values.push(node_368());
    values.push(node_369());
    values.push(node_371());
    values.push(node_372());
    values.push(node_374());
    values.push(node_375());
    values.push(node_377());
    values.push(node_378());
    values.push(node_380());
    values.push(node_382());
    values.push(node_383());
    values.push(node_384());
    values.push(node_386());
    values.push(node_388());
    Value::Sequence(values)
}

fn node_311() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Configure checkout line endings"));
    values.insert(text("run"), literal(LiteralRun::R264));
    Value::Mapping(values)
}

fn node_312() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_313());
    Value::Mapping(values)
}

fn node_313() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_314() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("sources"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"), text("hashFiles('Cargo.lock') != ''"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_315());
    Value::Mapping(values)
}

fn node_315() -> Value {
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

fn node_316() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R0));
    Value::Mapping(values)
}

fn node_317() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R1));
    values.insert(text("id"), text("driver-build"));
    Value::Mapping(values)
}

fn node_318() -> Value {
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

fn node_319() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.driver-build.outcome == 'success' && steps.bootstrap-home.outcome == 'success' && steps.bootstrap-home.outputs.bootstrap-home-matches == 'true' && steps.sources.outputs.cache-primary-key != '' && steps.sources.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_320());
    Value::Mapping(values)
}

fn node_320() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("~/.cargo/registry/cache\n~/.cargo/git/db\n"),
    );
    values.insert(
        text("key"),
        text("${{ steps.sources.outputs.cache-primary-key }}"),
    );
    Value::Mapping(values)
}

fn node_321() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-context"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_322() -> Value {
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
    values.insert(text("with"), node_323());
    Value::Mapping(values)
}

fn node_323() -> Value {
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

fn node_324() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R4));
    Value::Mapping(values)
}

fn node_325() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore"));
    values.insert(text("if"),text("steps.archive-seed-context.outputs.seed-lookup-key != '' && steps.workspace-downloads.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
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

fn node_327() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore-import"));
    values.insert(text("if"),text("steps.archive-seed-restore.outcome == 'success' && steps.archive-seed-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R5));
    Value::Mapping(values)
}

fn node_328() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R6));
    Value::Mapping(values)
}

fn node_329() -> Value {
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
    values.insert(text("with"), node_330());
    Value::Mapping(values)
}

fn node_330() -> Value {
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

fn node_331() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-restore-import"));
    values.insert(text("if"),text("steps.index-snapshot-restore.outcome == 'success' && steps.index-snapshot-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R7));
    Value::Mapping(values)
}

fn node_332() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(text("run"), literal(LiteralRun::R8));
    Value::Mapping(values)
}

fn node_333() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R9));
    Value::Mapping(values)
}

fn node_334() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-probe"));
    values.insert(text("if"),text("always() && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_335());
    Value::Mapping(values)
}

fn node_335() -> Value {
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

fn node_336() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility && steps.archive-seed-snapshot.outputs.snapshot-key != '' && steps.archive-seed-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
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
        text("key"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_338() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.archive-seed-snapshot.outcome == 'success' || steps.archive-seed-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R10));
    Value::Mapping(values)
}

fn node_339() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R11));
    Value::Mapping(values)
}

fn node_340() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-probe"));
    values.insert(text("if"),text("always() && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_341());
    Value::Mapping(values)
}

fn node_341() -> Value {
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

fn node_342() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility && steps.index-snapshot-snapshot.outputs.snapshot-key != '' && steps.index-snapshot-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_343());
    Value::Mapping(values)
}

fn node_343() -> Value {
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

fn node_344() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.index-snapshot-snapshot.outcome == 'success' || steps.index-snapshot-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R12));
    Value::Mapping(values)
}

fn node_345() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save-context"));
    values.insert(text("if"),text("always() && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-context.outputs.source-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_346() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save complete workspace downloads"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.workspace-download-context.outputs.source-key != '' && steps.workspace-download-context.outputs.source-paths != '' && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-save-context.outcome == 'success' && steps.workspace-download-save-context.outputs.source-key == steps.workspace-download-context.outputs.source-key && steps.workspace-download-save-context.outputs.source-key == steps.workspace-fetch.outputs.workspace-downloads-key && !(steps.workspace-downloads.outcome == 'success' && steps.workspace-downloads.outputs.cache-hit == 'true') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && steps.workspace-download-context.outputs.source-paths != ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_347());
    Value::Mapping(values)
}

fn node_347() -> Value {
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

fn node_348() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("context"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R265));
    Value::Mapping(values)
}

fn node_349() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("if"),
        text("steps.context.outputs.compiled-cache-usable == 'true'"),
    );
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_350());
    Value::Mapping(values)
}

fn node_350() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.context.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.context.outputs.product-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.context.outputs.product-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_351() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize products discard restore"));
    values.insert(
        text("id"),
        text("sanitize-windows-working-complete-native-tests-discard"),
    );
    values.insert(text("if"), text("steps.products.outcome == 'failure'"));
    values.insert(text("run"), literal(LiteralRun::R266));
    Value::Mapping(values)
}

fn node_352() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize products exact restore"));
    values.insert(
        text("id"),
        text("sanitize-windows-working-complete-native-tests-exact"),
    );
    values.insert(
        text("if"),
        text("steps.products.outcome == 'success' && steps.products.outputs.cache-hit == 'true'"),
    );
    values.insert(text("run"), literal(LiteralRun::R267));
    Value::Mapping(values)
}

fn node_353() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize products compatible restore"));
    values.insert(
        text("id"),
        text("sanitize-windows-working-complete-native-tests-compatible"),
    );
    values.insert(text("if"),text("steps.products.outcome == 'success' && steps.products.outputs.cache-matched-key != '' && steps.products.outputs.cache-hit != 'true'"));
    values.insert(text("run"), literal(LiteralRun::R268));
    Value::Mapping(values)
}

fn node_354() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("context-product"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R269));
    Value::Mapping(values)
}

fn node_355() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-product"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("if"),
        text("steps.context-product.outputs.compiled-cache-usable == 'true'"),
    );
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_356());
    Value::Mapping(values)
}

fn node_356() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.context-product.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.context-product.outputs.product-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.context-product.outputs.product-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_357() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize products discard restore"));
    values.insert(
        text("id"),
        text("sanitize-windows-working-complete-product-discard"),
    );
    values.insert(
        text("if"),
        text("steps.products-product.outcome == 'failure'"),
    );
    values.insert(text("run"), literal(LiteralRun::R270));
    Value::Mapping(values)
}

fn node_358() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize products exact restore"));
    values.insert(
        text("id"),
        text("sanitize-windows-working-complete-product-exact"),
    );
    values.insert(text("if"),text("steps.products-product.outcome == 'success' && steps.products-product.outputs.cache-hit == 'true'"));
    values.insert(text("run"), literal(LiteralRun::R271));
    Value::Mapping(values)
}

fn node_359() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize products compatible restore"));
    values.insert(
        text("id"),
        text("sanitize-windows-working-complete-product-compatible"),
    );
    values.insert(text("if"),text("steps.products-product.outcome == 'success' && steps.products-product.outputs.cache-matched-key != '' && steps.products-product.outputs.cache-hit != 'true'"));
    values.insert(text("run"), literal(LiteralRun::R272));
    Value::Mapping(values)
}

fn node_360() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-partial-context"));
    values.insert(text("if"),text("steps.context.outputs.product-key != '' && steps.products.outcome != 'failure' && steps.products.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R273));
    Value::Mapping(values)
}

fn node_361() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-partial-restore"));
    values.insert(text("if"),text("steps.products-partial-context.outputs.seed-lookup-key != '' && steps.context.outputs.product-key != '' && steps.products.outcome != 'failure' && steps.products.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_362());
    Value::Mapping(values)
}

fn node_362() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.products-partial-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.products-partial-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.products-partial-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_363() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-partial-import"));
    values.insert(text("if"),text("steps.products-partial-restore.outcome == 'success' && steps.products-partial-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R274));
    Value::Mapping(values)
}

fn node_364() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-product-partial-context"));
    values.insert(text("if"),text("steps.context-product.outputs.product-key != '' && steps.products-product.outcome != 'failure' && steps.products-product.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R275));
    Value::Mapping(values)
}

fn node_365() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-product-partial-restore"));
    values.insert(text("if"),text("steps.products-product-partial-context.outputs.seed-lookup-key != '' && steps.context-product.outputs.product-key != '' && steps.products-product.outcome != 'failure' && steps.products-product.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_366());
    Value::Mapping(values)
}

fn node_366() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.products-product-partial-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.products-product-partial-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.products-product-partial-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_367() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-product-partial-import"));
    values.insert(text("if"),text("steps.products-product-partial-restore.outcome == 'success' && steps.products-product-partial-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R276));
    Value::Mapping(values)
}

fn node_368() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("build"));
    values.insert(text("run"), literal(LiteralRun::R277));
    Value::Mapping(values)
}

fn node_369() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("uses"), text("./.github/actions/upload-artifact"));
    values.insert(text("with"), node_370());
    Value::Mapping(values)
}

fn node_370() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("windows-prepared-${{ matrix.id }}"));
    values.insert(text("path"), text("target/ci/windows-prepared"));
    values.insert(text("if-no-files-found"), text("error"));
    Value::Mapping(values)
}

fn node_371() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-discard.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-exact.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-compatible.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-compatible.outputs.cache-quiescent == 'true') && (steps.build.outcome == 'skipped' || steps.build.outputs.cache-quiescent == 'true') && steps.context.outputs.compiled-cache-usable == 'true' && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.products-partial-import.outcome == 'skipped' || steps.products-partial-import.outputs.cache-quiescent == 'true') && (steps.products-product-partial-import.outcome == 'skipped' || steps.products-product-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R278));
    Value::Mapping(values)
}

fn node_372() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-discard.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-exact.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-compatible.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-compatible.outputs.cache-quiescent == 'true') && (steps.build.outcome == 'skipped' || steps.build.outputs.cache-quiescent == 'true') && steps.context.outputs.product-key != '' && steps.products-save-context.outcome == 'success' && steps.products-save-context.outputs.product-key == steps.context.outputs.product-key && steps.products-save-context.outputs.payload-ready == 'true' && ((steps.build.outputs.compiled-native-complete == 'true') && (steps.build.outcome == 'skipped' || steps.build.outputs.compiled-native-complete == 'true')) && !(steps.products.outcome == 'success' && steps.products.outputs.cache-hit == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.products-partial-import.outcome == 'skipped' || steps.products-partial-import.outputs.cache-quiescent == 'true') && (steps.products-product-partial-import.outcome == 'skipped' || steps.products-product-partial-import.outputs.cache-quiescent == 'true') && steps.context.outputs.product-paths != '' && steps.context.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_373());
    Value::Mapping(values)
}

fn node_373() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.context.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.context.outputs.product-key }}"),
    );
    Value::Mapping(values)
}

fn node_374() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-save-context-product"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-discard.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-exact.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-compatible.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-compatible.outputs.cache-quiescent == 'true') && (steps.build.outcome == 'skipped' || steps.build.outputs.cache-quiescent == 'true') && steps.context-product.outputs.compiled-cache-usable == 'true' && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.products-partial-import.outcome == 'skipped' || steps.products-partial-import.outputs.cache-quiescent == 'true') && (steps.products-product-partial-import.outcome == 'skipped' || steps.products-product-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R279));
    Value::Mapping(values)
}

fn node_375() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-discard.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-exact.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-compatible.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-compatible.outputs.cache-quiescent == 'true') && (steps.build.outcome == 'skipped' || steps.build.outputs.cache-quiescent == 'true') && steps.context-product.outputs.product-key != '' && steps.products-save-context-product.outcome == 'success' && steps.products-save-context-product.outputs.product-key == steps.context-product.outputs.product-key && steps.products-save-context-product.outputs.payload-ready == 'true' && (steps.build.outputs.compiled-product-complete == 'true') && !(steps.products-product.outcome == 'success' && steps.products-product.outputs.cache-hit == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.products-partial-import.outcome == 'skipped' || steps.products-partial-import.outputs.cache-quiescent == 'true') && (steps.products-product-partial-import.outcome == 'skipped' || steps.products-product-partial-import.outputs.cache-quiescent == 'true') && steps.context-product.outputs.product-paths != '' && steps.context-product.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_376());
    Value::Mapping(values)
}

fn node_376() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.context-product.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.context-product.outputs.product-key }}"),
    );
    Value::Mapping(values)
}

fn node_377() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-partial"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.context.outputs.product-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-discard.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-exact.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-compatible.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-compatible.outputs.cache-quiescent == 'true') && (steps.build.outcome == 'skipped' || steps.build.outputs.cache-quiescent == 'true') && !(((steps.build.outputs.compiled-native-complete == 'true') && (steps.build.outcome == 'skipped' || steps.build.outputs.compiled-native-complete == 'true')) && steps.products-save-context.outputs.payload-ready == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.products-partial-import.outcome == 'skipped' || steps.products-partial-import.outputs.cache-quiescent == 'true') && (steps.products-product-partial-import.outcome == 'skipped' || steps.products-product-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R280));
    Value::Mapping(values)
}

fn node_378() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-partial-probe"));
    values.insert(text("if"),text("always() && steps.products-partial.outputs.snapshot-ready == 'true' && steps.products-partial.outputs.input-key == steps.context.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_379());
    Value::Mapping(values)
}

fn node_379() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.products-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.products-partial.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_380() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-partial-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.products-partial.outputs.snapshot-ready == 'true' && steps.products-partial.outputs.input-key == steps.context.outputs.product-key && steps.products-partial.outputs.snapshot-key != '' && steps.products-partial-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_381());
    Value::Mapping(values)
}

fn node_381() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.products-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.products-partial.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_382() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-partial-cleanup"));
    values.insert(text("if"),text("always() && (steps.products-partial.outcome == 'success' || steps.products-partial.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R281));
    Value::Mapping(values)
}

fn node_383() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-product-partial"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.context-product.outputs.product-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-windows-working-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-discard.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-exact.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-windows-working-complete-product-compatible.outcome == 'skipped' || steps.sanitize-windows-working-complete-product-compatible.outputs.cache-quiescent == 'true') && (steps.products-partial-import.outcome == 'skipped' || steps.products-partial-import.outputs.cache-quiescent == 'true') && (steps.build.outcome == 'skipped' || steps.build.outputs.cache-quiescent == 'true') && !((steps.build.outputs.compiled-product-complete == 'true') && steps.products-save-context-product.outputs.payload-ready == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.products-product-partial-import.outcome == 'skipped' || steps.products-product-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R282));
    Value::Mapping(values)
}

fn node_384() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-product-partial-probe"));
    values.insert(text("if"),text("always() && steps.products-product-partial.outputs.snapshot-ready == 'true' && steps.products-product-partial.outputs.input-key == steps.context-product.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_385());
    Value::Mapping(values)
}

fn node_385() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.products-product-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.products-product-partial.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_386() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-product-partial-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.products-product-partial.outputs.snapshot-ready == 'true' && steps.products-product-partial.outputs.input-key == steps.context-product.outputs.product-key && steps.products-product-partial.outputs.snapshot-key != '' && steps.products-product-partial-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_387());
    Value::Mapping(values)
}

fn node_387() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.products-product-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.products-product-partial.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_388() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("products-product-partial-cleanup"));
    values.insert(text("if"),text("always() && (steps.products-product-partial.outcome == 'success' || steps.products-product-partial.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R283));
    Value::Mapping(values)
}

fn node_389() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("github.event.deleted != true"));
    values.insert(text("needs"), text("windows-payload-x64"));
    values.insert(text("runs-on"), text("windows-2025"));
    values.insert(text("timeout-minutes"), number("151"));
    values.insert(text("strategy"), node_390());
    values.insert(text("steps"), node_395());
    Value::Mapping(values)
}

fn node_390() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("fail-fast"), Value::Bool(false));
    values.insert(text("matrix"), node_391());
    Value::Mapping(values)
}

fn node_391() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("include"), node_392());
    Value::Mapping(values)
}

fn node_392() -> Value {
    let mut values = Vec::new();
    values.push(node_393());
    values.push(node_394());
    Value::Sequence(values)
}

fn node_393() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("x64"));
    values.insert(text("channel"), text("native"));
    Value::Mapping(values)
}

fn node_394() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("x64"));
    values.insert(text("channel"), text("cargo"));
    Value::Mapping(values)
}

fn node_395() -> Value {
    let mut values = Vec::new();
    values.push(node_396());
    values.push(node_397());
    values.push(node_399());
    values.push(node_401());
    values.push(node_403());
    values.push(node_404());
    values.push(node_405());
    values.push(node_406());
    values.push(node_408());
    values.push(node_409());
    values.push(node_411());
    values.push(node_412());
    values.push(node_414());
    values.push(node_415());
    values.push(node_416());
    values.push(node_418());
    values.push(node_419());
    values.push(node_420());
    values.push(node_421());
    values.push(node_423());
    values.push(node_425());
    values.push(node_426());
    values.push(node_427());
    values.push(node_429());
    values.push(node_431());
    values.push(node_432());
    values.push(node_433());
    values.push(node_435());
    values.push(node_436());
    values.push(node_437());
    values.push(node_438());
    Value::Sequence(values)
}

fn node_396() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Configure checkout line endings"));
    values.insert(text("run"), literal(LiteralRun::R264));
    Value::Mapping(values)
}

fn node_397() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_398());
    Value::Mapping(values)
}

fn node_398() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_399() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"),
    );
    values.insert(text("with"), node_400());
    Value::Mapping(values)
}

fn node_400() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("windows-prepared-${{ matrix.id }}"));
    values.insert(text("path"), text("target/ci/windows-prepared"));
    values.insert(text("digest-mismatch"), text("error"));
    Value::Mapping(values)
}

fn node_401() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("sources"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"), text("hashFiles('Cargo.lock') != ''"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_402());
    Value::Mapping(values)
}

fn node_402() -> Value {
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

fn node_403() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R0));
    Value::Mapping(values)
}

fn node_404() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R1));
    values.insert(text("id"), text("driver-build"));
    Value::Mapping(values)
}

fn node_405() -> Value {
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

fn node_406() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.driver-build.outcome == 'success' && steps.bootstrap-home.outcome == 'success' && steps.bootstrap-home.outputs.bootstrap-home-matches == 'true' && steps.sources.outputs.cache-primary-key != '' && steps.sources.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_407());
    Value::Mapping(values)
}

fn node_407() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("~/.cargo/registry/cache\n~/.cargo/git/db\n"),
    );
    values.insert(
        text("key"),
        text("${{ steps.sources.outputs.cache-primary-key }}"),
    );
    Value::Mapping(values)
}

fn node_408() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-context"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_409() -> Value {
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
    values.insert(text("with"), node_410());
    Value::Mapping(values)
}

fn node_410() -> Value {
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

fn node_411() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R4));
    Value::Mapping(values)
}

fn node_412() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore"));
    values.insert(text("if"),text("steps.archive-seed-context.outputs.seed-lookup-key != '' && steps.workspace-downloads.outputs.cache-hit != 'true'"));
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

fn node_414() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore-import"));
    values.insert(text("if"),text("steps.archive-seed-restore.outcome == 'success' && steps.archive-seed-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R5));
    Value::Mapping(values)
}

fn node_415() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R6));
    Value::Mapping(values)
}

fn node_416() -> Value {
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
    values.insert(text("with"), node_417());
    Value::Mapping(values)
}

fn node_417() -> Value {
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

fn node_418() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-restore-import"));
    values.insert(text("if"),text("steps.index-snapshot-restore.outcome == 'success' && steps.index-snapshot-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R7));
    Value::Mapping(values)
}

fn node_419() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(text("run"), literal(LiteralRun::R8));
    Value::Mapping(values)
}

fn node_420() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R9));
    Value::Mapping(values)
}

fn node_421() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-probe"));
    values.insert(text("if"),text("always() && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_422());
    Value::Mapping(values)
}

fn node_422() -> Value {
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

fn node_423() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility && steps.archive-seed-snapshot.outputs.snapshot-key != '' && steps.archive-seed-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_424());
    Value::Mapping(values)
}

fn node_424() -> Value {
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

fn node_425() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.archive-seed-snapshot.outcome == 'success' || steps.archive-seed-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R10));
    Value::Mapping(values)
}

fn node_426() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R11));
    Value::Mapping(values)
}

fn node_427() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-probe"));
    values.insert(text("if"),text("always() && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_428());
    Value::Mapping(values)
}

fn node_428() -> Value {
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

fn node_429() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility && steps.index-snapshot-snapshot.outputs.snapshot-key != '' && steps.index-snapshot-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_430());
    Value::Mapping(values)
}

fn node_430() -> Value {
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

fn node_431() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.index-snapshot-snapshot.outcome == 'success' || steps.index-snapshot-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R12));
    Value::Mapping(values)
}

fn node_432() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save-context"));
    values.insert(text("if"),text("always() && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-context.outputs.source-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_433() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save complete workspace downloads"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.workspace-download-context.outputs.source-key != '' && steps.workspace-download-context.outputs.source-paths != '' && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-save-context.outcome == 'success' && steps.workspace-download-save-context.outputs.source-key == steps.workspace-download-context.outputs.source-key && steps.workspace-download-save-context.outputs.source-key == steps.workspace-fetch.outputs.workspace-downloads-key && !(steps.workspace-downloads.outcome == 'success' && steps.workspace-downloads.outputs.cache-hit == 'true') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && steps.workspace-download-context.outputs.source-paths != ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_434());
    Value::Mapping(values)
}

fn node_434() -> Value {
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

fn node_435() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("context"));
    values.insert(text("if"), text("matrix.channel == 'cargo'"));
    values.insert(text("run"), literal(LiteralRun::R284));
    Value::Mapping(values)
}

fn node_436() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("native"));
    values.insert(text("if"), text("matrix.channel == 'native'"));
    values.insert(text("run"), literal(LiteralRun::R285));
    Value::Mapping(values)
}

fn node_437() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cargo"));
    values.insert(text("if"), text("matrix.channel == 'cargo'"));
    values.insert(text("run"), literal(LiteralRun::R286));
    Value::Mapping(values)
}

fn node_438() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("always()"));
    values.insert(text("uses"), text("./.github/actions/upload-artifact"));
    values.insert(text("with"), node_439());
    Value::Mapping(values)
}

fn node_439() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("windows-installed-${{ matrix.id }}-${{ matrix.channel }}"),
    );
    values.insert(text("path"), text("target/ci/windows-installed"));
    values.insert(text("if-no-files-found"), text("error"));
    values.insert(text("include-hidden-files"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_440() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("github.event.deleted != true"));
    values.insert(text("needs"), text("windows-payload-arm64"));
    values.insert(text("runs-on"), text("windows-11-arm"));
    values.insert(text("timeout-minutes"), number("151"));
    values.insert(text("strategy"), node_441());
    values.insert(text("steps"), node_446());
    Value::Mapping(values)
}

fn node_441() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("fail-fast"), Value::Bool(false));
    values.insert(text("matrix"), node_442());
    Value::Mapping(values)
}

fn node_442() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("include"), node_443());
    Value::Mapping(values)
}

fn node_443() -> Value {
    let mut values = Vec::new();
    values.push(node_444());
    values.push(node_445());
    Value::Sequence(values)
}

fn node_444() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("arm64"));
    values.insert(text("channel"), text("native"));
    Value::Mapping(values)
}

fn node_445() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("arm64"));
    values.insert(text("channel"), text("cargo"));
    Value::Mapping(values)
}

fn node_446() -> Value {
    let mut values = Vec::new();
    values.push(node_447());
    values.push(node_448());
    values.push(node_450());
    values.push(node_452());
    values.push(node_454());
    values.push(node_455());
    values.push(node_456());
    values.push(node_457());
    values.push(node_459());
    values.push(node_460());
    values.push(node_462());
    values.push(node_463());
    values.push(node_465());
    values.push(node_466());
    values.push(node_467());
    values.push(node_469());
    values.push(node_470());
    values.push(node_471());
    values.push(node_472());
    values.push(node_474());
    values.push(node_476());
    values.push(node_477());
    values.push(node_478());
    values.push(node_480());
    values.push(node_482());
    values.push(node_483());
    values.push(node_484());
    values.push(node_486());
    values.push(node_487());
    values.push(node_488());
    values.push(node_489());
    Value::Sequence(values)
}

fn node_447() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Configure checkout line endings"));
    values.insert(text("run"), literal(LiteralRun::R264));
    Value::Mapping(values)
}

fn node_448() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_449());
    Value::Mapping(values)
}

fn node_449() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_450() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"),
    );
    values.insert(text("with"), node_451());
    Value::Mapping(values)
}

fn node_451() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("windows-prepared-${{ matrix.id }}"));
    values.insert(text("path"), text("target/ci/windows-prepared"));
    values.insert(text("digest-mismatch"), text("error"));
    Value::Mapping(values)
}

fn node_452() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("sources"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"), text("hashFiles('Cargo.lock') != ''"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_453());
    Value::Mapping(values)
}

fn node_453() -> Value {
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

fn node_454() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R0));
    Value::Mapping(values)
}

fn node_455() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R1));
    values.insert(text("id"), text("driver-build"));
    Value::Mapping(values)
}

fn node_456() -> Value {
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

fn node_457() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.driver-build.outcome == 'success' && steps.bootstrap-home.outcome == 'success' && steps.bootstrap-home.outputs.bootstrap-home-matches == 'true' && steps.sources.outputs.cache-primary-key != '' && steps.sources.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_458());
    Value::Mapping(values)
}

fn node_458() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("~/.cargo/registry/cache\n~/.cargo/git/db\n"),
    );
    values.insert(
        text("key"),
        text("${{ steps.sources.outputs.cache-primary-key }}"),
    );
    Value::Mapping(values)
}

fn node_459() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-context"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_460() -> Value {
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
    values.insert(text("with"), node_461());
    Value::Mapping(values)
}

fn node_461() -> Value {
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

fn node_462() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R4));
    Value::Mapping(values)
}

fn node_463() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore"));
    values.insert(text("if"),text("steps.archive-seed-context.outputs.seed-lookup-key != '' && steps.workspace-downloads.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_464());
    Value::Mapping(values)
}

fn node_464() -> Value {
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

fn node_465() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore-import"));
    values.insert(text("if"),text("steps.archive-seed-restore.outcome == 'success' && steps.archive-seed-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R5));
    Value::Mapping(values)
}

fn node_466() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R6));
    Value::Mapping(values)
}

fn node_467() -> Value {
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
    values.insert(text("with"), node_468());
    Value::Mapping(values)
}

fn node_468() -> Value {
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

fn node_469() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-restore-import"));
    values.insert(text("if"),text("steps.index-snapshot-restore.outcome == 'success' && steps.index-snapshot-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R7));
    Value::Mapping(values)
}

fn node_470() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(text("run"), literal(LiteralRun::R8));
    Value::Mapping(values)
}

fn node_471() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R9));
    Value::Mapping(values)
}

fn node_472() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-probe"));
    values.insert(text("if"),text("always() && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_473());
    Value::Mapping(values)
}

fn node_473() -> Value {
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

fn node_474() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility && steps.archive-seed-snapshot.outputs.snapshot-key != '' && steps.archive-seed-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_475());
    Value::Mapping(values)
}

fn node_475() -> Value {
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

fn node_476() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.archive-seed-snapshot.outcome == 'success' || steps.archive-seed-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R10));
    Value::Mapping(values)
}

fn node_477() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R11));
    Value::Mapping(values)
}

fn node_478() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-probe"));
    values.insert(text("if"),text("always() && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_479());
    Value::Mapping(values)
}

fn node_479() -> Value {
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

fn node_480() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility && steps.index-snapshot-snapshot.outputs.snapshot-key != '' && steps.index-snapshot-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_481());
    Value::Mapping(values)
}

fn node_481() -> Value {
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

fn node_482() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.index-snapshot-snapshot.outcome == 'success' || steps.index-snapshot-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R12));
    Value::Mapping(values)
}

fn node_483() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save-context"));
    values.insert(text("if"),text("always() && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-context.outputs.source-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_484() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save complete workspace downloads"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.workspace-download-context.outputs.source-key != '' && steps.workspace-download-context.outputs.source-paths != '' && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-save-context.outcome == 'success' && steps.workspace-download-save-context.outputs.source-key == steps.workspace-download-context.outputs.source-key && steps.workspace-download-save-context.outputs.source-key == steps.workspace-fetch.outputs.workspace-downloads-key && !(steps.workspace-downloads.outcome == 'success' && steps.workspace-downloads.outputs.cache-hit == 'true') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && steps.workspace-download-context.outputs.source-paths != ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_485());
    Value::Mapping(values)
}

fn node_485() -> Value {
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

fn node_486() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("context"));
    values.insert(text("if"), text("matrix.channel == 'cargo'"));
    values.insert(text("run"), literal(LiteralRun::R284));
    Value::Mapping(values)
}

fn node_487() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("native"));
    values.insert(text("if"), text("matrix.channel == 'native'"));
    values.insert(text("run"), literal(LiteralRun::R285));
    Value::Mapping(values)
}

fn node_488() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cargo"));
    values.insert(text("if"), text("matrix.channel == 'cargo'"));
    values.insert(text("run"), literal(LiteralRun::R286));
    Value::Mapping(values)
}

fn node_489() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("always()"));
    values.insert(text("uses"), text("./.github/actions/upload-artifact"));
    values.insert(text("with"), node_490());
    Value::Mapping(values)
}

fn node_490() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("windows-installed-${{ matrix.id }}-${{ matrix.channel }}"),
    );
    values.insert(text("path"), text("target/ci/windows-installed"));
    values.insert(text("if-no-files-found"), text("error"));
    values.insert(text("include-hidden-files"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_491() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("github.event.deleted != true"));
    values.insert(text("name"), text("Linux private TCP / ${{ matrix.id }}"));
    values.insert(text("strategy"), node_492());
    values.insert(text("runs-on"), text("${{ matrix.runner }}"));
    values.insert(text("timeout-minutes"), number("331"));
    values.insert(text("steps"), node_497());
    Value::Mapping(values)
}

fn node_492() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("fail-fast"), Value::Bool(false));
    values.insert(text("matrix"), node_493());
    Value::Mapping(values)
}

fn node_493() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("include"), node_494());
    Value::Mapping(values)
}

fn node_494() -> Value {
    let mut values = Vec::new();
    values.push(node_495());
    values.push(node_496());
    Value::Sequence(values)
}

fn node_495() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("linux-x64"));
    values.insert(text("runner"), text("ubuntu-24.04"));
    Value::Mapping(values)
}

fn node_496() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("linux-arm64"));
    values.insert(text("runner"), text("ubuntu-24.04-arm"));
    Value::Mapping(values)
}

fn node_497() -> Value {
    let mut values = Vec::new();
    values.push(node_498());
    values.push(node_500());
    values.push(node_502());
    values.push(node_503());
    values.push(node_504());
    values.push(node_505());
    values.push(node_507());
    values.push(node_508());
    values.push(node_510());
    values.push(node_511());
    values.push(node_513());
    values.push(node_514());
    values.push(node_515());
    values.push(node_517());
    values.push(node_518());
    values.push(node_519());
    values.push(node_520());
    values.push(node_522());
    values.push(node_524());
    values.push(node_525());
    values.push(node_526());
    values.push(node_528());
    values.push(node_530());
    values.push(node_531());
    values.push(node_532());
    values.push(node_534());
    values.push(node_535());
    values.push(node_537());
    values.push(node_538());
    values.push(node_539());
    values.push(node_540());
    values.push(node_541());
    values.push(node_543());
    values.push(node_544());
    values.push(node_545());
    values.push(node_546());
    values.push(node_547());
    values.push(node_549());
    values.push(node_550());
    values.push(node_551());
    values.push(node_552());
    values.push(node_553());
    values.push(node_555());
    values.push(node_556());
    values.push(node_557());
    values.push(node_559());
    values.push(node_560());
    values.push(node_561());
    values.push(node_563());
    values.push(node_564());
    values.push(node_565());
    values.push(node_566());
    values.push(node_568());
    values.push(node_569());
    values.push(node_571());
    values.push(node_572());
    values.push(node_574());
    values.push(node_576());
    values.push(node_577());
    values.push(node_579());
    values.push(node_581());
    values.push(node_582());
    values.push(node_583());
    values.push(node_585());
    values.push(node_587());
    values.push(node_588());
    values.push(node_589());
    values.push(node_591());
    values.push(node_593());
    Value::Sequence(values)
}

fn node_498() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_499());
    Value::Mapping(values)
}

fn node_499() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_500() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("private-deps"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"), text("hashFiles('Cargo.lock') != ''"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_501());
    Value::Mapping(values)
}

fn node_501() -> Value {
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

fn node_502() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R0));
    Value::Mapping(values)
}

fn node_503() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Build ordinary CI driver"));
    values.insert(text("id"), text("driver-build"));
    values.insert(text("run"), literal(LiteralRun::R1));
    Value::Mapping(values)
}

fn node_504() -> Value {
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

fn node_505() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.driver-build.outcome == 'success' && steps.bootstrap-home.outcome == 'success' && steps.bootstrap-home.outputs.bootstrap-home-matches == 'true' && steps.private-deps.outputs.cache-primary-key != '' && steps.private-deps.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_506());
    Value::Mapping(values)
}

fn node_506() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("~/.cargo/registry/cache\n~/.cargo/git/db\n"),
    );
    values.insert(
        text("key"),
        text("${{ steps.private-deps.outputs.cache-primary-key }}"),
    );
    Value::Mapping(values)
}

fn node_507() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-context"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_508() -> Value {
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
    values.insert(text("with"), node_509());
    Value::Mapping(values)
}

fn node_509() -> Value {
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

fn node_510() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R4));
    Value::Mapping(values)
}

fn node_511() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore"));
    values.insert(text("if"),text("steps.archive-seed-context.outputs.seed-lookup-key != '' && steps.workspace-downloads.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_512());
    Value::Mapping(values)
}

fn node_512() -> Value {
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

fn node_513() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore-import"));
    values.insert(text("if"),text("steps.archive-seed-restore.outcome == 'success' && steps.archive-seed-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R5));
    Value::Mapping(values)
}

fn node_514() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R6));
    Value::Mapping(values)
}

fn node_515() -> Value {
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
    values.insert(text("with"), node_516());
    Value::Mapping(values)
}

fn node_516() -> Value {
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

fn node_517() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-restore-import"));
    values.insert(text("if"),text("steps.index-snapshot-restore.outcome == 'success' && steps.index-snapshot-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R7));
    Value::Mapping(values)
}

fn node_518() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(text("run"), literal(LiteralRun::R8));
    Value::Mapping(values)
}

fn node_519() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R9));
    Value::Mapping(values)
}

fn node_520() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-probe"));
    values.insert(text("if"),text("always() && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_521());
    Value::Mapping(values)
}

fn node_521() -> Value {
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

fn node_522() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility && steps.archive-seed-snapshot.outputs.snapshot-key != '' && steps.archive-seed-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_523());
    Value::Mapping(values)
}

fn node_523() -> Value {
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

fn node_524() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.archive-seed-snapshot.outcome == 'success' || steps.archive-seed-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R10));
    Value::Mapping(values)
}

fn node_525() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R11));
    Value::Mapping(values)
}

fn node_526() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-probe"));
    values.insert(text("if"),text("always() && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_527());
    Value::Mapping(values)
}

fn node_527() -> Value {
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

fn node_528() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility && steps.index-snapshot-snapshot.outputs.snapshot-key != '' && steps.index-snapshot-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_529());
    Value::Mapping(values)
}

fn node_529() -> Value {
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

fn node_530() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.index-snapshot-snapshot.outcome == 'success' || steps.index-snapshot-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R12));
    Value::Mapping(values)
}

fn node_531() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save-context"));
    values.insert(text("if"),text("always() && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-context.outputs.source-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_532() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save complete workspace downloads"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.workspace-download-context.outputs.source-key != '' && steps.workspace-download-context.outputs.source-paths != '' && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-save-context.outcome == 'success' && steps.workspace-download-save-context.outputs.source-key == steps.workspace-download-context.outputs.source-key && steps.workspace-download-save-context.outputs.source-key == steps.workspace-fetch.outputs.workspace-downloads-key && !(steps.workspace-downloads.outcome == 'success' && steps.workspace-downloads.outputs.cache-hit == 'true') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && steps.workspace-download-context.outputs.source-paths != ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_533());
    Value::Mapping(values)
}

fn node_533() -> Value {
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

fn node_534() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("private-context"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R287));
    Value::Mapping(values)
}

fn node_535() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("private-compiled"));
    values.insert(
        text("if"),
        text("steps.private-context.outputs.compiled-cache-usable == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_536());
    Value::Mapping(values)
}

fn node_536() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.private-context.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.private-context.outputs.product-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.private-context.outputs.product-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_537() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("if"),
        text("steps.private-compiled.outcome == 'failure'"),
    );
    values.insert(
        text("id"),
        text("sanitize-private-complete-native-tests-discard"),
    );
    values.insert(text("run"), literal(LiteralRun::R288));
    Value::Mapping(values)
}

fn node_538() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("steps.private-compiled.outcome == 'success' && steps.private-compiled.outputs.cache-hit == 'true'"));
    values.insert(
        text("id"),
        text("sanitize-private-complete-native-tests-exact"),
    );
    values.insert(text("run"), literal(LiteralRun::R289));
    Value::Mapping(values)
}

fn node_539() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("steps.private-compiled.outcome == 'success' && steps.private-compiled.outputs.cache-matched-key != '' && steps.private-compiled.outputs.cache-hit != 'true'"));
    values.insert(
        text("id"),
        text("sanitize-private-complete-native-tests-compatible"),
    );
    values.insert(text("run"), literal(LiteralRun::R290));
    Value::Mapping(values)
}

fn node_540() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("private-context-product"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R291));
    Value::Mapping(values)
}

fn node_541() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("private-compiled-product"));
    values.insert(
        text("if"),
        text("steps.private-context-product.outputs.compiled-cache-usable == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_542());
    Value::Mapping(values)
}

fn node_542() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.private-context-product.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.private-context-product.outputs.product-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.private-context-product.outputs.product-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_543() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("if"),
        text("steps.private-compiled-product.outcome == 'failure'"),
    );
    values.insert(
        text("id"),
        text("sanitize-private-complete-product-discard"),
    );
    values.insert(text("run"), literal(LiteralRun::R292));
    Value::Mapping(values)
}

fn node_544() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("steps.private-compiled-product.outcome == 'success' && steps.private-compiled-product.outputs.cache-hit == 'true'"));
    values.insert(text("id"), text("sanitize-private-complete-product-exact"));
    values.insert(text("run"), literal(LiteralRun::R293));
    Value::Mapping(values)
}

fn node_545() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("steps.private-compiled-product.outcome == 'success' && steps.private-compiled-product.outputs.cache-matched-key != '' && steps.private-compiled-product.outputs.cache-hit != 'true'"));
    values.insert(
        text("id"),
        text("sanitize-private-complete-product-compatible"),
    );
    values.insert(text("run"), literal(LiteralRun::R294));
    Value::Mapping(values)
}

fn node_546() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("private-context-private-native-tests"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R295));
    Value::Mapping(values)
}

fn node_547() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("private-compiled-private-native-tests"));
    values.insert(
        text("if"),
        text("steps.private-context-private-native-tests.outputs.compiled-cache-usable == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_548());
    Value::Mapping(values)
}

fn node_548() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.private-context-private-native-tests.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.private-context-private-native-tests.outputs.product-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.private-context-private-native-tests.outputs.product-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_549() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("if"),
        text("steps.private-compiled-private-native-tests.outcome == 'failure'"),
    );
    values.insert(
        text("id"),
        text("sanitize-private-complete-private-native-tests-discard"),
    );
    values.insert(text("run"), literal(LiteralRun::R296));
    Value::Mapping(values)
}

fn node_550() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("steps.private-compiled-private-native-tests.outcome == 'success' && steps.private-compiled-private-native-tests.outputs.cache-hit == 'true'"));
    values.insert(
        text("id"),
        text("sanitize-private-complete-private-native-tests-exact"),
    );
    values.insert(text("run"), literal(LiteralRun::R297));
    Value::Mapping(values)
}

fn node_551() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("steps.private-compiled-private-native-tests.outcome == 'success' && steps.private-compiled-private-native-tests.outputs.cache-matched-key != '' && steps.private-compiled-private-native-tests.outputs.cache-hit != 'true'"));
    values.insert(
        text("id"),
        text("sanitize-private-complete-private-native-tests-compatible"),
    );
    values.insert(text("run"), literal(LiteralRun::R298));
    Value::Mapping(values)
}

fn node_552() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("private-compiled-partial-context"));
    values.insert(text("if"),text("steps.private-context.outputs.product-key != '' && steps.private-compiled.outcome != 'failure' && steps.private-compiled.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R299));
    Value::Mapping(values)
}

fn node_553() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("private-compiled-partial-restore"));
    values.insert(text("if"),text("steps.private-compiled-partial-context.outputs.seed-lookup-key != '' && steps.private-context.outputs.product-key != '' && steps.private-compiled.outcome != 'failure' && steps.private-compiled.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_554());
    Value::Mapping(values)
}

fn node_554() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.private-compiled-partial-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.private-compiled-partial-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.private-compiled-partial-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_555() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("private-compiled-partial-import"));
    values.insert(text("if"),text("steps.private-compiled-partial-restore.outcome == 'success' && steps.private-compiled-partial-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R300));
    Value::Mapping(values)
}

fn node_556() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("private-compiled-product-partial-context"));
    values.insert(text("if"),text("steps.private-context-product.outputs.product-key != '' && steps.private-compiled-product.outcome != 'failure' && steps.private-compiled-product.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R301));
    Value::Mapping(values)
}

fn node_557() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("private-compiled-product-partial-restore"));
    values.insert(text("if"),text("steps.private-compiled-product-partial-context.outputs.seed-lookup-key != '' && steps.private-context-product.outputs.product-key != '' && steps.private-compiled-product.outcome != 'failure' && steps.private-compiled-product.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_558());
    Value::Mapping(values)
}

fn node_558() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.private-compiled-product-partial-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.private-compiled-product-partial-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.private-compiled-product-partial-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_559() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("private-compiled-product-partial-import"));
    values.insert(text("if"),text("steps.private-compiled-product-partial-restore.outcome == 'success' && steps.private-compiled-product-partial-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R302));
    Value::Mapping(values)
}

fn node_560() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("private-compiled-private-native-tests-partial-context"),
    );
    values.insert(text("if"),text("steps.private-context-private-native-tests.outputs.product-key != '' && steps.private-compiled-private-native-tests.outcome != 'failure' && steps.private-compiled-private-native-tests.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R303));
    Value::Mapping(values)
}

fn node_561() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("private-compiled-private-native-tests-partial-restore"),
    );
    values.insert(text("if"),text("steps.private-compiled-private-native-tests-partial-context.outputs.seed-lookup-key != '' && steps.private-context-private-native-tests.outputs.product-key != '' && steps.private-compiled-private-native-tests.outcome != 'failure' && steps.private-compiled-private-native-tests.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_562());
    Value::Mapping(values)
}

fn node_562() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("key"),text("${{ steps.private-compiled-private-native-tests-partial-context.outputs.seed-lookup-key }}"));
    values.insert(text("path"),text("${{ steps.private-compiled-private-native-tests-partial-context.outputs.seed-import-path }}"));
    values.insert(text("restore-keys"),text("${{ steps.private-compiled-private-native-tests-partial-context.outputs.seed-restore-prefix }}"));
    Value::Mapping(values)
}

fn node_563() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("private-compiled-private-native-tests-partial-import"),
    );
    values.insert(text("if"),text("steps.private-compiled-private-native-tests-partial-restore.outcome == 'success' && steps.private-compiled-private-native-tests-partial-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R304));
    Value::Mapping(values)
}

fn node_564() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("private-run"));
    values.insert(text("run"), literal(LiteralRun::R305));
    Value::Mapping(values)
}

fn node_565() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("private-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-private-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-private-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-private-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-product-discard.outcome == 'skipped' || steps.sanitize-private-complete-product-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-product-exact.outcome == 'skipped' || steps.sanitize-private-complete-product-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-product-compatible.outcome == 'skipped' || steps.sanitize-private-complete-product-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-private-native-tests-discard.outcome == 'skipped' || steps.sanitize-private-complete-private-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-private-native-tests-exact.outcome == 'skipped' || steps.sanitize-private-complete-private-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-private-native-tests-compatible.outcome == 'skipped' || steps.sanitize-private-complete-private-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.private-run.outcome == 'skipped' || steps.private-run.outputs.cache-quiescent == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.private-compiled-partial-import.outcome == 'skipped' || steps.private-compiled-partial-import.outputs.cache-quiescent == 'true') && (steps.private-compiled-product-partial-import.outcome == 'skipped' || steps.private-compiled-product-partial-import.outputs.cache-quiescent == 'true') && (steps.private-compiled-private-native-tests-partial-import.outcome == 'skipped' || steps.private-compiled-private-native-tests-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R306));
    Value::Mapping(values)
}

fn node_566() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save settled private compilation"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-private-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-private-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-private-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-product-discard.outcome == 'skipped' || steps.sanitize-private-complete-product-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-product-exact.outcome == 'skipped' || steps.sanitize-private-complete-product-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-product-compatible.outcome == 'skipped' || steps.sanitize-private-complete-product-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-private-native-tests-discard.outcome == 'skipped' || steps.sanitize-private-complete-private-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-private-native-tests-exact.outcome == 'skipped' || steps.sanitize-private-complete-private-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-private-native-tests-compatible.outcome == 'skipped' || steps.sanitize-private-complete-private-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.private-run.outcome == 'skipped' || steps.private-run.outputs.cache-quiescent == 'true') && steps.private-context.outputs.product-key != '' && steps.private-save-context.outcome == 'success' && steps.private-save-context.outputs.product-key == steps.private-context.outputs.product-key && steps.private-save-context.outputs.payload-ready == 'true' && (steps.private-run.outputs.compiled-recipe-complete == 'true') && !(steps.private-compiled.outcome == 'success' && steps.private-compiled.outputs.cache-hit == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.private-compiled-partial-import.outcome == 'skipped' || steps.private-compiled-partial-import.outputs.cache-quiescent == 'true') && (steps.private-compiled-product-partial-import.outcome == 'skipped' || steps.private-compiled-product-partial-import.outputs.cache-quiescent == 'true') && (steps.private-compiled-private-native-tests-partial-import.outcome == 'skipped' || steps.private-compiled-private-native-tests-partial-import.outputs.cache-quiescent == 'true') && steps.private-context.outputs.product-paths != '' && steps.private-context.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_567());
    Value::Mapping(values)
}

fn node_567() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.private-context.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.private-context.outputs.product-key }}"),
    );
    Value::Mapping(values)
}

fn node_568() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("private-save-context-product"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-private-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-private-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-private-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-product-discard.outcome == 'skipped' || steps.sanitize-private-complete-product-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-product-exact.outcome == 'skipped' || steps.sanitize-private-complete-product-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-product-compatible.outcome == 'skipped' || steps.sanitize-private-complete-product-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-private-native-tests-discard.outcome == 'skipped' || steps.sanitize-private-complete-private-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-private-native-tests-exact.outcome == 'skipped' || steps.sanitize-private-complete-private-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-private-native-tests-compatible.outcome == 'skipped' || steps.sanitize-private-complete-private-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.private-run.outcome == 'skipped' || steps.private-run.outputs.cache-quiescent == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.private-compiled-partial-import.outcome == 'skipped' || steps.private-compiled-partial-import.outputs.cache-quiescent == 'true') && (steps.private-compiled-product-partial-import.outcome == 'skipped' || steps.private-compiled-product-partial-import.outputs.cache-quiescent == 'true') && (steps.private-compiled-private-native-tests-partial-import.outcome == 'skipped' || steps.private-compiled-private-native-tests-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R307));
    Value::Mapping(values)
}

fn node_569() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save settled private compilation"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-private-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-private-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-private-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-product-discard.outcome == 'skipped' || steps.sanitize-private-complete-product-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-product-exact.outcome == 'skipped' || steps.sanitize-private-complete-product-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-product-compatible.outcome == 'skipped' || steps.sanitize-private-complete-product-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-private-native-tests-discard.outcome == 'skipped' || steps.sanitize-private-complete-private-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-private-native-tests-exact.outcome == 'skipped' || steps.sanitize-private-complete-private-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-private-native-tests-compatible.outcome == 'skipped' || steps.sanitize-private-complete-private-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.private-run.outcome == 'skipped' || steps.private-run.outputs.cache-quiescent == 'true') && steps.private-context-product.outputs.product-key != '' && steps.private-save-context-product.outcome == 'success' && steps.private-save-context-product.outputs.product-key == steps.private-context-product.outputs.product-key && steps.private-save-context-product.outputs.payload-ready == 'true' && (steps.private-run.outputs.compiled-recipe-complete == 'true') && !(steps.private-compiled-product.outcome == 'success' && steps.private-compiled-product.outputs.cache-hit == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.private-compiled-partial-import.outcome == 'skipped' || steps.private-compiled-partial-import.outputs.cache-quiescent == 'true') && (steps.private-compiled-product-partial-import.outcome == 'skipped' || steps.private-compiled-product-partial-import.outputs.cache-quiescent == 'true') && (steps.private-compiled-private-native-tests-partial-import.outcome == 'skipped' || steps.private-compiled-private-native-tests-partial-import.outputs.cache-quiescent == 'true') && steps.private-context-product.outputs.product-paths != '' && steps.private-context-product.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_570());
    Value::Mapping(values)
}

fn node_570() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.private-context-product.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.private-context-product.outputs.product-key }}"),
    );
    Value::Mapping(values)
}

fn node_571() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("private-save-context-private-native-tests"),
    );
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-private-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-private-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-private-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-product-discard.outcome == 'skipped' || steps.sanitize-private-complete-product-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-product-exact.outcome == 'skipped' || steps.sanitize-private-complete-product-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-product-compatible.outcome == 'skipped' || steps.sanitize-private-complete-product-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-private-native-tests-discard.outcome == 'skipped' || steps.sanitize-private-complete-private-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-private-native-tests-exact.outcome == 'skipped' || steps.sanitize-private-complete-private-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-private-native-tests-compatible.outcome == 'skipped' || steps.sanitize-private-complete-private-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.private-run.outcome == 'skipped' || steps.private-run.outputs.cache-quiescent == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.private-compiled-partial-import.outcome == 'skipped' || steps.private-compiled-partial-import.outputs.cache-quiescent == 'true') && (steps.private-compiled-product-partial-import.outcome == 'skipped' || steps.private-compiled-product-partial-import.outputs.cache-quiescent == 'true') && (steps.private-compiled-private-native-tests-partial-import.outcome == 'skipped' || steps.private-compiled-private-native-tests-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R308));
    Value::Mapping(values)
}

fn node_572() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save settled private compilation"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-private-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-private-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-private-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-product-discard.outcome == 'skipped' || steps.sanitize-private-complete-product-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-product-exact.outcome == 'skipped' || steps.sanitize-private-complete-product-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-product-compatible.outcome == 'skipped' || steps.sanitize-private-complete-product-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-private-native-tests-discard.outcome == 'skipped' || steps.sanitize-private-complete-private-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-private-native-tests-exact.outcome == 'skipped' || steps.sanitize-private-complete-private-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-private-native-tests-compatible.outcome == 'skipped' || steps.sanitize-private-complete-private-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.private-run.outcome == 'skipped' || steps.private-run.outputs.cache-quiescent == 'true') && steps.private-context-private-native-tests.outputs.product-key != '' && steps.private-save-context-private-native-tests.outcome == 'success' && steps.private-save-context-private-native-tests.outputs.product-key == steps.private-context-private-native-tests.outputs.product-key && steps.private-save-context-private-native-tests.outputs.payload-ready == 'true' && (steps.private-run.outputs.compiled-recipe-complete == 'true') && !(steps.private-compiled-private-native-tests.outcome == 'success' && steps.private-compiled-private-native-tests.outputs.cache-hit == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.private-compiled-partial-import.outcome == 'skipped' || steps.private-compiled-partial-import.outputs.cache-quiescent == 'true') && (steps.private-compiled-product-partial-import.outcome == 'skipped' || steps.private-compiled-product-partial-import.outputs.cache-quiescent == 'true') && (steps.private-compiled-private-native-tests-partial-import.outcome == 'skipped' || steps.private-compiled-private-native-tests-partial-import.outputs.cache-quiescent == 'true') && steps.private-context-private-native-tests.outputs.product-paths != '' && steps.private-context-private-native-tests.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_573());
    Value::Mapping(values)
}

fn node_573() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.private-context-private-native-tests.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.private-context-private-native-tests.outputs.product-key }}"),
    );
    Value::Mapping(values)
}

fn node_574() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("always()"));
    values.insert(text("uses"), text("./.github/actions/upload-artifact"));
    values.insert(text("with"), node_575());
    Value::Mapping(values)
}

fn node_575() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("private-installed-${{ matrix.id }}"));
    values.insert(text("path"), text("target/ci/private-installed"));
    values.insert(text("if-no-files-found"), text("error"));
    values.insert(text("include-hidden-files"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_576() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("private-compiled-partial"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.private-context.outputs.product-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-private-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-private-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-private-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-product-discard.outcome == 'skipped' || steps.sanitize-private-complete-product-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-product-exact.outcome == 'skipped' || steps.sanitize-private-complete-product-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-product-compatible.outcome == 'skipped' || steps.sanitize-private-complete-product-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-private-native-tests-discard.outcome == 'skipped' || steps.sanitize-private-complete-private-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-private-native-tests-exact.outcome == 'skipped' || steps.sanitize-private-complete-private-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-private-native-tests-compatible.outcome == 'skipped' || steps.sanitize-private-complete-private-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.private-run.outcome == 'skipped' || steps.private-run.outputs.cache-quiescent == 'true') && !((steps.private-run.outputs.compiled-recipe-complete == 'true') && steps.private-save-context.outputs.payload-ready == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.private-compiled-partial-import.outcome == 'skipped' || steps.private-compiled-partial-import.outputs.cache-quiescent == 'true') && (steps.private-compiled-product-partial-import.outcome == 'skipped' || steps.private-compiled-product-partial-import.outputs.cache-quiescent == 'true') && (steps.private-compiled-private-native-tests-partial-import.outcome == 'skipped' || steps.private-compiled-private-native-tests-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R309));
    Value::Mapping(values)
}

fn node_577() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("private-compiled-partial-probe"));
    values.insert(text("if"),text("always() && steps.private-compiled-partial.outputs.snapshot-ready == 'true' && steps.private-compiled-partial.outputs.input-key == steps.private-context.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_578());
    Value::Mapping(values)
}

fn node_578() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.private-compiled-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.private-compiled-partial.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_579() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("private-compiled-partial-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.private-compiled-partial.outputs.snapshot-ready == 'true' && steps.private-compiled-partial.outputs.input-key == steps.private-context.outputs.product-key && steps.private-compiled-partial.outputs.snapshot-key != '' && steps.private-compiled-partial-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_580());
    Value::Mapping(values)
}

fn node_580() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.private-compiled-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.private-compiled-partial.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_581() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("private-compiled-partial-cleanup"));
    values.insert(text("if"),text("always() && (steps.private-compiled-partial.outcome == 'success' || steps.private-compiled-partial.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R310));
    Value::Mapping(values)
}

fn node_582() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("private-compiled-product-partial"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.private-context-product.outputs.product-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-private-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-private-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-private-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-product-discard.outcome == 'skipped' || steps.sanitize-private-complete-product-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-product-exact.outcome == 'skipped' || steps.sanitize-private-complete-product-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-product-compatible.outcome == 'skipped' || steps.sanitize-private-complete-product-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-private-native-tests-discard.outcome == 'skipped' || steps.sanitize-private-complete-private-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-private-native-tests-exact.outcome == 'skipped' || steps.sanitize-private-complete-private-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-private-native-tests-compatible.outcome == 'skipped' || steps.sanitize-private-complete-private-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.private-compiled-partial-import.outcome == 'skipped' || steps.private-compiled-partial-import.outputs.cache-quiescent == 'true') && (steps.private-run.outcome == 'skipped' || steps.private-run.outputs.cache-quiescent == 'true') && !((steps.private-run.outputs.compiled-recipe-complete == 'true') && steps.private-save-context-product.outputs.payload-ready == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.private-compiled-product-partial-import.outcome == 'skipped' || steps.private-compiled-product-partial-import.outputs.cache-quiescent == 'true') && (steps.private-compiled-private-native-tests-partial-import.outcome == 'skipped' || steps.private-compiled-private-native-tests-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R311));
    Value::Mapping(values)
}

fn node_583() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("private-compiled-product-partial-probe"));
    values.insert(text("if"),text("always() && steps.private-compiled-product-partial.outputs.snapshot-ready == 'true' && steps.private-compiled-product-partial.outputs.input-key == steps.private-context-product.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_584());
    Value::Mapping(values)
}

fn node_584() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.private-compiled-product-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.private-compiled-product-partial.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_585() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("private-compiled-product-partial-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.private-compiled-product-partial.outputs.snapshot-ready == 'true' && steps.private-compiled-product-partial.outputs.input-key == steps.private-context-product.outputs.product-key && steps.private-compiled-product-partial.outputs.snapshot-key != '' && steps.private-compiled-product-partial-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_586());
    Value::Mapping(values)
}

fn node_586() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.private-compiled-product-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.private-compiled-product-partial.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_587() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("private-compiled-product-partial-cleanup"));
    values.insert(text("if"),text("always() && (steps.private-compiled-product-partial.outcome == 'success' || steps.private-compiled-product-partial.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R312));
    Value::Mapping(values)
}

fn node_588() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("private-compiled-private-native-tests-partial"),
    );
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.private-context-private-native-tests.outputs.product-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-native-tests-discard.outcome == 'skipped' || steps.sanitize-private-complete-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-native-tests-exact.outcome == 'skipped' || steps.sanitize-private-complete-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-native-tests-compatible.outcome == 'skipped' || steps.sanitize-private-complete-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-product-discard.outcome == 'skipped' || steps.sanitize-private-complete-product-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-product-exact.outcome == 'skipped' || steps.sanitize-private-complete-product-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-product-compatible.outcome == 'skipped' || steps.sanitize-private-complete-product-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-private-native-tests-discard.outcome == 'skipped' || steps.sanitize-private-complete-private-native-tests-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-private-native-tests-exact.outcome == 'skipped' || steps.sanitize-private-complete-private-native-tests-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-private-complete-private-native-tests-compatible.outcome == 'skipped' || steps.sanitize-private-complete-private-native-tests-compatible.outputs.cache-quiescent == 'true') && (steps.private-compiled-partial-import.outcome == 'skipped' || steps.private-compiled-partial-import.outputs.cache-quiescent == 'true') && (steps.private-compiled-product-partial-import.outcome == 'skipped' || steps.private-compiled-product-partial-import.outputs.cache-quiescent == 'true') && (steps.private-run.outcome == 'skipped' || steps.private-run.outputs.cache-quiescent == 'true') && !((steps.private-run.outputs.compiled-recipe-complete == 'true') && steps.private-save-context-private-native-tests.outputs.payload-ready == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.private-compiled-private-native-tests-partial-import.outcome == 'skipped' || steps.private-compiled-private-native-tests-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R313));
    Value::Mapping(values)
}

fn node_589() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("private-compiled-private-native-tests-partial-probe"),
    );
    values.insert(text("if"),text("always() && steps.private-compiled-private-native-tests-partial.outputs.snapshot-ready == 'true' && steps.private-compiled-private-native-tests-partial.outputs.input-key == steps.private-context-private-native-tests.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_590());
    Value::Mapping(values)
}

fn node_590() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.private-compiled-private-native-tests-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.private-compiled-private-native-tests-partial.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_591() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("private-compiled-private-native-tests-partial-save"),
    );
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.private-compiled-private-native-tests-partial.outputs.snapshot-ready == 'true' && steps.private-compiled-private-native-tests-partial.outputs.input-key == steps.private-context-private-native-tests.outputs.product-key && steps.private-compiled-private-native-tests-partial.outputs.snapshot-key != '' && steps.private-compiled-private-native-tests-partial-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_592());
    Value::Mapping(values)
}

fn node_592() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.private-compiled-private-native-tests-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.private-compiled-private-native-tests-partial.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_593() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("private-compiled-private-native-tests-partial-cleanup"),
    );
    values.insert(text("if"),text("always() && (steps.private-compiled-private-native-tests-partial.outcome == 'success' || steps.private-compiled-private-native-tests-partial.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R314));
    Value::Mapping(values)
}

fn node_594() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("needs"), text("macos-performance-plan"));
    values.insert(
        text("if"),
        text("needs.macos-performance-plan.outputs.standalone-common == 'true'"),
    );
    values.insert(text("name"), text("Linux standard cgroup v2 / x64"));
    values.insert(text("runs-on"), text("ubuntu-24.04"));
    values.insert(text("timeout-minutes"), number("173"));
    values.insert(text("steps"), node_595());
    Value::Mapping(values)
}

fn node_595() -> Value {
    let mut values = Vec::new();
    values.push(node_596());
    values.push(node_598());
    values.push(node_600());
    values.push(node_601());
    values.push(node_602());
    values.push(node_603());
    values.push(node_605());
    values.push(node_606());
    values.push(node_608());
    values.push(node_609());
    values.push(node_611());
    values.push(node_612());
    values.push(node_613());
    values.push(node_615());
    values.push(node_616());
    values.push(node_617());
    values.push(node_618());
    values.push(node_620());
    values.push(node_621());
    values.push(node_623());
    values.push(node_625());
    values.push(node_626());
    values.push(node_627());
    values.push(node_629());
    values.push(node_631());
    values.push(node_632());
    values.push(node_633());
    values.push(node_635());
    values.push(node_636());
    values.push(node_637());
    values.push(node_638());
    values.push(node_639());
    values.push(node_641());
    values.push(node_642());
    values.push(node_643());
    values.push(node_644());
    values.push(node_646());
    values.push(node_647());
    values.push(node_649());
    values.push(node_651());
    Value::Sequence(values)
}

fn node_596() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("source"));
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_597());
    Value::Mapping(values)
}

fn node_597() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_598() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("standard-deps"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"), text("hashFiles('Cargo.lock') != ''"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_599());
    Value::Mapping(values)
}

fn node_599() -> Value {
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

fn node_600() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R0));
    Value::Mapping(values)
}

fn node_601() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Build ordinary CI driver"));
    values.insert(text("id"), text("driver-build"));
    values.insert(text("run"), literal(LiteralRun::R1));
    Value::Mapping(values)
}

fn node_602() -> Value {
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

fn node_603() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.driver-build.outcome == 'success' && steps.bootstrap-home.outcome == 'success' && steps.bootstrap-home.outputs.bootstrap-home-matches == 'true' && steps.standard-deps.outputs.cache-primary-key != '' && steps.standard-deps.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_604());
    Value::Mapping(values)
}

fn node_604() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("~/.cargo/registry/cache\n~/.cargo/git/db\n"),
    );
    values.insert(
        text("key"),
        text("${{ steps.standard-deps.outputs.cache-primary-key }}"),
    );
    Value::Mapping(values)
}

fn node_605() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-context"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_606() -> Value {
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
    values.insert(text("with"), node_607());
    Value::Mapping(values)
}

fn node_607() -> Value {
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

fn node_608() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R4));
    Value::Mapping(values)
}

fn node_609() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore"));
    values.insert(text("if"),text("steps.archive-seed-context.outputs.seed-lookup-key != '' && steps.workspace-downloads.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_610());
    Value::Mapping(values)
}

fn node_610() -> Value {
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

fn node_611() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore-import"));
    values.insert(text("if"),text("steps.archive-seed-restore.outcome == 'success' && steps.archive-seed-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R5));
    Value::Mapping(values)
}

fn node_612() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R6));
    Value::Mapping(values)
}

fn node_613() -> Value {
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
    values.insert(text("with"), node_614());
    Value::Mapping(values)
}

fn node_614() -> Value {
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

fn node_615() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-restore-import"));
    values.insert(text("if"),text("steps.index-snapshot-restore.outcome == 'success' && steps.index-snapshot-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R7));
    Value::Mapping(values)
}

fn node_616() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(text("run"), literal(LiteralRun::R8));
    Value::Mapping(values)
}

fn node_617() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save-context"));
    values.insert(text("if"),text("always() && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-context.outputs.source-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_618() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.workspace-download-context.outputs.source-key != '' && steps.workspace-download-context.outputs.source-paths != '' && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-save-context.outcome == 'success' && steps.workspace-download-save-context.outputs.source-key == steps.workspace-download-context.outputs.source-key && steps.workspace-download-save-context.outputs.source-key == steps.workspace-fetch.outputs.workspace-downloads-key && !(steps.workspace-downloads.outcome == 'success' && steps.workspace-downloads.outputs.cache-hit == 'true') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && steps.workspace-download-context.outputs.source-paths != ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_619());
    Value::Mapping(values)
}

fn node_619() -> Value {
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

fn node_620() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R9));
    Value::Mapping(values)
}

fn node_621() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-probe"));
    values.insert(text("if"),text("always() && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_622());
    Value::Mapping(values)
}

fn node_622() -> Value {
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

fn node_623() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility && steps.archive-seed-snapshot.outputs.snapshot-key != '' && steps.archive-seed-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_624());
    Value::Mapping(values)
}

fn node_624() -> Value {
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

fn node_625() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.archive-seed-snapshot.outcome == 'success' || steps.archive-seed-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R10));
    Value::Mapping(values)
}

fn node_626() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R11));
    Value::Mapping(values)
}

fn node_627() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-probe"));
    values.insert(text("if"),text("always() && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_628());
    Value::Mapping(values)
}

fn node_628() -> Value {
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

fn node_629() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility && steps.index-snapshot-snapshot.outputs.snapshot-key != '' && steps.index-snapshot-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_630());
    Value::Mapping(values)
}

fn node_630() -> Value {
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

fn node_631() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.index-snapshot-snapshot.outcome == 'success' || steps.index-snapshot-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R12));
    Value::Mapping(values)
}

fn node_632() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-context"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R315));
    Value::Mapping(values)
}

fn node_633() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-compiled"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("if"),
        text("steps.backend-context.outputs.compiled-cache-usable == 'true'"),
    );
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_634());
    Value::Mapping(values)
}

fn node_634() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.backend-context.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.backend-context.outputs.product-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.backend-context.outputs.product-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_635() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize backend-compiled discard restore"),
    );
    values.insert(text("id"), text("sanitize-backend-complete-recipe-discard"));
    values.insert(
        text("if"),
        text("steps.backend-compiled.outcome == 'failure'"),
    );
    values.insert(text("run"), literal(LiteralRun::R316));
    Value::Mapping(values)
}

fn node_636() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize backend-compiled exact restore"),
    );
    values.insert(text("id"), text("sanitize-backend-complete-recipe-exact"));
    values.insert(text("if"),text("steps.backend-compiled.outcome == 'success' && steps.backend-compiled.outputs.cache-hit == 'true'"));
    values.insert(text("run"), literal(LiteralRun::R317));
    Value::Mapping(values)
}

fn node_637() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize backend-compiled compatible restore"),
    );
    values.insert(
        text("id"),
        text("sanitize-backend-complete-recipe-compatible"),
    );
    values.insert(text("if"),text("steps.backend-compiled.outcome == 'success' && steps.backend-compiled.outputs.cache-matched-key != '' && steps.backend-compiled.outputs.cache-hit != 'true'"));
    values.insert(text("run"), literal(LiteralRun::R318));
    Value::Mapping(values)
}

fn node_638() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-compiled-partial-context"));
    values.insert(text("if"),text("steps.backend-context.outputs.product-key != '' && steps.backend-compiled.outcome != 'failure' && steps.backend-compiled.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R319));
    Value::Mapping(values)
}

fn node_639() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-compiled-partial-restore"));
    values.insert(text("if"),text("steps.backend-compiled-partial-context.outputs.seed-lookup-key != '' && steps.backend-context.outputs.product-key != '' && steps.backend-compiled.outcome != 'failure' && steps.backend-compiled.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_640());
    Value::Mapping(values)
}

fn node_640() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.backend-compiled-partial-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.backend-compiled-partial-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.backend-compiled-partial-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_641() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-compiled-partial-import"));
    values.insert(text("if"),text("steps.backend-compiled-partial-restore.outcome == 'success' && steps.backend-compiled-partial-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R320));
    Value::Mapping(values)
}

fn node_642() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-run"));
    values.insert(text("run"), literal(LiteralRun::R321));
    Value::Mapping(values)
}

fn node_643() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-compiled-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-backend-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-backend-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-backend-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-backend-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-backend-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-backend-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.backend-run.outcome == 'skipped' || steps.backend-run.outputs.cache-quiescent == 'true') && steps.backend-context.outputs.compiled-cache-usable == 'true' && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.backend-compiled-partial-import.outcome == 'skipped' || steps.backend-compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R322));
    Value::Mapping(values)
}

fn node_644() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-backend-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-backend-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-backend-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-backend-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-backend-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-backend-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.backend-run.outcome == 'skipped' || steps.backend-run.outputs.cache-quiescent == 'true') && steps.backend-context.outputs.product-key != '' && steps.backend-compiled-save-context.outcome == 'success' && steps.backend-compiled-save-context.outputs.product-key == steps.backend-context.outputs.product-key && steps.backend-compiled-save-context.outputs.payload-ready == 'true' && (steps.backend-run.outputs.compiled-recipe-complete == 'true') && !(steps.backend-compiled.outcome == 'success' && steps.backend-compiled.outputs.cache-hit == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.backend-compiled-partial-import.outcome == 'skipped' || steps.backend-compiled-partial-import.outputs.cache-quiescent == 'true') && steps.backend-context.outputs.product-paths != '' && steps.backend-context.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_645());
    Value::Mapping(values)
}

fn node_645() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.backend-context.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.backend-context.outputs.product-key }}"),
    );
    Value::Mapping(values)
}

fn node_646() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-compiled-partial"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.backend-context.outputs.product-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-backend-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-backend-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-backend-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-backend-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-backend-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-backend-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.backend-run.outcome == 'skipped' || steps.backend-run.outputs.cache-quiescent == 'true') && !((steps.backend-run.outputs.compiled-recipe-complete == 'true') && steps.backend-compiled-save-context.outputs.payload-ready == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.backend-compiled-partial-import.outcome == 'skipped' || steps.backend-compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R323));
    Value::Mapping(values)
}

fn node_647() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-compiled-partial-probe"));
    values.insert(text("if"),text("always() && steps.backend-compiled-partial.outputs.snapshot-ready == 'true' && steps.backend-compiled-partial.outputs.input-key == steps.backend-context.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_648());
    Value::Mapping(values)
}

fn node_648() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.backend-compiled-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.backend-compiled-partial.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_649() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-compiled-partial-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.backend-compiled-partial.outputs.snapshot-ready == 'true' && steps.backend-compiled-partial.outputs.input-key == steps.backend-context.outputs.product-key && steps.backend-compiled-partial.outputs.snapshot-key != '' && steps.backend-compiled-partial-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_650());
    Value::Mapping(values)
}

fn node_650() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.backend-compiled-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.backend-compiled-partial.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_651() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-compiled-partial-cleanup"));
    values.insert(text("if"),text("always() && (steps.backend-compiled-partial.outcome == 'success' || steps.backend-compiled-partial.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R324));
    Value::Mapping(values)
}

fn node_652() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("needs"), text("macos-performance-plan"));
    values.insert(
        text("if"),
        text("needs.macos-performance-plan.outputs.standalone-common == 'true'"),
    );
    values.insert(text("name"), text("Windows standard Job Object / x64"));
    values.insert(text("runs-on"), text("windows-2025"));
    values.insert(text("timeout-minutes"), number("173"));
    values.insert(text("steps"), node_653());
    Value::Mapping(values)
}

fn node_653() -> Value {
    let mut values = Vec::new();
    values.push(node_654());
    values.push(node_656());
    values.push(node_658());
    values.push(node_659());
    values.push(node_660());
    values.push(node_661());
    values.push(node_663());
    values.push(node_664());
    values.push(node_666());
    values.push(node_667());
    values.push(node_669());
    values.push(node_670());
    values.push(node_671());
    values.push(node_673());
    values.push(node_674());
    values.push(node_675());
    values.push(node_676());
    values.push(node_678());
    values.push(node_679());
    values.push(node_681());
    values.push(node_683());
    values.push(node_684());
    values.push(node_685());
    values.push(node_687());
    values.push(node_689());
    values.push(node_690());
    values.push(node_691());
    values.push(node_693());
    values.push(node_694());
    values.push(node_695());
    values.push(node_696());
    values.push(node_697());
    values.push(node_699());
    values.push(node_700());
    values.push(node_701());
    values.push(node_702());
    values.push(node_704());
    values.push(node_705());
    values.push(node_707());
    values.push(node_709());
    Value::Sequence(values)
}

fn node_654() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("source"));
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_655());
    Value::Mapping(values)
}

fn node_655() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_656() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("standard-deps"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"), text("hashFiles('Cargo.lock') != ''"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_657());
    Value::Mapping(values)
}

fn node_657() -> Value {
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

fn node_658() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R0));
    Value::Mapping(values)
}

fn node_659() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Build ordinary CI driver"));
    values.insert(text("id"), text("driver-build"));
    values.insert(text("run"), literal(LiteralRun::R1));
    Value::Mapping(values)
}

fn node_660() -> Value {
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

fn node_661() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.driver-build.outcome == 'success' && steps.bootstrap-home.outcome == 'success' && steps.bootstrap-home.outputs.bootstrap-home-matches == 'true' && steps.standard-deps.outputs.cache-primary-key != '' && steps.standard-deps.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_662());
    Value::Mapping(values)
}

fn node_662() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("~/.cargo/registry/cache\n~/.cargo/git/db\n"),
    );
    values.insert(
        text("key"),
        text("${{ steps.standard-deps.outputs.cache-primary-key }}"),
    );
    Value::Mapping(values)
}

fn node_663() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-context"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_664() -> Value {
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
    values.insert(text("with"), node_665());
    Value::Mapping(values)
}

fn node_665() -> Value {
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

fn node_666() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R4));
    Value::Mapping(values)
}

fn node_667() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore"));
    values.insert(text("if"),text("steps.archive-seed-context.outputs.seed-lookup-key != '' && steps.workspace-downloads.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_668());
    Value::Mapping(values)
}

fn node_668() -> Value {
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

fn node_669() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore-import"));
    values.insert(text("if"),text("steps.archive-seed-restore.outcome == 'success' && steps.archive-seed-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R5));
    Value::Mapping(values)
}

fn node_670() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R6));
    Value::Mapping(values)
}

fn node_671() -> Value {
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
    values.insert(text("with"), node_672());
    Value::Mapping(values)
}

fn node_672() -> Value {
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

fn node_673() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-restore-import"));
    values.insert(text("if"),text("steps.index-snapshot-restore.outcome == 'success' && steps.index-snapshot-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R7));
    Value::Mapping(values)
}

fn node_674() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(text("run"), literal(LiteralRun::R8));
    Value::Mapping(values)
}

fn node_675() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save-context"));
    values.insert(text("if"),text("always() && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-context.outputs.source-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_676() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.workspace-download-context.outputs.source-key != '' && steps.workspace-download-context.outputs.source-paths != '' && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-save-context.outcome == 'success' && steps.workspace-download-save-context.outputs.source-key == steps.workspace-download-context.outputs.source-key && steps.workspace-download-save-context.outputs.source-key == steps.workspace-fetch.outputs.workspace-downloads-key && !(steps.workspace-downloads.outcome == 'success' && steps.workspace-downloads.outputs.cache-hit == 'true') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && steps.workspace-download-context.outputs.source-paths != ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_677());
    Value::Mapping(values)
}

fn node_677() -> Value {
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

fn node_678() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R9));
    Value::Mapping(values)
}

fn node_679() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-probe"));
    values.insert(text("if"),text("always() && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_680());
    Value::Mapping(values)
}

fn node_680() -> Value {
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

fn node_681() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility && steps.archive-seed-snapshot.outputs.snapshot-key != '' && steps.archive-seed-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_682());
    Value::Mapping(values)
}

fn node_682() -> Value {
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

fn node_683() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.archive-seed-snapshot.outcome == 'success' || steps.archive-seed-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R10));
    Value::Mapping(values)
}

fn node_684() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R11));
    Value::Mapping(values)
}

fn node_685() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-probe"));
    values.insert(text("if"),text("always() && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_686());
    Value::Mapping(values)
}

fn node_686() -> Value {
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

fn node_687() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility && steps.index-snapshot-snapshot.outputs.snapshot-key != '' && steps.index-snapshot-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_688());
    Value::Mapping(values)
}

fn node_688() -> Value {
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

fn node_689() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.index-snapshot-snapshot.outcome == 'success' || steps.index-snapshot-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R12));
    Value::Mapping(values)
}

fn node_690() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-context"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R315));
    Value::Mapping(values)
}

fn node_691() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-compiled"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("if"),
        text("steps.backend-context.outputs.compiled-cache-usable == 'true'"),
    );
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_692());
    Value::Mapping(values)
}

fn node_692() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.backend-context.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.backend-context.outputs.product-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.backend-context.outputs.product-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_693() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize backend-compiled discard restore"),
    );
    values.insert(text("id"), text("sanitize-backend-complete-recipe-discard"));
    values.insert(
        text("if"),
        text("steps.backend-compiled.outcome == 'failure'"),
    );
    values.insert(text("run"), literal(LiteralRun::R316));
    Value::Mapping(values)
}

fn node_694() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize backend-compiled exact restore"),
    );
    values.insert(text("id"), text("sanitize-backend-complete-recipe-exact"));
    values.insert(text("if"),text("steps.backend-compiled.outcome == 'success' && steps.backend-compiled.outputs.cache-hit == 'true'"));
    values.insert(text("run"), literal(LiteralRun::R317));
    Value::Mapping(values)
}

fn node_695() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize backend-compiled compatible restore"),
    );
    values.insert(
        text("id"),
        text("sanitize-backend-complete-recipe-compatible"),
    );
    values.insert(text("if"),text("steps.backend-compiled.outcome == 'success' && steps.backend-compiled.outputs.cache-matched-key != '' && steps.backend-compiled.outputs.cache-hit != 'true'"));
    values.insert(text("run"), literal(LiteralRun::R318));
    Value::Mapping(values)
}

fn node_696() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-compiled-partial-context"));
    values.insert(text("if"),text("steps.backend-context.outputs.product-key != '' && steps.backend-compiled.outcome != 'failure' && steps.backend-compiled.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R319));
    Value::Mapping(values)
}

fn node_697() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-compiled-partial-restore"));
    values.insert(text("if"),text("steps.backend-compiled-partial-context.outputs.seed-lookup-key != '' && steps.backend-context.outputs.product-key != '' && steps.backend-compiled.outcome != 'failure' && steps.backend-compiled.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_698());
    Value::Mapping(values)
}

fn node_698() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.backend-compiled-partial-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.backend-compiled-partial-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.backend-compiled-partial-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_699() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-compiled-partial-import"));
    values.insert(text("if"),text("steps.backend-compiled-partial-restore.outcome == 'success' && steps.backend-compiled-partial-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R320));
    Value::Mapping(values)
}

fn node_700() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-run"));
    values.insert(text("run"), literal(LiteralRun::R325));
    Value::Mapping(values)
}

fn node_701() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-compiled-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-backend-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-backend-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-backend-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-backend-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-backend-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-backend-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.backend-run.outcome == 'skipped' || steps.backend-run.outputs.cache-quiescent == 'true') && steps.backend-context.outputs.compiled-cache-usable == 'true' && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.backend-compiled-partial-import.outcome == 'skipped' || steps.backend-compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R322));
    Value::Mapping(values)
}

fn node_702() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-backend-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-backend-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-backend-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-backend-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-backend-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-backend-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.backend-run.outcome == 'skipped' || steps.backend-run.outputs.cache-quiescent == 'true') && steps.backend-context.outputs.product-key != '' && steps.backend-compiled-save-context.outcome == 'success' && steps.backend-compiled-save-context.outputs.product-key == steps.backend-context.outputs.product-key && steps.backend-compiled-save-context.outputs.payload-ready == 'true' && (steps.backend-run.outputs.compiled-recipe-complete == 'true') && !(steps.backend-compiled.outcome == 'success' && steps.backend-compiled.outputs.cache-hit == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.backend-compiled-partial-import.outcome == 'skipped' || steps.backend-compiled-partial-import.outputs.cache-quiescent == 'true') && steps.backend-context.outputs.product-paths != '' && steps.backend-context.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_703());
    Value::Mapping(values)
}

fn node_703() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.backend-context.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.backend-context.outputs.product-key }}"),
    );
    Value::Mapping(values)
}

fn node_704() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-compiled-partial"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.backend-context.outputs.product-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-backend-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-backend-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-backend-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-backend-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-backend-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-backend-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.backend-run.outcome == 'skipped' || steps.backend-run.outputs.cache-quiescent == 'true') && !((steps.backend-run.outputs.compiled-recipe-complete == 'true') && steps.backend-compiled-save-context.outputs.payload-ready == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.backend-compiled-partial-import.outcome == 'skipped' || steps.backend-compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R323));
    Value::Mapping(values)
}

fn node_705() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-compiled-partial-probe"));
    values.insert(text("if"),text("always() && steps.backend-compiled-partial.outputs.snapshot-ready == 'true' && steps.backend-compiled-partial.outputs.input-key == steps.backend-context.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_706());
    Value::Mapping(values)
}

fn node_706() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.backend-compiled-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.backend-compiled-partial.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_707() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-compiled-partial-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.backend-compiled-partial.outputs.snapshot-ready == 'true' && steps.backend-compiled-partial.outputs.input-key == steps.backend-context.outputs.product-key && steps.backend-compiled-partial.outputs.snapshot-key != '' && steps.backend-compiled-partial-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_708());
    Value::Mapping(values)
}

fn node_708() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.backend-compiled-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.backend-compiled-partial.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_709() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-compiled-partial-cleanup"));
    values.insert(text("if"),text("always() && (steps.backend-compiled-partial.outcome == 'success' || steps.backend-compiled-partial.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R324));
    Value::Mapping(values)
}

fn node_710() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("needs"), text("macos-performance-plan"));
    values.insert(
        text("if"),
        text("needs.macos-performance-plan.outputs.standalone-common == 'true'"),
    );
    values.insert(text("name"), text("Windows standard Job Object / arm64"));
    values.insert(text("runs-on"), text("windows-11-arm"));
    values.insert(text("timeout-minutes"), number("173"));
    values.insert(text("steps"), node_711());
    Value::Mapping(values)
}

fn node_711() -> Value {
    let mut values = Vec::new();
    values.push(node_712());
    values.push(node_714());
    values.push(node_716());
    values.push(node_717());
    values.push(node_718());
    values.push(node_719());
    values.push(node_721());
    values.push(node_722());
    values.push(node_724());
    values.push(node_725());
    values.push(node_727());
    values.push(node_728());
    values.push(node_729());
    values.push(node_731());
    values.push(node_732());
    values.push(node_733());
    values.push(node_734());
    values.push(node_736());
    values.push(node_737());
    values.push(node_739());
    values.push(node_741());
    values.push(node_742());
    values.push(node_743());
    values.push(node_745());
    values.push(node_747());
    values.push(node_748());
    values.push(node_749());
    values.push(node_751());
    values.push(node_752());
    values.push(node_753());
    values.push(node_754());
    values.push(node_755());
    values.push(node_757());
    values.push(node_758());
    values.push(node_759());
    values.push(node_760());
    values.push(node_762());
    values.push(node_763());
    values.push(node_765());
    values.push(node_767());
    Value::Sequence(values)
}

fn node_712() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("source"));
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_713());
    Value::Mapping(values)
}

fn node_713() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_714() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("standard-deps"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"), text("hashFiles('Cargo.lock') != ''"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_715());
    Value::Mapping(values)
}

fn node_715() -> Value {
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

fn node_716() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R0));
    Value::Mapping(values)
}

fn node_717() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Build ordinary CI driver"));
    values.insert(text("id"), text("driver-build"));
    values.insert(text("run"), literal(LiteralRun::R1));
    Value::Mapping(values)
}

fn node_718() -> Value {
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

fn node_719() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.driver-build.outcome == 'success' && steps.bootstrap-home.outcome == 'success' && steps.bootstrap-home.outputs.bootstrap-home-matches == 'true' && steps.standard-deps.outputs.cache-primary-key != '' && steps.standard-deps.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_720());
    Value::Mapping(values)
}

fn node_720() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("~/.cargo/registry/cache\n~/.cargo/git/db\n"),
    );
    values.insert(
        text("key"),
        text("${{ steps.standard-deps.outputs.cache-primary-key }}"),
    );
    Value::Mapping(values)
}

fn node_721() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-context"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_722() -> Value {
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
    values.insert(text("with"), node_723());
    Value::Mapping(values)
}

fn node_723() -> Value {
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

fn node_724() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R4));
    Value::Mapping(values)
}

fn node_725() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore"));
    values.insert(text("if"),text("steps.archive-seed-context.outputs.seed-lookup-key != '' && steps.workspace-downloads.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_726());
    Value::Mapping(values)
}

fn node_726() -> Value {
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

fn node_727() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore-import"));
    values.insert(text("if"),text("steps.archive-seed-restore.outcome == 'success' && steps.archive-seed-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R5));
    Value::Mapping(values)
}

fn node_728() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R6));
    Value::Mapping(values)
}

fn node_729() -> Value {
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
    values.insert(text("with"), node_730());
    Value::Mapping(values)
}

fn node_730() -> Value {
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

fn node_731() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-restore-import"));
    values.insert(text("if"),text("steps.index-snapshot-restore.outcome == 'success' && steps.index-snapshot-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R7));
    Value::Mapping(values)
}

fn node_732() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(text("run"), literal(LiteralRun::R8));
    Value::Mapping(values)
}

fn node_733() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save-context"));
    values.insert(text("if"),text("always() && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-context.outputs.source-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_734() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.workspace-download-context.outputs.source-key != '' && steps.workspace-download-context.outputs.source-paths != '' && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-save-context.outcome == 'success' && steps.workspace-download-save-context.outputs.source-key == steps.workspace-download-context.outputs.source-key && steps.workspace-download-save-context.outputs.source-key == steps.workspace-fetch.outputs.workspace-downloads-key && !(steps.workspace-downloads.outcome == 'success' && steps.workspace-downloads.outputs.cache-hit == 'true') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && steps.workspace-download-context.outputs.source-paths != ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_735());
    Value::Mapping(values)
}

fn node_735() -> Value {
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

fn node_736() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R9));
    Value::Mapping(values)
}

fn node_737() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-probe"));
    values.insert(text("if"),text("always() && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_738());
    Value::Mapping(values)
}

fn node_738() -> Value {
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

fn node_739() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility && steps.archive-seed-snapshot.outputs.snapshot-key != '' && steps.archive-seed-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_740());
    Value::Mapping(values)
}

fn node_740() -> Value {
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

fn node_741() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.archive-seed-snapshot.outcome == 'success' || steps.archive-seed-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R10));
    Value::Mapping(values)
}

fn node_742() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R11));
    Value::Mapping(values)
}

fn node_743() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-probe"));
    values.insert(text("if"),text("always() && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_744());
    Value::Mapping(values)
}

fn node_744() -> Value {
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

fn node_745() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility && steps.index-snapshot-snapshot.outputs.snapshot-key != '' && steps.index-snapshot-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_746());
    Value::Mapping(values)
}

fn node_746() -> Value {
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

fn node_747() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.index-snapshot-snapshot.outcome == 'success' || steps.index-snapshot-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R12));
    Value::Mapping(values)
}

fn node_748() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-context"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R315));
    Value::Mapping(values)
}

fn node_749() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-compiled"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("if"),
        text("steps.backend-context.outputs.compiled-cache-usable == 'true'"),
    );
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_750());
    Value::Mapping(values)
}

fn node_750() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.backend-context.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.backend-context.outputs.product-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.backend-context.outputs.product-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_751() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize backend-compiled discard restore"),
    );
    values.insert(text("id"), text("sanitize-backend-complete-recipe-discard"));
    values.insert(
        text("if"),
        text("steps.backend-compiled.outcome == 'failure'"),
    );
    values.insert(text("run"), literal(LiteralRun::R316));
    Value::Mapping(values)
}

fn node_752() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize backend-compiled exact restore"),
    );
    values.insert(text("id"), text("sanitize-backend-complete-recipe-exact"));
    values.insert(text("if"),text("steps.backend-compiled.outcome == 'success' && steps.backend-compiled.outputs.cache-hit == 'true'"));
    values.insert(text("run"), literal(LiteralRun::R317));
    Value::Mapping(values)
}

fn node_753() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize backend-compiled compatible restore"),
    );
    values.insert(
        text("id"),
        text("sanitize-backend-complete-recipe-compatible"),
    );
    values.insert(text("if"),text("steps.backend-compiled.outcome == 'success' && steps.backend-compiled.outputs.cache-matched-key != '' && steps.backend-compiled.outputs.cache-hit != 'true'"));
    values.insert(text("run"), literal(LiteralRun::R318));
    Value::Mapping(values)
}

fn node_754() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-compiled-partial-context"));
    values.insert(text("if"),text("steps.backend-context.outputs.product-key != '' && steps.backend-compiled.outcome != 'failure' && steps.backend-compiled.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R319));
    Value::Mapping(values)
}

fn node_755() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-compiled-partial-restore"));
    values.insert(text("if"),text("steps.backend-compiled-partial-context.outputs.seed-lookup-key != '' && steps.backend-context.outputs.product-key != '' && steps.backend-compiled.outcome != 'failure' && steps.backend-compiled.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_756());
    Value::Mapping(values)
}

fn node_756() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.backend-compiled-partial-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.backend-compiled-partial-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.backend-compiled-partial-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_757() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-compiled-partial-import"));
    values.insert(text("if"),text("steps.backend-compiled-partial-restore.outcome == 'success' && steps.backend-compiled-partial-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R320));
    Value::Mapping(values)
}

fn node_758() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-run"));
    values.insert(text("run"), literal(LiteralRun::R325));
    Value::Mapping(values)
}

fn node_759() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-compiled-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-backend-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-backend-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-backend-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-backend-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-backend-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-backend-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.backend-run.outcome == 'skipped' || steps.backend-run.outputs.cache-quiescent == 'true') && steps.backend-context.outputs.compiled-cache-usable == 'true' && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.backend-compiled-partial-import.outcome == 'skipped' || steps.backend-compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R322));
    Value::Mapping(values)
}

fn node_760() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-backend-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-backend-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-backend-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-backend-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-backend-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-backend-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.backend-run.outcome == 'skipped' || steps.backend-run.outputs.cache-quiescent == 'true') && steps.backend-context.outputs.product-key != '' && steps.backend-compiled-save-context.outcome == 'success' && steps.backend-compiled-save-context.outputs.product-key == steps.backend-context.outputs.product-key && steps.backend-compiled-save-context.outputs.payload-ready == 'true' && (steps.backend-run.outputs.compiled-recipe-complete == 'true') && !(steps.backend-compiled.outcome == 'success' && steps.backend-compiled.outputs.cache-hit == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.backend-compiled-partial-import.outcome == 'skipped' || steps.backend-compiled-partial-import.outputs.cache-quiescent == 'true') && steps.backend-context.outputs.product-paths != '' && steps.backend-context.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_761());
    Value::Mapping(values)
}

fn node_761() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.backend-context.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.backend-context.outputs.product-key }}"),
    );
    Value::Mapping(values)
}

fn node_762() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-compiled-partial"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.backend-context.outputs.product-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-backend-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-backend-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-backend-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-backend-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-backend-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-backend-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.backend-run.outcome == 'skipped' || steps.backend-run.outputs.cache-quiescent == 'true') && !((steps.backend-run.outputs.compiled-recipe-complete == 'true') && steps.backend-compiled-save-context.outputs.payload-ready == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.backend-compiled-partial-import.outcome == 'skipped' || steps.backend-compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R323));
    Value::Mapping(values)
}

fn node_763() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-compiled-partial-probe"));
    values.insert(text("if"),text("always() && steps.backend-compiled-partial.outputs.snapshot-ready == 'true' && steps.backend-compiled-partial.outputs.input-key == steps.backend-context.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_764());
    Value::Mapping(values)
}

fn node_764() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.backend-compiled-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.backend-compiled-partial.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_765() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-compiled-partial-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.backend-compiled-partial.outputs.snapshot-ready == 'true' && steps.backend-compiled-partial.outputs.input-key == steps.backend-context.outputs.product-key && steps.backend-compiled-partial.outputs.snapshot-key != '' && steps.backend-compiled-partial-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_766());
    Value::Mapping(values)
}

fn node_766() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.backend-compiled-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.backend-compiled-partial.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_767() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("backend-compiled-partial-cleanup"));
    values.insert(text("if"),text("always() && (steps.backend-compiled-partial.outcome == 'success' || steps.backend-compiled-partial.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R324));
    Value::Mapping(values)
}
