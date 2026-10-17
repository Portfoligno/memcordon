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
    values.insert(text("name"), text("Deep CI"));
    values.insert(text("on"), node_1());
    values.insert(text("permissions"), node_6());
    values.insert(text("concurrency"), node_7());
    values.insert(text("jobs"), node_8());
    Value::Mapping(values)
}

fn node_1() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("push"), Value::Null);
    values.insert(text("workflow_dispatch"), node_2());
    Value::Mapping(values)
}

fn node_2() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("inputs"), node_3());
    Value::Mapping(values)
}

fn node_3() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("failure-mode"), node_4());
    Value::Mapping(values)
}

fn node_4() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("description"),
        text("Stop independent work after a failure or collect applicable diagnostics"),
    );
    values.insert(text("type"), text("choice"));
    values.insert(text("default"), text("collect-all"));
    values.insert(text("options"), node_5());
    Value::Mapping(values)
}

fn node_5() -> Value {
    let mut values = Vec::new();
    values.push(text("stop-after-failure"));
    values.push(text("collect-all"));
    Value::Sequence(values)
}

fn node_6() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("contents"), text("read"));
    Value::Mapping(values)
}

fn node_7() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("group"), text("deep-ci-${{ github.ref }}"));
    values.insert(text("cancel-in-progress"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_8() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("performance-plan"), node_9());
    values.insert(text("miri"), node_18());
    values.insert(text("fuzz"), node_153());
    values.insert(text("stress"), node_323());
    values.insert(text("stress-packages"), node_385());
    values.insert(text("stress-lifecycle"), node_447());
    values.insert(text("stress-assessment"), node_509());
    Value::Mapping(values)
}

fn node_9() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("github.event.deleted != true"));
    values.insert(text("runs-on"), text("ubuntu-24.04"));
    values.insert(text("timeout-minutes"), number("20"));
    values.insert(text("outputs"), node_10());
    values.insert(text("steps"), node_11());
    Value::Mapping(values)
}

fn node_10() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("combined"),
        text("${{ steps.plan.outputs.stress-combined }}"),
    );
    values.insert(
        text("split"),
        text("${{ steps.plan.outputs.stress-split }}"),
    );
    values.insert(
        text("has-combined"),
        text("${{ steps.plan.outputs.stress-has-combined }}"),
    );
    values.insert(
        text("has-split"),
        text("${{ steps.plan.outputs.stress-has-split }}"),
    );
    values.insert(
        text("standalone-common"),
        text("${{ steps.scope.outputs.standalone-common }}"),
    );
    Value::Mapping(values)
}

fn node_11() -> Value {
    let mut values = Vec::new();
    values.push(node_12());
    values.push(node_14());
    values.push(node_15());
    values.push(node_16());
    values.push(node_17());
    Value::Sequence(values)
}

fn node_12() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_13());
    Value::Mapping(values)
}

fn node_13() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_14() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R0));
    Value::Mapping(values)
}

fn node_15() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R1));
    Value::Mapping(values)
}

fn node_16() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("scope"));
    values.insert(text("run"), literal(LiteralRun::R90));
    Value::Mapping(values)
}

fn node_17() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("plan"));
    values.insert(text("run"), literal(LiteralRun::R91));
    Value::Mapping(values)
}

fn node_18() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("needs"), text("performance-plan"));
    values.insert(
        text("if"),
        text("needs.performance-plan.outputs.standalone-common == 'true'"),
    );
    values.insert(text("name"), text("Miri / ${{ matrix.shard }}"));
    values.insert(text("strategy"), node_19());
    values.insert(text("runs-on"), text("ubuntu-24.04"));
    values.insert(text("timeout-minutes"), number("113"));
    values.insert(text("steps"), node_22());
    Value::Mapping(values)
}

fn node_19() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("fail-fast"),text("${{ github.event_name != 'workflow_dispatch' || inputs.failure-mode != 'collect-all' }}"));
    values.insert(text("max-parallel"), number("4"));
    values.insert(text("matrix"), node_20());
    Value::Mapping(values)
}

fn node_20() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("shard"), node_21());
    Value::Mapping(values)
}

fn node_21() -> Value {
    let mut values = Vec::new();
    values.push(text("quarter-one"));
    values.push(text("quarter-two"));
    values.push(text("quarter-three"));
    values.push(text("quarter-four"));
    Value::Sequence(values)
}

fn node_22() -> Value {
    let mut values = Vec::new();
    values.push(node_23());
    values.push(node_25());
    values.push(node_27());
    values.push(node_28());
    values.push(node_29());
    values.push(node_30());
    values.push(node_32());
    values.push(node_33());
    values.push(node_35());
    values.push(node_36());
    values.push(node_38());
    values.push(node_39());
    values.push(node_40());
    values.push(node_42());
    values.push(node_43());
    values.push(node_44());
    values.push(node_45());
    values.push(node_47());
    values.push(node_48());
    values.push(node_49());
    values.push(node_51());
    values.push(node_52());
    values.push(node_53());
    values.push(node_55());
    values.push(node_56());
    values.push(node_57());
    values.push(node_58());
    values.push(node_59());
    values.push(node_61());
    values.push(node_63());
    values.push(node_64());
    values.push(node_65());
    values.push(node_66());
    values.push(node_67());
    values.push(node_68());
    values.push(node_69());
    values.push(node_71());
    values.push(node_73());
    values.push(node_74());
    values.push(node_75());
    values.push(node_76());
    values.push(node_77());
    values.push(node_78());
    values.push(node_79());
    values.push(node_80());
    values.push(node_82());
    values.push(node_83());
    values.push(node_84());
    values.push(node_86());
    values.push(node_87());
    values.push(node_88());
    values.push(node_90());
    values.push(node_91());
    values.push(node_92());
    values.push(node_94());
    values.push(node_95());
    values.push(node_96());
    values.push(node_97());
    values.push(node_98());
    values.push(node_99());
    values.push(node_100());
    values.push(node_101());
    values.push(node_102());
    values.push(node_103());
    values.push(node_105());
    values.push(node_106());
    values.push(node_107());
    values.push(node_109());
    values.push(node_111());
    values.push(node_112());
    values.push(node_113());
    values.push(node_115());
    values.push(node_117());
    values.push(node_118());
    values.push(node_120());
    values.push(node_122());
    values.push(node_123());
    values.push(node_124());
    values.push(node_126());
    values.push(node_128());
    values.push(node_129());
    values.push(node_130());
    values.push(node_132());
    values.push(node_134());
    values.push(node_135());
    values.push(node_136());
    values.push(node_138());
    values.push(node_140());
    values.push(node_141());
    values.push(node_142());
    values.push(node_144());
    values.push(node_146());
    values.push(node_147());
    values.push(node_148());
    values.push(node_150());
    values.push(node_152());
    Value::Sequence(values)
}

fn node_23() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_24());
    Value::Mapping(values)
}

fn node_24() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_25() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("miri-deps"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"), text("hashFiles('Cargo.lock') != ''"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_26());
    Value::Mapping(values)
}

fn node_26() -> Value {
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

fn node_27() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R0));
    Value::Mapping(values)
}

fn node_28() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Build ordinary CI driver"));
    values.insert(text("id"), text("driver-build"));
    values.insert(text("run"), literal(LiteralRun::R1));
    Value::Mapping(values)
}

fn node_29() -> Value {
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

fn node_30() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.driver-build.outcome == 'success' && steps.bootstrap-home.outcome == 'success' && steps.bootstrap-home.outputs.bootstrap-home-matches == 'true' && steps.miri-deps.outputs.cache-primary-key != '' && steps.miri-deps.outputs.cache-hit != 'true' && matrix.shard == 'quarter-one'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_31());
    Value::Mapping(values)
}

fn node_31() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("~/.cargo/registry/cache\n~/.cargo/git/db\n"),
    );
    values.insert(
        text("key"),
        text("${{ steps.miri-deps.outputs.cache-primary-key }}"),
    );
    Value::Mapping(values)
}

fn node_32() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-context"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_33() -> Value {
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
    values.insert(text("with"), node_34());
    Value::Mapping(values)
}

fn node_34() -> Value {
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

fn node_35() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-context"));
    values.insert(text("run"), literal(LiteralRun::R4));
    Value::Mapping(values)
}

fn node_36() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore"));
    values.insert(text("if"),text("steps.archive-seed-context.outputs.seed-lookup-key != '' && steps.workspace-downloads.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_37());
    Value::Mapping(values)
}

fn node_37() -> Value {
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

fn node_38() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("steps.archive-seed-restore.outcome == 'success' && steps.archive-seed-restore.outputs.cache-matched-key != ''"));
    values.insert(
        text("id"),
        text("import-registry-archives-sources-complete-recipe"),
    );
    values.insert(text("run"), literal(LiteralRun::R5));
    Value::Mapping(values)
}

fn node_39() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-context"));
    values.insert(text("run"), literal(LiteralRun::R6));
    Value::Mapping(values)
}

fn node_40() -> Value {
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
    values.insert(text("with"), node_41());
    Value::Mapping(values)
}

fn node_41() -> Value {
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

fn node_42() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("steps.index-snapshot-restore.outcome == 'success' && steps.index-snapshot-restore.outputs.cache-matched-key != ''"));
    values.insert(
        text("id"),
        text("import-registry-index-sources-complete-recipe"),
    );
    values.insert(text("run"), literal(LiteralRun::R7));
    Value::Mapping(values)
}

fn node_43() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(text("run"), literal(LiteralRun::R8));
    Value::Mapping(values)
}

fn node_44() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save-context"));
    values.insert(text("if"),text("always() && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-context.outputs.source-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_45() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.workspace-download-context.outputs.source-key != '' && steps.workspace-download-context.outputs.source-paths != '' && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-save-context.outcome == 'success' && steps.workspace-download-save-context.outputs.source-key == steps.workspace-download-context.outputs.source-key && steps.workspace-download-save-context.outputs.source-key == steps.workspace-fetch.outputs.workspace-downloads-key && !(steps.workspace-downloads.outcome == 'success' && steps.workspace-downloads.outputs.cache-hit == 'true') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && steps.workspace-download-context.outputs.source-paths != ''"));
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
        text("${{ steps.workspace-download-context.outputs.source-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-download-context.outputs.source-paths }}"),
    );
    Value::Mapping(values)
}

fn node_47() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R92));
    values.insert(text("id"), text("miri-components"));
    Value::Mapping(values)
}

fn node_48() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("miri-sysroot-context"));
    values.insert(text("run"), literal(LiteralRun::R93));
    Value::Mapping(values)
}

fn node_49() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("miri-sysroot-cache"));
    values.insert(
        text("if"),
        text("steps.miri-sysroot-context.outputs.sysroot-key != ''"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
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
        text("${{ steps.miri-sysroot-context.outputs.sysroot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.miri-sysroot-context.outputs.sysroot-path }}"),
    );
    Value::Mapping(values)
}

fn node_51() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("miri-sysroot-setup"));
    values.insert(text("run"), literal(LiteralRun::R94));
    Value::Mapping(values)
}

fn node_52() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("miri-sysroot-save-context"));
    values.insert(text("if"),text("always() && steps.miri-sysroot-setup.outputs.miri-sysroot-ready == 'true' && steps.miri-sysroot-setup.outputs.miri-sysroot-quiescent == 'true' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.miri-components.outcome == 'skipped' || steps.miri-components.outputs.cache-quiescent == 'true') && (steps.miri-sysroot-setup.outcome == 'skipped' || steps.miri-sysroot-setup.outputs.cache-quiescent == 'true')"));
    values.insert(text("run"), literal(LiteralRun::R93));
    Value::Mapping(values)
}

fn node_53() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save generated Miri standard library"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.miri-sysroot-setup.outputs.miri-sysroot-ready == 'true' && steps.miri-sysroot-setup.outputs.miri-sysroot-quiescent == 'true' && steps.miri-sysroot-context.outputs.sysroot-key != '' && steps.miri-sysroot-save-context.outputs.sysroot-key == steps.miri-sysroot-context.outputs.sysroot-key && steps.miri-sysroot-cache.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_54());
    Value::Mapping(values)
}

fn node_54() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.miri-sysroot-context.outputs.sysroot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.miri-sysroot-context.outputs.sysroot-path }}"),
    );
    Value::Mapping(values)
}

fn node_55() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-context-quarter-one"));
    values.insert(text("if"), text("matrix.shard == 'quarter-one'"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R95));
    Value::Mapping(values)
}

fn node_56() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-context-quarter-three"));
    values.insert(text("if"), text("matrix.shard == 'quarter-three'"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R96));
    Value::Mapping(values)
}

fn node_57() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-context-quarter-two"));
    values.insert(text("if"), text("matrix.shard == 'quarter-two'"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R97));
    Value::Mapping(values)
}

fn node_58() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-context-quarter-four"));
    values.insert(text("if"), text("matrix.shard == 'quarter-four'"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R98));
    Value::Mapping(values)
}

fn node_59() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-one"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"),text("matrix.shard == 'quarter-one' && steps.compiled-context-quarter-one.outputs.compiled-cache-usable == 'true'"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_60());
    Value::Mapping(values)
}

fn node_60() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.compiled-context-quarter-one.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.compiled-context-quarter-one.outputs.product-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.compiled-context-quarter-one.outputs.product-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_61() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-three"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"),text("matrix.shard == 'quarter-three' && steps.compiled-context-quarter-three.outputs.compiled-cache-usable == 'true'"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_62());
    Value::Mapping(values)
}

fn node_62() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.compiled-context-quarter-three.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.compiled-context-quarter-three.outputs.product-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.compiled-context-quarter-three.outputs.product-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_63() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize compiled-quarter-one discard restore"),
    );
    values.insert(text("id"), text("sanitize-miri-quarter-one-recipe-discard"));
    values.insert(
        text("if"),
        text("steps.compiled-quarter-one.outcome == 'failure'"),
    );
    values.insert(text("run"), literal(LiteralRun::R99));
    Value::Mapping(values)
}

fn node_64() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize compiled-quarter-three discard restore"),
    );
    values.insert(
        text("id"),
        text("sanitize-miri-quarter-three-recipe-discard"),
    );
    values.insert(
        text("if"),
        text("steps.compiled-quarter-three.outcome == 'failure'"),
    );
    values.insert(text("run"), literal(LiteralRun::R100));
    Value::Mapping(values)
}

fn node_65() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize compiled-quarter-one exact restore"),
    );
    values.insert(text("id"), text("sanitize-miri-quarter-one-recipe-exact"));
    values.insert(text("if"),text("steps.compiled-quarter-one.outcome == 'success' && steps.compiled-quarter-one.outputs.cache-hit == 'true'"));
    values.insert(text("run"), literal(LiteralRun::R101));
    Value::Mapping(values)
}

fn node_66() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize compiled-quarter-three exact restore"),
    );
    values.insert(text("id"), text("sanitize-miri-quarter-three-recipe-exact"));
    values.insert(text("if"),text("steps.compiled-quarter-three.outcome == 'success' && steps.compiled-quarter-three.outputs.cache-hit == 'true'"));
    values.insert(text("run"), literal(LiteralRun::R102));
    Value::Mapping(values)
}

fn node_67() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize compiled-quarter-one compatible restore"),
    );
    values.insert(
        text("id"),
        text("sanitize-miri-quarter-one-recipe-compatible"),
    );
    values.insert(text("if"),text("steps.compiled-quarter-one.outcome == 'success' && steps.compiled-quarter-one.outputs.cache-matched-key != '' && steps.compiled-quarter-one.outputs.cache-hit != 'true'"));
    values.insert(text("run"), literal(LiteralRun::R103));
    Value::Mapping(values)
}

fn node_68() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize compiled-quarter-three compatible restore"),
    );
    values.insert(
        text("id"),
        text("sanitize-miri-quarter-three-recipe-compatible"),
    );
    values.insert(text("if"),text("steps.compiled-quarter-three.outcome == 'success' && steps.compiled-quarter-three.outputs.cache-matched-key != '' && steps.compiled-quarter-three.outputs.cache-hit != 'true'"));
    values.insert(text("run"), literal(LiteralRun::R104));
    Value::Mapping(values)
}

fn node_69() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-two"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"),text("matrix.shard == 'quarter-two' && steps.compiled-context-quarter-two.outputs.compiled-cache-usable == 'true'"));
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
        text("path"),
        text("${{ steps.compiled-context-quarter-two.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.compiled-context-quarter-two.outputs.product-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.compiled-context-quarter-two.outputs.product-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_71() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-four"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"),text("matrix.shard == 'quarter-four' && steps.compiled-context-quarter-four.outputs.compiled-cache-usable == 'true'"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_72());
    Value::Mapping(values)
}

fn node_72() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.compiled-context-quarter-four.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.compiled-context-quarter-four.outputs.product-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.compiled-context-quarter-four.outputs.product-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_73() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize compiled-quarter-two discard restore"),
    );
    values.insert(text("id"), text("sanitize-miri-quarter-two-recipe-discard"));
    values.insert(
        text("if"),
        text("steps.compiled-quarter-two.outcome == 'failure'"),
    );
    values.insert(text("run"), literal(LiteralRun::R105));
    Value::Mapping(values)
}

fn node_74() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize compiled-quarter-four discard restore"),
    );
    values.insert(
        text("id"),
        text("sanitize-miri-quarter-four-recipe-discard"),
    );
    values.insert(
        text("if"),
        text("steps.compiled-quarter-four.outcome == 'failure'"),
    );
    values.insert(text("run"), literal(LiteralRun::R106));
    Value::Mapping(values)
}

fn node_75() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize compiled-quarter-two exact restore"),
    );
    values.insert(text("id"), text("sanitize-miri-quarter-two-recipe-exact"));
    values.insert(text("if"),text("steps.compiled-quarter-two.outcome == 'success' && steps.compiled-quarter-two.outputs.cache-hit == 'true'"));
    values.insert(text("run"), literal(LiteralRun::R107));
    Value::Mapping(values)
}

fn node_76() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize compiled-quarter-four exact restore"),
    );
    values.insert(text("id"), text("sanitize-miri-quarter-four-recipe-exact"));
    values.insert(text("if"),text("steps.compiled-quarter-four.outcome == 'success' && steps.compiled-quarter-four.outputs.cache-hit == 'true'"));
    values.insert(text("run"), literal(LiteralRun::R108));
    Value::Mapping(values)
}

fn node_77() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize compiled-quarter-two compatible restore"),
    );
    values.insert(
        text("id"),
        text("sanitize-miri-quarter-two-recipe-compatible"),
    );
    values.insert(text("if"),text("steps.compiled-quarter-two.outcome == 'success' && steps.compiled-quarter-two.outputs.cache-matched-key != '' && steps.compiled-quarter-two.outputs.cache-hit != 'true'"));
    values.insert(text("run"), literal(LiteralRun::R109));
    Value::Mapping(values)
}

fn node_78() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize compiled-quarter-four compatible restore"),
    );
    values.insert(
        text("id"),
        text("sanitize-miri-quarter-four-recipe-compatible"),
    );
    values.insert(text("if"),text("steps.compiled-quarter-four.outcome == 'success' && steps.compiled-quarter-four.outputs.cache-matched-key != '' && steps.compiled-quarter-four.outputs.cache-hit != 'true'"));
    values.insert(text("run"), literal(LiteralRun::R110));
    Value::Mapping(values)
}

fn node_79() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-one-partial-context"));
    values.insert(text("if"),text("steps.compiled-context-quarter-one.outputs.product-key != '' && steps.compiled-quarter-one.outcome != 'failure' && steps.compiled-quarter-one.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R111));
    Value::Mapping(values)
}

fn node_80() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-one-partial-restore"));
    values.insert(text("if"),text("steps.compiled-quarter-one-partial-context.outputs.seed-lookup-key != '' && steps.compiled-context-quarter-one.outputs.product-key != '' && steps.compiled-quarter-one.outcome != 'failure' && steps.compiled-quarter-one.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_81());
    Value::Mapping(values)
}

fn node_81() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.compiled-quarter-one-partial-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.compiled-quarter-one-partial-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.compiled-quarter-one-partial-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_82() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-one-partial-import"));
    values.insert(text("if"),text("steps.compiled-quarter-one-partial-restore.outcome == 'success' && steps.compiled-quarter-one-partial-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R112));
    Value::Mapping(values)
}

fn node_83() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-three-partial-context"));
    values.insert(text("if"),text("steps.compiled-context-quarter-three.outputs.product-key != '' && steps.compiled-quarter-three.outcome != 'failure' && steps.compiled-quarter-three.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R113));
    Value::Mapping(values)
}

fn node_84() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-three-partial-restore"));
    values.insert(text("if"),text("steps.compiled-quarter-three-partial-context.outputs.seed-lookup-key != '' && steps.compiled-context-quarter-three.outputs.product-key != '' && steps.compiled-quarter-three.outcome != 'failure' && steps.compiled-quarter-three.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
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
        text("${{ steps.compiled-quarter-three-partial-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.compiled-quarter-three-partial-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.compiled-quarter-three-partial-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_86() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-three-partial-import"));
    values.insert(text("if"),text("steps.compiled-quarter-three-partial-restore.outcome == 'success' && steps.compiled-quarter-three-partial-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R114));
    Value::Mapping(values)
}

fn node_87() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-two-partial-context"));
    values.insert(text("if"),text("steps.compiled-context-quarter-two.outputs.product-key != '' && steps.compiled-quarter-two.outcome != 'failure' && steps.compiled-quarter-two.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R115));
    Value::Mapping(values)
}

fn node_88() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-two-partial-restore"));
    values.insert(text("if"),text("steps.compiled-quarter-two-partial-context.outputs.seed-lookup-key != '' && steps.compiled-context-quarter-two.outputs.product-key != '' && steps.compiled-quarter-two.outcome != 'failure' && steps.compiled-quarter-two.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
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
        text("key"),
        text("${{ steps.compiled-quarter-two-partial-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.compiled-quarter-two-partial-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.compiled-quarter-two-partial-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_90() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-two-partial-import"));
    values.insert(text("if"),text("steps.compiled-quarter-two-partial-restore.outcome == 'success' && steps.compiled-quarter-two-partial-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R116));
    Value::Mapping(values)
}

fn node_91() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-four-partial-context"));
    values.insert(text("if"),text("steps.compiled-context-quarter-four.outputs.product-key != '' && steps.compiled-quarter-four.outcome != 'failure' && steps.compiled-quarter-four.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R117));
    Value::Mapping(values)
}

fn node_92() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-four-partial-restore"));
    values.insert(text("if"),text("steps.compiled-quarter-four-partial-context.outputs.seed-lookup-key != '' && steps.compiled-context-quarter-four.outputs.product-key != '' && steps.compiled-quarter-four.outcome != 'failure' && steps.compiled-quarter-four.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_93());
    Value::Mapping(values)
}

fn node_93() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.compiled-quarter-four-partial-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.compiled-quarter-four-partial-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.compiled-quarter-four-partial-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_94() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-four-partial-import"));
    values.insert(text("if"),text("steps.compiled-quarter-four-partial-restore.outcome == 'success' && steps.compiled-quarter-four-partial-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R118));
    Value::Mapping(values)
}

fn node_95() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("miri-quarter-one"));
    values.insert(text("if"),text("matrix.shard == 'quarter-one' && (github.event_name != 'workflow_dispatch' || inputs.failure-mode != 'collect-all')"));
    values.insert(text("run"), literal(LiteralRun::R119));
    Value::Mapping(values)
}

fn node_96() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("miri-quarter-one-diagnostic"));
    values.insert(text("if"),text("matrix.shard == 'quarter-one' && (github.event_name == 'workflow_dispatch' && inputs.failure-mode == 'collect-all')"));
    values.insert(text("run"), literal(LiteralRun::R120));
    Value::Mapping(values)
}

fn node_97() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("miri-quarter-three"));
    values.insert(text("if"),text("matrix.shard == 'quarter-three' && (github.event_name != 'workflow_dispatch' || inputs.failure-mode != 'collect-all')"));
    values.insert(text("run"), literal(LiteralRun::R121));
    Value::Mapping(values)
}

fn node_98() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("miri-quarter-three-diagnostic"));
    values.insert(text("if"),text("matrix.shard == 'quarter-three' && (github.event_name == 'workflow_dispatch' && inputs.failure-mode == 'collect-all')"));
    values.insert(text("run"), literal(LiteralRun::R122));
    Value::Mapping(values)
}

fn node_99() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("miri-quarter-two"));
    values.insert(text("if"),text("matrix.shard == 'quarter-two' && (github.event_name != 'workflow_dispatch' || inputs.failure-mode != 'collect-all')"));
    values.insert(text("run"), literal(LiteralRun::R123));
    Value::Mapping(values)
}

fn node_100() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("miri-quarter-two-diagnostic"));
    values.insert(text("if"),text("matrix.shard == 'quarter-two' && (github.event_name == 'workflow_dispatch' && inputs.failure-mode == 'collect-all')"));
    values.insert(text("run"), literal(LiteralRun::R124));
    Value::Mapping(values)
}

fn node_101() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("miri-quarter-four"));
    values.insert(text("if"),text("matrix.shard == 'quarter-four' && (github.event_name != 'workflow_dispatch' || inputs.failure-mode != 'collect-all')"));
    values.insert(text("run"), literal(LiteralRun::R125));
    Value::Mapping(values)
}

fn node_102() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("miri-quarter-four-diagnostic"));
    values.insert(text("if"),text("matrix.shard == 'quarter-four' && (github.event_name == 'workflow_dispatch' && inputs.failure-mode == 'collect-all')"));
    values.insert(text("run"), literal(LiteralRun::R126));
    Value::Mapping(values)
}

fn node_103() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("always()"));
    values.insert(text("uses"), text("./.github/actions/upload-artifact"));
    values.insert(text("with"), node_104());
    Value::Mapping(values)
}

fn node_104() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("miri-plan-${{ matrix.shard }}"));
    values.insert(text("path"), text("target/ci/reports/miri"));
    values.insert(text("if-no-files-found"), text("warn"));
    Value::Mapping(values)
}

fn node_105() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-one-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.miri-components.outcome == 'skipped' || steps.miri-components.outputs.cache-quiescent == 'true') && (steps.miri-sysroot-setup.outcome == 'skipped' || steps.miri-sysroot-setup.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.miri-quarter-one.outcome == 'skipped' || steps.miri-quarter-one.outputs.cache-quiescent == 'true') && (steps.miri-quarter-one-diagnostic.outcome == 'skipped' || steps.miri-quarter-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-three.outcome == 'skipped' || steps.miri-quarter-three.outputs.cache-quiescent == 'true') && (steps.miri-quarter-three-diagnostic.outcome == 'skipped' || steps.miri-quarter-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-two.outcome == 'skipped' || steps.miri-quarter-two.outputs.cache-quiescent == 'true') && (steps.miri-quarter-two-diagnostic.outcome == 'skipped' || steps.miri-quarter-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-four.outcome == 'skipped' || steps.miri-quarter-four.outputs.cache-quiescent == 'true') && (steps.miri-quarter-four-diagnostic.outcome == 'skipped' || steps.miri-quarter-four-diagnostic.outputs.cache-quiescent == 'true') && steps.compiled-context-quarter-one.outputs.compiled-cache-usable == 'true' && matrix.shard == 'quarter-one' && (steps.compiled-quarter-one-partial-import.outcome == 'skipped' || steps.compiled-quarter-one-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-three-partial-import.outcome == 'skipped' || steps.compiled-quarter-three-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-two-partial-import.outcome == 'skipped' || steps.compiled-quarter-two-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-four-partial-import.outcome == 'skipped' || steps.compiled-quarter-four-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R127));
    Value::Mapping(values)
}

fn node_106() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-three-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.miri-components.outcome == 'skipped' || steps.miri-components.outputs.cache-quiescent == 'true') && (steps.miri-sysroot-setup.outcome == 'skipped' || steps.miri-sysroot-setup.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.miri-quarter-one.outcome == 'skipped' || steps.miri-quarter-one.outputs.cache-quiescent == 'true') && (steps.miri-quarter-one-diagnostic.outcome == 'skipped' || steps.miri-quarter-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-three.outcome == 'skipped' || steps.miri-quarter-three.outputs.cache-quiescent == 'true') && (steps.miri-quarter-three-diagnostic.outcome == 'skipped' || steps.miri-quarter-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-two.outcome == 'skipped' || steps.miri-quarter-two.outputs.cache-quiescent == 'true') && (steps.miri-quarter-two-diagnostic.outcome == 'skipped' || steps.miri-quarter-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-four.outcome == 'skipped' || steps.miri-quarter-four.outputs.cache-quiescent == 'true') && (steps.miri-quarter-four-diagnostic.outcome == 'skipped' || steps.miri-quarter-four-diagnostic.outputs.cache-quiescent == 'true') && steps.compiled-context-quarter-three.outputs.compiled-cache-usable == 'true' && matrix.shard == 'quarter-three' && (steps.compiled-quarter-one-partial-import.outcome == 'skipped' || steps.compiled-quarter-one-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-three-partial-import.outcome == 'skipped' || steps.compiled-quarter-three-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-two-partial-import.outcome == 'skipped' || steps.compiled-quarter-two-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-four-partial-import.outcome == 'skipped' || steps.compiled-quarter-four-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R128));
    Value::Mapping(values)
}

fn node_107() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.miri-components.outcome == 'skipped' || steps.miri-components.outputs.cache-quiescent == 'true') && (steps.miri-sysroot-setup.outcome == 'skipped' || steps.miri-sysroot-setup.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.miri-quarter-one.outcome == 'skipped' || steps.miri-quarter-one.outputs.cache-quiescent == 'true') && (steps.miri-quarter-one-diagnostic.outcome == 'skipped' || steps.miri-quarter-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-three.outcome == 'skipped' || steps.miri-quarter-three.outputs.cache-quiescent == 'true') && (steps.miri-quarter-three-diagnostic.outcome == 'skipped' || steps.miri-quarter-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-two.outcome == 'skipped' || steps.miri-quarter-two.outputs.cache-quiescent == 'true') && (steps.miri-quarter-two-diagnostic.outcome == 'skipped' || steps.miri-quarter-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-four.outcome == 'skipped' || steps.miri-quarter-four.outputs.cache-quiescent == 'true') && (steps.miri-quarter-four-diagnostic.outcome == 'skipped' || steps.miri-quarter-four-diagnostic.outputs.cache-quiescent == 'true') && steps.compiled-context-quarter-one.outputs.product-key != '' && steps.compiled-quarter-one-save-context.outcome == 'success' && steps.compiled-quarter-one-save-context.outputs.product-key == steps.compiled-context-quarter-one.outputs.product-key && steps.compiled-quarter-one-save-context.outputs.payload-ready == 'true' && (steps.miri-quarter-one.outputs.compiled-recipe-complete == 'true' || steps.miri-quarter-one-diagnostic.outputs.compiled-recipe-complete == 'true') && !(steps.compiled-quarter-one.outcome == 'success' && steps.compiled-quarter-one.outputs.cache-hit == 'true') && matrix.shard == 'quarter-one' && (steps.compiled-quarter-one-partial-import.outcome == 'skipped' || steps.compiled-quarter-one-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-three-partial-import.outcome == 'skipped' || steps.compiled-quarter-three-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-two-partial-import.outcome == 'skipped' || steps.compiled-quarter-two-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-four-partial-import.outcome == 'skipped' || steps.compiled-quarter-four-partial-import.outputs.cache-quiescent == 'true') && steps.compiled-context-quarter-one.outputs.product-paths != '' && steps.compiled-context-quarter-one.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_108());
    Value::Mapping(values)
}

fn node_108() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.compiled-context-quarter-one.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.compiled-context-quarter-one.outputs.product-key }}"),
    );
    Value::Mapping(values)
}

fn node_109() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.miri-components.outcome == 'skipped' || steps.miri-components.outputs.cache-quiescent == 'true') && (steps.miri-sysroot-setup.outcome == 'skipped' || steps.miri-sysroot-setup.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.miri-quarter-one.outcome == 'skipped' || steps.miri-quarter-one.outputs.cache-quiescent == 'true') && (steps.miri-quarter-one-diagnostic.outcome == 'skipped' || steps.miri-quarter-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-three.outcome == 'skipped' || steps.miri-quarter-three.outputs.cache-quiescent == 'true') && (steps.miri-quarter-three-diagnostic.outcome == 'skipped' || steps.miri-quarter-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-two.outcome == 'skipped' || steps.miri-quarter-two.outputs.cache-quiescent == 'true') && (steps.miri-quarter-two-diagnostic.outcome == 'skipped' || steps.miri-quarter-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-four.outcome == 'skipped' || steps.miri-quarter-four.outputs.cache-quiescent == 'true') && (steps.miri-quarter-four-diagnostic.outcome == 'skipped' || steps.miri-quarter-four-diagnostic.outputs.cache-quiescent == 'true') && steps.compiled-context-quarter-three.outputs.product-key != '' && steps.compiled-quarter-three-save-context.outcome == 'success' && steps.compiled-quarter-three-save-context.outputs.product-key == steps.compiled-context-quarter-three.outputs.product-key && steps.compiled-quarter-three-save-context.outputs.payload-ready == 'true' && (steps.miri-quarter-three.outputs.compiled-recipe-complete == 'true' || steps.miri-quarter-three-diagnostic.outputs.compiled-recipe-complete == 'true') && !(steps.compiled-quarter-three.outcome == 'success' && steps.compiled-quarter-three.outputs.cache-hit == 'true') && matrix.shard == 'quarter-three' && (steps.compiled-quarter-one-partial-import.outcome == 'skipped' || steps.compiled-quarter-one-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-three-partial-import.outcome == 'skipped' || steps.compiled-quarter-three-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-two-partial-import.outcome == 'skipped' || steps.compiled-quarter-two-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-four-partial-import.outcome == 'skipped' || steps.compiled-quarter-four-partial-import.outputs.cache-quiescent == 'true') && steps.compiled-context-quarter-three.outputs.product-paths != '' && steps.compiled-context-quarter-three.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_110());
    Value::Mapping(values)
}

fn node_110() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.compiled-context-quarter-three.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.compiled-context-quarter-three.outputs.product-key }}"),
    );
    Value::Mapping(values)
}

fn node_111() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-two-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.miri-components.outcome == 'skipped' || steps.miri-components.outputs.cache-quiescent == 'true') && (steps.miri-sysroot-setup.outcome == 'skipped' || steps.miri-sysroot-setup.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.miri-quarter-one.outcome == 'skipped' || steps.miri-quarter-one.outputs.cache-quiescent == 'true') && (steps.miri-quarter-one-diagnostic.outcome == 'skipped' || steps.miri-quarter-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-three.outcome == 'skipped' || steps.miri-quarter-three.outputs.cache-quiescent == 'true') && (steps.miri-quarter-three-diagnostic.outcome == 'skipped' || steps.miri-quarter-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-two.outcome == 'skipped' || steps.miri-quarter-two.outputs.cache-quiescent == 'true') && (steps.miri-quarter-two-diagnostic.outcome == 'skipped' || steps.miri-quarter-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-four.outcome == 'skipped' || steps.miri-quarter-four.outputs.cache-quiescent == 'true') && (steps.miri-quarter-four-diagnostic.outcome == 'skipped' || steps.miri-quarter-four-diagnostic.outputs.cache-quiescent == 'true') && steps.compiled-context-quarter-two.outputs.compiled-cache-usable == 'true' && matrix.shard == 'quarter-two' && (steps.compiled-quarter-one-partial-import.outcome == 'skipped' || steps.compiled-quarter-one-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-three-partial-import.outcome == 'skipped' || steps.compiled-quarter-three-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-two-partial-import.outcome == 'skipped' || steps.compiled-quarter-two-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-four-partial-import.outcome == 'skipped' || steps.compiled-quarter-four-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R129));
    Value::Mapping(values)
}

fn node_112() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-four-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.miri-components.outcome == 'skipped' || steps.miri-components.outputs.cache-quiescent == 'true') && (steps.miri-sysroot-setup.outcome == 'skipped' || steps.miri-sysroot-setup.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.miri-quarter-one.outcome == 'skipped' || steps.miri-quarter-one.outputs.cache-quiescent == 'true') && (steps.miri-quarter-one-diagnostic.outcome == 'skipped' || steps.miri-quarter-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-three.outcome == 'skipped' || steps.miri-quarter-three.outputs.cache-quiescent == 'true') && (steps.miri-quarter-three-diagnostic.outcome == 'skipped' || steps.miri-quarter-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-two.outcome == 'skipped' || steps.miri-quarter-two.outputs.cache-quiescent == 'true') && (steps.miri-quarter-two-diagnostic.outcome == 'skipped' || steps.miri-quarter-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-four.outcome == 'skipped' || steps.miri-quarter-four.outputs.cache-quiescent == 'true') && (steps.miri-quarter-four-diagnostic.outcome == 'skipped' || steps.miri-quarter-four-diagnostic.outputs.cache-quiescent == 'true') && steps.compiled-context-quarter-four.outputs.compiled-cache-usable == 'true' && matrix.shard == 'quarter-four' && (steps.compiled-quarter-one-partial-import.outcome == 'skipped' || steps.compiled-quarter-one-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-three-partial-import.outcome == 'skipped' || steps.compiled-quarter-three-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-two-partial-import.outcome == 'skipped' || steps.compiled-quarter-two-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-four-partial-import.outcome == 'skipped' || steps.compiled-quarter-four-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R130));
    Value::Mapping(values)
}

fn node_113() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.miri-components.outcome == 'skipped' || steps.miri-components.outputs.cache-quiescent == 'true') && (steps.miri-sysroot-setup.outcome == 'skipped' || steps.miri-sysroot-setup.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.miri-quarter-one.outcome == 'skipped' || steps.miri-quarter-one.outputs.cache-quiescent == 'true') && (steps.miri-quarter-one-diagnostic.outcome == 'skipped' || steps.miri-quarter-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-three.outcome == 'skipped' || steps.miri-quarter-three.outputs.cache-quiescent == 'true') && (steps.miri-quarter-three-diagnostic.outcome == 'skipped' || steps.miri-quarter-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-two.outcome == 'skipped' || steps.miri-quarter-two.outputs.cache-quiescent == 'true') && (steps.miri-quarter-two-diagnostic.outcome == 'skipped' || steps.miri-quarter-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-four.outcome == 'skipped' || steps.miri-quarter-four.outputs.cache-quiescent == 'true') && (steps.miri-quarter-four-diagnostic.outcome == 'skipped' || steps.miri-quarter-four-diagnostic.outputs.cache-quiescent == 'true') && steps.compiled-context-quarter-two.outputs.product-key != '' && steps.compiled-quarter-two-save-context.outcome == 'success' && steps.compiled-quarter-two-save-context.outputs.product-key == steps.compiled-context-quarter-two.outputs.product-key && steps.compiled-quarter-two-save-context.outputs.payload-ready == 'true' && (steps.miri-quarter-two.outputs.compiled-recipe-complete == 'true' || steps.miri-quarter-two-diagnostic.outputs.compiled-recipe-complete == 'true') && !(steps.compiled-quarter-two.outcome == 'success' && steps.compiled-quarter-two.outputs.cache-hit == 'true') && matrix.shard == 'quarter-two' && (steps.compiled-quarter-one-partial-import.outcome == 'skipped' || steps.compiled-quarter-one-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-three-partial-import.outcome == 'skipped' || steps.compiled-quarter-three-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-two-partial-import.outcome == 'skipped' || steps.compiled-quarter-two-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-four-partial-import.outcome == 'skipped' || steps.compiled-quarter-four-partial-import.outputs.cache-quiescent == 'true') && steps.compiled-context-quarter-two.outputs.product-paths != '' && steps.compiled-context-quarter-two.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_114());
    Value::Mapping(values)
}

fn node_114() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.compiled-context-quarter-two.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.compiled-context-quarter-two.outputs.product-key }}"),
    );
    Value::Mapping(values)
}

fn node_115() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.miri-components.outcome == 'skipped' || steps.miri-components.outputs.cache-quiescent == 'true') && (steps.miri-sysroot-setup.outcome == 'skipped' || steps.miri-sysroot-setup.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.miri-quarter-one.outcome == 'skipped' || steps.miri-quarter-one.outputs.cache-quiescent == 'true') && (steps.miri-quarter-one-diagnostic.outcome == 'skipped' || steps.miri-quarter-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-three.outcome == 'skipped' || steps.miri-quarter-three.outputs.cache-quiescent == 'true') && (steps.miri-quarter-three-diagnostic.outcome == 'skipped' || steps.miri-quarter-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-two.outcome == 'skipped' || steps.miri-quarter-two.outputs.cache-quiescent == 'true') && (steps.miri-quarter-two-diagnostic.outcome == 'skipped' || steps.miri-quarter-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-four.outcome == 'skipped' || steps.miri-quarter-four.outputs.cache-quiescent == 'true') && (steps.miri-quarter-four-diagnostic.outcome == 'skipped' || steps.miri-quarter-four-diagnostic.outputs.cache-quiescent == 'true') && steps.compiled-context-quarter-four.outputs.product-key != '' && steps.compiled-quarter-four-save-context.outcome == 'success' && steps.compiled-quarter-four-save-context.outputs.product-key == steps.compiled-context-quarter-four.outputs.product-key && steps.compiled-quarter-four-save-context.outputs.payload-ready == 'true' && (steps.miri-quarter-four.outputs.compiled-recipe-complete == 'true' || steps.miri-quarter-four-diagnostic.outputs.compiled-recipe-complete == 'true') && !(steps.compiled-quarter-four.outcome == 'success' && steps.compiled-quarter-four.outputs.cache-hit == 'true') && matrix.shard == 'quarter-four' && (steps.compiled-quarter-one-partial-import.outcome == 'skipped' || steps.compiled-quarter-one-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-three-partial-import.outcome == 'skipped' || steps.compiled-quarter-three-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-two-partial-import.outcome == 'skipped' || steps.compiled-quarter-two-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-four-partial-import.outcome == 'skipped' || steps.compiled-quarter-four-partial-import.outputs.cache-quiescent == 'true') && steps.compiled-context-quarter-four.outputs.product-paths != '' && steps.compiled-context-quarter-four.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_116());
    Value::Mapping(values)
}

fn node_116() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.compiled-context-quarter-four.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.compiled-context-quarter-four.outputs.product-key }}"),
    );
    Value::Mapping(values)
}

fn node_117() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.miri-components.outcome == 'skipped' || steps.miri-components.outputs.cache-quiescent == 'true') && (steps.miri-sysroot-setup.outcome == 'skipped' || steps.miri-sysroot-setup.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.miri-quarter-one.outcome == 'skipped' || steps.miri-quarter-one.outputs.cache-quiescent == 'true') && (steps.miri-quarter-one-diagnostic.outcome == 'skipped' || steps.miri-quarter-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-three.outcome == 'skipped' || steps.miri-quarter-three.outputs.cache-quiescent == 'true') && (steps.miri-quarter-three-diagnostic.outcome == 'skipped' || steps.miri-quarter-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-two.outcome == 'skipped' || steps.miri-quarter-two.outputs.cache-quiescent == 'true') && (steps.miri-quarter-two-diagnostic.outcome == 'skipped' || steps.miri-quarter-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-four.outcome == 'skipped' || steps.miri-quarter-four.outputs.cache-quiescent == 'true') && (steps.miri-quarter-four-diagnostic.outcome == 'skipped' || steps.miri-quarter-four-diagnostic.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-one-partial-import.outcome == 'skipped' || steps.compiled-quarter-one-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-three-partial-import.outcome == 'skipped' || steps.compiled-quarter-three-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-two-partial-import.outcome == 'skipped' || steps.compiled-quarter-two-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-four-partial-import.outcome == 'skipped' || steps.compiled-quarter-four-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("run"), literal(LiteralRun::R9));
    Value::Mapping(values)
}

fn node_118() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-probe"));
    values.insert(text("if"),text("always() && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_119());
    Value::Mapping(values)
}

fn node_119() -> Value {
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

fn node_120() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save observed registry-archives"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility && steps.archive-seed-probe.outputs.cache-hit != 'true'"));
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
        text("key"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.archive-seed-snapshot.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_122() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (steps.archive-seed-snapshot.outcome == 'success' || steps.archive-seed-snapshot.outcome == 'failure')"));
    values.insert(text("run"), literal(LiteralRun::R10));
    Value::Mapping(values)
}

fn node_123() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.miri-components.outcome == 'skipped' || steps.miri-components.outputs.cache-quiescent == 'true') && (steps.miri-sysroot-setup.outcome == 'skipped' || steps.miri-sysroot-setup.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.miri-quarter-one.outcome == 'skipped' || steps.miri-quarter-one.outputs.cache-quiescent == 'true') && (steps.miri-quarter-one-diagnostic.outcome == 'skipped' || steps.miri-quarter-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-three.outcome == 'skipped' || steps.miri-quarter-three.outputs.cache-quiescent == 'true') && (steps.miri-quarter-three-diagnostic.outcome == 'skipped' || steps.miri-quarter-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-two.outcome == 'skipped' || steps.miri-quarter-two.outputs.cache-quiescent == 'true') && (steps.miri-quarter-two-diagnostic.outcome == 'skipped' || steps.miri-quarter-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-four.outcome == 'skipped' || steps.miri-quarter-four.outputs.cache-quiescent == 'true') && (steps.miri-quarter-four-diagnostic.outcome == 'skipped' || steps.miri-quarter-four-diagnostic.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-one-partial-import.outcome == 'skipped' || steps.compiled-quarter-one-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-three-partial-import.outcome == 'skipped' || steps.compiled-quarter-three-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-two-partial-import.outcome == 'skipped' || steps.compiled-quarter-two-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-four-partial-import.outcome == 'skipped' || steps.compiled-quarter-four-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("run"), literal(LiteralRun::R11));
    Value::Mapping(values)
}

fn node_124() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-probe"));
    values.insert(text("if"),text("always() && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_125());
    Value::Mapping(values)
}

fn node_125() -> Value {
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

fn node_126() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save observed registry-index"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility && steps.index-snapshot-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_127());
    Value::Mapping(values)
}

fn node_127() -> Value {
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

fn node_128() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (steps.index-snapshot-snapshot.outcome == 'success' || steps.index-snapshot-snapshot.outcome == 'failure')"));
    values.insert(text("run"), literal(LiteralRun::R12));
    Value::Mapping(values)
}

fn node_129() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-one-partial"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.compiled-context-quarter-one.outputs.product-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.miri-components.outcome == 'skipped' || steps.miri-components.outputs.cache-quiescent == 'true') && (steps.miri-sysroot-setup.outcome == 'skipped' || steps.miri-sysroot-setup.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.miri-quarter-one.outcome == 'skipped' || steps.miri-quarter-one.outputs.cache-quiescent == 'true') && (steps.miri-quarter-one-diagnostic.outcome == 'skipped' || steps.miri-quarter-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-three.outcome == 'skipped' || steps.miri-quarter-three.outputs.cache-quiescent == 'true') && (steps.miri-quarter-three-diagnostic.outcome == 'skipped' || steps.miri-quarter-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-two.outcome == 'skipped' || steps.miri-quarter-two.outputs.cache-quiescent == 'true') && (steps.miri-quarter-two-diagnostic.outcome == 'skipped' || steps.miri-quarter-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-four.outcome == 'skipped' || steps.miri-quarter-four.outputs.cache-quiescent == 'true') && (steps.miri-quarter-four-diagnostic.outcome == 'skipped' || steps.miri-quarter-four-diagnostic.outputs.cache-quiescent == 'true') && !((steps.miri-quarter-one.outputs.compiled-recipe-complete == 'true' || steps.miri-quarter-one-diagnostic.outputs.compiled-recipe-complete == 'true') && steps.compiled-quarter-one-save-context.outputs.payload-ready == 'true') && (steps.compiled-quarter-one-partial-import.outcome == 'skipped' || steps.compiled-quarter-one-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-three-partial-import.outcome == 'skipped' || steps.compiled-quarter-three-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-two-partial-import.outcome == 'skipped' || steps.compiled-quarter-two-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-four-partial-import.outcome == 'skipped' || steps.compiled-quarter-four-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R131));
    Value::Mapping(values)
}

fn node_130() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-one-partial-probe"));
    values.insert(text("if"),text("always() && steps.compiled-quarter-one-partial.outputs.snapshot-ready == 'true' && steps.compiled-quarter-one-partial.outputs.input-key == steps.compiled-context-quarter-one.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_131());
    Value::Mapping(values)
}

fn node_131() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.compiled-quarter-one-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.compiled-quarter-one-partial.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_132() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-one-partial-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.compiled-quarter-one-partial.outputs.snapshot-ready == 'true' && steps.compiled-quarter-one-partial.outputs.input-key == steps.compiled-context-quarter-one.outputs.product-key && steps.compiled-quarter-one-partial.outputs.snapshot-key != '' && steps.compiled-quarter-one-partial-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_133());
    Value::Mapping(values)
}

fn node_133() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.compiled-quarter-one-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.compiled-quarter-one-partial.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_134() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-one-partial-cleanup"));
    values.insert(text("if"),text("always() && (steps.compiled-quarter-one-partial.outcome == 'success' || steps.compiled-quarter-one-partial.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R132));
    Value::Mapping(values)
}

fn node_135() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-three-partial"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.compiled-context-quarter-three.outputs.product-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.miri-components.outcome == 'skipped' || steps.miri-components.outputs.cache-quiescent == 'true') && (steps.miri-sysroot-setup.outcome == 'skipped' || steps.miri-sysroot-setup.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-one-partial-import.outcome == 'skipped' || steps.compiled-quarter-one-partial-import.outputs.cache-quiescent == 'true') && (steps.miri-quarter-one.outcome == 'skipped' || steps.miri-quarter-one.outputs.cache-quiescent == 'true') && (steps.miri-quarter-one-diagnostic.outcome == 'skipped' || steps.miri-quarter-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-three.outcome == 'skipped' || steps.miri-quarter-three.outputs.cache-quiescent == 'true') && (steps.miri-quarter-three-diagnostic.outcome == 'skipped' || steps.miri-quarter-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-two.outcome == 'skipped' || steps.miri-quarter-two.outputs.cache-quiescent == 'true') && (steps.miri-quarter-two-diagnostic.outcome == 'skipped' || steps.miri-quarter-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-four.outcome == 'skipped' || steps.miri-quarter-four.outputs.cache-quiescent == 'true') && (steps.miri-quarter-four-diagnostic.outcome == 'skipped' || steps.miri-quarter-four-diagnostic.outputs.cache-quiescent == 'true') && !((steps.miri-quarter-three.outputs.compiled-recipe-complete == 'true' || steps.miri-quarter-three-diagnostic.outputs.compiled-recipe-complete == 'true') && steps.compiled-quarter-three-save-context.outputs.payload-ready == 'true') && (steps.compiled-quarter-three-partial-import.outcome == 'skipped' || steps.compiled-quarter-three-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-two-partial-import.outcome == 'skipped' || steps.compiled-quarter-two-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-four-partial-import.outcome == 'skipped' || steps.compiled-quarter-four-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R133));
    Value::Mapping(values)
}

fn node_136() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-three-partial-probe"));
    values.insert(text("if"),text("always() && steps.compiled-quarter-three-partial.outputs.snapshot-ready == 'true' && steps.compiled-quarter-three-partial.outputs.input-key == steps.compiled-context-quarter-three.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_137());
    Value::Mapping(values)
}

fn node_137() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.compiled-quarter-three-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.compiled-quarter-three-partial.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_138() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-three-partial-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.compiled-quarter-three-partial.outputs.snapshot-ready == 'true' && steps.compiled-quarter-three-partial.outputs.input-key == steps.compiled-context-quarter-three.outputs.product-key && steps.compiled-quarter-three-partial.outputs.snapshot-key != '' && steps.compiled-quarter-three-partial-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_139());
    Value::Mapping(values)
}

fn node_139() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.compiled-quarter-three-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.compiled-quarter-three-partial.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_140() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-three-partial-cleanup"));
    values.insert(text("if"),text("always() && (steps.compiled-quarter-three-partial.outcome == 'success' || steps.compiled-quarter-three-partial.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R134));
    Value::Mapping(values)
}

fn node_141() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-two-partial"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.compiled-context-quarter-two.outputs.product-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.miri-components.outcome == 'skipped' || steps.miri-components.outputs.cache-quiescent == 'true') && (steps.miri-sysroot-setup.outcome == 'skipped' || steps.miri-sysroot-setup.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-one-partial-import.outcome == 'skipped' || steps.compiled-quarter-one-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-three-partial-import.outcome == 'skipped' || steps.compiled-quarter-three-partial-import.outputs.cache-quiescent == 'true') && (steps.miri-quarter-one.outcome == 'skipped' || steps.miri-quarter-one.outputs.cache-quiescent == 'true') && (steps.miri-quarter-one-diagnostic.outcome == 'skipped' || steps.miri-quarter-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-three.outcome == 'skipped' || steps.miri-quarter-three.outputs.cache-quiescent == 'true') && (steps.miri-quarter-three-diagnostic.outcome == 'skipped' || steps.miri-quarter-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-two.outcome == 'skipped' || steps.miri-quarter-two.outputs.cache-quiescent == 'true') && (steps.miri-quarter-two-diagnostic.outcome == 'skipped' || steps.miri-quarter-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-four.outcome == 'skipped' || steps.miri-quarter-four.outputs.cache-quiescent == 'true') && (steps.miri-quarter-four-diagnostic.outcome == 'skipped' || steps.miri-quarter-four-diagnostic.outputs.cache-quiescent == 'true') && !((steps.miri-quarter-two.outputs.compiled-recipe-complete == 'true' || steps.miri-quarter-two-diagnostic.outputs.compiled-recipe-complete == 'true') && steps.compiled-quarter-two-save-context.outputs.payload-ready == 'true') && (steps.compiled-quarter-two-partial-import.outcome == 'skipped' || steps.compiled-quarter-two-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-four-partial-import.outcome == 'skipped' || steps.compiled-quarter-four-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R135));
    Value::Mapping(values)
}

fn node_142() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-two-partial-probe"));
    values.insert(text("if"),text("always() && steps.compiled-quarter-two-partial.outputs.snapshot-ready == 'true' && steps.compiled-quarter-two-partial.outputs.input-key == steps.compiled-context-quarter-two.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_143());
    Value::Mapping(values)
}

fn node_143() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.compiled-quarter-two-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.compiled-quarter-two-partial.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_144() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-two-partial-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.compiled-quarter-two-partial.outputs.snapshot-ready == 'true' && steps.compiled-quarter-two-partial.outputs.input-key == steps.compiled-context-quarter-two.outputs.product-key && steps.compiled-quarter-two-partial.outputs.snapshot-key != '' && steps.compiled-quarter-two-partial-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_145());
    Value::Mapping(values)
}

fn node_145() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.compiled-quarter-two-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.compiled-quarter-two-partial.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_146() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-two-partial-cleanup"));
    values.insert(text("if"),text("always() && (steps.compiled-quarter-two-partial.outcome == 'success' || steps.compiled-quarter-two-partial.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R136));
    Value::Mapping(values)
}

fn node_147() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-four-partial"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.compiled-context-quarter-four.outputs.product-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.miri-components.outcome == 'skipped' || steps.miri-components.outputs.cache-quiescent == 'true') && (steps.miri-sysroot-setup.outcome == 'skipped' || steps.miri-sysroot-setup.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-one-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-one-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-three-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-three-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-discard.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-exact.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-two-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-two-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-miri-quarter-four-recipe-compatible.outcome == 'skipped' || steps.sanitize-miri-quarter-four-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-one-partial-import.outcome == 'skipped' || steps.compiled-quarter-one-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-three-partial-import.outcome == 'skipped' || steps.compiled-quarter-three-partial-import.outputs.cache-quiescent == 'true') && (steps.compiled-quarter-two-partial-import.outcome == 'skipped' || steps.compiled-quarter-two-partial-import.outputs.cache-quiescent == 'true') && (steps.miri-quarter-one.outcome == 'skipped' || steps.miri-quarter-one.outputs.cache-quiescent == 'true') && (steps.miri-quarter-one-diagnostic.outcome == 'skipped' || steps.miri-quarter-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-three.outcome == 'skipped' || steps.miri-quarter-three.outputs.cache-quiescent == 'true') && (steps.miri-quarter-three-diagnostic.outcome == 'skipped' || steps.miri-quarter-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-two.outcome == 'skipped' || steps.miri-quarter-two.outputs.cache-quiescent == 'true') && (steps.miri-quarter-two-diagnostic.outcome == 'skipped' || steps.miri-quarter-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.miri-quarter-four.outcome == 'skipped' || steps.miri-quarter-four.outputs.cache-quiescent == 'true') && (steps.miri-quarter-four-diagnostic.outcome == 'skipped' || steps.miri-quarter-four-diagnostic.outputs.cache-quiescent == 'true') && !((steps.miri-quarter-four.outputs.compiled-recipe-complete == 'true' || steps.miri-quarter-four-diagnostic.outputs.compiled-recipe-complete == 'true') && steps.compiled-quarter-four-save-context.outputs.payload-ready == 'true') && (steps.compiled-quarter-four-partial-import.outcome == 'skipped' || steps.compiled-quarter-four-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R137));
    Value::Mapping(values)
}

fn node_148() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-four-partial-probe"));
    values.insert(text("if"),text("always() && steps.compiled-quarter-four-partial.outputs.snapshot-ready == 'true' && steps.compiled-quarter-four-partial.outputs.input-key == steps.compiled-context-quarter-four.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_149());
    Value::Mapping(values)
}

fn node_149() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.compiled-quarter-four-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.compiled-quarter-four-partial.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_150() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-four-partial-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.compiled-quarter-four-partial.outputs.snapshot-ready == 'true' && steps.compiled-quarter-four-partial.outputs.input-key == steps.compiled-context-quarter-four.outputs.product-key && steps.compiled-quarter-four-partial.outputs.snapshot-key != '' && steps.compiled-quarter-four-partial-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
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
        text("key"),
        text("${{ steps.compiled-quarter-four-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.compiled-quarter-four-partial.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_152() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-four-partial-cleanup"));
    values.insert(text("if"),text("always() && (steps.compiled-quarter-four-partial.outcome == 'success' || steps.compiled-quarter-four-partial.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R138));
    Value::Mapping(values)
}

fn node_153() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("needs"), text("performance-plan"));
    values.insert(
        text("if"),
        text("needs.performance-plan.outputs.standalone-common == 'true'"),
    );
    values.insert(text("name"), text("fuzz smoke / ${{ matrix.shard }}"));
    values.insert(text("strategy"), node_154());
    values.insert(text("runs-on"), text("ubuntu-24.04"));
    values.insert(text("timeout-minutes"), number("100"));
    values.insert(text("steps"), node_157());
    Value::Mapping(values)
}

fn node_154() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("fail-fast"),text("${{ github.event_name != 'workflow_dispatch' || inputs.failure-mode != 'collect-all' }}"));
    values.insert(text("matrix"), node_155());
    Value::Mapping(values)
}

fn node_155() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("shard"), node_156());
    Value::Mapping(values)
}

fn node_156() -> Value {
    let mut values = Vec::new();
    values.push(text("quarter-one"));
    values.push(text("quarter-two"));
    values.push(text("quarter-three"));
    values.push(text("quarter-four"));
    Value::Sequence(values)
}

fn node_157() -> Value {
    let mut values = Vec::new();
    values.push(node_158());
    values.push(node_160());
    values.push(node_162());
    values.push(node_163());
    values.push(node_164());
    values.push(node_165());
    values.push(node_167());
    values.push(node_168());
    values.push(node_170());
    values.push(node_171());
    values.push(node_173());
    values.push(node_174());
    values.push(node_175());
    values.push(node_177());
    values.push(node_178());
    values.push(node_179());
    values.push(node_180());
    values.push(node_182());
    values.push(node_183());
    values.push(node_184());
    values.push(node_186());
    values.push(node_188());
    values.push(node_190());
    values.push(node_191());
    values.push(node_192());
    values.push(node_194());
    values.push(node_195());
    values.push(node_197());
    values.push(node_198());
    values.push(node_199());
    values.push(node_200());
    values.push(node_201());
    values.push(node_202());
    values.push(node_203());
    values.push(node_204());
    values.push(node_206());
    values.push(node_207());
    values.push(node_208());
    values.push(node_209());
    values.push(node_211());
    values.push(node_212());
    values.push(node_213());
    values.push(node_214());
    values.push(node_216());
    values.push(node_217());
    values.push(node_218());
    values.push(node_219());
    values.push(node_221());
    values.push(node_222());
    values.push(node_223());
    values.push(node_224());
    values.push(node_225());
    values.push(node_227());
    values.push(node_228());
    values.push(node_229());
    values.push(node_230());
    values.push(node_231());
    values.push(node_233());
    values.push(node_235());
    values.push(node_236());
    values.push(node_237());
    values.push(node_238());
    values.push(node_239());
    values.push(node_241());
    values.push(node_242());
    values.push(node_243());
    values.push(node_244());
    values.push(node_245());
    values.push(node_247());
    values.push(node_249());
    values.push(node_250());
    values.push(node_251());
    values.push(node_252());
    values.push(node_253());
    values.push(node_255());
    values.push(node_256());
    values.push(node_257());
    values.push(node_258());
    values.push(node_259());
    values.push(node_261());
    values.push(node_263());
    values.push(node_264());
    values.push(node_265());
    values.push(node_266());
    values.push(node_267());
    values.push(node_269());
    values.push(node_270());
    values.push(node_271());
    values.push(node_272());
    values.push(node_273());
    values.push(node_275());
    values.push(node_277());
    values.push(node_278());
    values.push(node_279());
    values.push(node_280());
    values.push(node_282());
    values.push(node_283());
    values.push(node_285());
    values.push(node_286());
    values.push(node_288());
    values.push(node_289());
    values.push(node_291());
    values.push(node_292());
    values.push(node_294());
    values.push(node_295());
    values.push(node_297());
    values.push(node_298());
    values.push(node_299());
    values.push(node_301());
    values.push(node_303());
    values.push(node_305());
    values.push(node_306());
    values.push(node_308());
    values.push(node_310());
    values.push(node_311());
    values.push(node_312());
    values.push(node_314());
    values.push(node_316());
    values.push(node_317());
    values.push(node_318());
    values.push(node_320());
    values.push(node_322());
    Value::Sequence(values)
}

fn node_158() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_159());
    Value::Mapping(values)
}

fn node_159() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_160() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-deps"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("if"),
        text("hashFiles('Cargo.lock') != '' && hashFiles('fuzz/Cargo.lock') != ''"),
    );
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_161());
    Value::Mapping(values)
}

fn node_161() -> Value {
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

fn node_162() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R0));
    Value::Mapping(values)
}

fn node_163() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Build ordinary CI driver"));
    values.insert(text("id"), text("driver-build"));
    values.insert(text("run"), literal(LiteralRun::R1));
    Value::Mapping(values)
}

fn node_164() -> Value {
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

fn node_165() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.driver-build.outcome == 'success' && steps.bootstrap-home.outcome == 'success' && steps.bootstrap-home.outputs.bootstrap-home-matches == 'true' && steps.fuzz-deps.outputs.cache-primary-key != '' && steps.fuzz-deps.outputs.cache-hit != 'true' && matrix.shard == 'quarter-one'"));
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
        text("~/.cargo/registry/cache\n~/.cargo/git/db\n"),
    );
    values.insert(
        text("key"),
        text("${{ steps.fuzz-deps.outputs.cache-primary-key }}"),
    );
    Value::Mapping(values)
}

fn node_167() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-context"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_168() -> Value {
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
    values.insert(text("with"), node_169());
    Value::Mapping(values)
}

fn node_169() -> Value {
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

fn node_170() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-context"));
    values.insert(text("run"), literal(LiteralRun::R4));
    Value::Mapping(values)
}

fn node_171() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore"));
    values.insert(text("if"),text("steps.archive-seed-context.outputs.seed-lookup-key != '' && steps.workspace-downloads.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_172());
    Value::Mapping(values)
}

fn node_172() -> Value {
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

fn node_173() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("steps.archive-seed-restore.outcome == 'success' && steps.archive-seed-restore.outputs.cache-matched-key != ''"));
    values.insert(
        text("id"),
        text("import-registry-archives-sources-complete-recipe"),
    );
    values.insert(text("run"), literal(LiteralRun::R5));
    Value::Mapping(values)
}

fn node_174() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-context"));
    values.insert(text("run"), literal(LiteralRun::R6));
    Value::Mapping(values)
}

fn node_175() -> Value {
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
    values.insert(text("with"), node_176());
    Value::Mapping(values)
}

fn node_176() -> Value {
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

fn node_177() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("steps.index-snapshot-restore.outcome == 'success' && steps.index-snapshot-restore.outputs.cache-matched-key != ''"));
    values.insert(
        text("id"),
        text("import-registry-index-sources-complete-recipe"),
    );
    values.insert(text("run"), literal(LiteralRun::R7));
    Value::Mapping(values)
}

fn node_178() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(text("run"), literal(LiteralRun::R8));
    Value::Mapping(values)
}

fn node_179() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save-context"));
    values.insert(text("if"),text("always() && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-context.outputs.source-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_180() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.workspace-download-context.outputs.source-key != '' && steps.workspace-download-context.outputs.source-paths != '' && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-save-context.outcome == 'success' && steps.workspace-download-save-context.outputs.source-key == steps.workspace-download-context.outputs.source-key && steps.workspace-download-save-context.outputs.source-key == steps.workspace-fetch.outputs.workspace-downloads-key && !(steps.workspace-downloads.outcome == 'success' && steps.workspace-downloads.outputs.cache-hit == 'true') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && steps.workspace-download-context.outputs.source-paths != ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_181());
    Value::Mapping(values)
}

fn node_181() -> Value {
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

fn node_182() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-fuzz-download-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R139));
    Value::Mapping(values)
}

fn node_183() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-fuzz"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R140));
    Value::Mapping(values)
}

fn node_184() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-fuzz-downloads"));
    values.insert(
        text("if"),
        text("steps.cache-cargo-fuzz-download-context.outputs.source-key != ''"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_185());
    Value::Mapping(values)
}

fn node_185() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.cache-cargo-fuzz-download-context.outputs.source-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.cache-cargo-fuzz-download-context.outputs.source-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.cache-cargo-fuzz-download-context.outputs.source-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_186() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-fuzz-binary"));
    values.insert(
        text("if"),
        text("steps.cache-cargo-fuzz.outputs.tool-key != ''"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_187());
    Value::Mapping(values)
}

fn node_187() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.cache-cargo-fuzz.outputs.tool-path }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.cache-cargo-fuzz.outputs.tool-key }}"),
    );
    Value::Mapping(values)
}

fn node_188() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-fuzz-build"));
    values.insert(
        text("if"),
        text("steps.cache-cargo-fuzz.outputs.tool-build-key != ''"),
    );
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
        text("path"),
        text("${{ steps.cache-cargo-fuzz.outputs.tool-build-path }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.cache-cargo-fuzz.outputs.tool-build-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.cache-cargo-fuzz.outputs.tool-build-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_190() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R141));
    Value::Mapping(values)
}

fn node_191() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-download-context"));
    values.insert(text("run"), literal(LiteralRun::R142));
    Value::Mapping(values)
}

fn node_192() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-downloads"));
    values.insert(
        text("if"),
        text("steps.fuzz-download-context.outputs.source-key != ''"),
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
        text("path"),
        text("${{ steps.fuzz-download-context.outputs.source-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.fuzz-download-context.outputs.source-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.fuzz-download-context.outputs.source-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_194() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-fuzz-build-partial-context"));
    values.insert(text("if"),text("steps.cache-cargo-fuzz.outputs.tool-build-key != '' && steps.cache-cargo-fuzz-build.outcome != 'failure' && steps.cache-cargo-fuzz-build.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R143));
    Value::Mapping(values)
}

fn node_195() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-fuzz-build-partial-restore"));
    values.insert(text("if"),text("steps.cache-cargo-fuzz-build-partial-context.outputs.seed-lookup-key != '' && steps.cache-cargo-fuzz.outputs.tool-build-key != '' && steps.cache-cargo-fuzz-build.outcome != 'failure' && steps.cache-cargo-fuzz-build.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_196());
    Value::Mapping(values)
}

fn node_196() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.cache-cargo-fuzz-build-partial-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.cache-cargo-fuzz-build-partial-context.outputs.seed-import-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.cache-cargo-fuzz-build-partial-context.outputs.seed-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_197() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-fuzz-build-partial-import"));
    values.insert(text("if"),text("steps.cache-cargo-fuzz-build-partial-restore.outcome == 'success' && steps.cache-cargo-fuzz-build-partial-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R144));
    Value::Mapping(values)
}

fn node_198() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("prepare-fuzz"));
    values.insert(
        text("if"),
        text("github.event_name != 'workflow_dispatch' || inputs.failure-mode != 'collect-all'"),
    );
    values.insert(text("run"), literal(LiteralRun::R145));
    Value::Mapping(values)
}

fn node_199() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("prepare-fuzz-diagnostic"));
    values.insert(
        text("if"),
        text("github.event_name == 'workflow_dispatch' && inputs.failure-mode == 'collect-all'"),
    );
    values.insert(text("run"), literal(LiteralRun::R146));
    Value::Mapping(values)
}

fn node_200() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-context-quarter-one"));
    values.insert(text("if"), text("matrix.shard == 'quarter-one'"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R147));
    Value::Mapping(values)
}

fn node_201() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-context-quarter-two"));
    values.insert(text("if"), text("matrix.shard == 'quarter-two'"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R148));
    Value::Mapping(values)
}

fn node_202() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-context-quarter-three"));
    values.insert(text("if"), text("matrix.shard == 'quarter-three'"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R149));
    Value::Mapping(values)
}

fn node_203() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-context-quarter-four"));
    values.insert(text("if"), text("matrix.shard == 'quarter-four'"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R150));
    Value::Mapping(values)
}

fn node_204() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-one"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"),text("matrix.shard == 'quarter-one' && steps.compiled-context-quarter-one.outputs.compiled-cache-usable == 'true'"));
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
        text("${{ steps.compiled-context-quarter-one.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.compiled-context-quarter-one.outputs.product-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.compiled-context-quarter-one.outputs.product-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_206() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize compiled-quarter-one discard restore"),
    );
    values.insert(
        text("id"),
        text("sanitize-fuzz-quarter-one-fuzz-targets-discard"),
    );
    values.insert(
        text("if"),
        text("steps.compiled-quarter-one.outcome == 'failure'"),
    );
    values.insert(text("run"), literal(LiteralRun::R151));
    Value::Mapping(values)
}

fn node_207() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize compiled-quarter-one exact restore"),
    );
    values.insert(
        text("id"),
        text("sanitize-fuzz-quarter-one-fuzz-targets-exact"),
    );
    values.insert(text("if"),text("steps.compiled-quarter-one.outcome == 'success' && steps.compiled-quarter-one.outputs.cache-hit == 'true'"));
    values.insert(text("run"), literal(LiteralRun::R152));
    Value::Mapping(values)
}

fn node_208() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize compiled-quarter-one compatible restore"),
    );
    values.insert(
        text("id"),
        text("sanitize-fuzz-quarter-one-fuzz-targets-compatible"),
    );
    values.insert(text("if"),text("steps.compiled-quarter-one.outcome == 'success' && steps.compiled-quarter-one.outputs.cache-matched-key != '' && steps.compiled-quarter-one.outputs.cache-hit != 'true'"));
    values.insert(text("run"), literal(LiteralRun::R153));
    Value::Mapping(values)
}

fn node_209() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-two"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"),text("matrix.shard == 'quarter-two' && steps.compiled-context-quarter-two.outputs.compiled-cache-usable == 'true'"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_210());
    Value::Mapping(values)
}

fn node_210() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.compiled-context-quarter-two.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.compiled-context-quarter-two.outputs.product-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.compiled-context-quarter-two.outputs.product-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_211() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize compiled-quarter-two discard restore"),
    );
    values.insert(
        text("id"),
        text("sanitize-fuzz-quarter-two-fuzz-targets-discard"),
    );
    values.insert(
        text("if"),
        text("steps.compiled-quarter-two.outcome == 'failure'"),
    );
    values.insert(text("run"), literal(LiteralRun::R154));
    Value::Mapping(values)
}

fn node_212() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize compiled-quarter-two exact restore"),
    );
    values.insert(
        text("id"),
        text("sanitize-fuzz-quarter-two-fuzz-targets-exact"),
    );
    values.insert(text("if"),text("steps.compiled-quarter-two.outcome == 'success' && steps.compiled-quarter-two.outputs.cache-hit == 'true'"));
    values.insert(text("run"), literal(LiteralRun::R155));
    Value::Mapping(values)
}

fn node_213() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize compiled-quarter-two compatible restore"),
    );
    values.insert(
        text("id"),
        text("sanitize-fuzz-quarter-two-fuzz-targets-compatible"),
    );
    values.insert(text("if"),text("steps.compiled-quarter-two.outcome == 'success' && steps.compiled-quarter-two.outputs.cache-matched-key != '' && steps.compiled-quarter-two.outputs.cache-hit != 'true'"));
    values.insert(text("run"), literal(LiteralRun::R156));
    Value::Mapping(values)
}

fn node_214() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-three"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"),text("matrix.shard == 'quarter-three' && steps.compiled-context-quarter-three.outputs.compiled-cache-usable == 'true'"));
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
        text("${{ steps.compiled-context-quarter-three.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.compiled-context-quarter-three.outputs.product-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.compiled-context-quarter-three.outputs.product-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_216() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize compiled-quarter-three discard restore"),
    );
    values.insert(
        text("id"),
        text("sanitize-fuzz-quarter-three-fuzz-targets-discard"),
    );
    values.insert(
        text("if"),
        text("steps.compiled-quarter-three.outcome == 'failure'"),
    );
    values.insert(text("run"), literal(LiteralRun::R157));
    Value::Mapping(values)
}

fn node_217() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize compiled-quarter-three exact restore"),
    );
    values.insert(
        text("id"),
        text("sanitize-fuzz-quarter-three-fuzz-targets-exact"),
    );
    values.insert(text("if"),text("steps.compiled-quarter-three.outcome == 'success' && steps.compiled-quarter-three.outputs.cache-hit == 'true'"));
    values.insert(text("run"), literal(LiteralRun::R158));
    Value::Mapping(values)
}

fn node_218() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize compiled-quarter-three compatible restore"),
    );
    values.insert(
        text("id"),
        text("sanitize-fuzz-quarter-three-fuzz-targets-compatible"),
    );
    values.insert(text("if"),text("steps.compiled-quarter-three.outcome == 'success' && steps.compiled-quarter-three.outputs.cache-matched-key != '' && steps.compiled-quarter-three.outputs.cache-hit != 'true'"));
    values.insert(text("run"), literal(LiteralRun::R159));
    Value::Mapping(values)
}

fn node_219() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-four"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"),text("matrix.shard == 'quarter-four' && steps.compiled-context-quarter-four.outputs.compiled-cache-usable == 'true'"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_220());
    Value::Mapping(values)
}

fn node_220() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.compiled-context-quarter-four.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.compiled-context-quarter-four.outputs.product-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.compiled-context-quarter-four.outputs.product-restore-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_221() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize compiled-quarter-four discard restore"),
    );
    values.insert(
        text("id"),
        text("sanitize-fuzz-quarter-four-fuzz-targets-discard"),
    );
    values.insert(
        text("if"),
        text("steps.compiled-quarter-four.outcome == 'failure'"),
    );
    values.insert(text("run"), literal(LiteralRun::R160));
    Value::Mapping(values)
}

fn node_222() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize compiled-quarter-four exact restore"),
    );
    values.insert(
        text("id"),
        text("sanitize-fuzz-quarter-four-fuzz-targets-exact"),
    );
    values.insert(text("if"),text("steps.compiled-quarter-four.outcome == 'success' && steps.compiled-quarter-four.outputs.cache-hit == 'true'"));
    values.insert(text("run"), literal(LiteralRun::R161));
    Value::Mapping(values)
}

fn node_223() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Sanitize compiled-quarter-four compatible restore"),
    );
    values.insert(
        text("id"),
        text("sanitize-fuzz-quarter-four-fuzz-targets-compatible"),
    );
    values.insert(text("if"),text("steps.compiled-quarter-four.outcome == 'success' && steps.compiled-quarter-four.outputs.cache-matched-key != '' && steps.compiled-quarter-four.outputs.cache-hit != 'true'"));
    values.insert(text("run"), literal(LiteralRun::R162));
    Value::Mapping(values)
}

fn node_224() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-one-seed-context"));
    values.insert(text("if"),text("matrix.shard == 'quarter-one' && steps.compiled-context-quarter-one.outputs.product-key != '' && steps.compiled-quarter-one.outputs.cache-matched-key == ''"));
    values.insert(text("run"), literal(LiteralRun::R163));
    Value::Mapping(values)
}

fn node_225() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-one-seed"));
    values.insert(
        text("if"),
        text("steps.fuzz-one-seed-context.outputs.seed-lookup-key != ''"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_226());
    Value::Mapping(values)
}

fn node_226() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.fuzz-one-seed-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.fuzz-one-seed-context.outputs.seed-restore-prefix }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.fuzz-one-seed-context.outputs.seed-import-path }}"),
    );
    Value::Mapping(values)
}

fn node_227() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("steps.fuzz-one-seed.outcome == 'success' && steps.fuzz-one-seed.outputs.cache-matched-key != ''"));
    values.insert(
        text("id"),
        text("import-compiled-fuzz-quarter-one-fuzz-targets"),
    );
    values.insert(text("run"), literal(LiteralRun::R164));
    Value::Mapping(values)
}

fn node_228() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-one-compile"));
    values.insert(text("if"),text("matrix.shard == 'quarter-one' && (github.event_name != 'workflow_dispatch' || inputs.failure-mode != 'collect-all')"));
    values.insert(text("run"), literal(LiteralRun::R165));
    Value::Mapping(values)
}

fn node_229() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-one-compile-diagnostic"));
    values.insert(text("if"),text("matrix.shard == 'quarter-one' && (github.event_name == 'workflow_dispatch' && inputs.failure-mode == 'collect-all')"));
    values.insert(text("run"), literal(LiteralRun::R166));
    Value::Mapping(values)
}

fn node_230() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-one-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz.outcome == 'skipped' || steps.prepare-fuzz.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz-diagnostic.outcome == 'skipped' || steps.prepare-fuzz-diagnostic.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-one-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-one-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile.outcome == 'skipped' || steps.fuzz-one-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile-diagnostic.outcome == 'skipped' || steps.fuzz-one-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.cache-cargo-fuzz-build-partial-import.outcome == 'skipped' || steps.cache-cargo-fuzz-build-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("run"), literal(LiteralRun::R167));
    Value::Mapping(values)
}

fn node_231() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-one-probe"));
    values.insert(text("if"),text("always() && steps.fuzz-one-snapshot.outputs.snapshot-ready == 'true' && steps.fuzz-one-snapshot.outputs.input-key == steps.compiled-context-quarter-one.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_232());
    Value::Mapping(values)
}

fn node_232() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.fuzz-one-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.fuzz-one-snapshot.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_233() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Retain settled fuzz dependencies"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.fuzz-one-snapshot.outputs.snapshot-ready == 'true' && steps.fuzz-one-snapshot.outputs.input-key == steps.compiled-context-quarter-one.outputs.product-key && steps.fuzz-one-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_234());
    Value::Mapping(values)
}

fn node_234() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.fuzz-one-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.fuzz-one-snapshot.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_235() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (steps.fuzz-one-snapshot.outcome == 'success' || steps.fuzz-one-snapshot.outcome == 'failure')"));
    values.insert(text("run"), literal(LiteralRun::R168));
    Value::Mapping(values)
}

fn node_236() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-one"));
    values.insert(text("if"),text("matrix.shard == 'quarter-one' && (github.event_name != 'workflow_dispatch' || inputs.failure-mode != 'collect-all')"));
    values.insert(text("run"), literal(LiteralRun::R169));
    Value::Mapping(values)
}

fn node_237() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-one-diagnostic"));
    values.insert(text("if"),text("matrix.shard == 'quarter-one' && (github.event_name == 'workflow_dispatch' && inputs.failure-mode == 'collect-all')"));
    values.insert(text("run"), literal(LiteralRun::R170));
    Value::Mapping(values)
}

fn node_238() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-two-seed-context"));
    values.insert(text("if"),text("matrix.shard == 'quarter-two' && steps.compiled-context-quarter-two.outputs.product-key != '' && steps.compiled-quarter-two.outputs.cache-matched-key == ''"));
    values.insert(text("run"), literal(LiteralRun::R171));
    Value::Mapping(values)
}

fn node_239() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-two-seed"));
    values.insert(
        text("if"),
        text("steps.fuzz-two-seed-context.outputs.seed-lookup-key != ''"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_240());
    Value::Mapping(values)
}

fn node_240() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.fuzz-two-seed-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.fuzz-two-seed-context.outputs.seed-restore-prefix }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.fuzz-two-seed-context.outputs.seed-import-path }}"),
    );
    Value::Mapping(values)
}

fn node_241() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("steps.fuzz-two-seed.outcome == 'success' && steps.fuzz-two-seed.outputs.cache-matched-key != ''"));
    values.insert(
        text("id"),
        text("import-compiled-fuzz-quarter-two-fuzz-targets"),
    );
    values.insert(text("run"), literal(LiteralRun::R172));
    Value::Mapping(values)
}

fn node_242() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-two-compile"));
    values.insert(text("if"),text("matrix.shard == 'quarter-two' && (github.event_name != 'workflow_dispatch' || inputs.failure-mode != 'collect-all')"));
    values.insert(text("run"), literal(LiteralRun::R173));
    Value::Mapping(values)
}

fn node_243() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-two-compile-diagnostic"));
    values.insert(text("if"),text("matrix.shard == 'quarter-two' && (github.event_name == 'workflow_dispatch' && inputs.failure-mode == 'collect-all')"));
    values.insert(text("run"), literal(LiteralRun::R174));
    Value::Mapping(values)
}

fn node_244() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-two-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz.outcome == 'skipped' || steps.prepare-fuzz.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz-diagnostic.outcome == 'skipped' || steps.prepare-fuzz-diagnostic.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-one-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-one-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile.outcome == 'skipped' || steps.fuzz-one-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile-diagnostic.outcome == 'skipped' || steps.fuzz-one-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-one.outcome == 'skipped' || steps.fuzz-one.outputs.cache-quiescent == 'true') && (steps.fuzz-one-diagnostic.outcome == 'skipped' || steps.fuzz-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-two-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-two-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile.outcome == 'skipped' || steps.fuzz-two-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile-diagnostic.outcome == 'skipped' || steps.fuzz-two-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.cache-cargo-fuzz-build-partial-import.outcome == 'skipped' || steps.cache-cargo-fuzz-build-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("run"), literal(LiteralRun::R175));
    Value::Mapping(values)
}

fn node_245() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-two-probe"));
    values.insert(text("if"),text("always() && steps.fuzz-two-snapshot.outputs.snapshot-ready == 'true' && steps.fuzz-two-snapshot.outputs.input-key == steps.compiled-context-quarter-two.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
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
        text("${{ steps.fuzz-two-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.fuzz-two-snapshot.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_247() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Retain settled fuzz dependencies"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.fuzz-two-snapshot.outputs.snapshot-ready == 'true' && steps.fuzz-two-snapshot.outputs.input-key == steps.compiled-context-quarter-two.outputs.product-key && steps.fuzz-two-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_248());
    Value::Mapping(values)
}

fn node_248() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.fuzz-two-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.fuzz-two-snapshot.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_249() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (steps.fuzz-two-snapshot.outcome == 'success' || steps.fuzz-two-snapshot.outcome == 'failure')"));
    values.insert(text("run"), literal(LiteralRun::R176));
    Value::Mapping(values)
}

fn node_250() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-two"));
    values.insert(text("if"),text("matrix.shard == 'quarter-two' && (github.event_name != 'workflow_dispatch' || inputs.failure-mode != 'collect-all')"));
    values.insert(text("run"), literal(LiteralRun::R177));
    Value::Mapping(values)
}

fn node_251() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-two-diagnostic"));
    values.insert(text("if"),text("matrix.shard == 'quarter-two' && (github.event_name == 'workflow_dispatch' && inputs.failure-mode == 'collect-all')"));
    values.insert(text("run"), literal(LiteralRun::R178));
    Value::Mapping(values)
}

fn node_252() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-three-seed-context"));
    values.insert(text("if"),text("matrix.shard == 'quarter-three' && steps.compiled-context-quarter-three.outputs.product-key != '' && steps.compiled-quarter-three.outputs.cache-matched-key == ''"));
    values.insert(text("run"), literal(LiteralRun::R179));
    Value::Mapping(values)
}

fn node_253() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-three-seed"));
    values.insert(
        text("if"),
        text("steps.fuzz-three-seed-context.outputs.seed-lookup-key != ''"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_254());
    Value::Mapping(values)
}

fn node_254() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.fuzz-three-seed-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.fuzz-three-seed-context.outputs.seed-restore-prefix }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.fuzz-three-seed-context.outputs.seed-import-path }}"),
    );
    Value::Mapping(values)
}

fn node_255() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("steps.fuzz-three-seed.outcome == 'success' && steps.fuzz-three-seed.outputs.cache-matched-key != ''"));
    values.insert(
        text("id"),
        text("import-compiled-fuzz-quarter-three-fuzz-targets"),
    );
    values.insert(text("run"), literal(LiteralRun::R180));
    Value::Mapping(values)
}

fn node_256() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-three-compile"));
    values.insert(text("if"),text("matrix.shard == 'quarter-three' && (github.event_name != 'workflow_dispatch' || inputs.failure-mode != 'collect-all')"));
    values.insert(text("run"), literal(LiteralRun::R181));
    Value::Mapping(values)
}

fn node_257() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-three-compile-diagnostic"));
    values.insert(text("if"),text("matrix.shard == 'quarter-three' && (github.event_name == 'workflow_dispatch' && inputs.failure-mode == 'collect-all')"));
    values.insert(text("run"), literal(LiteralRun::R182));
    Value::Mapping(values)
}

fn node_258() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-three-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz.outcome == 'skipped' || steps.prepare-fuzz.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz-diagnostic.outcome == 'skipped' || steps.prepare-fuzz-diagnostic.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-one-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-one-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile.outcome == 'skipped' || steps.fuzz-one-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile-diagnostic.outcome == 'skipped' || steps.fuzz-one-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-one.outcome == 'skipped' || steps.fuzz-one.outputs.cache-quiescent == 'true') && (steps.fuzz-one-diagnostic.outcome == 'skipped' || steps.fuzz-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-two-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-two-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile.outcome == 'skipped' || steps.fuzz-two-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile-diagnostic.outcome == 'skipped' || steps.fuzz-two-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-two.outcome == 'skipped' || steps.fuzz-two.outputs.cache-quiescent == 'true') && (steps.fuzz-two-diagnostic.outcome == 'skipped' || steps.fuzz-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-three-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-three-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile.outcome == 'skipped' || steps.fuzz-three-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile-diagnostic.outcome == 'skipped' || steps.fuzz-three-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.cache-cargo-fuzz-build-partial-import.outcome == 'skipped' || steps.cache-cargo-fuzz-build-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("run"), literal(LiteralRun::R183));
    Value::Mapping(values)
}

fn node_259() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-three-probe"));
    values.insert(text("if"),text("always() && steps.fuzz-three-snapshot.outputs.snapshot-ready == 'true' && steps.fuzz-three-snapshot.outputs.input-key == steps.compiled-context-quarter-three.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_260());
    Value::Mapping(values)
}

fn node_260() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.fuzz-three-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.fuzz-three-snapshot.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_261() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Retain settled fuzz dependencies"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.fuzz-three-snapshot.outputs.snapshot-ready == 'true' && steps.fuzz-three-snapshot.outputs.input-key == steps.compiled-context-quarter-three.outputs.product-key && steps.fuzz-three-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_262());
    Value::Mapping(values)
}

fn node_262() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.fuzz-three-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.fuzz-three-snapshot.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_263() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (steps.fuzz-three-snapshot.outcome == 'success' || steps.fuzz-three-snapshot.outcome == 'failure')"));
    values.insert(text("run"), literal(LiteralRun::R184));
    Value::Mapping(values)
}

fn node_264() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-three"));
    values.insert(text("if"),text("matrix.shard == 'quarter-three' && (github.event_name != 'workflow_dispatch' || inputs.failure-mode != 'collect-all')"));
    values.insert(text("run"), literal(LiteralRun::R185));
    Value::Mapping(values)
}

fn node_265() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-three-diagnostic"));
    values.insert(text("if"),text("matrix.shard == 'quarter-three' && (github.event_name == 'workflow_dispatch' && inputs.failure-mode == 'collect-all')"));
    values.insert(text("run"), literal(LiteralRun::R186));
    Value::Mapping(values)
}

fn node_266() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-four-seed-context"));
    values.insert(text("if"),text("matrix.shard == 'quarter-four' && steps.compiled-context-quarter-four.outputs.product-key != '' && steps.compiled-quarter-four.outputs.cache-matched-key == ''"));
    values.insert(text("run"), literal(LiteralRun::R187));
    Value::Mapping(values)
}

fn node_267() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-four-seed"));
    values.insert(
        text("if"),
        text("steps.fuzz-four-seed-context.outputs.seed-lookup-key != ''"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_268());
    Value::Mapping(values)
}

fn node_268() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.fuzz-four-seed-context.outputs.seed-lookup-key }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.fuzz-four-seed-context.outputs.seed-restore-prefix }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.fuzz-four-seed-context.outputs.seed-import-path }}"),
    );
    Value::Mapping(values)
}

fn node_269() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("steps.fuzz-four-seed.outcome == 'success' && steps.fuzz-four-seed.outputs.cache-matched-key != ''"));
    values.insert(
        text("id"),
        text("import-compiled-fuzz-quarter-four-fuzz-targets"),
    );
    values.insert(text("run"), literal(LiteralRun::R188));
    Value::Mapping(values)
}

fn node_270() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-four-compile"));
    values.insert(text("if"),text("matrix.shard == 'quarter-four' && (github.event_name != 'workflow_dispatch' || inputs.failure-mode != 'collect-all')"));
    values.insert(text("run"), literal(LiteralRun::R189));
    Value::Mapping(values)
}

fn node_271() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-four-compile-diagnostic"));
    values.insert(text("if"),text("matrix.shard == 'quarter-four' && (github.event_name == 'workflow_dispatch' && inputs.failure-mode == 'collect-all')"));
    values.insert(text("run"), literal(LiteralRun::R190));
    Value::Mapping(values)
}

fn node_272() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-four-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz.outcome == 'skipped' || steps.prepare-fuzz.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz-diagnostic.outcome == 'skipped' || steps.prepare-fuzz-diagnostic.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-one-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-one-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile.outcome == 'skipped' || steps.fuzz-one-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile-diagnostic.outcome == 'skipped' || steps.fuzz-one-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-one.outcome == 'skipped' || steps.fuzz-one.outputs.cache-quiescent == 'true') && (steps.fuzz-one-diagnostic.outcome == 'skipped' || steps.fuzz-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-two-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-two-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile.outcome == 'skipped' || steps.fuzz-two-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile-diagnostic.outcome == 'skipped' || steps.fuzz-two-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-two.outcome == 'skipped' || steps.fuzz-two.outputs.cache-quiescent == 'true') && (steps.fuzz-two-diagnostic.outcome == 'skipped' || steps.fuzz-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-three-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-three-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile.outcome == 'skipped' || steps.fuzz-three-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile-diagnostic.outcome == 'skipped' || steps.fuzz-three-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-three.outcome == 'skipped' || steps.fuzz-three.outputs.cache-quiescent == 'true') && (steps.fuzz-three-diagnostic.outcome == 'skipped' || steps.fuzz-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-four-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-four-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile.outcome == 'skipped' || steps.fuzz-four-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile-diagnostic.outcome == 'skipped' || steps.fuzz-four-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.cache-cargo-fuzz-build-partial-import.outcome == 'skipped' || steps.cache-cargo-fuzz-build-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("run"), literal(LiteralRun::R191));
    Value::Mapping(values)
}

fn node_273() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-four-probe"));
    values.insert(text("if"),text("always() && steps.fuzz-four-snapshot.outputs.snapshot-ready == 'true' && steps.fuzz-four-snapshot.outputs.input-key == steps.compiled-context-quarter-four.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_274());
    Value::Mapping(values)
}

fn node_274() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.fuzz-four-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.fuzz-four-snapshot.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_275() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Retain settled fuzz dependencies"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.fuzz-four-snapshot.outputs.snapshot-ready == 'true' && steps.fuzz-four-snapshot.outputs.input-key == steps.compiled-context-quarter-four.outputs.product-key && steps.fuzz-four-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_276());
    Value::Mapping(values)
}

fn node_276() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.fuzz-four-snapshot.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.fuzz-four-snapshot.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_277() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (steps.fuzz-four-snapshot.outcome == 'success' || steps.fuzz-four-snapshot.outcome == 'failure')"));
    values.insert(text("run"), literal(LiteralRun::R192));
    Value::Mapping(values)
}

fn node_278() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-four"));
    values.insert(text("if"),text("matrix.shard == 'quarter-four' && (github.event_name != 'workflow_dispatch' || inputs.failure-mode != 'collect-all')"));
    values.insert(text("run"), literal(LiteralRun::R193));
    Value::Mapping(values)
}

fn node_279() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-four-diagnostic"));
    values.insert(text("if"),text("matrix.shard == 'quarter-four' && (github.event_name == 'workflow_dispatch' && inputs.failure-mode == 'collect-all')"));
    values.insert(text("run"), literal(LiteralRun::R194));
    Value::Mapping(values)
}

fn node_280() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("always()"));
    values.insert(text("uses"), text("./.github/actions/upload-artifact"));
    values.insert(text("with"), node_281());
    Value::Mapping(values)
}

fn node_281() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("fuzz-plan-${{ matrix.shard }}"));
    values.insert(text("path"), text("target/ci/reports/fuzz"));
    values.insert(text("if-no-files-found"), text("warn"));
    Value::Mapping(values)
}

fn node_282() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-one-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz.outcome == 'skipped' || steps.prepare-fuzz.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz-diagnostic.outcome == 'skipped' || steps.prepare-fuzz-diagnostic.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-one-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-one-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile.outcome == 'skipped' || steps.fuzz-one-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile-diagnostic.outcome == 'skipped' || steps.fuzz-one-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-one.outcome == 'skipped' || steps.fuzz-one.outputs.cache-quiescent == 'true') && (steps.fuzz-one-diagnostic.outcome == 'skipped' || steps.fuzz-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-two-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-two-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile.outcome == 'skipped' || steps.fuzz-two-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile-diagnostic.outcome == 'skipped' || steps.fuzz-two-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-two.outcome == 'skipped' || steps.fuzz-two.outputs.cache-quiescent == 'true') && (steps.fuzz-two-diagnostic.outcome == 'skipped' || steps.fuzz-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-three-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-three-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile.outcome == 'skipped' || steps.fuzz-three-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile-diagnostic.outcome == 'skipped' || steps.fuzz-three-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-three.outcome == 'skipped' || steps.fuzz-three.outputs.cache-quiescent == 'true') && (steps.fuzz-three-diagnostic.outcome == 'skipped' || steps.fuzz-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-four-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-four-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile.outcome == 'skipped' || steps.fuzz-four-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile-diagnostic.outcome == 'skipped' || steps.fuzz-four-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-four.outcome == 'skipped' || steps.fuzz-four.outputs.cache-quiescent == 'true') && (steps.fuzz-four-diagnostic.outcome == 'skipped' || steps.fuzz-four-diagnostic.outputs.cache-quiescent == 'true') && steps.compiled-context-quarter-one.outputs.compiled-cache-usable == 'true' && matrix.shard == 'quarter-one' && (steps.cache-cargo-fuzz-build-partial-import.outcome == 'skipped' || steps.cache-cargo-fuzz-build-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R195));
    Value::Mapping(values)
}

fn node_283() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz.outcome == 'skipped' || steps.prepare-fuzz.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz-diagnostic.outcome == 'skipped' || steps.prepare-fuzz-diagnostic.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-one-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-one-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile.outcome == 'skipped' || steps.fuzz-one-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile-diagnostic.outcome == 'skipped' || steps.fuzz-one-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-one.outcome == 'skipped' || steps.fuzz-one.outputs.cache-quiescent == 'true') && (steps.fuzz-one-diagnostic.outcome == 'skipped' || steps.fuzz-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-two-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-two-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile.outcome == 'skipped' || steps.fuzz-two-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile-diagnostic.outcome == 'skipped' || steps.fuzz-two-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-two.outcome == 'skipped' || steps.fuzz-two.outputs.cache-quiescent == 'true') && (steps.fuzz-two-diagnostic.outcome == 'skipped' || steps.fuzz-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-three-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-three-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile.outcome == 'skipped' || steps.fuzz-three-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile-diagnostic.outcome == 'skipped' || steps.fuzz-three-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-three.outcome == 'skipped' || steps.fuzz-three.outputs.cache-quiescent == 'true') && (steps.fuzz-three-diagnostic.outcome == 'skipped' || steps.fuzz-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-four-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-four-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile.outcome == 'skipped' || steps.fuzz-four-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile-diagnostic.outcome == 'skipped' || steps.fuzz-four-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-four.outcome == 'skipped' || steps.fuzz-four.outputs.cache-quiescent == 'true') && (steps.fuzz-four-diagnostic.outcome == 'skipped' || steps.fuzz-four-diagnostic.outputs.cache-quiescent == 'true') && steps.compiled-context-quarter-one.outputs.product-key != '' && steps.compiled-quarter-one-save-context.outcome == 'success' && steps.compiled-quarter-one-save-context.outputs.product-key == steps.compiled-context-quarter-one.outputs.product-key && steps.compiled-quarter-one-save-context.outputs.payload-ready == 'true' && ((steps.fuzz-one.outputs.compiled-recipe-complete == 'true' || steps.fuzz-one-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-one-compile.outcome == 'skipped' || steps.fuzz-one-compile.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-one-compile-diagnostic.outcome == 'skipped' || steps.fuzz-one-compile-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-one.outcome == 'skipped' || steps.fuzz-one.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-one-diagnostic.outcome == 'skipped' || steps.fuzz-one-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-two-compile.outcome == 'skipped' || steps.fuzz-two-compile.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-two-compile-diagnostic.outcome == 'skipped' || steps.fuzz-two-compile-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-two.outcome == 'skipped' || steps.fuzz-two.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-two-diagnostic.outcome == 'skipped' || steps.fuzz-two-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-three-compile.outcome == 'skipped' || steps.fuzz-three-compile.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-three-compile-diagnostic.outcome == 'skipped' || steps.fuzz-three-compile-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-three.outcome == 'skipped' || steps.fuzz-three.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-three-diagnostic.outcome == 'skipped' || steps.fuzz-three-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-four-compile.outcome == 'skipped' || steps.fuzz-four-compile.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-four-compile-diagnostic.outcome == 'skipped' || steps.fuzz-four-compile-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-four.outcome == 'skipped' || steps.fuzz-four.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-four-diagnostic.outcome == 'skipped' || steps.fuzz-four-diagnostic.outputs.compiled-recipe-complete == 'true')) && !(steps.compiled-quarter-one.outcome == 'success' && steps.compiled-quarter-one.outputs.cache-hit == 'true') && matrix.shard == 'quarter-one' && (steps.cache-cargo-fuzz-build-partial-import.outcome == 'skipped' || steps.cache-cargo-fuzz-build-partial-import.outputs.cache-quiescent == 'true') && steps.compiled-context-quarter-one.outputs.product-paths != '' && steps.compiled-context-quarter-one.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_284());
    Value::Mapping(values)
}

fn node_284() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.compiled-context-quarter-one.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.compiled-context-quarter-one.outputs.product-key }}"),
    );
    Value::Mapping(values)
}

fn node_285() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-two-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz.outcome == 'skipped' || steps.prepare-fuzz.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz-diagnostic.outcome == 'skipped' || steps.prepare-fuzz-diagnostic.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-one-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-one-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile.outcome == 'skipped' || steps.fuzz-one-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile-diagnostic.outcome == 'skipped' || steps.fuzz-one-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-one.outcome == 'skipped' || steps.fuzz-one.outputs.cache-quiescent == 'true') && (steps.fuzz-one-diagnostic.outcome == 'skipped' || steps.fuzz-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-two-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-two-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile.outcome == 'skipped' || steps.fuzz-two-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile-diagnostic.outcome == 'skipped' || steps.fuzz-two-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-two.outcome == 'skipped' || steps.fuzz-two.outputs.cache-quiescent == 'true') && (steps.fuzz-two-diagnostic.outcome == 'skipped' || steps.fuzz-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-three-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-three-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile.outcome == 'skipped' || steps.fuzz-three-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile-diagnostic.outcome == 'skipped' || steps.fuzz-three-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-three.outcome == 'skipped' || steps.fuzz-three.outputs.cache-quiescent == 'true') && (steps.fuzz-three-diagnostic.outcome == 'skipped' || steps.fuzz-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-four-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-four-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile.outcome == 'skipped' || steps.fuzz-four-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile-diagnostic.outcome == 'skipped' || steps.fuzz-four-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-four.outcome == 'skipped' || steps.fuzz-four.outputs.cache-quiescent == 'true') && (steps.fuzz-four-diagnostic.outcome == 'skipped' || steps.fuzz-four-diagnostic.outputs.cache-quiescent == 'true') && steps.compiled-context-quarter-two.outputs.compiled-cache-usable == 'true' && matrix.shard == 'quarter-two' && (steps.cache-cargo-fuzz-build-partial-import.outcome == 'skipped' || steps.cache-cargo-fuzz-build-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R196));
    Value::Mapping(values)
}

fn node_286() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz.outcome == 'skipped' || steps.prepare-fuzz.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz-diagnostic.outcome == 'skipped' || steps.prepare-fuzz-diagnostic.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-one-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-one-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile.outcome == 'skipped' || steps.fuzz-one-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile-diagnostic.outcome == 'skipped' || steps.fuzz-one-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-one.outcome == 'skipped' || steps.fuzz-one.outputs.cache-quiescent == 'true') && (steps.fuzz-one-diagnostic.outcome == 'skipped' || steps.fuzz-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-two-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-two-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile.outcome == 'skipped' || steps.fuzz-two-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile-diagnostic.outcome == 'skipped' || steps.fuzz-two-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-two.outcome == 'skipped' || steps.fuzz-two.outputs.cache-quiescent == 'true') && (steps.fuzz-two-diagnostic.outcome == 'skipped' || steps.fuzz-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-three-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-three-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile.outcome == 'skipped' || steps.fuzz-three-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile-diagnostic.outcome == 'skipped' || steps.fuzz-three-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-three.outcome == 'skipped' || steps.fuzz-three.outputs.cache-quiescent == 'true') && (steps.fuzz-three-diagnostic.outcome == 'skipped' || steps.fuzz-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-four-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-four-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile.outcome == 'skipped' || steps.fuzz-four-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile-diagnostic.outcome == 'skipped' || steps.fuzz-four-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-four.outcome == 'skipped' || steps.fuzz-four.outputs.cache-quiescent == 'true') && (steps.fuzz-four-diagnostic.outcome == 'skipped' || steps.fuzz-four-diagnostic.outputs.cache-quiescent == 'true') && steps.compiled-context-quarter-two.outputs.product-key != '' && steps.compiled-quarter-two-save-context.outcome == 'success' && steps.compiled-quarter-two-save-context.outputs.product-key == steps.compiled-context-quarter-two.outputs.product-key && steps.compiled-quarter-two-save-context.outputs.payload-ready == 'true' && ((steps.fuzz-two.outputs.compiled-recipe-complete == 'true' || steps.fuzz-two-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-one-compile.outcome == 'skipped' || steps.fuzz-one-compile.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-one-compile-diagnostic.outcome == 'skipped' || steps.fuzz-one-compile-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-one.outcome == 'skipped' || steps.fuzz-one.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-one-diagnostic.outcome == 'skipped' || steps.fuzz-one-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-two-compile.outcome == 'skipped' || steps.fuzz-two-compile.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-two-compile-diagnostic.outcome == 'skipped' || steps.fuzz-two-compile-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-two.outcome == 'skipped' || steps.fuzz-two.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-two-diagnostic.outcome == 'skipped' || steps.fuzz-two-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-three-compile.outcome == 'skipped' || steps.fuzz-three-compile.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-three-compile-diagnostic.outcome == 'skipped' || steps.fuzz-three-compile-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-three.outcome == 'skipped' || steps.fuzz-three.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-three-diagnostic.outcome == 'skipped' || steps.fuzz-three-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-four-compile.outcome == 'skipped' || steps.fuzz-four-compile.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-four-compile-diagnostic.outcome == 'skipped' || steps.fuzz-four-compile-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-four.outcome == 'skipped' || steps.fuzz-four.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-four-diagnostic.outcome == 'skipped' || steps.fuzz-four-diagnostic.outputs.compiled-recipe-complete == 'true')) && !(steps.compiled-quarter-two.outcome == 'success' && steps.compiled-quarter-two.outputs.cache-hit == 'true') && matrix.shard == 'quarter-two' && (steps.cache-cargo-fuzz-build-partial-import.outcome == 'skipped' || steps.cache-cargo-fuzz-build-partial-import.outputs.cache-quiescent == 'true') && steps.compiled-context-quarter-two.outputs.product-paths != '' && steps.compiled-context-quarter-two.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_287());
    Value::Mapping(values)
}

fn node_287() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.compiled-context-quarter-two.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.compiled-context-quarter-two.outputs.product-key }}"),
    );
    Value::Mapping(values)
}

fn node_288() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-three-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz.outcome == 'skipped' || steps.prepare-fuzz.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz-diagnostic.outcome == 'skipped' || steps.prepare-fuzz-diagnostic.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-one-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-one-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile.outcome == 'skipped' || steps.fuzz-one-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile-diagnostic.outcome == 'skipped' || steps.fuzz-one-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-one.outcome == 'skipped' || steps.fuzz-one.outputs.cache-quiescent == 'true') && (steps.fuzz-one-diagnostic.outcome == 'skipped' || steps.fuzz-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-two-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-two-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile.outcome == 'skipped' || steps.fuzz-two-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile-diagnostic.outcome == 'skipped' || steps.fuzz-two-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-two.outcome == 'skipped' || steps.fuzz-two.outputs.cache-quiescent == 'true') && (steps.fuzz-two-diagnostic.outcome == 'skipped' || steps.fuzz-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-three-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-three-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile.outcome == 'skipped' || steps.fuzz-three-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile-diagnostic.outcome == 'skipped' || steps.fuzz-three-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-three.outcome == 'skipped' || steps.fuzz-three.outputs.cache-quiescent == 'true') && (steps.fuzz-three-diagnostic.outcome == 'skipped' || steps.fuzz-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-four-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-four-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile.outcome == 'skipped' || steps.fuzz-four-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile-diagnostic.outcome == 'skipped' || steps.fuzz-four-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-four.outcome == 'skipped' || steps.fuzz-four.outputs.cache-quiescent == 'true') && (steps.fuzz-four-diagnostic.outcome == 'skipped' || steps.fuzz-four-diagnostic.outputs.cache-quiescent == 'true') && steps.compiled-context-quarter-three.outputs.compiled-cache-usable == 'true' && matrix.shard == 'quarter-three' && (steps.cache-cargo-fuzz-build-partial-import.outcome == 'skipped' || steps.cache-cargo-fuzz-build-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R197));
    Value::Mapping(values)
}

fn node_289() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz.outcome == 'skipped' || steps.prepare-fuzz.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz-diagnostic.outcome == 'skipped' || steps.prepare-fuzz-diagnostic.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-one-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-one-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile.outcome == 'skipped' || steps.fuzz-one-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile-diagnostic.outcome == 'skipped' || steps.fuzz-one-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-one.outcome == 'skipped' || steps.fuzz-one.outputs.cache-quiescent == 'true') && (steps.fuzz-one-diagnostic.outcome == 'skipped' || steps.fuzz-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-two-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-two-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile.outcome == 'skipped' || steps.fuzz-two-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile-diagnostic.outcome == 'skipped' || steps.fuzz-two-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-two.outcome == 'skipped' || steps.fuzz-two.outputs.cache-quiescent == 'true') && (steps.fuzz-two-diagnostic.outcome == 'skipped' || steps.fuzz-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-three-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-three-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile.outcome == 'skipped' || steps.fuzz-three-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile-diagnostic.outcome == 'skipped' || steps.fuzz-three-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-three.outcome == 'skipped' || steps.fuzz-three.outputs.cache-quiescent == 'true') && (steps.fuzz-three-diagnostic.outcome == 'skipped' || steps.fuzz-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-four-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-four-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile.outcome == 'skipped' || steps.fuzz-four-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile-diagnostic.outcome == 'skipped' || steps.fuzz-four-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-four.outcome == 'skipped' || steps.fuzz-four.outputs.cache-quiescent == 'true') && (steps.fuzz-four-diagnostic.outcome == 'skipped' || steps.fuzz-four-diagnostic.outputs.cache-quiescent == 'true') && steps.compiled-context-quarter-three.outputs.product-key != '' && steps.compiled-quarter-three-save-context.outcome == 'success' && steps.compiled-quarter-three-save-context.outputs.product-key == steps.compiled-context-quarter-three.outputs.product-key && steps.compiled-quarter-three-save-context.outputs.payload-ready == 'true' && ((steps.fuzz-three.outputs.compiled-recipe-complete == 'true' || steps.fuzz-three-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-one-compile.outcome == 'skipped' || steps.fuzz-one-compile.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-one-compile-diagnostic.outcome == 'skipped' || steps.fuzz-one-compile-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-one.outcome == 'skipped' || steps.fuzz-one.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-one-diagnostic.outcome == 'skipped' || steps.fuzz-one-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-two-compile.outcome == 'skipped' || steps.fuzz-two-compile.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-two-compile-diagnostic.outcome == 'skipped' || steps.fuzz-two-compile-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-two.outcome == 'skipped' || steps.fuzz-two.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-two-diagnostic.outcome == 'skipped' || steps.fuzz-two-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-three-compile.outcome == 'skipped' || steps.fuzz-three-compile.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-three-compile-diagnostic.outcome == 'skipped' || steps.fuzz-three-compile-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-three.outcome == 'skipped' || steps.fuzz-three.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-three-diagnostic.outcome == 'skipped' || steps.fuzz-three-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-four-compile.outcome == 'skipped' || steps.fuzz-four-compile.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-four-compile-diagnostic.outcome == 'skipped' || steps.fuzz-four-compile-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-four.outcome == 'skipped' || steps.fuzz-four.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-four-diagnostic.outcome == 'skipped' || steps.fuzz-four-diagnostic.outputs.compiled-recipe-complete == 'true')) && !(steps.compiled-quarter-three.outcome == 'success' && steps.compiled-quarter-three.outputs.cache-hit == 'true') && matrix.shard == 'quarter-three' && (steps.cache-cargo-fuzz-build-partial-import.outcome == 'skipped' || steps.cache-cargo-fuzz-build-partial-import.outputs.cache-quiescent == 'true') && steps.compiled-context-quarter-three.outputs.product-paths != '' && steps.compiled-context-quarter-three.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_290());
    Value::Mapping(values)
}

fn node_290() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.compiled-context-quarter-three.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.compiled-context-quarter-three.outputs.product-key }}"),
    );
    Value::Mapping(values)
}

fn node_291() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-quarter-four-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz.outcome == 'skipped' || steps.prepare-fuzz.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz-diagnostic.outcome == 'skipped' || steps.prepare-fuzz-diagnostic.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-one-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-one-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile.outcome == 'skipped' || steps.fuzz-one-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile-diagnostic.outcome == 'skipped' || steps.fuzz-one-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-one.outcome == 'skipped' || steps.fuzz-one.outputs.cache-quiescent == 'true') && (steps.fuzz-one-diagnostic.outcome == 'skipped' || steps.fuzz-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-two-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-two-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile.outcome == 'skipped' || steps.fuzz-two-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile-diagnostic.outcome == 'skipped' || steps.fuzz-two-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-two.outcome == 'skipped' || steps.fuzz-two.outputs.cache-quiescent == 'true') && (steps.fuzz-two-diagnostic.outcome == 'skipped' || steps.fuzz-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-three-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-three-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile.outcome == 'skipped' || steps.fuzz-three-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile-diagnostic.outcome == 'skipped' || steps.fuzz-three-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-three.outcome == 'skipped' || steps.fuzz-three.outputs.cache-quiescent == 'true') && (steps.fuzz-three-diagnostic.outcome == 'skipped' || steps.fuzz-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-four-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-four-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile.outcome == 'skipped' || steps.fuzz-four-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile-diagnostic.outcome == 'skipped' || steps.fuzz-four-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-four.outcome == 'skipped' || steps.fuzz-four.outputs.cache-quiescent == 'true') && (steps.fuzz-four-diagnostic.outcome == 'skipped' || steps.fuzz-four-diagnostic.outputs.cache-quiescent == 'true') && steps.compiled-context-quarter-four.outputs.compiled-cache-usable == 'true' && matrix.shard == 'quarter-four' && (steps.cache-cargo-fuzz-build-partial-import.outcome == 'skipped' || steps.cache-cargo-fuzz-build-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R198));
    Value::Mapping(values)
}

fn node_292() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz.outcome == 'skipped' || steps.prepare-fuzz.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz-diagnostic.outcome == 'skipped' || steps.prepare-fuzz-diagnostic.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-one-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-one-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile.outcome == 'skipped' || steps.fuzz-one-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile-diagnostic.outcome == 'skipped' || steps.fuzz-one-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-one.outcome == 'skipped' || steps.fuzz-one.outputs.cache-quiescent == 'true') && (steps.fuzz-one-diagnostic.outcome == 'skipped' || steps.fuzz-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-two-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-two-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile.outcome == 'skipped' || steps.fuzz-two-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile-diagnostic.outcome == 'skipped' || steps.fuzz-two-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-two.outcome == 'skipped' || steps.fuzz-two.outputs.cache-quiescent == 'true') && (steps.fuzz-two-diagnostic.outcome == 'skipped' || steps.fuzz-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-three-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-three-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile.outcome == 'skipped' || steps.fuzz-three-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile-diagnostic.outcome == 'skipped' || steps.fuzz-three-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-three.outcome == 'skipped' || steps.fuzz-three.outputs.cache-quiescent == 'true') && (steps.fuzz-three-diagnostic.outcome == 'skipped' || steps.fuzz-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-four-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-four-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile.outcome == 'skipped' || steps.fuzz-four-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile-diagnostic.outcome == 'skipped' || steps.fuzz-four-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-four.outcome == 'skipped' || steps.fuzz-four.outputs.cache-quiescent == 'true') && (steps.fuzz-four-diagnostic.outcome == 'skipped' || steps.fuzz-four-diagnostic.outputs.cache-quiescent == 'true') && steps.compiled-context-quarter-four.outputs.product-key != '' && steps.compiled-quarter-four-save-context.outcome == 'success' && steps.compiled-quarter-four-save-context.outputs.product-key == steps.compiled-context-quarter-four.outputs.product-key && steps.compiled-quarter-four-save-context.outputs.payload-ready == 'true' && ((steps.fuzz-four.outputs.compiled-recipe-complete == 'true' || steps.fuzz-four-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-one-compile.outcome == 'skipped' || steps.fuzz-one-compile.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-one-compile-diagnostic.outcome == 'skipped' || steps.fuzz-one-compile-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-one.outcome == 'skipped' || steps.fuzz-one.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-one-diagnostic.outcome == 'skipped' || steps.fuzz-one-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-two-compile.outcome == 'skipped' || steps.fuzz-two-compile.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-two-compile-diagnostic.outcome == 'skipped' || steps.fuzz-two-compile-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-two.outcome == 'skipped' || steps.fuzz-two.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-two-diagnostic.outcome == 'skipped' || steps.fuzz-two-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-three-compile.outcome == 'skipped' || steps.fuzz-three-compile.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-three-compile-diagnostic.outcome == 'skipped' || steps.fuzz-three-compile-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-three.outcome == 'skipped' || steps.fuzz-three.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-three-diagnostic.outcome == 'skipped' || steps.fuzz-three-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-four-compile.outcome == 'skipped' || steps.fuzz-four-compile.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-four-compile-diagnostic.outcome == 'skipped' || steps.fuzz-four-compile-diagnostic.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-four.outcome == 'skipped' || steps.fuzz-four.outputs.compiled-recipe-complete == 'true') && (steps.fuzz-four-diagnostic.outcome == 'skipped' || steps.fuzz-four-diagnostic.outputs.compiled-recipe-complete == 'true')) && !(steps.compiled-quarter-four.outcome == 'success' && steps.compiled-quarter-four.outputs.cache-hit == 'true') && matrix.shard == 'quarter-four' && (steps.cache-cargo-fuzz-build-partial-import.outcome == 'skipped' || steps.cache-cargo-fuzz-build-partial-import.outputs.cache-quiescent == 'true') && steps.compiled-context-quarter-four.outputs.product-paths != '' && steps.compiled-context-quarter-four.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_293());
    Value::Mapping(values)
}

fn node_293() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.compiled-context-quarter-four.outputs.product-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.compiled-context-quarter-four.outputs.product-key }}"),
    );
    Value::Mapping(values)
}

fn node_294() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("fuzz-download-save-context"));
    values.insert(text("if"),text("always() && (steps.prepare-fuzz.outputs.cache-quiescent || steps.prepare-fuzz-diagnostic.outputs.cache-quiescent) == 'true' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.cache-cargo-fuzz-build-partial-import.outcome == 'skipped' || steps.cache-cargo-fuzz-build-partial-import.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz.outcome == 'skipped' || steps.prepare-fuzz.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz-diagnostic.outcome == 'skipped' || steps.prepare-fuzz-diagnostic.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-one-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-one-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile.outcome == 'skipped' || steps.fuzz-one-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile-diagnostic.outcome == 'skipped' || steps.fuzz-one-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-one.outcome == 'skipped' || steps.fuzz-one.outputs.cache-quiescent == 'true') && (steps.fuzz-one-diagnostic.outcome == 'skipped' || steps.fuzz-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-two-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-two-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile.outcome == 'skipped' || steps.fuzz-two-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile-diagnostic.outcome == 'skipped' || steps.fuzz-two-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-two.outcome == 'skipped' || steps.fuzz-two.outputs.cache-quiescent == 'true') && (steps.fuzz-two-diagnostic.outcome == 'skipped' || steps.fuzz-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-three-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-three-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile.outcome == 'skipped' || steps.fuzz-three-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile-diagnostic.outcome == 'skipped' || steps.fuzz-three-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-three.outcome == 'skipped' || steps.fuzz-three.outputs.cache-quiescent == 'true') && (steps.fuzz-three-diagnostic.outcome == 'skipped' || steps.fuzz-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-four-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-four-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile.outcome == 'skipped' || steps.fuzz-four-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile-diagnostic.outcome == 'skipped' || steps.fuzz-four-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-four.outcome == 'skipped' || steps.fuzz-four.outputs.cache-quiescent == 'true') && (steps.fuzz-four-diagnostic.outcome == 'skipped' || steps.fuzz-four-diagnostic.outputs.cache-quiescent == 'true')"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R142));
    Value::Mapping(values)
}

fn node_295() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save complete fuzz downloads"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz.outcome == 'skipped' || steps.prepare-fuzz.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz-diagnostic.outcome == 'skipped' || steps.prepare-fuzz-diagnostic.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-one-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-one-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile.outcome == 'skipped' || steps.fuzz-one-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile-diagnostic.outcome == 'skipped' || steps.fuzz-one-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-one.outcome == 'skipped' || steps.fuzz-one.outputs.cache-quiescent == 'true') && (steps.fuzz-one-diagnostic.outcome == 'skipped' || steps.fuzz-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-two-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-two-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile.outcome == 'skipped' || steps.fuzz-two-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile-diagnostic.outcome == 'skipped' || steps.fuzz-two-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-two.outcome == 'skipped' || steps.fuzz-two.outputs.cache-quiescent == 'true') && (steps.fuzz-two-diagnostic.outcome == 'skipped' || steps.fuzz-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-three-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-three-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile.outcome == 'skipped' || steps.fuzz-three-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile-diagnostic.outcome == 'skipped' || steps.fuzz-three-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-three.outcome == 'skipped' || steps.fuzz-three.outputs.cache-quiescent == 'true') && (steps.fuzz-three-diagnostic.outcome == 'skipped' || steps.fuzz-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-four-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-four-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile.outcome == 'skipped' || steps.fuzz-four-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile-diagnostic.outcome == 'skipped' || steps.fuzz-four-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-four.outcome == 'skipped' || steps.fuzz-four.outputs.cache-quiescent == 'true') && (steps.fuzz-four-diagnostic.outcome == 'skipped' || steps.fuzz-four-diagnostic.outputs.cache-quiescent == 'true') && steps.fuzz-download-context.outputs.source-key != '' && steps.fuzz-download-save-context.outcome == 'success' && steps.fuzz-download-save-context.outputs.source-key == steps.fuzz-download-context.outputs.source-key && ((steps.prepare-fuzz.outputs.fuzz-downloads-populated == 'true' && steps.fuzz-download-save-context.outputs.source-key == steps.prepare-fuzz.outputs.fuzz-downloads-key) || (steps.prepare-fuzz-diagnostic.outputs.fuzz-downloads-populated == 'true' && steps.fuzz-download-save-context.outputs.source-key == steps.prepare-fuzz-diagnostic.outputs.fuzz-downloads-key)) && !(steps.fuzz-downloads.outcome == 'success' && steps.fuzz-downloads.outputs.cache-hit == 'true') && matrix.shard == 'quarter-one' && (steps.cache-cargo-fuzz-build-partial-import.outcome == 'skipped' || steps.cache-cargo-fuzz-build-partial-import.outputs.cache-quiescent == 'true') && steps.fuzz-download-context.outputs.source-paths != ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_296());
    Value::Mapping(values)
}

fn node_296() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.fuzz-download-context.outputs.source-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.fuzz-download-context.outputs.source-key }}"),
    );
    Value::Mapping(values)
}

fn node_297() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-fuzz-download-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz.outcome == 'skipped' || steps.prepare-fuzz.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz-diagnostic.outcome == 'skipped' || steps.prepare-fuzz-diagnostic.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-one-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-one-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile.outcome == 'skipped' || steps.fuzz-one-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile-diagnostic.outcome == 'skipped' || steps.fuzz-one-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-one.outcome == 'skipped' || steps.fuzz-one.outputs.cache-quiescent == 'true') && (steps.fuzz-one-diagnostic.outcome == 'skipped' || steps.fuzz-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-two-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-two-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile.outcome == 'skipped' || steps.fuzz-two-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile-diagnostic.outcome == 'skipped' || steps.fuzz-two-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-two.outcome == 'skipped' || steps.fuzz-two.outputs.cache-quiescent == 'true') && (steps.fuzz-two-diagnostic.outcome == 'skipped' || steps.fuzz-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-three-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-three-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile.outcome == 'skipped' || steps.fuzz-three-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile-diagnostic.outcome == 'skipped' || steps.fuzz-three-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-three.outcome == 'skipped' || steps.fuzz-three.outputs.cache-quiescent == 'true') && (steps.fuzz-three-diagnostic.outcome == 'skipped' || steps.fuzz-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-four-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-four-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile.outcome == 'skipped' || steps.fuzz-four-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile-diagnostic.outcome == 'skipped' || steps.fuzz-four-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-four.outcome == 'skipped' || steps.fuzz-four.outputs.cache-quiescent == 'true') && (steps.fuzz-four-diagnostic.outcome == 'skipped' || steps.fuzz-four-diagnostic.outputs.cache-quiescent == 'true') && (steps.cache-cargo-fuzz-build-partial-import.outcome == 'skipped' || steps.cache-cargo-fuzz-build-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R139));
    Value::Mapping(values)
}

fn node_298() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-fuzz-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz.outcome == 'skipped' || steps.prepare-fuzz.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz-diagnostic.outcome == 'skipped' || steps.prepare-fuzz-diagnostic.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-one-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-one-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile.outcome == 'skipped' || steps.fuzz-one-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile-diagnostic.outcome == 'skipped' || steps.fuzz-one-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-one.outcome == 'skipped' || steps.fuzz-one.outputs.cache-quiescent == 'true') && (steps.fuzz-one-diagnostic.outcome == 'skipped' || steps.fuzz-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-two-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-two-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile.outcome == 'skipped' || steps.fuzz-two-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile-diagnostic.outcome == 'skipped' || steps.fuzz-two-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-two.outcome == 'skipped' || steps.fuzz-two.outputs.cache-quiescent == 'true') && (steps.fuzz-two-diagnostic.outcome == 'skipped' || steps.fuzz-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-three-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-three-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile.outcome == 'skipped' || steps.fuzz-three-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile-diagnostic.outcome == 'skipped' || steps.fuzz-three-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-three.outcome == 'skipped' || steps.fuzz-three.outputs.cache-quiescent == 'true') && (steps.fuzz-three-diagnostic.outcome == 'skipped' || steps.fuzz-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-four-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-four-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile.outcome == 'skipped' || steps.fuzz-four-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile-diagnostic.outcome == 'skipped' || steps.fuzz-four-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-four.outcome == 'skipped' || steps.fuzz-four.outputs.cache-quiescent == 'true') && (steps.fuzz-four-diagnostic.outcome == 'skipped' || steps.fuzz-four-diagnostic.outputs.cache-quiescent == 'true') && (steps.cache-cargo-fuzz-build-partial-import.outcome == 'skipped' || steps.cache-cargo-fuzz-build-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R199));
    Value::Mapping(values)
}

fn node_299() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save cache-cargo-fuzz-binary"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz.outcome == 'skipped' || steps.prepare-fuzz.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz-diagnostic.outcome == 'skipped' || steps.prepare-fuzz-diagnostic.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-one-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-one-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile.outcome == 'skipped' || steps.fuzz-one-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile-diagnostic.outcome == 'skipped' || steps.fuzz-one-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-one.outcome == 'skipped' || steps.fuzz-one.outputs.cache-quiescent == 'true') && (steps.fuzz-one-diagnostic.outcome == 'skipped' || steps.fuzz-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-two-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-two-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile.outcome == 'skipped' || steps.fuzz-two-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile-diagnostic.outcome == 'skipped' || steps.fuzz-two-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-two.outcome == 'skipped' || steps.fuzz-two.outputs.cache-quiescent == 'true') && (steps.fuzz-two-diagnostic.outcome == 'skipped' || steps.fuzz-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-three-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-three-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile.outcome == 'skipped' || steps.fuzz-three-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile-diagnostic.outcome == 'skipped' || steps.fuzz-three-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-three.outcome == 'skipped' || steps.fuzz-three.outputs.cache-quiescent == 'true') && (steps.fuzz-three-diagnostic.outcome == 'skipped' || steps.fuzz-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-four-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-four-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile.outcome == 'skipped' || steps.fuzz-four-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile-diagnostic.outcome == 'skipped' || steps.fuzz-four-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-four.outcome == 'skipped' || steps.fuzz-four.outputs.cache-quiescent == 'true') && (steps.fuzz-four-diagnostic.outcome == 'skipped' || steps.fuzz-four-diagnostic.outputs.cache-quiescent == 'true') && steps.cache-cargo-fuzz.outputs.tool-key != '' && steps.cache-cargo-fuzz-save-context.outcome == 'success' && steps.cache-cargo-fuzz-save-context.outputs.tool-key == steps.cache-cargo-fuzz.outputs.tool-key && (steps.prepare-fuzz.outputs.tool-cargo-fuzz-ready == 'true' || steps.prepare-fuzz-diagnostic.outputs.tool-cargo-fuzz-ready == 'true') && !(steps.cache-cargo-fuzz-binary.outcome == 'success' && steps.cache-cargo-fuzz-binary.outputs.cache-hit == 'true') && (steps.cache-cargo-fuzz-build-partial-import.outcome == 'skipped' || steps.cache-cargo-fuzz-build-partial-import.outputs.cache-quiescent == 'true') && steps.cache-cargo-fuzz.outputs.tool-path != ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_300());
    Value::Mapping(values)
}

fn node_300() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.cache-cargo-fuzz.outputs.tool-path }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.cache-cargo-fuzz.outputs.tool-key }}"),
    );
    Value::Mapping(values)
}

fn node_301() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save cargo-fuzz downloads"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz.outcome == 'skipped' || steps.prepare-fuzz.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz-diagnostic.outcome == 'skipped' || steps.prepare-fuzz-diagnostic.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-one-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-one-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile.outcome == 'skipped' || steps.fuzz-one-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile-diagnostic.outcome == 'skipped' || steps.fuzz-one-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-one.outcome == 'skipped' || steps.fuzz-one.outputs.cache-quiescent == 'true') && (steps.fuzz-one-diagnostic.outcome == 'skipped' || steps.fuzz-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-two-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-two-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile.outcome == 'skipped' || steps.fuzz-two-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile-diagnostic.outcome == 'skipped' || steps.fuzz-two-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-two.outcome == 'skipped' || steps.fuzz-two.outputs.cache-quiescent == 'true') && (steps.fuzz-two-diagnostic.outcome == 'skipped' || steps.fuzz-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-three-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-three-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile.outcome == 'skipped' || steps.fuzz-three-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile-diagnostic.outcome == 'skipped' || steps.fuzz-three-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-three.outcome == 'skipped' || steps.fuzz-three.outputs.cache-quiescent == 'true') && (steps.fuzz-three-diagnostic.outcome == 'skipped' || steps.fuzz-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-four-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-four-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile.outcome == 'skipped' || steps.fuzz-four-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile-diagnostic.outcome == 'skipped' || steps.fuzz-four-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-four.outcome == 'skipped' || steps.fuzz-four.outputs.cache-quiescent == 'true') && (steps.fuzz-four-diagnostic.outcome == 'skipped' || steps.fuzz-four-diagnostic.outputs.cache-quiescent == 'true') && steps.cache-cargo-fuzz-download-context.outputs.source-key != '' && steps.cache-cargo-fuzz-download-save-context.outcome == 'success' && steps.cache-cargo-fuzz-download-save-context.outputs.source-key == steps.cache-cargo-fuzz-download-context.outputs.source-key && ((steps.prepare-fuzz.outputs.download-cargo-fuzz-populated == 'true' && steps.cache-cargo-fuzz-download-save-context.outputs.source-key == steps.prepare-fuzz.outputs.download-cargo-fuzz-key) || (steps.prepare-fuzz-diagnostic.outputs.download-cargo-fuzz-populated == 'true' && steps.cache-cargo-fuzz-download-save-context.outputs.source-key == steps.prepare-fuzz-diagnostic.outputs.download-cargo-fuzz-key)) && !(steps.cache-cargo-fuzz-downloads.outcome == 'success' && steps.cache-cargo-fuzz-downloads.outputs.cache-hit == 'true') && (steps.cache-cargo-fuzz-build-partial-import.outcome == 'skipped' || steps.cache-cargo-fuzz-build-partial-import.outputs.cache-quiescent == 'true') && steps.cache-cargo-fuzz-download-context.outputs.source-paths != ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_302());
    Value::Mapping(values)
}

fn node_302() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.cache-cargo-fuzz-download-context.outputs.source-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.cache-cargo-fuzz-download-context.outputs.source-key }}"),
    );
    Value::Mapping(values)
}

fn node_303() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save cache-cargo-fuzz-build"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz.outcome == 'skipped' || steps.prepare-fuzz.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz-diagnostic.outcome == 'skipped' || steps.prepare-fuzz-diagnostic.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-one-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-one-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile.outcome == 'skipped' || steps.fuzz-one-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile-diagnostic.outcome == 'skipped' || steps.fuzz-one-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-one.outcome == 'skipped' || steps.fuzz-one.outputs.cache-quiescent == 'true') && (steps.fuzz-one-diagnostic.outcome == 'skipped' || steps.fuzz-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-two-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-two-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile.outcome == 'skipped' || steps.fuzz-two-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile-diagnostic.outcome == 'skipped' || steps.fuzz-two-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-two.outcome == 'skipped' || steps.fuzz-two.outputs.cache-quiescent == 'true') && (steps.fuzz-two-diagnostic.outcome == 'skipped' || steps.fuzz-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-three-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-three-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile.outcome == 'skipped' || steps.fuzz-three-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile-diagnostic.outcome == 'skipped' || steps.fuzz-three-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-three.outcome == 'skipped' || steps.fuzz-three.outputs.cache-quiescent == 'true') && (steps.fuzz-three-diagnostic.outcome == 'skipped' || steps.fuzz-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-four-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-four-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile.outcome == 'skipped' || steps.fuzz-four-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile-diagnostic.outcome == 'skipped' || steps.fuzz-four-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-four.outcome == 'skipped' || steps.fuzz-four.outputs.cache-quiescent == 'true') && (steps.fuzz-four-diagnostic.outcome == 'skipped' || steps.fuzz-four-diagnostic.outputs.cache-quiescent == 'true') && steps.cache-cargo-fuzz.outputs.tool-build-key != '' && steps.cache-cargo-fuzz-save-context.outcome == 'success' && steps.cache-cargo-fuzz-save-context.outputs.tool-build-key == steps.cache-cargo-fuzz.outputs.tool-build-key && steps.cache-cargo-fuzz-save-context.outputs.payload-ready == 'true' && (steps.prepare-fuzz.outputs.tool-cargo-fuzz-build-complete == 'true' || steps.prepare-fuzz-diagnostic.outputs.tool-cargo-fuzz-build-complete == 'true') && !(steps.cache-cargo-fuzz-build.outcome == 'success' && steps.cache-cargo-fuzz-build.outputs.cache-hit == 'true') && (steps.cache-cargo-fuzz-build-partial-import.outcome == 'skipped' || steps.cache-cargo-fuzz-build-partial-import.outputs.cache-quiescent == 'true') && steps.cache-cargo-fuzz.outputs.tool-build-path != '' && steps.cache-cargo-fuzz.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_304());
    Value::Mapping(values)
}

fn node_304() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("path"),
        text("${{ steps.cache-cargo-fuzz.outputs.tool-build-path }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.cache-cargo-fuzz.outputs.tool-build-key }}"),
    );
    Value::Mapping(values)
}

fn node_305() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz.outcome == 'skipped' || steps.prepare-fuzz.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz-diagnostic.outcome == 'skipped' || steps.prepare-fuzz-diagnostic.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-one-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-one-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile.outcome == 'skipped' || steps.fuzz-one-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile-diagnostic.outcome == 'skipped' || steps.fuzz-one-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-one.outcome == 'skipped' || steps.fuzz-one.outputs.cache-quiescent == 'true') && (steps.fuzz-one-diagnostic.outcome == 'skipped' || steps.fuzz-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-two-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-two-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile.outcome == 'skipped' || steps.fuzz-two-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile-diagnostic.outcome == 'skipped' || steps.fuzz-two-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-two.outcome == 'skipped' || steps.fuzz-two.outputs.cache-quiescent == 'true') && (steps.fuzz-two-diagnostic.outcome == 'skipped' || steps.fuzz-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-three-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-three-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile.outcome == 'skipped' || steps.fuzz-three-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile-diagnostic.outcome == 'skipped' || steps.fuzz-three-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-three.outcome == 'skipped' || steps.fuzz-three.outputs.cache-quiescent == 'true') && (steps.fuzz-three-diagnostic.outcome == 'skipped' || steps.fuzz-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-four-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-four-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile.outcome == 'skipped' || steps.fuzz-four-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile-diagnostic.outcome == 'skipped' || steps.fuzz-four-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-four.outcome == 'skipped' || steps.fuzz-four.outputs.cache-quiescent == 'true') && (steps.fuzz-four-diagnostic.outcome == 'skipped' || steps.fuzz-four-diagnostic.outputs.cache-quiescent == 'true') && (steps.cache-cargo-fuzz-build-partial-import.outcome == 'skipped' || steps.cache-cargo-fuzz-build-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("run"), literal(LiteralRun::R9));
    Value::Mapping(values)
}

fn node_306() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-probe"));
    values.insert(text("if"),text("always() && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_307());
    Value::Mapping(values)
}

fn node_307() -> Value {
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

fn node_308() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save observed registry-archives"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility && steps.archive-seed-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_309());
    Value::Mapping(values)
}

fn node_309() -> Value {
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

fn node_310() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (steps.archive-seed-snapshot.outcome == 'success' || steps.archive-seed-snapshot.outcome == 'failure')"));
    values.insert(text("run"), literal(LiteralRun::R10));
    Value::Mapping(values)
}

fn node_311() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz.outcome == 'skipped' || steps.prepare-fuzz.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz-diagnostic.outcome == 'skipped' || steps.prepare-fuzz-diagnostic.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-one-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-one-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile.outcome == 'skipped' || steps.fuzz-one-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile-diagnostic.outcome == 'skipped' || steps.fuzz-one-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-one.outcome == 'skipped' || steps.fuzz-one.outputs.cache-quiescent == 'true') && (steps.fuzz-one-diagnostic.outcome == 'skipped' || steps.fuzz-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-two-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-two-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile.outcome == 'skipped' || steps.fuzz-two-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile-diagnostic.outcome == 'skipped' || steps.fuzz-two-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-two.outcome == 'skipped' || steps.fuzz-two.outputs.cache-quiescent == 'true') && (steps.fuzz-two-diagnostic.outcome == 'skipped' || steps.fuzz-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-three-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-three-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile.outcome == 'skipped' || steps.fuzz-three-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile-diagnostic.outcome == 'skipped' || steps.fuzz-three-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-three.outcome == 'skipped' || steps.fuzz-three.outputs.cache-quiescent == 'true') && (steps.fuzz-three-diagnostic.outcome == 'skipped' || steps.fuzz-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-four-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-four-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile.outcome == 'skipped' || steps.fuzz-four-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile-diagnostic.outcome == 'skipped' || steps.fuzz-four-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-four.outcome == 'skipped' || steps.fuzz-four.outputs.cache-quiescent == 'true') && (steps.fuzz-four-diagnostic.outcome == 'skipped' || steps.fuzz-four-diagnostic.outputs.cache-quiescent == 'true') && (steps.cache-cargo-fuzz-build-partial-import.outcome == 'skipped' || steps.cache-cargo-fuzz-build-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("run"), literal(LiteralRun::R11));
    Value::Mapping(values)
}

fn node_312() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-probe"));
    values.insert(text("if"),text("always() && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_313());
    Value::Mapping(values)
}

fn node_313() -> Value {
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

fn node_314() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save observed registry-index"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility && steps.index-snapshot-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_315());
    Value::Mapping(values)
}

fn node_315() -> Value {
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

fn node_316() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (steps.index-snapshot-snapshot.outcome == 'success' || steps.index-snapshot-snapshot.outcome == 'failure')"));
    values.insert(text("run"), literal(LiteralRun::R12));
    Value::Mapping(values)
}

fn node_317() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-fuzz-build-partial"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.cache-cargo-fuzz.outputs.tool-build-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.import-registry-archives-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-archives-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.import-registry-index-sources-complete-recipe.outcome == 'skipped' || steps.import-registry-index-sources-complete-recipe.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz.outcome == 'skipped' || steps.prepare-fuzz.outputs.cache-quiescent == 'true') && (steps.prepare-fuzz-diagnostic.outcome == 'skipped' || steps.prepare-fuzz-diagnostic.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-one-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-two-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-three-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outcome == 'skipped' || steps.sanitize-fuzz-quarter-four-fuzz-targets-compatible.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-one-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-one-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile.outcome == 'skipped' || steps.fuzz-one-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-one-compile-diagnostic.outcome == 'skipped' || steps.fuzz-one-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-one.outcome == 'skipped' || steps.fuzz-one.outputs.cache-quiescent == 'true') && (steps.fuzz-one-diagnostic.outcome == 'skipped' || steps.fuzz-one-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-two-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-two-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile.outcome == 'skipped' || steps.fuzz-two-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-two-compile-diagnostic.outcome == 'skipped' || steps.fuzz-two-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-two.outcome == 'skipped' || steps.fuzz-two.outputs.cache-quiescent == 'true') && (steps.fuzz-two-diagnostic.outcome == 'skipped' || steps.fuzz-two-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-three-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-three-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile.outcome == 'skipped' || steps.fuzz-three-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-three-compile-diagnostic.outcome == 'skipped' || steps.fuzz-three-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-three.outcome == 'skipped' || steps.fuzz-three.outputs.cache-quiescent == 'true') && (steps.fuzz-three-diagnostic.outcome == 'skipped' || steps.fuzz-three-diagnostic.outputs.cache-quiescent == 'true') && (steps.import-compiled-fuzz-quarter-four-fuzz-targets.outcome == 'skipped' || steps.import-compiled-fuzz-quarter-four-fuzz-targets.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile.outcome == 'skipped' || steps.fuzz-four-compile.outputs.cache-quiescent == 'true') && (steps.fuzz-four-compile-diagnostic.outcome == 'skipped' || steps.fuzz-four-compile-diagnostic.outputs.cache-quiescent == 'true') && (steps.fuzz-four.outcome == 'skipped' || steps.fuzz-four.outputs.cache-quiescent == 'true') && (steps.fuzz-four-diagnostic.outcome == 'skipped' || steps.fuzz-four-diagnostic.outputs.cache-quiescent == 'true') && !((steps.prepare-fuzz.outputs.tool-cargo-fuzz-build-complete == 'true' || steps.prepare-fuzz-diagnostic.outputs.tool-cargo-fuzz-build-complete == 'true') && steps.cache-cargo-fuzz-save-context.outputs.payload-ready == 'true') && (steps.cache-cargo-fuzz-build-partial-import.outcome == 'skipped' || steps.cache-cargo-fuzz-build-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R200));
    Value::Mapping(values)
}

fn node_318() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-fuzz-build-partial-probe"));
    values.insert(text("if"),text("always() && steps.cache-cargo-fuzz-build-partial.outputs.snapshot-ready == 'true' && steps.cache-cargo-fuzz-build-partial.outputs.input-key == steps.cache-cargo-fuzz.outputs.tool-build-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_319());
    Value::Mapping(values)
}

fn node_319() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.cache-cargo-fuzz-build-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.cache-cargo-fuzz-build-partial.outputs.snapshot-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_320() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-fuzz-build-partial-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.cache-cargo-fuzz-build-partial.outputs.snapshot-ready == 'true' && steps.cache-cargo-fuzz-build-partial.outputs.input-key == steps.cache-cargo-fuzz.outputs.tool-build-key && steps.cache-cargo-fuzz-build-partial.outputs.snapshot-key != '' && steps.cache-cargo-fuzz-build-partial-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_321());
    Value::Mapping(values)
}

fn node_321() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.cache-cargo-fuzz-build-partial.outputs.snapshot-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.cache-cargo-fuzz-build-partial.outputs.snapshot-path }}"),
    );
    Value::Mapping(values)
}

fn node_322() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("cache-cargo-fuzz-build-partial-cleanup"));
    values.insert(text("if"),text("always() && (steps.cache-cargo-fuzz-build-partial.outcome == 'success' || steps.cache-cargo-fuzz-build-partial.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R201));
    Value::Mapping(values)
}

fn node_323() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("stress / ${{ matrix.id }}"));
    values.insert(text("needs"), text("performance-plan"));
    values.insert(
        text("if"),
        text("needs.performance-plan.outputs.has-combined == 'true'"),
    );
    values.insert(text("strategy"), node_324());
    values.insert(text("runs-on"), text("${{ matrix.runner }}"));
    values.insert(text("timeout-minutes"), number("218"));
    values.insert(text("steps"), node_326());
    Value::Mapping(values)
}

fn node_324() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("fail-fast"), Value::Bool(false));
    values.insert(text("matrix"), node_325());
    Value::Mapping(values)
}

fn node_325() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("include"),
        text("${{ fromJSON(needs.performance-plan.outputs.combined) }}"),
    );
    Value::Mapping(values)
}

fn node_326() -> Value {
    let mut values = Vec::new();
    values.push(node_327());
    values.push(node_329());
    values.push(node_331());
    values.push(node_332());
    values.push(node_333());
    values.push(node_334());
    values.push(node_336());
    values.push(node_337());
    values.push(node_339());
    values.push(node_340());
    values.push(node_342());
    values.push(node_343());
    values.push(node_344());
    values.push(node_346());
    values.push(node_347());
    values.push(node_348());
    values.push(node_349());
    values.push(node_351());
    values.push(node_352());
    values.push(node_354());
    values.push(node_356());
    values.push(node_357());
    values.push(node_358());
    values.push(node_360());
    values.push(node_362());
    values.push(node_363());
    values.push(node_364());
    values.push(node_366());
    values.push(node_367());
    values.push(node_368());
    values.push(node_369());
    values.push(node_370());
    values.push(node_372());
    values.push(node_373());
    values.push(node_374());
    values.push(node_376());
    values.push(node_377());
    values.push(node_379());
    values.push(node_380());
    values.push(node_382());
    values.push(node_384());
    Value::Sequence(values)
}

fn node_327() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_328());
    Value::Mapping(values)
}

fn node_328() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_329() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("stress-deps"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"), text("hashFiles('Cargo.lock') != ''"));
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

fn node_331() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R0));
    Value::Mapping(values)
}

fn node_332() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Build ordinary CI driver"));
    values.insert(text("id"), text("driver-build"));
    values.insert(text("run"), literal(LiteralRun::R1));
    Value::Mapping(values)
}

fn node_333() -> Value {
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

fn node_334() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.driver-build.outcome == 'success' && steps.bootstrap-home.outcome == 'success' && steps.bootstrap-home.outputs.bootstrap-home-matches == 'true' && steps.stress-deps.outputs.cache-primary-key != '' && steps.stress-deps.outputs.cache-hit != 'true'"));
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
        text("~/.cargo/registry/cache\n~/.cargo/git/db\n"),
    );
    values.insert(
        text("key"),
        text("${{ steps.stress-deps.outputs.cache-primary-key }}"),
    );
    Value::Mapping(values)
}

fn node_336() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-context"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_337() -> Value {
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
    values.insert(text("with"), node_338());
    Value::Mapping(values)
}

fn node_338() -> Value {
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

fn node_339() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R4));
    Value::Mapping(values)
}

fn node_340() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore"));
    values.insert(text("if"),text("steps.archive-seed-context.outputs.seed-lookup-key != '' && steps.workspace-downloads.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
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

fn node_342() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore-import"));
    values.insert(text("if"),text("steps.archive-seed-restore.outcome == 'success' && steps.archive-seed-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R5));
    Value::Mapping(values)
}

fn node_343() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R6));
    Value::Mapping(values)
}

fn node_344() -> Value {
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
    values.insert(text("with"), node_345());
    Value::Mapping(values)
}

fn node_345() -> Value {
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

fn node_346() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-restore-import"));
    values.insert(text("if"),text("steps.index-snapshot-restore.outcome == 'success' && steps.index-snapshot-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R7));
    Value::Mapping(values)
}

fn node_347() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(text("run"), literal(LiteralRun::R8));
    Value::Mapping(values)
}

fn node_348() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save-context"));
    values.insert(text("if"),text("always() && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-context.outputs.source-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_349() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.workspace-download-context.outputs.source-key != '' && steps.workspace-download-context.outputs.source-paths != '' && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-save-context.outcome == 'success' && steps.workspace-download-save-context.outputs.source-key == steps.workspace-download-context.outputs.source-key && steps.workspace-download-save-context.outputs.source-key == steps.workspace-fetch.outputs.workspace-downloads-key && !(steps.workspace-downloads.outcome == 'success' && steps.workspace-downloads.outputs.cache-hit == 'true') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && steps.workspace-download-context.outputs.source-paths != ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_350());
    Value::Mapping(values)
}

fn node_350() -> Value {
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

fn node_351() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R9));
    Value::Mapping(values)
}

fn node_352() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-probe"));
    values.insert(text("if"),text("always() && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_353());
    Value::Mapping(values)
}

fn node_353() -> Value {
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

fn node_354() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility && steps.archive-seed-snapshot.outputs.snapshot-key != '' && steps.archive-seed-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_355());
    Value::Mapping(values)
}

fn node_355() -> Value {
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

fn node_356() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.archive-seed-snapshot.outcome == 'success' || steps.archive-seed-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R10));
    Value::Mapping(values)
}

fn node_357() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R11));
    Value::Mapping(values)
}

fn node_358() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-probe"));
    values.insert(text("if"),text("always() && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_359());
    Value::Mapping(values)
}

fn node_359() -> Value {
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

fn node_360() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility && steps.index-snapshot-snapshot.outputs.snapshot-key != '' && steps.index-snapshot-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_361());
    Value::Mapping(values)
}

fn node_361() -> Value {
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

fn node_362() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.index-snapshot-snapshot.outcome == 'success' || steps.index-snapshot-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R12));
    Value::Mapping(values)
}

fn node_363() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-context"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R202));
    Value::Mapping(values)
}

fn node_364() -> Value {
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
    values.insert(text("with"), node_365());
    Value::Mapping(values)
}

fn node_365() -> Value {
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

fn node_366() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize compiled discard restore"));
    values.insert(text("id"), text("sanitize-stress-complete-recipe-discard"));
    values.insert(text("if"), text("steps.compiled.outcome == 'failure'"));
    values.insert(text("run"), literal(LiteralRun::R203));
    Value::Mapping(values)
}

fn node_367() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize compiled exact restore"));
    values.insert(text("id"), text("sanitize-stress-complete-recipe-exact"));
    values.insert(
        text("if"),
        text("steps.compiled.outcome == 'success' && steps.compiled.outputs.cache-hit == 'true'"),
    );
    values.insert(text("run"), literal(LiteralRun::R204));
    Value::Mapping(values)
}

fn node_368() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize compiled compatible restore"));
    values.insert(
        text("id"),
        text("sanitize-stress-complete-recipe-compatible"),
    );
    values.insert(text("if"),text("steps.compiled.outcome == 'success' && steps.compiled.outputs.cache-matched-key != '' && steps.compiled.outputs.cache-hit != 'true'"));
    values.insert(text("run"), literal(LiteralRun::R205));
    Value::Mapping(values)
}

fn node_369() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-context"));
    values.insert(text("if"),text("steps.compiled-context.outputs.product-key != '' && steps.compiled.outcome != 'failure' && steps.compiled.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R206));
    Value::Mapping(values)
}

fn node_370() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-restore"));
    values.insert(text("if"),text("steps.compiled-partial-context.outputs.seed-lookup-key != '' && steps.compiled-context.outputs.product-key != '' && steps.compiled.outcome != 'failure' && steps.compiled.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_371());
    Value::Mapping(values)
}

fn node_371() -> Value {
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

fn node_372() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-import"));
    values.insert(text("if"),text("steps.compiled-partial-restore.outcome == 'success' && steps.compiled-partial-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R207));
    Value::Mapping(values)
}

fn node_373() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("stress-run"));
    values.insert(text("run"), literal(LiteralRun::R208));
    Value::Mapping(values)
}

fn node_374() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("always()"));
    values.insert(text("uses"), text("./.github/actions/upload-artifact"));
    values.insert(text("with"), node_375());
    Value::Mapping(values)
}

fn node_375() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("stress-combined-${{ matrix.id }}"));
    values.insert(text("include-hidden-files"), Value::Bool(true));
    values.insert(text("path"),text("target/ci/reports/stress\ntarget/ci/reports/stress-seed.txt\ntarget/ci/reports/stress-active-target.txt\ntarget/ci/reports/stress-deep_short_child_iterations.json\n"));
    values.insert(text("if-no-files-found"), text("warn"));
    Value::Mapping(values)
}

fn node_376() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-stress-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-stress-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-stress-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-stress-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-stress-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-stress-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.stress-run.outcome == 'skipped' || steps.stress-run.outputs.cache-quiescent == 'true') && steps.compiled-context.outputs.compiled-cache-usable == 'true' && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.compiled-partial-import.outcome == 'skipped' || steps.compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R209));
    Value::Mapping(values)
}

fn node_377() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-stress-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-stress-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-stress-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-stress-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-stress-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-stress-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.stress-run.outcome == 'skipped' || steps.stress-run.outputs.cache-quiescent == 'true') && steps.compiled-context.outputs.product-key != '' && steps.compiled-save-context.outcome == 'success' && steps.compiled-save-context.outputs.product-key == steps.compiled-context.outputs.product-key && steps.compiled-save-context.outputs.payload-ready == 'true' && (steps.stress-run.outputs.compiled-recipe-complete == 'true') && !(steps.compiled.outcome == 'success' && steps.compiled.outputs.cache-hit == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.compiled-partial-import.outcome == 'skipped' || steps.compiled-partial-import.outputs.cache-quiescent == 'true') && steps.compiled-context.outputs.product-paths != '' && steps.compiled-context.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_378());
    Value::Mapping(values)
}

fn node_378() -> Value {
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

fn node_379() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.compiled-context.outputs.product-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-stress-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-stress-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-stress-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-stress-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-stress-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-stress-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.stress-run.outcome == 'skipped' || steps.stress-run.outputs.cache-quiescent == 'true') && !((steps.stress-run.outputs.compiled-recipe-complete == 'true') && steps.compiled-save-context.outputs.payload-ready == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.compiled-partial-import.outcome == 'skipped' || steps.compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R210));
    Value::Mapping(values)
}

fn node_380() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-probe"));
    values.insert(text("if"),text("always() && steps.compiled-partial.outputs.snapshot-ready == 'true' && steps.compiled-partial.outputs.input-key == steps.compiled-context.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_381());
    Value::Mapping(values)
}

fn node_381() -> Value {
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

fn node_382() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.compiled-partial.outputs.snapshot-ready == 'true' && steps.compiled-partial.outputs.input-key == steps.compiled-context.outputs.product-key && steps.compiled-partial.outputs.snapshot-key != '' && steps.compiled-partial-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_383());
    Value::Mapping(values)
}

fn node_383() -> Value {
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

fn node_384() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-cleanup"));
    values.insert(text("if"),text("always() && (steps.compiled-partial.outcome == 'success' || steps.compiled-partial.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R211));
    Value::Mapping(values)
}

fn node_385() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("stress packages / ${{ matrix.id }}"));
    values.insert(text("needs"), text("performance-plan"));
    values.insert(
        text("if"),
        text("needs.performance-plan.outputs.has-split == 'true'"),
    );
    values.insert(text("strategy"), node_386());
    values.insert(text("runs-on"), text("${{ matrix.runner }}"));
    values.insert(text("timeout-minutes"), number("211"));
    values.insert(text("steps"), node_388());
    Value::Mapping(values)
}

fn node_386() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("fail-fast"), Value::Bool(false));
    values.insert(text("matrix"), node_387());
    Value::Mapping(values)
}

fn node_387() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("include"),
        text("${{ fromJSON(needs.performance-plan.outputs.split) }}"),
    );
    Value::Mapping(values)
}

fn node_388() -> Value {
    let mut values = Vec::new();
    values.push(node_389());
    values.push(node_391());
    values.push(node_393());
    values.push(node_394());
    values.push(node_395());
    values.push(node_396());
    values.push(node_398());
    values.push(node_399());
    values.push(node_401());
    values.push(node_402());
    values.push(node_404());
    values.push(node_405());
    values.push(node_406());
    values.push(node_408());
    values.push(node_409());
    values.push(node_410());
    values.push(node_411());
    values.push(node_413());
    values.push(node_415());
    values.push(node_416());
    values.push(node_417());
    values.push(node_419());
    values.push(node_421());
    values.push(node_422());
    values.push(node_423());
    values.push(node_425());
    values.push(node_426());
    values.push(node_428());
    values.push(node_429());
    values.push(node_430());
    values.push(node_431());
    values.push(node_432());
    values.push(node_434());
    values.push(node_435());
    values.push(node_436());
    values.push(node_438());
    values.push(node_439());
    values.push(node_441());
    values.push(node_442());
    values.push(node_444());
    values.push(node_446());
    Value::Sequence(values)
}

fn node_389() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_390());
    Value::Mapping(values)
}

fn node_390() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_391() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("sources"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"), text("hashFiles('Cargo.lock') != ''"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_392());
    Value::Mapping(values)
}

fn node_392() -> Value {
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

fn node_393() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R0));
    Value::Mapping(values)
}

fn node_394() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R1));
    values.insert(text("id"), text("driver-build"));
    Value::Mapping(values)
}

fn node_395() -> Value {
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

fn node_396() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.driver-build.outcome == 'success' && steps.bootstrap-home.outcome == 'success' && steps.bootstrap-home.outputs.bootstrap-home-matches == 'true' && steps.sources.outputs.cache-primary-key != '' && steps.sources.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
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
        text("path"),
        text("~/.cargo/registry/cache\n~/.cargo/git/db\n"),
    );
    values.insert(
        text("key"),
        text("${{ steps.sources.outputs.cache-primary-key }}"),
    );
    Value::Mapping(values)
}

fn node_398() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-context"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_399() -> Value {
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
    values.insert(text("with"), node_400());
    Value::Mapping(values)
}

fn node_400() -> Value {
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

fn node_401() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R4));
    Value::Mapping(values)
}

fn node_402() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore"));
    values.insert(text("if"),text("steps.archive-seed-context.outputs.seed-lookup-key != '' && steps.workspace-downloads.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_403());
    Value::Mapping(values)
}

fn node_403() -> Value {
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

fn node_404() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore-import"));
    values.insert(text("if"),text("steps.archive-seed-restore.outcome == 'success' && steps.archive-seed-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R5));
    Value::Mapping(values)
}

fn node_405() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R6));
    Value::Mapping(values)
}

fn node_406() -> Value {
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
    values.insert(text("with"), node_407());
    Value::Mapping(values)
}

fn node_407() -> Value {
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

fn node_408() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-restore-import"));
    values.insert(text("if"),text("steps.index-snapshot-restore.outcome == 'success' && steps.index-snapshot-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R7));
    Value::Mapping(values)
}

fn node_409() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(text("run"), literal(LiteralRun::R8));
    Value::Mapping(values)
}

fn node_410() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R9));
    Value::Mapping(values)
}

fn node_411() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-probe"));
    values.insert(text("if"),text("always() && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_412());
    Value::Mapping(values)
}

fn node_412() -> Value {
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

fn node_413() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility && steps.archive-seed-snapshot.outputs.snapshot-key != '' && steps.archive-seed-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_414());
    Value::Mapping(values)
}

fn node_414() -> Value {
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

fn node_415() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.archive-seed-snapshot.outcome == 'success' || steps.archive-seed-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R10));
    Value::Mapping(values)
}

fn node_416() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R11));
    Value::Mapping(values)
}

fn node_417() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-probe"));
    values.insert(text("if"),text("always() && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_418());
    Value::Mapping(values)
}

fn node_418() -> Value {
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

fn node_419() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility && steps.index-snapshot-snapshot.outputs.snapshot-key != '' && steps.index-snapshot-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_420());
    Value::Mapping(values)
}

fn node_420() -> Value {
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

fn node_421() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.index-snapshot-snapshot.outcome == 'success' || steps.index-snapshot-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R12));
    Value::Mapping(values)
}

fn node_422() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save-context"));
    values.insert(text("if"),text("always() && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-context.outputs.source-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_423() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save complete workspace downloads"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.workspace-download-context.outputs.source-key != '' && steps.workspace-download-context.outputs.source-paths != '' && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-save-context.outcome == 'success' && steps.workspace-download-save-context.outputs.source-key == steps.workspace-download-context.outputs.source-key && steps.workspace-download-save-context.outputs.source-key == steps.workspace-fetch.outputs.workspace-downloads-key && !(steps.workspace-downloads.outcome == 'success' && steps.workspace-downloads.outputs.cache-hit == 'true') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && steps.workspace-download-context.outputs.source-paths != ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
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
        text("path"),
        text("${{ steps.workspace-download-context.outputs.source-paths }}"),
    );
    values.insert(
        text("key"),
        text("${{ steps.workspace-download-context.outputs.source-key }}"),
    );
    Value::Mapping(values)
}

fn node_425() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-context"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R212));
    Value::Mapping(values)
}

fn node_426() -> Value {
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
    values.insert(text("with"), node_427());
    Value::Mapping(values)
}

fn node_427() -> Value {
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

fn node_428() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize compiled discard restore"));
    values.insert(
        text("id"),
        text("sanitize-stress-packages-complete-recipe-discard"),
    );
    values.insert(text("if"), text("steps.compiled.outcome == 'failure'"));
    values.insert(text("run"), literal(LiteralRun::R213));
    Value::Mapping(values)
}

fn node_429() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize compiled exact restore"));
    values.insert(
        text("id"),
        text("sanitize-stress-packages-complete-recipe-exact"),
    );
    values.insert(
        text("if"),
        text("steps.compiled.outcome == 'success' && steps.compiled.outputs.cache-hit == 'true'"),
    );
    values.insert(text("run"), literal(LiteralRun::R214));
    Value::Mapping(values)
}

fn node_430() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize compiled compatible restore"));
    values.insert(
        text("id"),
        text("sanitize-stress-packages-complete-recipe-compatible"),
    );
    values.insert(text("if"),text("steps.compiled.outcome == 'success' && steps.compiled.outputs.cache-matched-key != '' && steps.compiled.outputs.cache-hit != 'true'"));
    values.insert(text("run"), literal(LiteralRun::R215));
    Value::Mapping(values)
}

fn node_431() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-context"));
    values.insert(text("if"),text("steps.compiled-context.outputs.product-key != '' && steps.compiled.outcome != 'failure' && steps.compiled.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R216));
    Value::Mapping(values)
}

fn node_432() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-restore"));
    values.insert(text("if"),text("steps.compiled-partial-context.outputs.seed-lookup-key != '' && steps.compiled-context.outputs.product-key != '' && steps.compiled.outcome != 'failure' && steps.compiled.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_433());
    Value::Mapping(values)
}

fn node_433() -> Value {
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

fn node_434() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-import"));
    values.insert(text("if"),text("steps.compiled-partial-restore.outcome == 'success' && steps.compiled-partial-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R217));
    Value::Mapping(values)
}

fn node_435() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("stress-run"));
    values.insert(text("run"), literal(LiteralRun::R218));
    Value::Mapping(values)
}

fn node_436() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("always()"));
    values.insert(text("uses"), text("./.github/actions/upload-artifact"));
    values.insert(text("with"), node_437());
    Value::Mapping(values)
}

fn node_437() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("stress-packages-${{ matrix.id }}"));
    values.insert(text("include-hidden-files"), Value::Bool(true));
    values.insert(
        text("path"),
        text("target/ci/reports/stress\ntarget/ci/reports/stress-active-target.txt\n"),
    );
    values.insert(text("if-no-files-found"), text("warn"));
    Value::Mapping(values)
}

fn node_438() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-stress-packages-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-stress-packages-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-stress-packages-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-stress-packages-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-stress-packages-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-stress-packages-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.stress-run.outcome == 'skipped' || steps.stress-run.outputs.cache-quiescent == 'true') && steps.compiled-context.outputs.compiled-cache-usable == 'true' && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.compiled-partial-import.outcome == 'skipped' || steps.compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R219));
    Value::Mapping(values)
}

fn node_439() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-stress-packages-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-stress-packages-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-stress-packages-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-stress-packages-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-stress-packages-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-stress-packages-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.stress-run.outcome == 'skipped' || steps.stress-run.outputs.cache-quiescent == 'true') && steps.compiled-context.outputs.product-key != '' && steps.compiled-save-context.outcome == 'success' && steps.compiled-save-context.outputs.product-key == steps.compiled-context.outputs.product-key && steps.compiled-save-context.outputs.payload-ready == 'true' && (steps.stress-run.outputs.compiled-recipe-complete == 'true') && !(steps.compiled.outcome == 'success' && steps.compiled.outputs.cache-hit == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.compiled-partial-import.outcome == 'skipped' || steps.compiled-partial-import.outputs.cache-quiescent == 'true') && steps.compiled-context.outputs.product-paths != '' && steps.compiled-context.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_440());
    Value::Mapping(values)
}

fn node_440() -> Value {
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

fn node_441() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.compiled-context.outputs.product-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-stress-packages-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-stress-packages-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-stress-packages-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-stress-packages-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-stress-packages-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-stress-packages-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.stress-run.outcome == 'skipped' || steps.stress-run.outputs.cache-quiescent == 'true') && !((steps.stress-run.outputs.compiled-recipe-complete == 'true') && steps.compiled-save-context.outputs.payload-ready == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.compiled-partial-import.outcome == 'skipped' || steps.compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R220));
    Value::Mapping(values)
}

fn node_442() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-probe"));
    values.insert(text("if"),text("always() && steps.compiled-partial.outputs.snapshot-ready == 'true' && steps.compiled-partial.outputs.input-key == steps.compiled-context.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_443());
    Value::Mapping(values)
}

fn node_443() -> Value {
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

fn node_444() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.compiled-partial.outputs.snapshot-ready == 'true' && steps.compiled-partial.outputs.input-key == steps.compiled-context.outputs.product-key && steps.compiled-partial.outputs.snapshot-key != '' && steps.compiled-partial-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_445());
    Value::Mapping(values)
}

fn node_445() -> Value {
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

fn node_446() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-cleanup"));
    values.insert(text("if"),text("always() && (steps.compiled-partial.outcome == 'success' || steps.compiled-partial.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R221));
    Value::Mapping(values)
}

fn node_447() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("stress lifecycle / ${{ matrix.id }}"));
    values.insert(text("needs"), text("performance-plan"));
    values.insert(
        text("if"),
        text("needs.performance-plan.outputs.has-split == 'true'"),
    );
    values.insert(text("strategy"), node_448());
    values.insert(text("runs-on"), text("${{ matrix.runner }}"));
    values.insert(text("timeout-minutes"), number("211"));
    values.insert(text("steps"), node_450());
    Value::Mapping(values)
}

fn node_448() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("fail-fast"), Value::Bool(false));
    values.insert(text("matrix"), node_449());
    Value::Mapping(values)
}

fn node_449() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("include"),
        text("${{ fromJSON(needs.performance-plan.outputs.split) }}"),
    );
    Value::Mapping(values)
}

fn node_450() -> Value {
    let mut values = Vec::new();
    values.push(node_451());
    values.push(node_453());
    values.push(node_455());
    values.push(node_456());
    values.push(node_457());
    values.push(node_458());
    values.push(node_460());
    values.push(node_461());
    values.push(node_463());
    values.push(node_464());
    values.push(node_466());
    values.push(node_467());
    values.push(node_468());
    values.push(node_470());
    values.push(node_471());
    values.push(node_472());
    values.push(node_473());
    values.push(node_475());
    values.push(node_477());
    values.push(node_478());
    values.push(node_479());
    values.push(node_481());
    values.push(node_483());
    values.push(node_484());
    values.push(node_485());
    values.push(node_487());
    values.push(node_488());
    values.push(node_490());
    values.push(node_491());
    values.push(node_492());
    values.push(node_493());
    values.push(node_494());
    values.push(node_496());
    values.push(node_497());
    values.push(node_498());
    values.push(node_500());
    values.push(node_501());
    values.push(node_503());
    values.push(node_504());
    values.push(node_506());
    values.push(node_508());
    Value::Sequence(values)
}

fn node_451() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_452());
    Value::Mapping(values)
}

fn node_452() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_453() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("sources"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("if"), text("hashFiles('Cargo.lock') != ''"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_454());
    Value::Mapping(values)
}

fn node_454() -> Value {
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

fn node_455() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R0));
    Value::Mapping(values)
}

fn node_456() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R1));
    values.insert(text("id"), text("driver-build"));
    Value::Mapping(values)
}

fn node_457() -> Value {
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

fn node_458() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.driver-build.outcome == 'success' && steps.bootstrap-home.outcome == 'success' && steps.bootstrap-home.outputs.bootstrap-home-matches == 'true' && steps.sources.outputs.cache-primary-key != '' && steps.sources.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_459());
    Value::Mapping(values)
}

fn node_459() -> Value {
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

fn node_460() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-context"));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_461() -> Value {
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
    values.insert(text("with"), node_462());
    Value::Mapping(values)
}

fn node_462() -> Value {
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

fn node_463() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R4));
    Value::Mapping(values)
}

fn node_464() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore"));
    values.insert(text("if"),text("steps.archive-seed-context.outputs.seed-lookup-key != '' && steps.workspace-downloads.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_465());
    Value::Mapping(values)
}

fn node_465() -> Value {
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

fn node_466() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-restore-import"));
    values.insert(text("if"),text("steps.archive-seed-restore.outcome == 'success' && steps.archive-seed-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R5));
    Value::Mapping(values)
}

fn node_467() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-context"));
    values.insert(text("if"), text("success()"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R6));
    Value::Mapping(values)
}

fn node_468() -> Value {
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
    values.insert(text("with"), node_469());
    Value::Mapping(values)
}

fn node_469() -> Value {
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

fn node_470() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-restore-import"));
    values.insert(text("if"),text("steps.index-snapshot-restore.outcome == 'success' && steps.index-snapshot-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R7));
    Value::Mapping(values)
}

fn node_471() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(text("run"), literal(LiteralRun::R8));
    Value::Mapping(values)
}

fn node_472() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R9));
    Value::Mapping(values)
}

fn node_473() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-probe"));
    values.insert(text("if"),text("always() && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_474());
    Value::Mapping(values)
}

fn node_474() -> Value {
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

fn node_475() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.archive-seed-snapshot.outputs.snapshot-ready == 'true' && steps.archive-seed-snapshot.outputs.seed-compatibility == steps.archive-seed-context.outputs.seed-compatibility && steps.archive-seed-snapshot.outputs.snapshot-key != '' && steps.archive-seed-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_476());
    Value::Mapping(values)
}

fn node_476() -> Value {
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

fn node_477() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("archive-seed-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.archive-seed-snapshot.outcome == 'success' || steps.archive-seed-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R10));
    Value::Mapping(values)
}

fn node_478() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R11));
    Value::Mapping(values)
}

fn node_479() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-probe"));
    values.insert(text("if"),text("always() && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_480());
    Value::Mapping(values)
}

fn node_480() -> Value {
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

fn node_481() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.index-snapshot-snapshot.outputs.snapshot-ready == 'true' && steps.index-snapshot-snapshot.outputs.seed-compatibility == steps.index-snapshot-context.outputs.seed-compatibility && steps.index-snapshot-snapshot.outputs.snapshot-key != '' && steps.index-snapshot-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_482());
    Value::Mapping(values)
}

fn node_482() -> Value {
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

fn node_483() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("index-snapshot-snapshot-cleanup"));
    values.insert(text("if"),text("always() && (steps.index-snapshot-snapshot.outcome == 'success' || steps.index-snapshot-snapshot.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R12));
    Value::Mapping(values)
}

fn node_484() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-download-save-context"));
    values.insert(text("if"),text("always() && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-context.outputs.source-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true')"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R3));
    Value::Mapping(values)
}

fn node_485() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Save complete workspace downloads"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.workspace-download-context.outputs.source-key != '' && steps.workspace-download-context.outputs.source-paths != '' && steps.workspace-fetch.outputs.cache-quiescent == 'true' && steps.workspace-fetch.outputs.workspace-downloads-populated == 'true' && steps.workspace-download-save-context.outcome == 'success' && steps.workspace-download-save-context.outputs.source-key == steps.workspace-download-context.outputs.source-key && steps.workspace-download-save-context.outputs.source-key == steps.workspace-fetch.outputs.workspace-downloads-key && !(steps.workspace-downloads.outcome == 'success' && steps.workspace-downloads.outputs.cache-hit == 'true') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && steps.workspace-download-context.outputs.source-paths != ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_486());
    Value::Mapping(values)
}

fn node_486() -> Value {
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

fn node_487() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-context"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R222));
    Value::Mapping(values)
}

fn node_488() -> Value {
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
    values.insert(text("with"), node_489());
    Value::Mapping(values)
}

fn node_489() -> Value {
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

fn node_490() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize compiled discard restore"));
    values.insert(
        text("id"),
        text("sanitize-stress-lifecycle-complete-recipe-discard"),
    );
    values.insert(text("if"), text("steps.compiled.outcome == 'failure'"));
    values.insert(text("run"), literal(LiteralRun::R223));
    Value::Mapping(values)
}

fn node_491() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize compiled exact restore"));
    values.insert(
        text("id"),
        text("sanitize-stress-lifecycle-complete-recipe-exact"),
    );
    values.insert(
        text("if"),
        text("steps.compiled.outcome == 'success' && steps.compiled.outputs.cache-hit == 'true'"),
    );
    values.insert(text("run"), literal(LiteralRun::R224));
    Value::Mapping(values)
}

fn node_492() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Sanitize compiled compatible restore"));
    values.insert(
        text("id"),
        text("sanitize-stress-lifecycle-complete-recipe-compatible"),
    );
    values.insert(text("if"),text("steps.compiled.outcome == 'success' && steps.compiled.outputs.cache-matched-key != '' && steps.compiled.outputs.cache-hit != 'true'"));
    values.insert(text("run"), literal(LiteralRun::R225));
    Value::Mapping(values)
}

fn node_493() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-context"));
    values.insert(text("if"),text("steps.compiled-context.outputs.product-key != '' && steps.compiled.outcome != 'failure' && steps.compiled.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("1"));
    values.insert(text("run"), literal(LiteralRun::R226));
    Value::Mapping(values)
}

fn node_494() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-restore"));
    values.insert(text("if"),text("steps.compiled-partial-context.outputs.seed-lookup-key != '' && steps.compiled-context.outputs.product-key != '' && steps.compiled.outcome != 'failure' && steps.compiled.outputs.cache-matched-key == ''"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_495());
    Value::Mapping(values)
}

fn node_495() -> Value {
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

fn node_496() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-import"));
    values.insert(text("if"),text("steps.compiled-partial-restore.outcome == 'success' && steps.compiled-partial-restore.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R227));
    Value::Mapping(values)
}

fn node_497() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("stress-run"));
    values.insert(text("run"), literal(LiteralRun::R228));
    Value::Mapping(values)
}

fn node_498() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("always()"));
    values.insert(text("uses"), text("./.github/actions/upload-artifact"));
    values.insert(text("with"), node_499());
    Value::Mapping(values)
}

fn node_499() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("stress-lifecycle-${{ matrix.id }}"));
    values.insert(text("include-hidden-files"), Value::Bool(true));
    values.insert(text("path"),text("target/ci/reports/stress\ntarget/ci/reports/stress-seed.txt\ntarget/ci/reports/stress-deep_short_child_iterations.json\n"));
    values.insert(text("if-no-files-found"), text("warn"));
    Value::Mapping(values)
}

fn node_500() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-save-context"));
    values.insert(text("if"),text("always() && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-stress-lifecycle-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-stress-lifecycle-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-stress-lifecycle-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-stress-lifecycle-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-stress-lifecycle-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-stress-lifecycle-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.stress-run.outcome == 'skipped' || steps.stress-run.outputs.cache-quiescent == 'true') && steps.compiled-context.outputs.compiled-cache-usable == 'true' && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.compiled-partial-import.outcome == 'skipped' || steps.compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("run"), literal(LiteralRun::R229));
    Value::Mapping(values)
}

fn node_501() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-stress-lifecycle-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-stress-lifecycle-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-stress-lifecycle-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-stress-lifecycle-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-stress-lifecycle-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-stress-lifecycle-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.stress-run.outcome == 'skipped' || steps.stress-run.outputs.cache-quiescent == 'true') && steps.compiled-context.outputs.product-key != '' && steps.compiled-save-context.outcome == 'success' && steps.compiled-save-context.outputs.product-key == steps.compiled-context.outputs.product-key && steps.compiled-save-context.outputs.payload-ready == 'true' && (steps.stress-run.outputs.compiled-recipe-complete == 'true') && !(steps.compiled.outcome == 'success' && steps.compiled.outputs.cache-hit == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.compiled-partial-import.outcome == 'skipped' || steps.compiled-partial-import.outputs.cache-quiescent == 'true') && steps.compiled-context.outputs.product-paths != '' && steps.compiled-context.outputs.compiled-cache-usable == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_502());
    Value::Mapping(values)
}

fn node_502() -> Value {
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

fn node_503() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.compiled-context.outputs.product-key != '' && (steps.driver-build.outcome == 'skipped' || steps.driver-build.outcome == 'success') && (steps.workspace-fetch.outcome == 'skipped' || steps.workspace-fetch.outputs.cache-quiescent == 'true') && (steps.sanitize-stress-lifecycle-complete-recipe-discard.outcome == 'skipped' || steps.sanitize-stress-lifecycle-complete-recipe-discard.outputs.cache-quiescent == 'true') && (steps.sanitize-stress-lifecycle-complete-recipe-exact.outcome == 'skipped' || steps.sanitize-stress-lifecycle-complete-recipe-exact.outputs.cache-quiescent == 'true') && (steps.sanitize-stress-lifecycle-complete-recipe-compatible.outcome == 'skipped' || steps.sanitize-stress-lifecycle-complete-recipe-compatible.outputs.cache-quiescent == 'true') && (steps.stress-run.outcome == 'skipped' || steps.stress-run.outputs.cache-quiescent == 'true') && !((steps.stress-run.outputs.compiled-recipe-complete == 'true') && steps.compiled-save-context.outputs.payload-ready == 'true') && (steps.archive-seed-restore-import.outcome == 'skipped' || steps.archive-seed-restore-import.outputs.cache-quiescent == 'true') && (steps.index-snapshot-restore-import.outcome == 'skipped' || steps.index-snapshot-restore-import.outputs.cache-quiescent == 'true') && (steps.compiled-partial-import.outcome == 'skipped' || steps.compiled-partial-import.outputs.cache-quiescent == 'true')"));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(text("run"), literal(LiteralRun::R230));
    Value::Mapping(values)
}

fn node_504() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-probe"));
    values.insert(text("if"),text("always() && steps.compiled-partial.outputs.snapshot-ready == 'true' && steps.compiled-partial.outputs.input-key == steps.compiled-context.outputs.product-key"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_505());
    Value::Mapping(values)
}

fn node_505() -> Value {
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

fn node_506() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-save"));
    values.insert(text("if"),text("always() && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && steps.compiled-partial.outputs.snapshot-ready == 'true' && steps.compiled-partial.outputs.input-key == steps.compiled-context.outputs.product-key && steps.compiled-partial.outputs.snapshot-key != '' && steps.compiled-partial-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), number("6"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_507());
    Value::Mapping(values)
}

fn node_507() -> Value {
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

fn node_508() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("compiled-partial-cleanup"));
    values.insert(text("if"),text("always() && (steps.compiled-partial.outcome == 'success' || steps.compiled-partial.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), number("2"));
    values.insert(text("run"), literal(LiteralRun::R231));
    Value::Mapping(values)
}

fn node_509() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("always() && github.event.deleted != true"));
    values.insert(text("needs"), node_510());
    values.insert(text("runs-on"), text("ubuntu-24.04"));
    values.insert(text("timeout-minutes"), number("20"));
    values.insert(text("steps"), node_511());
    Value::Mapping(values)
}

fn node_510() -> Value {
    let mut values = Vec::new();
    values.push(text("performance-plan"));
    values.push(text("stress"));
    values.push(text("stress-packages"));
    values.push(text("stress-lifecycle"));
    Value::Sequence(values)
}

fn node_511() -> Value {
    let mut values = Vec::new();
    values.push(node_512());
    values.push(node_514());
    values.push(node_516());
    values.push(node_517());
    values.push(node_518());
    values.push(node_519());
    Value::Sequence(values)
}

fn node_512() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_513());
    Value::Mapping(values)
}

fn node_513() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_514() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"),
    );
    values.insert(text("with"), node_515());
    Value::Mapping(values)
}

fn node_515() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("pattern"), text("stress-*"));
    values.insert(text("path"), text("target/ci/stress-artifacts"));
    Value::Mapping(values)
}

fn node_516() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R0));
    Value::Mapping(values)
}

fn node_517() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R1));
    Value::Mapping(values)
}

fn node_518() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("run"), literal(LiteralRun::R232));
    Value::Mapping(values)
}

fn node_519() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("always()"));
    values.insert(text("uses"), text("./.github/actions/upload-artifact"));
    values.insert(text("with"), node_520());
    Value::Mapping(values)
}

fn node_520() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("stress-assessment"));
    values.insert(
        text("path"),
        text("target/ci/reports/stress-assessment.json"),
    );
    values.insert(text("if-no-files-found"), text("warn"));
    Value::Mapping(values)
}
