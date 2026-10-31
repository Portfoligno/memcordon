//! Current workflow authoring values; generated YAML is derived from this graph.
#![allow(clippy::vec_init_then_push)]
use super::text;
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

fn node_14() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("policy"), node_15());
    values.insert(text("quality"), node_80());
    values.insert(text("msrv"), node_176());
    values.insert(text("quality-docs"), node_273());
    values.insert(text("native"), node_369());
    values.insert(text("macos-deadline"), node_590());
    values.insert(text("supply-chain-audit"), node_693());
    values.insert(text("supply-chain-deny"), node_815());
    values.insert(text("source-seed"), node_937());
    values.insert(text("format"), node_955());
    values.insert(text("current-contracts"), node_963());
    values.insert(text("tooling-contracts"), node_985());
    values.insert(text("macos-administrative-contracts"), node_1002());
    values.insert(text("macos-startup-deadline-feedback"), node_1019());
    values.insert(text("windows-fixture-feedback"), node_1036());
    values.insert(text("windows-sealed-agent-contracts"), node_1060());
    values.insert(text("windows-fixture-native"), node_1084());
    Value::Mapping(values)
}

fn node_1084() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("github.event.deleted != true"));
    values.insert(
        text("name"),
        text("Windows fixture native / ${{ matrix.id }}"),
    );
    values.insert(text("strategy"), node_1085());
    values.insert(text("runs-on"), text("${{ matrix.runner }}"));
    values.insert(text("timeout-minutes"), Value::Number(219.into()));
    values.insert(text("steps"), node_1090());
    values.insert(text("env"), node_1239());
    Value::Mapping(values)
}

fn node_1239() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("CARGO_HOME"),
        text("${{ github.workspace }}/target/ci-cargo-home"),
    );
    Value::Mapping(values)
}

fn node_1090() -> Value {
    let mut values = Vec::new();
    values.push(node_1091());
    values.push(node_1092());
    values.push(node_1094());
    values.push(node_1095());
    values.push(node_1096());
    values.push(node_1098());
    values.push(node_1100());
    values.push(node_1101());
    values.push(node_1102());
    values.push(node_1104());
    values.push(node_1105());
    values.push(node_1107());
    values.push(node_1109());
    values.push(node_1111());
    values.push(node_1113());
    values.push(node_1115());
    values.push(node_1116());
    values.push(node_1118());
    values.push(node_1120());
    values.push(node_1122());
    values.push(node_1124());
    values.push(node_1126());
    values.push(node_1128());
    values.push(node_1130());
    values.push(node_1132());
    values.push(node_1134());
    values.push(node_1136());
    values.push(node_1138());
    values.push(node_1139());
    values.push(node_1140());
    values.push(node_1141());
    values.push(node_1143());
    values.push(node_1145());
    values.push(node_1147());
    values.push(node_1149());
    values.push(node_1151());
    values.push(node_1153());
    values.push(node_1154());
    values.push(node_1155());
    values.push(node_1157());
    values.push(node_1158());
    values.push(node_1159());
    values.push(node_1161());
    values.push(node_1162());
    values.push(node_1164());
    values.push(node_1166());
    values.push(node_1168());
    values.push(node_1170());
    values.push(node_1172());
    values.push(node_1173());
    values.push(node_1175());
    values.push(node_1177());
    values.push(node_1179());
    values.push(node_1181());
    values.push(node_1183());
    values.push(node_1185());
    values.push(node_1187());
    values.push(node_1189());
    values.push(node_1191());
    values.push(node_1193());
    values.push(node_1195());
    values.push(node_1196());
    values.push(node_1197());
    values.push(node_1198());
    values.push(node_1200());
    values.push(node_1202());
    values.push(node_1204());
    values.push(node_1206());
    values.push(node_1208());
    values.push(node_1210());
    values.push(node_1211());
    values.push(node_1212());
    values.push(node_1213());
    values.push(node_1215());
    values.push(node_1217());
    values.push(node_1219());
    values.push(node_1221());
    values.push(node_1223());
    values.push(node_1224());
    values.push(node_1226());
    values.push(node_1228());
    values.push(node_1230());
    values.push(node_1232());
    values.push(node_1234());
    values.push(node_1236());
    values.push(node_1238());
    Value::Sequence(values)
}

fn node_1238() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("windows-fixture-native-cleanup"));
    values.insert(text("if"), text("always() && (steps.windows-fixture-native.outcome == 'success' || steps.windows-fixture-native.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(text("run"), text("./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers windows-fixture-native"));
    Value::Mapping(values)
}

fn node_1236() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("windows-fixture-native-compiled-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.windows-fixture-native.outputs.compiled-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1237());
    Value::Mapping(values)
}

fn node_1237() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.windows-fixture-native.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.windows-fixture-native.outputs.compiled-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_1234() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("windows-fixture-native-compiled-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.windows-fixture-native.outputs.compiled-complete-save == 'true' && steps.windows-fixture-native-compiled-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1235());
    Value::Mapping(values)
}

fn node_1235() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.windows-fixture-native.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.windows-fixture-native.outputs.compiled-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_1232() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("windows-fixture-native-compiled-complete-probe"),
    );
    values.insert(
        text("if"),
        text(
            "!cancelled() && steps.windows-fixture-native.outputs.compiled-complete-save == 'true'",
        ),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1233());
    Value::Mapping(values)
}

fn node_1233() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.windows-fixture-native.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.windows-fixture-native.outputs.compiled-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_1230() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("windows-fixture-native-index-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.windows-fixture-native.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1231());
    Value::Mapping(values)
}

fn node_1231() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.windows-fixture-native.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.windows-fixture-native.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_1228() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("windows-fixture-native-archives-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.windows-fixture-native.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1229());
    Value::Mapping(values)
}

fn node_1229() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.windows-fixture-native.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.windows-fixture-native.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_1226() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("windows-fixture-native-source-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.windows-fixture-native.outputs.source-complete-save == 'true' && steps.windows-fixture-native-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1227());
    Value::Mapping(values)
}

fn node_1227() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.windows-fixture-native.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.windows-fixture-native.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_1224() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("windows-fixture-native-source-complete-probe"),
    );
    values.insert(
        text("if"),
        text("!cancelled() && steps.windows-fixture-native.outputs.source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1225());
    Value::Mapping(values)
}

fn node_1225() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.windows-fixture-native.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.windows-fixture-native.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_1223() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Compile and execute the exact Windows fixture native contract"),
    );
    values.insert(text("timeout-minutes"), Value::Number(70.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci.exe ci segment windows-fixture-native"),
    );
    values.insert(text("id"), text("windows-fixture-native"));
    values.insert(text("if"), text("runner.os == 'Windows'"));
    Value::Mapping(values)
}

fn node_1221() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("windows-fixture-native-request-compiled-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.windows-fixture-native-request.outputs.compiled-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1222());
    Value::Mapping(values)
}

fn node_1222() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.windows-fixture-native-request.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.windows-fixture-native-request.outputs.compiled-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.windows-fixture-native-request.outputs.compiled-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_1219() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("windows-fixture-native-request-compiled-complete-restore"),
    );
    values.insert(
        text("if"),
        text("steps.windows-fixture-native-request.outputs.compiled-complete-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1220());
    Value::Mapping(values)
}

fn node_1220() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.windows-fixture-native-request.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.windows-fixture-native-request.outputs.compiled-complete-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.windows-fixture-native-request.outputs.compiled-complete-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_1217() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("windows-fixture-native-request-index-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.windows-fixture-native-request.outputs.index-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1218());
    Value::Mapping(values)
}

fn node_1218() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.windows-fixture-native-request.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.windows-fixture-native-request.outputs.index-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.windows-fixture-native-request.outputs.index-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_1215() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("windows-fixture-native-request-archives-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.windows-fixture-native-request.outputs.archives-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1216());
    Value::Mapping(values)
}

fn node_1216() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.windows-fixture-native-request.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.windows-fixture-native-request.outputs.archives-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.windows-fixture-native-request.outputs.archives-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_1213() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("windows-fixture-native-request-source-restore"),
    );
    values.insert(
        text("if"),
        text("steps.windows-fixture-native-request.outputs.source-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1214());
    Value::Mapping(values)
}

fn node_1214() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.windows-fixture-native-request.outputs.source-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.windows-fixture-native-request.outputs.source-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.windows-fixture-native-request.outputs.source-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_1212() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("windows-fixture-native-request"));
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text(
            "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests windows-fixture-native",
        ),
    );
    values.insert(text("if"), text("runner.os == 'Windows'"));
    Value::Mapping(values)
}

fn node_1211() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-workflows-check-windows"));
    values.insert(text("if"), text("runner.os == 'Windows'"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci.exe ci workflows --check"),
    );
    Value::Mapping(values)
}

fn node_1210() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-cleanup-windows"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt-windows.outcome == 'success'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci.exe ci driver-cleanup"),
    );
    Value::Mapping(values)
}

fn node_1208() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-cold-adopt-windows-index-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt-windows.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1209());
    Value::Mapping(values)
}

fn node_1209() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt-windows.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt-windows.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_1206() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-cold-adopt-windows-archives-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt-windows.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1207());
    Value::Mapping(values)
}

fn node_1207() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt-windows.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt-windows.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_1204() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-cold-adopt-windows-source-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-cold-adopt-windows.outputs.source-complete-save == 'true' && steps.driver-cold-adopt-windows-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1205());
    Value::Mapping(values)
}

fn node_1205() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt-windows.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt-windows.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_1202() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-cold-adopt-windows-source-complete-probe"),
    );
    values.insert(text("if"), text("!cancelled() && steps.driver-cold-adopt-windows.outputs.source-complete-save == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1203());
    Value::Mapping(values)
}

fn node_1203() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt-windows.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt-windows.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_1200() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-windows-bootstrap-save"));
    values.insert(text("if"), text("always() && steps.driver-cold-adopt-windows.outputs.bootstrap-save == 'true' && steps.driver-cold-adopt-windows-bootstrap-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1201());
    Value::Mapping(values)
}

fn node_1201() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt-windows.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt-windows.outputs.bootstrap-path }}"),
    );
    Value::Mapping(values)
}

fn node_1198() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-cold-adopt-windows-bootstrap-probe"),
    );
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-cold-adopt-windows.outputs.bootstrap-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1199());
    Value::Mapping(values)
}

fn node_1199() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt-windows.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt-windows.outputs.bootstrap-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_1197() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-windows"));
    values.insert(
        text("if"),
        text("steps.driver-cold-build-windows.outcome == 'success'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    values.insert(
        text("run"),
        text("./target/ci-driver-cold/release/memcordon-ci.exe ci driver-adopt-cold"),
    );
    Value::Mapping(values)
}

fn node_1196() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-build-windows"));
    values.insert(text("if"), text("runner.os == 'Windows' && steps.driver-bootstrap-windows.outputs.bootstrap-ready != 'true'"));
    values.insert(text("timeout-minutes"), Value::Number(30.into()));
    values.insert(text("run"), text("rustup run 1.97.1 cargo build --locked --release --target-dir target/ci-driver-cold -p memcordon-ci --bin memcordon-ci"));
    Value::Mapping(values)
}

fn node_1195() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-cleanup-windows"));
    values.insert(text("if"), text("always() && (steps.driver-managed-build-windows.outcome == 'success' || steps.driver-managed-build-windows.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci.exe ci driver-cleanup"),
    );
    Value::Mapping(values)
}

fn node_1193() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-windows-index-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build-windows.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1194());
    Value::Mapping(values)
}

fn node_1194() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build-windows.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build-windows.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_1191() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-windows-archives-partial-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-managed-build-windows.outputs.archives-partial-save == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1192());
    Value::Mapping(values)
}

fn node_1192() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build-windows.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build-windows.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_1189() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-windows-source-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-managed-build-windows.outputs.source-complete-save == 'true' && steps.driver-managed-build-windows-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1190());
    Value::Mapping(values)
}

fn node_1190() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build-windows.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build-windows.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_1187() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-windows-source-complete-probe"),
    );
    values.insert(text("if"), text("!cancelled() && steps.driver-managed-build-windows.outputs.source-complete-save == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1188());
    Value::Mapping(values)
}

fn node_1188() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build-windows.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build-windows.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_1185() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-windows-compiled-partial-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-managed-build-windows.outputs.compiled-partial-save == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1186());
    Value::Mapping(values)
}

fn node_1186() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build-windows.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build-windows.outputs.compiled-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_1183() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-windows-compiled-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-managed-build-windows.outputs.compiled-complete-save == 'true' && steps.driver-managed-build-windows-compiled-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1184());
    Value::Mapping(values)
}

fn node_1184() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build-windows.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build-windows.outputs.compiled-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_1181() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-windows-compiled-complete-probe"),
    );
    values.insert(text("if"), text("!cancelled() && steps.driver-managed-build-windows.outputs.compiled-complete-save == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1182());
    Value::Mapping(values)
}

fn node_1182() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build-windows.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build-windows.outputs.compiled-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_1179() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-windows-image-save"));
    values.insert(text("if"), text("always() && steps.driver-managed-build-windows.outputs.image-save == 'true' && steps.driver-managed-build-windows-image-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1180());
    Value::Mapping(values)
}

fn node_1180() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build-windows.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build-windows.outputs.image-path }}"),
    );
    Value::Mapping(values)
}

fn node_1177() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-windows-image-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build-windows.outputs.image-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1178());
    Value::Mapping(values)
}

fn node_1178() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build-windows.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build-windows.outputs.image-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_1175() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-windows-bootstrap-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-managed-build-windows.outputs.bootstrap-save == 'true' && steps.driver-managed-build-windows-bootstrap-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1176());
    Value::Mapping(values)
}

fn node_1176() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build-windows.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build-windows.outputs.bootstrap-path }}"),
    );
    Value::Mapping(values)
}

fn node_1173() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-windows-bootstrap-probe"),
    );
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build-windows.outputs.bootstrap-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1174());
    Value::Mapping(values)
}

fn node_1174() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build-windows.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build-windows.outputs.bootstrap-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_1172() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-windows"));
    values.insert(
        text("if"),
        text("steps.driver-selection-windows.outputs.build-required == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(50.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci.exe ci driver-build"),
    );
    Value::Mapping(values)
}

fn node_1170() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-context-windows-compiled-partial-restore"),
    );
    values.insert(text("if"), text("steps.driver-selection-windows.outputs.build-required == 'true' && steps.driver-context-windows.outputs.compiled-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1171());
    Value::Mapping(values)
}

fn node_1171() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context-windows.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context-windows.outputs.compiled-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context-windows.outputs.compiled-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_1168() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-context-windows-compiled-complete-restore"),
    );
    values.insert(text("if"), text("steps.driver-selection-windows.outputs.build-required == 'true' && steps.driver-context-windows.outputs.compiled-complete-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1169());
    Value::Mapping(values)
}

fn node_1169() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context-windows.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context-windows.outputs.compiled-complete-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context-windows.outputs.compiled-complete-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_1166() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-context-windows-index-partial-restore"),
    );
    values.insert(text("if"), text("steps.driver-selection-windows.outputs.build-required == 'true' && steps.driver-context-windows.outputs.index-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1167());
    Value::Mapping(values)
}

fn node_1167() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context-windows.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context-windows.outputs.index-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context-windows.outputs.index-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_1164() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-context-windows-archives-partial-restore"),
    );
    values.insert(text("if"), text("steps.driver-selection-windows.outputs.build-required == 'true' && steps.driver-context-windows.outputs.archives-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1165());
    Value::Mapping(values)
}

fn node_1165() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context-windows.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context-windows.outputs.archives-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context-windows.outputs.archives-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_1162() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-windows-source-restore"));
    values.insert(text("if"), text("steps.driver-selection-windows.outputs.build-required == 'true' && steps.driver-context-windows.outputs.source-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1163());
    Value::Mapping(values)
}

fn node_1163() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context-windows.outputs.source-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context-windows.outputs.source-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context-windows.outputs.source-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_1161() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-selection-windows"));
    values.insert(
        text("if"),
        text("steps.driver-bootstrap-windows.outputs.bootstrap-ready == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(4.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci.exe ci driver-select"),
    );
    Value::Mapping(values)
}

fn node_1159() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-windows-image-restore"));
    values.insert(
        text("if"),
        text("steps.driver-context-windows.outputs.image-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1160());
    Value::Mapping(values)
}

fn node_1160() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context-windows.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context-windows.outputs.image-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context-windows.outputs.image-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_1158() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-windows"));
    values.insert(
        text("if"),
        text("steps.driver-bootstrap-windows.outputs.bootstrap-ready == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci.exe ci driver-context"),
    );
    Value::Mapping(values)
}

fn node_1157() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-bootstrap-windows"));
    values.insert(text("if"), text("runner.os == 'Windows' && steps.driver-bootstrap-cache-windows.outcome == 'success' && steps.driver-bootstrap-cache-windows.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-bootstrap-in/memcordon-ci.exe ci driver-bootstrap"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_1155() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-bootstrap-cache-windows"));
    values.insert(text("if"), text("runner.os == 'Windows'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1156());
    Value::Mapping(values)
}

fn node_1156() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-bootstrap-in"));
    values.insert(text("key"), text("mc-ci-bootstrap-v3-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/driver-bootstrap.toml', 'ci/toolchains.toml') }}-lookup"));
    values.insert(text("restore-keys"), text("mc-ci-bootstrap-v3-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/driver-bootstrap.toml', 'ci/toolchains.toml') }}-"));
    Value::Mapping(values)
}

fn node_1154() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-workflows-check"));
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci workflows --check"),
    );
    Value::Mapping(values)
}

fn node_1153() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-cleanup"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt.outcome == 'success'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci driver-cleanup"),
    );
    Value::Mapping(values)
}

fn node_1151() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-index-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1152());
    Value::Mapping(values)
}

fn node_1152() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_1149() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-archives-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1150());
    Value::Mapping(values)
}

fn node_1150() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_1147() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-source-complete-save"));
    values.insert(text("if"), text("always() && steps.driver-cold-adopt.outputs.source-complete-save == 'true' && steps.driver-cold-adopt-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1148());
    Value::Mapping(values)
}

fn node_1148() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_1145() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-source-complete-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-cold-adopt.outputs.source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1146());
    Value::Mapping(values)
}

fn node_1146() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_1143() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-bootstrap-save"));
    values.insert(text("if"), text("always() && steps.driver-cold-adopt.outputs.bootstrap-save == 'true' && steps.driver-cold-adopt-bootstrap-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1144());
    Value::Mapping(values)
}

fn node_1144() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-path }}"),
    );
    Value::Mapping(values)
}

fn node_1141() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-bootstrap-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-cold-adopt.outputs.bootstrap-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1142());
    Value::Mapping(values)
}

fn node_1142() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_1140() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt"));
    values.insert(
        text("if"),
        text("steps.driver-cold-build.outcome == 'success'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    values.insert(
        text("run"),
        text("./target/ci-driver-cold/release/memcordon-ci ci driver-adopt-cold"),
    );
    Value::Mapping(values)
}

fn node_1139() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-build"));
    values.insert(
        text("if"),
        text("runner.os != 'Windows' && steps.driver-bootstrap.outputs.bootstrap-ready != 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(30.into()));
    values.insert(text("run"), text("rustup run 1.97.1 cargo build --locked --release --target-dir target/ci-driver-cold -p memcordon-ci --bin memcordon-ci"));
    Value::Mapping(values)
}

fn node_1138() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-cleanup"));
    values.insert(text("if"), text("always() && (steps.driver-managed-build.outcome == 'success' || steps.driver-managed-build.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-cleanup"),
    );
    Value::Mapping(values)
}

fn node_1136() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-index-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1137());
    Value::Mapping(values)
}

fn node_1137() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_1134() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-archives-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1135());
    Value::Mapping(values)
}

fn node_1135() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_1132() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-source-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.source-complete-save == 'true' && steps.driver-managed-build-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1133());
    Value::Mapping(values)
}

fn node_1133() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_1130() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-source-complete-probe"),
    );
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1131());
    Value::Mapping(values)
}

fn node_1131() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_1128() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-compiled-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build.outputs.compiled-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1129());
    Value::Mapping(values)
}

fn node_1129() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.compiled-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_1126() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-compiled-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.compiled-complete-save == 'true' && steps.driver-managed-build-compiled-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1127());
    Value::Mapping(values)
}

fn node_1127() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_1124() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-compiled-complete-probe"),
    );
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.compiled-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1125());
    Value::Mapping(values)
}

fn node_1125() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_1122() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-image-save"));
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.image-save == 'true' && steps.driver-managed-build-image-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1123());
    Value::Mapping(values)
}

fn node_1123() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.image-path }}"),
    );
    Value::Mapping(values)
}

fn node_1120() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-image-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.image-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1121());
    Value::Mapping(values)
}

fn node_1121() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.image-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_1118() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-bootstrap-save"));
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.bootstrap-save == 'true' && steps.driver-managed-build-bootstrap-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1119());
    Value::Mapping(values)
}

fn node_1119() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-path }}"),
    );
    Value::Mapping(values)
}

fn node_1116() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-bootstrap-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.bootstrap-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1117());
    Value::Mapping(values)
}

fn node_1117() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_1115() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build"));
    values.insert(
        text("if"),
        text("steps.driver-selection.outputs.build-required == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(50.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-build"),
    );
    Value::Mapping(values)
}

fn node_1113() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-compiled-partial-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.compiled-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1114());
    Value::Mapping(values)
}

fn node_1114() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.compiled-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.compiled-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_1111() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-compiled-complete-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.compiled-complete-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1112());
    Value::Mapping(values)
}

fn node_1112() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.compiled-complete-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.compiled-complete-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_1109() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-index-partial-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.index-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1110());
    Value::Mapping(values)
}

fn node_1110() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.index-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.index-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_1107() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-archives-partial-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.archives-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1108());
    Value::Mapping(values)
}

fn node_1108() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.archives-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.archives-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_1105() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-source-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.source-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1106());
    Value::Mapping(values)
}

fn node_1106() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.source-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.source-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.source-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_1104() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-selection"));
    values.insert(
        text("if"),
        text("steps.driver-bootstrap.outputs.bootstrap-ready == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(4.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-select"),
    );
    Value::Mapping(values)
}

fn node_1102() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-image-restore"));
    values.insert(
        text("if"),
        text("steps.driver-context.outputs.image-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1103());
    Value::Mapping(values)
}

fn node_1103() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.image-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.image-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_1101() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context"));
    values.insert(
        text("if"),
        text("steps.driver-bootstrap.outputs.bootstrap-ready == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-context"),
    );
    Value::Mapping(values)
}

fn node_1100() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-bootstrap"));
    values.insert(text("if"), text("runner.os != 'Windows' && steps.driver-bootstrap-cache.outcome == 'success' && steps.driver-bootstrap-cache.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-bootstrap-in/memcordon-ci ci driver-bootstrap"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_1098() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-bootstrap-cache"));
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_1099());
    Value::Mapping(values)
}

fn node_1099() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-bootstrap-in"));
    values.insert(text("key"), text("mc-ci-bootstrap-v3-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/driver-bootstrap.toml', 'ci/toolchains.toml') }}-lookup"));
    values.insert(text("restore-keys"), text("mc-ci-bootstrap-v3-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/driver-bootstrap.toml', 'ci/toolchains.toml') }}-"));
    Value::Mapping(values)
}

fn node_1096() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("public-source-seed-restore"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(text("with"), node_1097());
    Value::Mapping(values)
}

fn node_1097() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-cargo-home/registry/cache/index.crates.io-1949cf8c6b5b557f/*.crate\ntarget/ci-cargo-home/registry/cache/index.crates.io-6f17d22bba15001f/*.crate\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/.cache\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/config.json"));
    values.insert(text("key"), text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-${{ hashFiles('Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', 'tools/*/Cargo.toml', '.cargo/**') }}"));
    values.insert(
        text("restore-keys"),
        text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-"),
    );
    Value::Mapping(values)
}

fn node_1095() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Initialize genuine auxiliary Cargo target"),
    );
    values.insert(
        text("run"),
        text("rustup run 1.97.1 cargo clean --locked --package memcordon-ci --target-dir target"),
    );
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    Value::Mapping(values)
}

fn node_1094() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Install pinned Rust"));
    values.insert(
        text("run"),
        text("rustup toolchain install 1.97.1 --profile minimal"),
    );
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    Value::Mapping(values)
}

fn node_1092() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Check out repository"));
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_1093());
    values.insert(text("timeout-minutes"), Value::Number(6.into()));
    Value::Mapping(values)
}

fn node_1093() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_1091() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Configure checkout line endings"));
    values.insert(text("run"), text("git config --global core.autocrlf false"));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    Value::Mapping(values)
}

fn node_1085() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("fail-fast"), Value::Bool(false));
    values.insert(text("matrix"), node_1086());
    Value::Mapping(values)
}

fn node_1086() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("include"), node_1087());
    Value::Mapping(values)
}

fn node_1087() -> Value {
    let mut values = Vec::new();
    values.push(node_1088());
    values.push(node_1089());
    Value::Sequence(values)
}

fn node_1089() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("windows-arm64"));
    values.insert(text("runner"), text("windows-11-arm"));
    Value::Mapping(values)
}

fn node_1088() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("windows-x64"));
    values.insert(text("runner"), text("windows-2025"));
    Value::Mapping(values)
}

fn node_1060() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Windows sealed-agent contracts / ${{ matrix.id }}"),
    );
    values.insert(text("if"), text("github.event.deleted != true"));
    values.insert(text("permissions"), node_1061());
    values.insert(text("steps"), node_1062());
    values.insert(text("runs-on"), text("${{ matrix.runner }}"));
    values.insert(text("timeout-minutes"), Value::Number(53.into()));
    values.insert(text("env"), node_1078());
    values.insert(text("strategy"), node_1079());
    Value::Mapping(values)
}

fn node_1079() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("fail-fast"), Value::Bool(false));
    values.insert(text("matrix"), node_1080());
    Value::Mapping(values)
}

fn node_1080() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("include"), node_1081());
    Value::Mapping(values)
}

fn node_1081() -> Value {
    let mut values = Vec::new();
    values.push(node_1082());
    values.push(node_1083());
    Value::Sequence(values)
}

fn node_1083() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("windows-arm64"));
    values.insert(text("runner"), text("windows-11-arm"));
    Value::Mapping(values)
}

fn node_1082() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("windows-x64"));
    values.insert(text("runner"), text("windows-2025"));
    Value::Mapping(values)
}

fn node_1078() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("CARGO_HOME"),
        text("${{ github.workspace }}/target/ci-cargo-home"),
    );
    Value::Mapping(values)
}

fn node_1062() -> Value {
    let mut values = Vec::new();
    values.push(node_1063());
    values.push(node_1064());
    values.push(node_1066());
    values.push(node_1067());
    values.push(node_1069());
    values.push(node_1071());
    values.push(node_1072());
    values.push(node_1074());
    values.push(node_1076());
    Value::Sequence(values)
}

fn node_1076() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Retain passive Win32 module evidence"));
    values.insert(text("if"), text("!cancelled() && runner.os == 'Windows'"));
    values.insert(text("uses"), text("./.github/actions/upload-artifact"));
    values.insert(text("with"), node_1077());
    values.insert(text("timeout-minutes"), Value::Number(6.into()));
    Value::Mapping(values)
}

fn node_1077() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("namespace-win32-${{ github.job }}-${{ runner.arch }}-${{ strategy.job-index }}-${{ github.run_id }}-${{ github.run_attempt }}"));
    values.insert(text("path"), text("target/ci/reports/namespace-win32"));
    values.insert(text("if-no-files-found"), text("ignore"));
    values.insert(text("retention-days"), Value::Number(7.into()));
    Value::Mapping(values)
}

fn node_1074() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("current-contracts-source-save"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("if"), text("always() && steps.public-source-seed-restore.outputs.cache-primary-key != '' && steps.public-source-seed-restore.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(text("with"), node_1075());
    Value::Mapping(values)
}

fn node_1075() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-cargo-home/registry/cache/index.crates.io-1949cf8c6b5b557f/*.crate\ntarget/ci-cargo-home/registry/cache/index.crates.io-6f17d22bba15001f/*.crate\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/.cache\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/config.json"));
    values.insert(
        text("key"),
        text("${{ steps.public-source-seed-restore.outputs.cache-primary-key }}"),
    );
    Value::Mapping(values)
}

fn node_1072() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("current-contracts-save"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("if"), text("always() && steps.current-contracts-restore.outcome != 'skipped' && steps.current-contracts-restore.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(3.into()));
    values.insert(text("with"), node_1073());
    Value::Mapping(values)
}

fn node_1073() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-current-contracts"));
    values.insert(text("key"), text("mc-windows-sealed-agent-feedback-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', '.cargo/**') }}-${{ hashFiles('crates/**/*.rs') }}"));
    Value::Mapping(values)
}

fn node_1071() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Windows sealed-agent contracts / ${{ matrix.id }}"),
    );
    values.insert(text("run"), text("rustup run 1.97.1 cargo test --locked --all-features --target-dir target/ci-current-contracts -p memcordon --test sealed_agent -- --exact --nocapture windows_security::exact_predecessor_delete_child_grant_is_refused_unchanged_and_current_policy_denies windows_security::certification_marker_security_accepts_only_current_policy_and_preserves_refused_descriptors windows_security::server_response_completion_waits_for_small_and_large_frames_to_be_consumed windows_security::support_control_release_reads_only_complete_bounded_frames_before_original_cutoff windows_guardian_startup::structured_bootstrap_rejection_is_preserved_while_guardian_is_live windows_security::frame_read_diagnostics_distinguish_length_payload_decode_and_peer_close windows_terminal_transport::partial_initial_request_uses_the_fixed_whole_frame_cutoff"));
    values.insert(text("timeout-minutes"), Value::Number(10.into()));
    Value::Mapping(values)
}

fn node_1069() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("current-contracts-restore"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(3.into()));
    values.insert(text("with"), node_1070());
    Value::Mapping(values)
}

fn node_1070() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-current-contracts"));
    values.insert(text("key"), text("mc-windows-sealed-agent-feedback-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', '.cargo/**') }}-${{ hashFiles('crates/**/*.rs') }}"));
    values.insert(text("restore-keys"), text("mc-windows-sealed-agent-feedback-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', '.cargo/**') }}-"));
    Value::Mapping(values)
}

fn node_1067() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("public-source-seed-restore"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(text("with"), node_1068());
    Value::Mapping(values)
}

fn node_1068() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-cargo-home/registry/cache/index.crates.io-1949cf8c6b5b557f/*.crate\ntarget/ci-cargo-home/registry/cache/index.crates.io-6f17d22bba15001f/*.crate\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/.cache\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/config.json"));
    values.insert(text("key"), text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-${{ hashFiles('Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', 'tools/*/Cargo.toml', '.cargo/**') }}"));
    values.insert(
        text("restore-keys"),
        text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-"),
    );
    Value::Mapping(values)
}

fn node_1066() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Install pinned Cargo toolchain"));
    values.insert(
        text("run"),
        text("rustup toolchain install 1.97.1 --profile minimal"),
    );
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    Value::Mapping(values)
}

fn node_1064() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_1065());
    values.insert(text("timeout-minutes"), Value::Number(6.into()));
    Value::Mapping(values)
}

fn node_1065() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_1063() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Configure checkout line endings"));
    values.insert(text("run"), text("git config --global core.autocrlf false"));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    Value::Mapping(values)
}

fn node_1061() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("contents"), text("read"));
    Value::Mapping(values)
}

fn node_1036() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Windows fixture feedback / ${{ matrix.id }}"),
    );
    values.insert(text("if"), text("github.event.deleted != true"));
    values.insert(text("permissions"), node_1037());
    values.insert(text("steps"), node_1038());
    values.insert(text("runs-on"), text("${{ matrix.runner }}"));
    values.insert(text("timeout-minutes"), Value::Number(53.into()));
    values.insert(text("env"), node_1054());
    values.insert(text("strategy"), node_1055());
    Value::Mapping(values)
}

fn node_1055() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("fail-fast"), Value::Bool(false));
    values.insert(text("matrix"), node_1056());
    Value::Mapping(values)
}

fn node_1056() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("include"), node_1057());
    Value::Mapping(values)
}

fn node_1057() -> Value {
    let mut values = Vec::new();
    values.push(node_1058());
    values.push(node_1059());
    Value::Sequence(values)
}

fn node_1059() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("windows-arm64"));
    values.insert(text("runner"), text("windows-11-arm"));
    Value::Mapping(values)
}

fn node_1058() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("windows-x64"));
    values.insert(text("runner"), text("windows-2025"));
    Value::Mapping(values)
}

fn node_1054() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("CARGO_HOME"),
        text("${{ github.workspace }}/target/ci-cargo-home"),
    );
    Value::Mapping(values)
}

fn node_1038() -> Value {
    let mut values = Vec::new();
    values.push(node_1039());
    values.push(node_1040());
    values.push(node_1042());
    values.push(node_1043());
    values.push(node_1045());
    values.push(node_1047());
    values.push(node_1048());
    values.push(node_1050());
    values.push(node_1052());
    Value::Sequence(values)
}

fn node_1052() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Retain passive Win32 module evidence"));
    values.insert(text("if"), text("!cancelled() && runner.os == 'Windows'"));
    values.insert(text("uses"), text("./.github/actions/upload-artifact"));
    values.insert(text("with"), node_1053());
    values.insert(text("timeout-minutes"), Value::Number(6.into()));
    Value::Mapping(values)
}

fn node_1053() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("namespace-win32-${{ github.job }}-${{ runner.arch }}-${{ strategy.job-index }}-${{ github.run_id }}-${{ github.run_attempt }}"));
    values.insert(text("path"), text("target/ci/reports/namespace-win32"));
    values.insert(text("if-no-files-found"), text("ignore"));
    values.insert(text("retention-days"), Value::Number(7.into()));
    Value::Mapping(values)
}

fn node_1050() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("current-contracts-source-save"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("if"), text("always() && steps.public-source-seed-restore.outputs.cache-primary-key != '' && steps.public-source-seed-restore.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(text("with"), node_1051());
    Value::Mapping(values)
}

fn node_1051() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-cargo-home/registry/cache/index.crates.io-1949cf8c6b5b557f/*.crate\ntarget/ci-cargo-home/registry/cache/index.crates.io-6f17d22bba15001f/*.crate\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/.cache\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/config.json"));
    values.insert(
        text("key"),
        text("${{ steps.public-source-seed-restore.outputs.cache-primary-key }}"),
    );
    Value::Mapping(values)
}

fn node_1048() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("current-contracts-save"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("if"), text("always() && steps.current-contracts-restore.outcome != 'skipped' && steps.current-contracts-restore.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(3.into()));
    values.insert(text("with"), node_1049());
    Value::Mapping(values)
}

fn node_1049() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-current-contracts"));
    values.insert(text("key"), text("mc-windows-fixture-feedback-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', '.cargo/**') }}-${{ hashFiles('crates/**/*.rs') }}"));
    Value::Mapping(values)
}

fn node_1047() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Windows fixture feedback / ${{ matrix.id }}"),
    );
    values.insert(text("run"), text("rustup run 1.97.1 cargo test --locked --all-features --target-dir target/ci-current-contracts -p memcordon --test windows_namespace_primary fresh_restricted_primary_namespace_access_is_observed_without_inherited_gate_capabilities -- --exact --nocapture"));
    values.insert(text("timeout-minutes"), Value::Number(10.into()));
    Value::Mapping(values)
}

fn node_1045() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("current-contracts-restore"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(3.into()));
    values.insert(text("with"), node_1046());
    Value::Mapping(values)
}

fn node_1046() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-current-contracts"));
    values.insert(text("key"), text("mc-windows-fixture-feedback-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', '.cargo/**') }}-${{ hashFiles('crates/**/*.rs') }}"));
    values.insert(text("restore-keys"), text("mc-windows-fixture-feedback-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', '.cargo/**') }}-"));
    Value::Mapping(values)
}

fn node_1043() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("public-source-seed-restore"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(text("with"), node_1044());
    Value::Mapping(values)
}

fn node_1044() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-cargo-home/registry/cache/index.crates.io-1949cf8c6b5b557f/*.crate\ntarget/ci-cargo-home/registry/cache/index.crates.io-6f17d22bba15001f/*.crate\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/.cache\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/config.json"));
    values.insert(text("key"), text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-${{ hashFiles('Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', 'tools/*/Cargo.toml', '.cargo/**') }}"));
    values.insert(
        text("restore-keys"),
        text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-"),
    );
    Value::Mapping(values)
}

fn node_1042() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Install pinned Cargo toolchain"));
    values.insert(
        text("run"),
        text("rustup toolchain install 1.97.1 --profile minimal"),
    );
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    Value::Mapping(values)
}

fn node_1040() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_1041());
    values.insert(text("timeout-minutes"), Value::Number(6.into()));
    Value::Mapping(values)
}

fn node_1041() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_1039() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Configure checkout line endings"));
    values.insert(text("run"), text("git config --global core.autocrlf false"));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    Value::Mapping(values)
}

fn node_1037() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("contents"), text("read"));
    Value::Mapping(values)
}

fn node_1019() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("macOS x64 startup deadline feedback"));
    values.insert(text("if"), text("github.event.deleted != true"));
    values.insert(text("permissions"), node_1020());
    values.insert(text("steps"), node_1021());
    values.insert(text("runs-on"), text("macos-15-intel"));
    values.insert(text("timeout-minutes"), Value::Number(47.into()));
    values.insert(text("env"), node_1035());
    Value::Mapping(values)
}

fn node_1035() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("CARGO_HOME"),
        text("${{ github.workspace }}/target/ci-cargo-home"),
    );
    Value::Mapping(values)
}

fn node_1021() -> Value {
    let mut values = Vec::new();
    values.push(node_1022());
    values.push(node_1023());
    values.push(node_1025());
    values.push(node_1026());
    values.push(node_1028());
    values.push(node_1030());
    values.push(node_1031());
    values.push(node_1033());
    Value::Sequence(values)
}

fn node_1033() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("current-contracts-source-save"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("if"), text("always() && steps.public-source-seed-restore.outputs.cache-primary-key != '' && steps.public-source-seed-restore.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(text("with"), node_1034());
    Value::Mapping(values)
}

fn node_1034() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-cargo-home/registry/cache/index.crates.io-1949cf8c6b5b557f/*.crate\ntarget/ci-cargo-home/registry/cache/index.crates.io-6f17d22bba15001f/*.crate\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/.cache\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/config.json"));
    values.insert(
        text("key"),
        text("${{ steps.public-source-seed-restore.outputs.cache-primary-key }}"),
    );
    Value::Mapping(values)
}

fn node_1031() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("current-contracts-save"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("if"), text("always() && steps.current-contracts-restore.outcome != 'skipped' && steps.current-contracts-restore.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(3.into()));
    values.insert(text("with"), node_1032());
    Value::Mapping(values)
}

fn node_1032() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-current-contracts"));
    values.insert(text("key"), text("mc-macos-startup-deadline-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', '.cargo/**') }}-${{ hashFiles('crates/**/*.rs') }}"));
    Value::Mapping(values)
}

fn node_1030() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("macOS x64 startup deadline feedback"));
    values.insert(text("run"), text("rustup run 1.97.1 cargo test --locked --all-features --target-dir target/ci-current-contracts -p memcordon --test macos_remediation requested_deadline_expires_during_unacknowledged_startup -- --exact --nocapture"));
    values.insert(text("timeout-minutes"), Value::Number(10.into()));
    Value::Mapping(values)
}

fn node_1028() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("current-contracts-restore"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(3.into()));
    values.insert(text("with"), node_1029());
    Value::Mapping(values)
}

fn node_1029() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-current-contracts"));
    values.insert(text("key"), text("mc-macos-startup-deadline-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', '.cargo/**') }}-${{ hashFiles('crates/**/*.rs') }}"));
    values.insert(text("restore-keys"), text("mc-macos-startup-deadline-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', '.cargo/**') }}-"));
    Value::Mapping(values)
}

fn node_1026() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("public-source-seed-restore"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(text("with"), node_1027());
    Value::Mapping(values)
}

fn node_1027() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-cargo-home/registry/cache/index.crates.io-1949cf8c6b5b557f/*.crate\ntarget/ci-cargo-home/registry/cache/index.crates.io-6f17d22bba15001f/*.crate\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/.cache\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/config.json"));
    values.insert(text("key"), text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-${{ hashFiles('Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', 'tools/*/Cargo.toml', '.cargo/**') }}"));
    values.insert(
        text("restore-keys"),
        text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-"),
    );
    Value::Mapping(values)
}

fn node_1025() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Install pinned Cargo toolchain"));
    values.insert(
        text("run"),
        text("rustup toolchain install 1.97.1 --profile minimal"),
    );
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    Value::Mapping(values)
}

fn node_1023() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_1024());
    values.insert(text("timeout-minutes"), Value::Number(6.into()));
    Value::Mapping(values)
}

fn node_1024() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_1022() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Configure checkout line endings"));
    values.insert(text("run"), text("git config --global core.autocrlf false"));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    Value::Mapping(values)
}

fn node_1020() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("contents"), text("read"));
    Value::Mapping(values)
}

fn node_1002() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("macOS administrative contracts"));
    values.insert(text("if"), text("github.event.deleted != true"));
    values.insert(text("permissions"), node_1003());
    values.insert(text("steps"), node_1004());
    values.insert(text("runs-on"), text("macos-15"));
    values.insert(text("timeout-minutes"), Value::Number(47.into()));
    values.insert(text("env"), node_1018());
    Value::Mapping(values)
}

fn node_1018() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("CARGO_HOME"),
        text("${{ github.workspace }}/target/ci-cargo-home"),
    );
    Value::Mapping(values)
}

fn node_1004() -> Value {
    let mut values = Vec::new();
    values.push(node_1005());
    values.push(node_1006());
    values.push(node_1008());
    values.push(node_1009());
    values.push(node_1011());
    values.push(node_1013());
    values.push(node_1014());
    values.push(node_1016());
    Value::Sequence(values)
}

fn node_1016() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("current-contracts-source-save"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("if"), text("always() && steps.public-source-seed-restore.outputs.cache-primary-key != '' && steps.public-source-seed-restore.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(text("with"), node_1017());
    Value::Mapping(values)
}

fn node_1017() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-cargo-home/registry/cache/index.crates.io-1949cf8c6b5b557f/*.crate\ntarget/ci-cargo-home/registry/cache/index.crates.io-6f17d22bba15001f/*.crate\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/.cache\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/config.json"));
    values.insert(
        text("key"),
        text("${{ steps.public-source-seed-restore.outputs.cache-primary-key }}"),
    );
    Value::Mapping(values)
}

fn node_1014() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("current-contracts-save"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("if"), text("always() && steps.current-contracts-restore.outcome != 'skipped' && steps.current-contracts-restore.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(3.into()));
    values.insert(text("with"), node_1015());
    Value::Mapping(values)
}

fn node_1015() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-current-contracts"));
    values.insert(text("key"), text("mc-macos-administrative-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', '.cargo/**') }}-${{ hashFiles('crates/**/*.rs') }}"));
    Value::Mapping(values)
}

fn node_1013() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("macOS administrative contracts"));
    values.insert(text("run"), text("rustup run 1.97.1 cargo test --locked --all-features --target-dir target/ci-current-contracts -p memcordon --test sealed_agent_distribution"));
    values.insert(text("timeout-minutes"), Value::Number(10.into()));
    Value::Mapping(values)
}

fn node_1011() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("current-contracts-restore"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(3.into()));
    values.insert(text("with"), node_1012());
    Value::Mapping(values)
}

fn node_1012() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-current-contracts"));
    values.insert(text("key"), text("mc-macos-administrative-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', '.cargo/**') }}-${{ hashFiles('crates/**/*.rs') }}"));
    values.insert(text("restore-keys"), text("mc-macos-administrative-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', '.cargo/**') }}-"));
    Value::Mapping(values)
}

fn node_1009() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("public-source-seed-restore"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(text("with"), node_1010());
    Value::Mapping(values)
}

fn node_1010() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-cargo-home/registry/cache/index.crates.io-1949cf8c6b5b557f/*.crate\ntarget/ci-cargo-home/registry/cache/index.crates.io-6f17d22bba15001f/*.crate\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/.cache\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/config.json"));
    values.insert(text("key"), text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-${{ hashFiles('Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', 'tools/*/Cargo.toml', '.cargo/**') }}"));
    values.insert(
        text("restore-keys"),
        text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-"),
    );
    Value::Mapping(values)
}

fn node_1008() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Install pinned Cargo toolchain"));
    values.insert(
        text("run"),
        text("rustup toolchain install 1.97.1 --profile minimal"),
    );
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    Value::Mapping(values)
}

fn node_1006() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_1007());
    values.insert(text("timeout-minutes"), Value::Number(6.into()));
    Value::Mapping(values)
}

fn node_1007() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_1005() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Configure checkout line endings"));
    values.insert(text("run"), text("git config --global core.autocrlf false"));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    Value::Mapping(values)
}

fn node_1003() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("contents"), text("read"));
    Value::Mapping(values)
}

fn node_985() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Current tooling contracts"));
    values.insert(text("if"), text("github.event.deleted != true"));
    values.insert(text("permissions"), node_986());
    values.insert(text("steps"), node_987());
    values.insert(text("runs-on"), text("ubuntu-24.04"));
    values.insert(text("timeout-minutes"), Value::Number(47.into()));
    values.insert(text("env"), node_1001());
    Value::Mapping(values)
}

fn node_1001() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("CARGO_HOME"),
        text("${{ github.workspace }}/target/ci-cargo-home"),
    );
    Value::Mapping(values)
}

fn node_987() -> Value {
    let mut values = Vec::new();
    values.push(node_988());
    values.push(node_989());
    values.push(node_991());
    values.push(node_992());
    values.push(node_994());
    values.push(node_996());
    values.push(node_997());
    values.push(node_999());
    Value::Sequence(values)
}

fn node_999() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("current-contracts-source-save"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("if"), text("always() && steps.public-source-seed-restore.outputs.cache-primary-key != '' && steps.public-source-seed-restore.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(text("with"), node_1000());
    Value::Mapping(values)
}

fn node_1000() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-cargo-home/registry/cache/index.crates.io-1949cf8c6b5b557f/*.crate\ntarget/ci-cargo-home/registry/cache/index.crates.io-6f17d22bba15001f/*.crate\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/.cache\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/config.json"));
    values.insert(
        text("key"),
        text("${{ steps.public-source-seed-restore.outputs.cache-primary-key }}"),
    );
    Value::Mapping(values)
}

fn node_997() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("tooling-contracts-save"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("if"), text("always() && steps.tooling-contracts-restore.outcome != 'skipped' && steps.tooling-contracts-restore.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(3.into()));
    values.insert(text("with"), node_998());
    Value::Mapping(values)
}

fn node_998() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-tooling-contracts"));
    values.insert(text("key"), text("mc-tooling-contracts-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', 'tools/*/Cargo.toml', '.cargo/**') }}-${{ hashFiles('tools/memcordon-ci/**/*.rs', 'crates/**/*.rs', 'fuzz/Cargo.toml', 'fuzz/corpus/**', '.github/workflows/deep-ci.yml') }}"));
    Value::Mapping(values)
}

fn node_996() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Current external consumer contracts"));
    values.insert(text("run"), text("rustup run 1.97.1 cargo test --locked --target-dir target/ci-tooling-contracts -p memcordon-ci --test external_consumer --test windows_installed_paths --test target_shard --test fuzz_targets --test msrv_source --test workflow_policy --test concurrency_budget --test private_phase_workflow --test release_fuzz_phase --test windows_fixture_workflow --test suite_failure_policy --test windows_consumer_readiness --test launch_event_wait"));
    values.insert(text("timeout-minutes"), Value::Number(10.into()));
    Value::Mapping(values)
}

fn node_994() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("tooling-contracts-restore"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(3.into()));
    values.insert(text("with"), node_995());
    Value::Mapping(values)
}

fn node_995() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-tooling-contracts"));
    values.insert(text("key"), text("mc-tooling-contracts-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', 'tools/*/Cargo.toml', '.cargo/**') }}-${{ hashFiles('tools/memcordon-ci/**/*.rs', 'crates/**/*.rs', 'fuzz/Cargo.toml', 'fuzz/corpus/**', '.github/workflows/deep-ci.yml') }}"));
    values.insert(text("restore-keys"), text("mc-tooling-contracts-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', 'tools/*/Cargo.toml', '.cargo/**') }}-"));
    Value::Mapping(values)
}

fn node_992() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("public-source-seed-restore"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(text("with"), node_993());
    Value::Mapping(values)
}

fn node_993() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-cargo-home/registry/cache/index.crates.io-1949cf8c6b5b557f/*.crate\ntarget/ci-cargo-home/registry/cache/index.crates.io-6f17d22bba15001f/*.crate\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/.cache\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/config.json"));
    values.insert(text("key"), text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-${{ hashFiles('Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', 'tools/*/Cargo.toml', '.cargo/**') }}"));
    values.insert(
        text("restore-keys"),
        text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-"),
    );
    Value::Mapping(values)
}

fn node_991() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Install pinned Cargo toolchain"));
    values.insert(
        text("run"),
        text("rustup toolchain install 1.97.1 --profile minimal"),
    );
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    Value::Mapping(values)
}

fn node_989() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_990());
    values.insert(text("timeout-minutes"), Value::Number(6.into()));
    Value::Mapping(values)
}

fn node_990() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_988() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Configure checkout line endings"));
    values.insert(text("run"), text("git config --global core.autocrlf false"));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    Value::Mapping(values)
}

fn node_986() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("contents"), text("read"));
    Value::Mapping(values)
}

fn node_963() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Current portable contracts"));
    values.insert(text("if"), text("github.event.deleted != true"));
    values.insert(text("permissions"), node_964());
    values.insert(text("steps"), node_965());
    values.insert(text("runs-on"), text("ubuntu-24.04"));
    values.insert(text("timeout-minutes"), Value::Number(97.into()));
    values.insert(text("env"), node_984());
    Value::Mapping(values)
}

fn node_984() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("CARGO_HOME"),
        text("${{ github.workspace }}/target/ci-cargo-home"),
    );
    Value::Mapping(values)
}

fn node_965() -> Value {
    let mut values = Vec::new();
    values.push(node_966());
    values.push(node_967());
    values.push(node_969());
    values.push(node_970());
    values.push(node_972());
    values.push(node_974());
    values.push(node_975());
    values.push(node_976());
    values.push(node_977());
    values.push(node_978());
    values.push(node_979());
    values.push(node_980());
    values.push(node_982());
    Value::Sequence(values)
}

fn node_982() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("current-contracts-source-save"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("if"), text("always() && steps.public-source-seed-restore.outputs.cache-primary-key != '' && steps.public-source-seed-restore.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(text("with"), node_983());
    Value::Mapping(values)
}

fn node_983() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-cargo-home/registry/cache/index.crates.io-1949cf8c6b5b557f/*.crate\ntarget/ci-cargo-home/registry/cache/index.crates.io-6f17d22bba15001f/*.crate\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/.cache\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/config.json"));
    values.insert(
        text("key"),
        text("${{ steps.public-source-seed-restore.outputs.cache-primary-key }}"),
    );
    Value::Mapping(values)
}

fn node_980() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("current-contracts-save"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("if"), text("always() && steps.current-contracts-restore.outcome != 'skipped' && steps.current-contracts-restore.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(3.into()));
    values.insert(text("with"), node_981());
    Value::Mapping(values)
}

fn node_981() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-current-contracts"));
    values.insert(text("key"), text("mc-current-contracts-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', '.cargo/**') }}-${{ hashFiles('crates/**/*.rs') }}"));
    Value::Mapping(values)
}

fn node_979() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Current doctor presentation"));
    values.insert(text("run"), text("rustup run 1.97.1 cargo test --locked --all-features --target-dir target/ci-current-contracts -p memcordon --test cli doctor_text_and_json_have_distinct_complete_shapes -- --exact"));
    values.insert(text("timeout-minutes"), Value::Number(10.into()));
    Value::Mapping(values)
}

fn node_978() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Current fail-closed CLI reports"));
    values.insert(text("run"), text("rustup run 1.97.1 cargo test --locked --all-features --target-dir target/ci-current-contracts -p memcordon --test cli sealed_execution_plan_and_doctor_fail_closed -- --exact"));
    values.insert(text("timeout-minutes"), Value::Number(10.into()));
    Value::Mapping(values)
}

fn node_977() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Current Linux package inspection"));
    values.insert(text("run"), text("rustup run 1.97.1 cargo test --locked --all-features --target-dir target/ci-current-contracts -p memcordon --test sealed_agent_distribution"));
    values.insert(text("timeout-minutes"), Value::Number(10.into()));
    Value::Mapping(values)
}

fn node_976() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Retired native package routes refuse before authorization"),
    );
    values.insert(text("run"), text("rustup run 1.97.1 cargo test --locked --all-features --target-dir target/ci-current-contracts -p memcordon --test native_package_recovery_dispatch"));
    values.insert(text("timeout-minutes"), Value::Number(10.into()));
    Value::Mapping(values)
}

fn node_975() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Current public help"));
    values.insert(text("run"), text("rustup run 1.97.1 cargo test --locked --all-features --target-dir target/ci-current-contracts -p memcordon --test documentation"));
    values.insert(text("timeout-minutes"), Value::Number(10.into()));
    Value::Mapping(values)
}

fn node_974() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Current core wire contracts"));
    values.insert(text("run"), text("rustup run 1.97.1 cargo test --locked --all-features --target-dir target/ci-current-contracts -p memcordon-core --test diagnostics --test current_formats --test windows_guardian_observation"));
    values.insert(text("timeout-minutes"), Value::Number(10.into()));
    Value::Mapping(values)
}

fn node_972() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("current-contracts-restore"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(3.into()));
    values.insert(text("with"), node_973());
    Value::Mapping(values)
}

fn node_973() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-current-contracts"));
    values.insert(text("key"), text("mc-current-contracts-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', '.cargo/**') }}-${{ hashFiles('crates/**/*.rs') }}"));
    values.insert(text("restore-keys"), text("mc-current-contracts-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', '.cargo/**') }}-"));
    Value::Mapping(values)
}

fn node_970() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("public-source-seed-restore"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(text("with"), node_971());
    Value::Mapping(values)
}

fn node_971() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-cargo-home/registry/cache/index.crates.io-1949cf8c6b5b557f/*.crate\ntarget/ci-cargo-home/registry/cache/index.crates.io-6f17d22bba15001f/*.crate\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/.cache\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/config.json"));
    values.insert(text("key"), text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-${{ hashFiles('Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', 'tools/*/Cargo.toml', '.cargo/**') }}"));
    values.insert(
        text("restore-keys"),
        text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-"),
    );
    Value::Mapping(values)
}

fn node_969() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Install pinned Cargo toolchain"));
    values.insert(
        text("run"),
        text("rustup toolchain install 1.97.1 --profile minimal"),
    );
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    Value::Mapping(values)
}

fn node_967() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_968());
    values.insert(text("timeout-minutes"), Value::Number(6.into()));
    Value::Mapping(values)
}

fn node_968() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_966() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Configure checkout line endings"));
    values.insert(text("run"), text("git config --global core.autocrlf false"));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    Value::Mapping(values)
}

fn node_964() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("contents"), text("read"));
    Value::Mapping(values)
}

fn node_955() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("CI source formatting"));
    values.insert(text("if"), text("github.event_name != 'push'"));
    values.insert(text("permissions"), node_956());
    values.insert(text("runs-on"), text("ubuntu-24.04"));
    values.insert(text("timeout-minutes"), Value::Number(42.into()));
    values.insert(text("steps"), node_957());
    Value::Mapping(values)
}

fn node_957() -> Value {
    let mut values = Vec::new();
    values.push(node_958());
    values.push(node_959());
    values.push(node_961());
    values.push(node_962());
    Value::Sequence(values)
}

fn node_962() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Check formatting"));
    values.insert(
        text("run"),
        text("rustup run 1.97.1 cargo fmt --all -- --check"),
    );
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    Value::Mapping(values)
}

fn node_961() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Install formatter"));
    values.insert(
        text("run"),
        text("rustup toolchain install 1.97.1 --profile minimal --component rustfmt"),
    );
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    Value::Mapping(values)
}

fn node_959() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Check out repository"));
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_960());
    values.insert(text("timeout-minutes"), Value::Number(6.into()));
    Value::Mapping(values)
}

fn node_960() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_958() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Configure checkout line endings"));
    values.insert(text("run"), text("git config --global core.autocrlf false"));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    Value::Mapping(values)
}

fn node_956() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("contents"), text("read"));
    Value::Mapping(values)
}

fn node_937() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Public Cargo source seed / ${{ matrix.runner }}"),
    );
    values.insert(text("if"), text("github.event.deleted != true && (github.event_name == 'workflow_dispatch' && startsWith(github.ref, 'refs/heads/') && github.ref != 'refs/heads/')"));
    values.insert(text("permissions"), node_938());
    values.insert(text("strategy"), node_939());
    values.insert(text("runs-on"), text("${{ matrix.runner }}"));
    values.insert(text("timeout-minutes"), Value::Number(62.into()));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("env"), node_942());
    values.insert(text("steps"), node_943());
    Value::Mapping(values)
}

fn node_943() -> Value {
    let mut values = Vec::new();
    values.push(node_944());
    values.push(node_945());
    values.push(node_947());
    values.push(node_948());
    values.push(node_950());
    values.push(node_951());
    values.push(node_953());
    Value::Sequence(values)
}

fn node_953() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Retain passive Win32 module evidence"));
    values.insert(text("if"), text("!cancelled() && runner.os == 'Windows'"));
    values.insert(text("uses"), text("./.github/actions/upload-artifact"));
    values.insert(text("with"), node_954());
    values.insert(text("timeout-minutes"), Value::Number(6.into()));
    Value::Mapping(values)
}

fn node_954() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("namespace-win32-${{ github.job }}-${{ runner.arch }}-${{ strategy.job-index }}-${{ github.run_id }}-${{ github.run_attempt }}"));
    values.insert(text("path"), text("target/ci/reports/namespace-win32"));
    values.insert(text("if-no-files-found"), text("ignore"));
    values.insert(text("retention-days"), Value::Number(7.into()));
    Value::Mapping(values)
}

fn node_951() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("public-source-seed-save"));
    values.insert(text("if"), text("always() && steps.public-source-fetch.outcome == 'success' && steps.public-source-seed-restore.outputs.cache-primary-key != '' && steps.public-source-seed-restore.outputs.cache-hit != 'true' && ((github.event_name == 'push' && ((startsWith(github.ref, 'refs/heads/') && github.ref != 'refs/heads/') || (startsWith(github.ref, 'refs/tags/') && github.ref != 'refs/tags/'))) || (github.event_name == 'workflow_dispatch' && startsWith(github.ref, 'refs/heads/') && github.ref != 'refs/heads/'))"));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(text("with"), node_952());
    Value::Mapping(values)
}

fn node_952() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-cargo-home/registry/cache/index.crates.io-1949cf8c6b5b557f/*.crate\ntarget/ci-cargo-home/registry/cache/index.crates.io-6f17d22bba15001f/*.crate\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/.cache\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/config.json"));
    values.insert(
        text("key"),
        text("${{ steps.public-source-seed-restore.outputs.cache-primary-key }}"),
    );
    Value::Mapping(values)
}

fn node_950() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Acquire locked public workspace sources"),
    );
    values.insert(text("run"), text("rustup run 1.97.1 cargo fetch --locked"));
    values.insert(text("timeout-minutes"), Value::Number(25.into()));
    values.insert(text("id"), text("public-source-fetch"));
    Value::Mapping(values)
}

fn node_948() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("public-source-seed-restore"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(text("with"), node_949());
    Value::Mapping(values)
}

fn node_949() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-cargo-home/registry/cache/index.crates.io-1949cf8c6b5b557f/*.crate\ntarget/ci-cargo-home/registry/cache/index.crates.io-6f17d22bba15001f/*.crate\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/.cache\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/config.json"));
    values.insert(text("key"), text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-${{ hashFiles('Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', 'tools/*/Cargo.toml', '.cargo/**') }}"));
    values.insert(
        text("restore-keys"),
        text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-"),
    );
    Value::Mapping(values)
}

fn node_947() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Install pinned Cargo toolchain"));
    values.insert(
        text("run"),
        text("rustup toolchain install 1.97.1 --profile minimal"),
    );
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    Value::Mapping(values)
}

fn node_945() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_946());
    values.insert(text("timeout-minutes"), Value::Number(6.into()));
    Value::Mapping(values)
}

fn node_946() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_944() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Configure checkout line endings"));
    values.insert(text("run"), text("git config --global core.autocrlf false"));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    Value::Mapping(values)
}

fn node_942() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("CARGO_HOME"),
        text("${{ github.workspace }}/target/ci-cargo-home"),
    );
    Value::Mapping(values)
}

fn node_939() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("fail-fast"), Value::Bool(false));
    values.insert(text("matrix"), node_940());
    Value::Mapping(values)
}

fn node_940() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("runner"), node_941());
    Value::Mapping(values)
}

fn node_941() -> Value {
    let mut values = Vec::new();
    values.push(text("ubuntu-24.04"));
    values.push(text("macos-15"));
    values.push(text("windows-2025"));
    Value::Sequence(values)
}

fn node_938() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("contents"), text("read"));
    Value::Mapping(values)
}

fn node_815() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("github.event_name != 'push'"));
    values.insert(text("name"), text("Supply chain / deny"));
    values.insert(text("runs-on"), text("ubuntu-24.04"));
    values.insert(text("timeout-minutes"), Value::Number(330.into()));
    values.insert(text("steps"), node_816());
    values.insert(text("env"), node_936());
    Value::Mapping(values)
}

fn node_936() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("CARGO_HOME"),
        text("${{ github.workspace }}/target/ci-cargo-home"),
    );
    Value::Mapping(values)
}

fn node_816() -> Value {
    let mut values = Vec::new();
    values.push(node_817());
    values.push(node_818());
    values.push(node_820());
    values.push(node_821());
    values.push(node_823());
    values.push(node_825());
    values.push(node_826());
    values.push(node_827());
    values.push(node_829());
    values.push(node_830());
    values.push(node_832());
    values.push(node_834());
    values.push(node_836());
    values.push(node_838());
    values.push(node_840());
    values.push(node_841());
    values.push(node_843());
    values.push(node_845());
    values.push(node_847());
    values.push(node_849());
    values.push(node_851());
    values.push(node_853());
    values.push(node_855());
    values.push(node_857());
    values.push(node_859());
    values.push(node_861());
    values.push(node_863());
    values.push(node_864());
    values.push(node_865());
    values.push(node_866());
    values.push(node_868());
    values.push(node_870());
    values.push(node_872());
    values.push(node_874());
    values.push(node_876());
    values.push(node_878());
    values.push(node_879());
    values.push(node_880());
    values.push(node_881());
    values.push(node_883());
    values.push(node_885());
    values.push(node_887());
    values.push(node_888());
    values.push(node_890());
    values.push(node_892());
    values.push(node_894());
    values.push(node_896());
    values.push(node_897());
    values.push(node_898());
    values.push(node_900());
    values.push(node_902());
    values.push(node_904());
    values.push(node_906());
    values.push(node_908());
    values.push(node_910());
    values.push(node_912());
    values.push(node_913());
    values.push(node_915());
    values.push(node_917());
    values.push(node_919());
    values.push(node_921());
    values.push(node_923());
    values.push(node_925());
    values.push(node_927());
    values.push(node_929());
    values.push(node_931());
    values.push(node_933());
    values.push(node_935());
    Value::Sequence(values)
}

fn node_935() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("supply-run-cleanup"));
    values.insert(text("if"), text("always() && (steps.supply-run.outcome == 'success' || steps.supply-run.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cleanup-transfers supply-deny"),
    );
    Value::Mapping(values)
}

fn node_933() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("supply-run-cargo-deny-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.supply-run.outputs.cargo-deny-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_934());
    Value::Mapping(values)
}

fn node_934() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run.outputs.cargo-deny-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run.outputs.cargo-deny-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_931() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("supply-run-cargo-deny-complete-save"));
    values.insert(text("if"), text("always() && steps.supply-run.outputs.cargo-deny-complete-save == 'true' && steps.supply-run-cargo-deny-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_932());
    Value::Mapping(values)
}

fn node_932() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run.outputs.cargo-deny-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run.outputs.cargo-deny-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_929() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("supply-run-cargo-deny-complete-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.supply-run.outputs.cargo-deny-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_930());
    Value::Mapping(values)
}

fn node_930() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run.outputs.cargo-deny-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run.outputs.cargo-deny-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_927() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("supply-run-cargo-deny-source-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.supply-run.outputs.cargo-deny-source-complete-save == 'true' && steps.supply-run-cargo-deny-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_928());
    Value::Mapping(values)
}

fn node_928() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run.outputs.cargo-deny-source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run.outputs.cargo-deny-source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_925() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("supply-run-cargo-deny-source-complete-probe"),
    );
    values.insert(
        text("if"),
        text("!cancelled() && steps.supply-run.outputs.cargo-deny-source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_926());
    Value::Mapping(values)
}

fn node_926() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run.outputs.cargo-deny-source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run.outputs.cargo-deny-source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_923() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("supply-run-cargo-deny-image-save"));
    values.insert(text("if"), text("always() && steps.supply-run.outputs.cargo-deny-image-save == 'true' && steps.supply-run-cargo-deny-image-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_924());
    Value::Mapping(values)
}

fn node_924() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run.outputs.cargo-deny-image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run.outputs.cargo-deny-image-path }}"),
    );
    Value::Mapping(values)
}

fn node_921() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("supply-run-cargo-deny-image-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.supply-run.outputs.cargo-deny-image-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_922());
    Value::Mapping(values)
}

fn node_922() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run.outputs.cargo-deny-image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run.outputs.cargo-deny-image-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_919() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("supply-run-index-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.supply-run.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_920());
    Value::Mapping(values)
}

fn node_920() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_917() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("supply-run-archives-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.supply-run.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_918());
    Value::Mapping(values)
}

fn node_918() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_915() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("supply-run-source-complete-save"));
    values.insert(text("if"), text("always() && steps.supply-run.outputs.source-complete-save == 'true' && steps.supply-run-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_916());
    Value::Mapping(values)
}

fn node_916() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_913() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("supply-run-source-complete-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.supply-run.outputs.source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_914());
    Value::Mapping(values)
}

fn node_914() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_912() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Run supply-chain suite"));
    values.insert(text("id"), text("supply-run"));
    values.insert(text("timeout-minutes"), Value::Number(130.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci segment supply-deny"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    Value::Mapping(values)
}

fn node_910() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("supply-run-request-cargo-deny-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.supply-run-request.outputs.cargo-deny-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_911());
    Value::Mapping(values)
}

fn node_911() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run-request.outputs.cargo-deny-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run-request.outputs.cargo-deny-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.supply-run-request.outputs.cargo-deny-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_908() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("supply-run-request-cargo-deny-complete-restore"),
    );
    values.insert(
        text("if"),
        text("steps.supply-run-request.outputs.cargo-deny-complete-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_909());
    Value::Mapping(values)
}

fn node_909() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run-request.outputs.cargo-deny-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run-request.outputs.cargo-deny-complete-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.supply-run-request.outputs.cargo-deny-complete-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_906() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("supply-run-request-cargo-deny-source-restore"),
    );
    values.insert(
        text("if"),
        text("steps.supply-run-request.outputs.cargo-deny-source-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_907());
    Value::Mapping(values)
}

fn node_907() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run-request.outputs.cargo-deny-source-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run-request.outputs.cargo-deny-source-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.supply-run-request.outputs.cargo-deny-source-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_904() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("supply-run-request-cargo-deny-image-restore"),
    );
    values.insert(
        text("if"),
        text("steps.supply-run-request.outputs.cargo-deny-image-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_905());
    Value::Mapping(values)
}

fn node_905() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run-request.outputs.cargo-deny-image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run-request.outputs.cargo-deny-image-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.supply-run-request.outputs.cargo-deny-image-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_902() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("supply-run-request-index-partial-restore"));
    values.insert(
        text("if"),
        text("steps.supply-run-request.outputs.index-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_903());
    Value::Mapping(values)
}

fn node_903() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run-request.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run-request.outputs.index-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.supply-run-request.outputs.index-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_900() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("supply-run-request-archives-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.supply-run-request.outputs.archives-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_901());
    Value::Mapping(values)
}

fn node_901() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run-request.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run-request.outputs.archives-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.supply-run-request.outputs.archives-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_898() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("supply-run-request-source-restore"));
    values.insert(
        text("if"),
        text("steps.supply-run-request.outputs.source-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_899());
    Value::Mapping(values)
}

fn node_899() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run-request.outputs.source-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run-request.outputs.source-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.supply-run-request.outputs.source-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_897() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("supply-run-request"));
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cache-requests supply-deny"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    Value::Mapping(values)
}

fn node_896() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-cleanup"));
    values.insert(text("if"), text("always() && (steps.workspace-fetch.outcome == 'success' || steps.workspace-fetch.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cleanup-transfers workspace-fetch"),
    );
    Value::Mapping(values)
}

fn node_894() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-index-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.workspace-fetch.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_895());
    Value::Mapping(values)
}

fn node_895() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_892() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-archives-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.workspace-fetch.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_893());
    Value::Mapping(values)
}

fn node_893() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_890() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-source-complete-save"));
    values.insert(text("if"), text("always() && steps.workspace-fetch.outputs.source-complete-save == 'true' && steps.workspace-fetch-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_891());
    Value::Mapping(values)
}

fn node_891() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_888() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-source-complete-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.workspace-fetch.outputs.source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_889());
    Value::Mapping(values)
}

fn node_889() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_887() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci segment workspace-fetch"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("timeout-minutes"), Value::Number(25.into()));
    Value::Mapping(values)
}

fn node_885() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("workspace-fetch-request-index-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.workspace-fetch-request.outputs.index-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_886());
    Value::Mapping(values)
}

fn node_886() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch-request.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch-request.outputs.index-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-fetch-request.outputs.index-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_883() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("workspace-fetch-request-archives-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.workspace-fetch-request.outputs.archives-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_884());
    Value::Mapping(values)
}

fn node_884() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch-request.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch-request.outputs.archives-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-fetch-request.outputs.archives-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_881() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-request-source-restore"));
    values.insert(
        text("if"),
        text("steps.workspace-fetch-request.outputs.source-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_882());
    Value::Mapping(values)
}

fn node_882() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch-request.outputs.source-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch-request.outputs.source-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-fetch-request.outputs.source-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_880() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-request"));
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cache-requests workspace-fetch"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    Value::Mapping(values)
}

fn node_879() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-workflows-check"));
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci workflows --check"),
    );
    Value::Mapping(values)
}

fn node_878() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-cleanup"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt.outcome == 'success'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci driver-cleanup"),
    );
    Value::Mapping(values)
}

fn node_876() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-index-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_877());
    Value::Mapping(values)
}

fn node_877() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_874() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-archives-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_875());
    Value::Mapping(values)
}

fn node_875() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_872() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-source-complete-save"));
    values.insert(text("if"), text("always() && steps.driver-cold-adopt.outputs.source-complete-save == 'true' && steps.driver-cold-adopt-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_873());
    Value::Mapping(values)
}

fn node_873() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_870() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-source-complete-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-cold-adopt.outputs.source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_871());
    Value::Mapping(values)
}

fn node_871() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_868() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-bootstrap-save"));
    values.insert(text("if"), text("always() && steps.driver-cold-adopt.outputs.bootstrap-save == 'true' && steps.driver-cold-adopt-bootstrap-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_869());
    Value::Mapping(values)
}

fn node_869() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-path }}"),
    );
    Value::Mapping(values)
}

fn node_866() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-bootstrap-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-cold-adopt.outputs.bootstrap-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_867());
    Value::Mapping(values)
}

fn node_867() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_865() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt"));
    values.insert(
        text("if"),
        text("steps.driver-cold-build.outcome == 'success'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    values.insert(
        text("run"),
        text("./target/ci-driver-cold/release/memcordon-ci ci driver-adopt-cold"),
    );
    Value::Mapping(values)
}

fn node_864() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-build"));
    values.insert(
        text("if"),
        text("runner.os != 'Windows' && steps.driver-bootstrap.outputs.bootstrap-ready != 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(30.into()));
    values.insert(text("run"), text("rustup run 1.97.1 cargo build --locked --release --target-dir target/ci-driver-cold -p memcordon-ci --bin memcordon-ci"));
    Value::Mapping(values)
}

fn node_863() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-cleanup"));
    values.insert(text("if"), text("always() && (steps.driver-managed-build.outcome == 'success' || steps.driver-managed-build.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-cleanup"),
    );
    Value::Mapping(values)
}

fn node_861() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-index-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_862());
    Value::Mapping(values)
}

fn node_862() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_859() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-archives-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_860());
    Value::Mapping(values)
}

fn node_860() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_857() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-source-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.source-complete-save == 'true' && steps.driver-managed-build-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_858());
    Value::Mapping(values)
}

fn node_858() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_855() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-source-complete-probe"),
    );
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_856());
    Value::Mapping(values)
}

fn node_856() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_853() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-compiled-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build.outputs.compiled-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_854());
    Value::Mapping(values)
}

fn node_854() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.compiled-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_851() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-compiled-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.compiled-complete-save == 'true' && steps.driver-managed-build-compiled-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_852());
    Value::Mapping(values)
}

fn node_852() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_849() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-compiled-complete-probe"),
    );
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.compiled-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_850());
    Value::Mapping(values)
}

fn node_850() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_847() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-image-save"));
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.image-save == 'true' && steps.driver-managed-build-image-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_848());
    Value::Mapping(values)
}

fn node_848() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.image-path }}"),
    );
    Value::Mapping(values)
}

fn node_845() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-image-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.image-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_846());
    Value::Mapping(values)
}

fn node_846() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.image-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_843() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-bootstrap-save"));
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.bootstrap-save == 'true' && steps.driver-managed-build-bootstrap-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_844());
    Value::Mapping(values)
}

fn node_844() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-path }}"),
    );
    Value::Mapping(values)
}

fn node_841() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-bootstrap-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.bootstrap-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_842());
    Value::Mapping(values)
}

fn node_842() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_840() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build"));
    values.insert(
        text("if"),
        text("steps.driver-selection.outputs.build-required == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(50.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-build"),
    );
    Value::Mapping(values)
}

fn node_838() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-compiled-partial-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.compiled-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_839());
    Value::Mapping(values)
}

fn node_839() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.compiled-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.compiled-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_836() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-compiled-complete-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.compiled-complete-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_837());
    Value::Mapping(values)
}

fn node_837() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.compiled-complete-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.compiled-complete-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_834() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-index-partial-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.index-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_835());
    Value::Mapping(values)
}

fn node_835() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.index-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.index-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_832() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-archives-partial-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.archives-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_833());
    Value::Mapping(values)
}

fn node_833() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.archives-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.archives-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_830() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-source-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.source-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_831());
    Value::Mapping(values)
}

fn node_831() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.source-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.source-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.source-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_829() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-selection"));
    values.insert(
        text("if"),
        text("steps.driver-bootstrap.outputs.bootstrap-ready == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(4.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-select"),
    );
    Value::Mapping(values)
}

fn node_827() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-image-restore"));
    values.insert(
        text("if"),
        text("steps.driver-context.outputs.image-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_828());
    Value::Mapping(values)
}

fn node_828() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.image-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.image-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_826() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context"));
    values.insert(
        text("if"),
        text("steps.driver-bootstrap.outputs.bootstrap-ready == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-context"),
    );
    Value::Mapping(values)
}

fn node_825() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-bootstrap"));
    values.insert(text("if"), text("runner.os != 'Windows' && steps.driver-bootstrap-cache.outcome == 'success' && steps.driver-bootstrap-cache.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-bootstrap-in/memcordon-ci ci driver-bootstrap"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_823() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-bootstrap-cache"));
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_824());
    Value::Mapping(values)
}

fn node_824() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-bootstrap-in"));
    values.insert(text("key"), text("mc-ci-bootstrap-v3-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/driver-bootstrap.toml', 'ci/toolchains.toml') }}-lookup"));
    values.insert(text("restore-keys"), text("mc-ci-bootstrap-v3-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/driver-bootstrap.toml', 'ci/toolchains.toml') }}-"));
    Value::Mapping(values)
}

fn node_821() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("public-source-seed-restore"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(text("with"), node_822());
    Value::Mapping(values)
}

fn node_822() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-cargo-home/registry/cache/index.crates.io-1949cf8c6b5b557f/*.crate\ntarget/ci-cargo-home/registry/cache/index.crates.io-6f17d22bba15001f/*.crate\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/.cache\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/config.json"));
    values.insert(text("key"), text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-${{ hashFiles('Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', 'tools/*/Cargo.toml', '.cargo/**') }}"));
    values.insert(
        text("restore-keys"),
        text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-"),
    );
    Value::Mapping(values)
}

fn node_820() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Install pinned Rust"));
    values.insert(
        text("run"),
        text("rustup toolchain install 1.97.1 --profile minimal"),
    );
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    Value::Mapping(values)
}

fn node_818() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Check out repository"));
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_819());
    values.insert(text("timeout-minutes"), Value::Number(6.into()));
    Value::Mapping(values)
}

fn node_819() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_817() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Configure checkout line endings"));
    values.insert(text("run"), text("git config --global core.autocrlf false"));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    Value::Mapping(values)
}

fn node_693() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("github.event_name != 'push'"));
    values.insert(text("name"), text("Supply chain / audit"));
    values.insert(text("runs-on"), text("ubuntu-24.04"));
    values.insert(text("timeout-minutes"), Value::Number(330.into()));
    values.insert(text("steps"), node_694());
    values.insert(text("env"), node_814());
    Value::Mapping(values)
}

fn node_814() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("CARGO_HOME"),
        text("${{ github.workspace }}/target/ci-cargo-home"),
    );
    Value::Mapping(values)
}

fn node_694() -> Value {
    let mut values = Vec::new();
    values.push(node_695());
    values.push(node_696());
    values.push(node_698());
    values.push(node_699());
    values.push(node_701());
    values.push(node_703());
    values.push(node_704());
    values.push(node_705());
    values.push(node_707());
    values.push(node_708());
    values.push(node_710());
    values.push(node_712());
    values.push(node_714());
    values.push(node_716());
    values.push(node_718());
    values.push(node_719());
    values.push(node_721());
    values.push(node_723());
    values.push(node_725());
    values.push(node_727());
    values.push(node_729());
    values.push(node_731());
    values.push(node_733());
    values.push(node_735());
    values.push(node_737());
    values.push(node_739());
    values.push(node_741());
    values.push(node_742());
    values.push(node_743());
    values.push(node_744());
    values.push(node_746());
    values.push(node_748());
    values.push(node_750());
    values.push(node_752());
    values.push(node_754());
    values.push(node_756());
    values.push(node_757());
    values.push(node_758());
    values.push(node_759());
    values.push(node_761());
    values.push(node_763());
    values.push(node_765());
    values.push(node_766());
    values.push(node_768());
    values.push(node_770());
    values.push(node_772());
    values.push(node_774());
    values.push(node_775());
    values.push(node_776());
    values.push(node_778());
    values.push(node_780());
    values.push(node_782());
    values.push(node_784());
    values.push(node_786());
    values.push(node_788());
    values.push(node_790());
    values.push(node_791());
    values.push(node_793());
    values.push(node_795());
    values.push(node_797());
    values.push(node_799());
    values.push(node_801());
    values.push(node_803());
    values.push(node_805());
    values.push(node_807());
    values.push(node_809());
    values.push(node_811());
    values.push(node_813());
    Value::Sequence(values)
}

fn node_813() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("supply-run-cleanup"));
    values.insert(text("if"), text("always() && (steps.supply-run.outcome == 'success' || steps.supply-run.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cleanup-transfers supply-audit"),
    );
    Value::Mapping(values)
}

fn node_811() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("supply-run-cargo-audit-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.supply-run.outputs.cargo-audit-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_812());
    Value::Mapping(values)
}

fn node_812() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run.outputs.cargo-audit-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run.outputs.cargo-audit-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_809() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("supply-run-cargo-audit-complete-save"));
    values.insert(text("if"), text("always() && steps.supply-run.outputs.cargo-audit-complete-save == 'true' && steps.supply-run-cargo-audit-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_810());
    Value::Mapping(values)
}

fn node_810() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run.outputs.cargo-audit-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run.outputs.cargo-audit-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_807() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("supply-run-cargo-audit-complete-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.supply-run.outputs.cargo-audit-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_808());
    Value::Mapping(values)
}

fn node_808() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run.outputs.cargo-audit-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run.outputs.cargo-audit-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_805() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("supply-run-cargo-audit-source-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.supply-run.outputs.cargo-audit-source-complete-save == 'true' && steps.supply-run-cargo-audit-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_806());
    Value::Mapping(values)
}

fn node_806() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run.outputs.cargo-audit-source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run.outputs.cargo-audit-source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_803() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("supply-run-cargo-audit-source-complete-probe"),
    );
    values.insert(
        text("if"),
        text("!cancelled() && steps.supply-run.outputs.cargo-audit-source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_804());
    Value::Mapping(values)
}

fn node_804() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run.outputs.cargo-audit-source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run.outputs.cargo-audit-source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_801() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("supply-run-cargo-audit-image-save"));
    values.insert(text("if"), text("always() && steps.supply-run.outputs.cargo-audit-image-save == 'true' && steps.supply-run-cargo-audit-image-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_802());
    Value::Mapping(values)
}

fn node_802() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run.outputs.cargo-audit-image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run.outputs.cargo-audit-image-path }}"),
    );
    Value::Mapping(values)
}

fn node_799() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("supply-run-cargo-audit-image-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.supply-run.outputs.cargo-audit-image-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_800());
    Value::Mapping(values)
}

fn node_800() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run.outputs.cargo-audit-image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run.outputs.cargo-audit-image-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_797() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("supply-run-index-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.supply-run.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_798());
    Value::Mapping(values)
}

fn node_798() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_795() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("supply-run-archives-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.supply-run.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_796());
    Value::Mapping(values)
}

fn node_796() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_793() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("supply-run-source-complete-save"));
    values.insert(text("if"), text("always() && steps.supply-run.outputs.source-complete-save == 'true' && steps.supply-run-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_794());
    Value::Mapping(values)
}

fn node_794() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_791() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("supply-run-source-complete-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.supply-run.outputs.source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_792());
    Value::Mapping(values)
}

fn node_792() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_790() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Run supply-chain suite"));
    values.insert(text("id"), text("supply-run"));
    values.insert(text("timeout-minutes"), Value::Number(130.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci segment supply-audit"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    Value::Mapping(values)
}

fn node_788() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("supply-run-request-cargo-audit-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.supply-run-request.outputs.cargo-audit-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_789());
    Value::Mapping(values)
}

fn node_789() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run-request.outputs.cargo-audit-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run-request.outputs.cargo-audit-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.supply-run-request.outputs.cargo-audit-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_786() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("supply-run-request-cargo-audit-complete-restore"),
    );
    values.insert(
        text("if"),
        text("steps.supply-run-request.outputs.cargo-audit-complete-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_787());
    Value::Mapping(values)
}

fn node_787() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run-request.outputs.cargo-audit-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run-request.outputs.cargo-audit-complete-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.supply-run-request.outputs.cargo-audit-complete-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_784() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("supply-run-request-cargo-audit-source-restore"),
    );
    values.insert(
        text("if"),
        text("steps.supply-run-request.outputs.cargo-audit-source-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_785());
    Value::Mapping(values)
}

fn node_785() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run-request.outputs.cargo-audit-source-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run-request.outputs.cargo-audit-source-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.supply-run-request.outputs.cargo-audit-source-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_782() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("supply-run-request-cargo-audit-image-restore"),
    );
    values.insert(
        text("if"),
        text("steps.supply-run-request.outputs.cargo-audit-image-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_783());
    Value::Mapping(values)
}

fn node_783() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run-request.outputs.cargo-audit-image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run-request.outputs.cargo-audit-image-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.supply-run-request.outputs.cargo-audit-image-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_780() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("supply-run-request-index-partial-restore"));
    values.insert(
        text("if"),
        text("steps.supply-run-request.outputs.index-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_781());
    Value::Mapping(values)
}

fn node_781() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run-request.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run-request.outputs.index-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.supply-run-request.outputs.index-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_778() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("supply-run-request-archives-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.supply-run-request.outputs.archives-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_779());
    Value::Mapping(values)
}

fn node_779() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run-request.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run-request.outputs.archives-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.supply-run-request.outputs.archives-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_776() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("supply-run-request-source-restore"));
    values.insert(
        text("if"),
        text("steps.supply-run-request.outputs.source-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_777());
    Value::Mapping(values)
}

fn node_777() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.supply-run-request.outputs.source-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.supply-run-request.outputs.source-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.supply-run-request.outputs.source-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_775() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("supply-run-request"));
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cache-requests supply-audit"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    Value::Mapping(values)
}

fn node_774() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-cleanup"));
    values.insert(text("if"), text("always() && (steps.workspace-fetch.outcome == 'success' || steps.workspace-fetch.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cleanup-transfers workspace-fetch"),
    );
    Value::Mapping(values)
}

fn node_772() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-index-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.workspace-fetch.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_773());
    Value::Mapping(values)
}

fn node_773() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_770() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-archives-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.workspace-fetch.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_771());
    Value::Mapping(values)
}

fn node_771() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_768() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-source-complete-save"));
    values.insert(text("if"), text("always() && steps.workspace-fetch.outputs.source-complete-save == 'true' && steps.workspace-fetch-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_769());
    Value::Mapping(values)
}

fn node_769() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_766() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-source-complete-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.workspace-fetch.outputs.source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_767());
    Value::Mapping(values)
}

fn node_767() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_765() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci segment workspace-fetch"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("timeout-minutes"), Value::Number(25.into()));
    Value::Mapping(values)
}

fn node_763() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("workspace-fetch-request-index-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.workspace-fetch-request.outputs.index-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.workspace-fetch-request.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch-request.outputs.index-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-fetch-request.outputs.index-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_761() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("workspace-fetch-request-archives-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.workspace-fetch-request.outputs.archives-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_762());
    Value::Mapping(values)
}

fn node_762() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch-request.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch-request.outputs.archives-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-fetch-request.outputs.archives-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_759() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-request-source-restore"));
    values.insert(
        text("if"),
        text("steps.workspace-fetch-request.outputs.source-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_760());
    Value::Mapping(values)
}

fn node_760() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch-request.outputs.source-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch-request.outputs.source-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-fetch-request.outputs.source-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_758() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-request"));
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cache-requests workspace-fetch"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    Value::Mapping(values)
}

fn node_757() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-workflows-check"));
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci workflows --check"),
    );
    Value::Mapping(values)
}

fn node_756() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-cleanup"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt.outcome == 'success'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci driver-cleanup"),
    );
    Value::Mapping(values)
}

fn node_754() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-index-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_755());
    Value::Mapping(values)
}

fn node_755() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_752() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-archives-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_753());
    Value::Mapping(values)
}

fn node_753() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_750() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-source-complete-save"));
    values.insert(text("if"), text("always() && steps.driver-cold-adopt.outputs.source-complete-save == 'true' && steps.driver-cold-adopt-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_751());
    Value::Mapping(values)
}

fn node_751() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_748() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-source-complete-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-cold-adopt.outputs.source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_749());
    Value::Mapping(values)
}

fn node_749() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_746() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-bootstrap-save"));
    values.insert(text("if"), text("always() && steps.driver-cold-adopt.outputs.bootstrap-save == 'true' && steps.driver-cold-adopt-bootstrap-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_747());
    Value::Mapping(values)
}

fn node_747() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-path }}"),
    );
    Value::Mapping(values)
}

fn node_744() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-bootstrap-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-cold-adopt.outputs.bootstrap-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_745());
    Value::Mapping(values)
}

fn node_745() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_743() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt"));
    values.insert(
        text("if"),
        text("steps.driver-cold-build.outcome == 'success'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    values.insert(
        text("run"),
        text("./target/ci-driver-cold/release/memcordon-ci ci driver-adopt-cold"),
    );
    Value::Mapping(values)
}

fn node_742() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-build"));
    values.insert(
        text("if"),
        text("runner.os != 'Windows' && steps.driver-bootstrap.outputs.bootstrap-ready != 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(30.into()));
    values.insert(text("run"), text("rustup run 1.97.1 cargo build --locked --release --target-dir target/ci-driver-cold -p memcordon-ci --bin memcordon-ci"));
    Value::Mapping(values)
}

fn node_741() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-cleanup"));
    values.insert(text("if"), text("always() && (steps.driver-managed-build.outcome == 'success' || steps.driver-managed-build.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-cleanup"),
    );
    Value::Mapping(values)
}

fn node_739() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-index-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.driver-managed-build.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_737() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-archives-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_738());
    Value::Mapping(values)
}

fn node_738() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_735() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-source-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.source-complete-save == 'true' && steps.driver-managed-build-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_736());
    Value::Mapping(values)
}

fn node_736() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_733() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-source-complete-probe"),
    );
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_734());
    Value::Mapping(values)
}

fn node_734() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_731() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-compiled-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build.outputs.compiled-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_732());
    Value::Mapping(values)
}

fn node_732() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.compiled-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_729() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-compiled-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.compiled-complete-save == 'true' && steps.driver-managed-build-compiled-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_730());
    Value::Mapping(values)
}

fn node_730() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_727() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-compiled-complete-probe"),
    );
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.compiled-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_728());
    Value::Mapping(values)
}

fn node_728() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_725() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-image-save"));
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.image-save == 'true' && steps.driver-managed-build-image-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_726());
    Value::Mapping(values)
}

fn node_726() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.image-path }}"),
    );
    Value::Mapping(values)
}

fn node_723() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-image-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.image-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_724());
    Value::Mapping(values)
}

fn node_724() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.image-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_721() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-bootstrap-save"));
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.bootstrap-save == 'true' && steps.driver-managed-build-bootstrap-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_722());
    Value::Mapping(values)
}

fn node_722() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-path }}"),
    );
    Value::Mapping(values)
}

fn node_719() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-bootstrap-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.bootstrap-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_720());
    Value::Mapping(values)
}

fn node_720() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_718() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build"));
    values.insert(
        text("if"),
        text("steps.driver-selection.outputs.build-required == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(50.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-build"),
    );
    Value::Mapping(values)
}

fn node_716() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-compiled-partial-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.compiled-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_717());
    Value::Mapping(values)
}

fn node_717() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.compiled-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.compiled-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_714() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-compiled-complete-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.compiled-complete-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("key"),
        text("${{ steps.driver-context.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.compiled-complete-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.compiled-complete-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_712() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-index-partial-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.index-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_713());
    Value::Mapping(values)
}

fn node_713() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.index-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.index-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_710() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-archives-partial-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.archives-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_711());
    Value::Mapping(values)
}

fn node_711() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.archives-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.archives-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_708() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-source-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.source-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_709());
    Value::Mapping(values)
}

fn node_709() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.source-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.source-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.source-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_707() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-selection"));
    values.insert(
        text("if"),
        text("steps.driver-bootstrap.outputs.bootstrap-ready == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(4.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-select"),
    );
    Value::Mapping(values)
}

fn node_705() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-image-restore"));
    values.insert(
        text("if"),
        text("steps.driver-context.outputs.image-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.driver-context.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.image-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.image-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_704() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context"));
    values.insert(
        text("if"),
        text("steps.driver-bootstrap.outputs.bootstrap-ready == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-context"),
    );
    Value::Mapping(values)
}

fn node_703() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-bootstrap"));
    values.insert(text("if"), text("runner.os != 'Windows' && steps.driver-bootstrap-cache.outcome == 'success' && steps.driver-bootstrap-cache.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-bootstrap-in/memcordon-ci ci driver-bootstrap"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_701() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-bootstrap-cache"));
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_702());
    Value::Mapping(values)
}

fn node_702() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-bootstrap-in"));
    values.insert(text("key"), text("mc-ci-bootstrap-v3-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/driver-bootstrap.toml', 'ci/toolchains.toml') }}-lookup"));
    values.insert(text("restore-keys"), text("mc-ci-bootstrap-v3-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/driver-bootstrap.toml', 'ci/toolchains.toml') }}-"));
    Value::Mapping(values)
}

fn node_699() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("public-source-seed-restore"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(text("with"), node_700());
    Value::Mapping(values)
}

fn node_700() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-cargo-home/registry/cache/index.crates.io-1949cf8c6b5b557f/*.crate\ntarget/ci-cargo-home/registry/cache/index.crates.io-6f17d22bba15001f/*.crate\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/.cache\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/config.json"));
    values.insert(text("key"), text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-${{ hashFiles('Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', 'tools/*/Cargo.toml', '.cargo/**') }}"));
    values.insert(
        text("restore-keys"),
        text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-"),
    );
    Value::Mapping(values)
}

fn node_698() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Install pinned Rust"));
    values.insert(
        text("run"),
        text("rustup toolchain install 1.97.1 --profile minimal"),
    );
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    Value::Mapping(values)
}

fn node_696() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Check out repository"));
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_697());
    values.insert(text("timeout-minutes"), Value::Number(6.into()));
    Value::Mapping(values)
}

fn node_697() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_695() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Configure checkout line endings"));
    values.insert(text("run"), text("git config --global core.autocrlf false"));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    Value::Mapping(values)
}

fn node_590() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("github.event_name != 'push'"));
    values.insert(text("name"), text("macOS deadline / ${{ matrix.id }}"));
    values.insert(text("strategy"), node_591());
    values.insert(text("runs-on"), text("${{ matrix.runner }}"));
    values.insert(text("timeout-minutes"), Value::Number(260.into()));
    values.insert(text("steps"), node_596());
    values.insert(text("env"), node_692());
    Value::Mapping(values)
}

fn node_692() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("CARGO_HOME"),
        text("${{ github.workspace }}/target/ci-cargo-home"),
    );
    Value::Mapping(values)
}

fn node_596() -> Value {
    let mut values = Vec::new();
    values.push(node_597());
    values.push(node_598());
    values.push(node_600());
    values.push(node_601());
    values.push(node_603());
    values.push(node_605());
    values.push(node_606());
    values.push(node_607());
    values.push(node_609());
    values.push(node_610());
    values.push(node_612());
    values.push(node_614());
    values.push(node_616());
    values.push(node_618());
    values.push(node_620());
    values.push(node_621());
    values.push(node_623());
    values.push(node_625());
    values.push(node_627());
    values.push(node_629());
    values.push(node_631());
    values.push(node_633());
    values.push(node_635());
    values.push(node_637());
    values.push(node_639());
    values.push(node_641());
    values.push(node_643());
    values.push(node_644());
    values.push(node_645());
    values.push(node_646());
    values.push(node_648());
    values.push(node_650());
    values.push(node_652());
    values.push(node_654());
    values.push(node_656());
    values.push(node_658());
    values.push(node_659());
    values.push(node_660());
    values.push(node_661());
    values.push(node_663());
    values.push(node_665());
    values.push(node_667());
    values.push(node_668());
    values.push(node_670());
    values.push(node_672());
    values.push(node_674());
    values.push(node_676());
    values.push(node_677());
    values.push(node_678());
    values.push(node_680());
    values.push(node_682());
    values.push(node_683());
    values.push(node_685());
    values.push(node_687());
    values.push(node_689());
    values.push(node_690());
    Value::Sequence(values)
}

fn node_690() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("!cancelled()"));
    values.insert(text("uses"), text("./.github/actions/upload-artifact"));
    values.insert(text("with"), node_691());
    values.insert(text("timeout-minutes"), Value::Number(6.into()));
    Value::Mapping(values)
}

fn node_691() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("macos-deadline-${{ matrix.id }}"));
    values.insert(text("path"), text("target/ci/deadline-evidence"));
    values.insert(text("if-no-files-found"), text("error"));
    values.insert(text("retention-days"), Value::Number(14.into()));
    Value::Mapping(values)
}

fn node_689() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("deadline-run-cleanup"));
    values.insert(text("if"), text("always() && (steps.deadline-run.outcome == 'success' || steps.deadline-run.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cleanup-transfers macos-deadline"),
    );
    Value::Mapping(values)
}

fn node_687() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("deadline-run-compiled-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.deadline-run.outputs.compiled-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.deadline-run.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.deadline-run.outputs.compiled-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_685() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("deadline-run-compiled-complete-save"));
    values.insert(text("if"), text("always() && steps.deadline-run.outputs.compiled-complete-save == 'true' && steps.deadline-run-compiled-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_686());
    Value::Mapping(values)
}

fn node_686() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.deadline-run.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.deadline-run.outputs.compiled-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_683() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("deadline-run-compiled-complete-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.deadline-run.outputs.compiled-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_684());
    Value::Mapping(values)
}

fn node_684() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.deadline-run.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.deadline-run.outputs.compiled-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_682() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("deadline-run"));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci segment macos-deadline"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("timeout-minutes"), Value::Number(75.into()));
    Value::Mapping(values)
}

fn node_680() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("deadline-run-request-compiled-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.deadline-run-request.outputs.compiled-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_681());
    Value::Mapping(values)
}

fn node_681() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.deadline-run-request.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.deadline-run-request.outputs.compiled-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.deadline-run-request.outputs.compiled-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_678() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("deadline-run-request-compiled-complete-restore"),
    );
    values.insert(
        text("if"),
        text("steps.deadline-run-request.outputs.compiled-complete-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_679());
    Value::Mapping(values)
}

fn node_679() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.deadline-run-request.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.deadline-run-request.outputs.compiled-complete-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.deadline-run-request.outputs.compiled-complete-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_677() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("deadline-run-request"));
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cache-requests macos-deadline"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    Value::Mapping(values)
}

fn node_676() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-cleanup"));
    values.insert(text("if"), text("always() && (steps.workspace-fetch.outcome == 'success' || steps.workspace-fetch.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cleanup-transfers workspace-fetch"),
    );
    Value::Mapping(values)
}

fn node_674() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-index-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.workspace-fetch.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_675());
    Value::Mapping(values)
}

fn node_675() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_672() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-archives-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.workspace-fetch.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_673());
    Value::Mapping(values)
}

fn node_673() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_670() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-source-complete-save"));
    values.insert(text("if"), text("always() && steps.workspace-fetch.outputs.source-complete-save == 'true' && steps.workspace-fetch-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_671());
    Value::Mapping(values)
}

fn node_671() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_668() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-source-complete-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.workspace-fetch.outputs.source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_669());
    Value::Mapping(values)
}

fn node_669() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_667() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci segment workspace-fetch"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("timeout-minutes"), Value::Number(25.into()));
    Value::Mapping(values)
}

fn node_665() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("workspace-fetch-request-index-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.workspace-fetch-request.outputs.index-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_666());
    Value::Mapping(values)
}

fn node_666() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch-request.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch-request.outputs.index-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-fetch-request.outputs.index-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_663() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("workspace-fetch-request-archives-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.workspace-fetch-request.outputs.archives-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_664());
    Value::Mapping(values)
}

fn node_664() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch-request.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch-request.outputs.archives-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-fetch-request.outputs.archives-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_661() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-request-source-restore"));
    values.insert(
        text("if"),
        text("steps.workspace-fetch-request.outputs.source-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_662());
    Value::Mapping(values)
}

fn node_662() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch-request.outputs.source-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch-request.outputs.source-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-fetch-request.outputs.source-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_660() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-request"));
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cache-requests workspace-fetch"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    Value::Mapping(values)
}

fn node_659() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-workflows-check"));
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci workflows --check"),
    );
    Value::Mapping(values)
}

fn node_658() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-cleanup"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt.outcome == 'success'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci driver-cleanup"),
    );
    Value::Mapping(values)
}

fn node_656() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-index-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_657());
    Value::Mapping(values)
}

fn node_657() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_654() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-archives-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_655());
    Value::Mapping(values)
}

fn node_655() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_652() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-source-complete-save"));
    values.insert(text("if"), text("always() && steps.driver-cold-adopt.outputs.source-complete-save == 'true' && steps.driver-cold-adopt-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_653());
    Value::Mapping(values)
}

fn node_653() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_650() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-source-complete-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-cold-adopt.outputs.source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_651());
    Value::Mapping(values)
}

fn node_651() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_648() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-bootstrap-save"));
    values.insert(text("if"), text("always() && steps.driver-cold-adopt.outputs.bootstrap-save == 'true' && steps.driver-cold-adopt-bootstrap-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_649());
    Value::Mapping(values)
}

fn node_649() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-path }}"),
    );
    Value::Mapping(values)
}

fn node_646() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-bootstrap-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-cold-adopt.outputs.bootstrap-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_647());
    Value::Mapping(values)
}

fn node_647() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_645() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt"));
    values.insert(
        text("if"),
        text("steps.driver-cold-build.outcome == 'success'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    values.insert(
        text("run"),
        text("./target/ci-driver-cold/release/memcordon-ci ci driver-adopt-cold"),
    );
    Value::Mapping(values)
}

fn node_644() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-build"));
    values.insert(
        text("if"),
        text("runner.os != 'Windows' && steps.driver-bootstrap.outputs.bootstrap-ready != 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(30.into()));
    values.insert(text("run"), text("rustup run 1.97.1 cargo build --locked --release --target-dir target/ci-driver-cold -p memcordon-ci --bin memcordon-ci"));
    Value::Mapping(values)
}

fn node_643() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-cleanup"));
    values.insert(text("if"), text("always() && (steps.driver-managed-build.outcome == 'success' || steps.driver-managed-build.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-cleanup"),
    );
    Value::Mapping(values)
}

fn node_641() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-index-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_642());
    Value::Mapping(values)
}

fn node_642() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_639() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-archives-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_640());
    Value::Mapping(values)
}

fn node_640() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_637() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-source-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.source-complete-save == 'true' && steps.driver-managed-build-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_638());
    Value::Mapping(values)
}

fn node_638() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_635() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-source-complete-probe"),
    );
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_636());
    Value::Mapping(values)
}

fn node_636() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_633() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-compiled-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build.outputs.compiled-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_634());
    Value::Mapping(values)
}

fn node_634() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.compiled-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_631() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-compiled-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.compiled-complete-save == 'true' && steps.driver-managed-build-compiled-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_632());
    Value::Mapping(values)
}

fn node_632() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_629() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-compiled-complete-probe"),
    );
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.compiled-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_630());
    Value::Mapping(values)
}

fn node_630() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_627() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-image-save"));
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.image-save == 'true' && steps.driver-managed-build-image-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_628());
    Value::Mapping(values)
}

fn node_628() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.image-path }}"),
    );
    Value::Mapping(values)
}

fn node_625() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-image-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.image-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_626());
    Value::Mapping(values)
}

fn node_626() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.image-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_623() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-bootstrap-save"));
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.bootstrap-save == 'true' && steps.driver-managed-build-bootstrap-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.driver-managed-build.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-path }}"),
    );
    Value::Mapping(values)
}

fn node_621() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-bootstrap-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.bootstrap-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
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
        text("${{ steps.driver-managed-build.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_620() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build"));
    values.insert(
        text("if"),
        text("steps.driver-selection.outputs.build-required == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(50.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-build"),
    );
    Value::Mapping(values)
}

fn node_618() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-compiled-partial-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.compiled-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_619());
    Value::Mapping(values)
}

fn node_619() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.compiled-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.compiled-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_616() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-compiled-complete-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.compiled-complete-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_617());
    Value::Mapping(values)
}

fn node_617() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.compiled-complete-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.compiled-complete-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_614() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-index-partial-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.index-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_615());
    Value::Mapping(values)
}

fn node_615() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.index-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.index-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_612() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-archives-partial-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.archives-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_613());
    Value::Mapping(values)
}

fn node_613() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.archives-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.archives-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_610() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-source-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.source-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_611());
    Value::Mapping(values)
}

fn node_611() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.source-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.source-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.source-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_609() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-selection"));
    values.insert(
        text("if"),
        text("steps.driver-bootstrap.outputs.bootstrap-ready == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(4.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-select"),
    );
    Value::Mapping(values)
}

fn node_607() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-image-restore"));
    values.insert(
        text("if"),
        text("steps.driver-context.outputs.image-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_608());
    Value::Mapping(values)
}

fn node_608() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.image-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.image-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_606() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context"));
    values.insert(
        text("if"),
        text("steps.driver-bootstrap.outputs.bootstrap-ready == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-context"),
    );
    Value::Mapping(values)
}

fn node_605() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-bootstrap"));
    values.insert(text("if"), text("runner.os != 'Windows' && steps.driver-bootstrap-cache.outcome == 'success' && steps.driver-bootstrap-cache.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-bootstrap-in/memcordon-ci ci driver-bootstrap"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_603() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-bootstrap-cache"));
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_604());
    Value::Mapping(values)
}

fn node_604() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-bootstrap-in"));
    values.insert(text("key"), text("mc-ci-bootstrap-v3-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/driver-bootstrap.toml', 'ci/toolchains.toml') }}-lookup"));
    values.insert(text("restore-keys"), text("mc-ci-bootstrap-v3-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/driver-bootstrap.toml', 'ci/toolchains.toml') }}-"));
    Value::Mapping(values)
}

fn node_601() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("public-source-seed-restore"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(text("with"), node_602());
    Value::Mapping(values)
}

fn node_602() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-cargo-home/registry/cache/index.crates.io-1949cf8c6b5b557f/*.crate\ntarget/ci-cargo-home/registry/cache/index.crates.io-6f17d22bba15001f/*.crate\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/.cache\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/config.json"));
    values.insert(text("key"), text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-${{ hashFiles('Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', 'tools/*/Cargo.toml', '.cargo/**') }}"));
    values.insert(
        text("restore-keys"),
        text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-"),
    );
    Value::Mapping(values)
}

fn node_600() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("run"),
        text("rustup toolchain install 1.97.1 --profile minimal"),
    );
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    Value::Mapping(values)
}

fn node_598() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_599());
    values.insert(text("timeout-minutes"), Value::Number(6.into()));
    Value::Mapping(values)
}

fn node_599() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_597() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Configure checkout line endings"));
    values.insert(text("run"), text("git config --global core.autocrlf false"));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    Value::Mapping(values)
}

fn node_591() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("fail-fast"), Value::Bool(false));
    values.insert(text("matrix"), node_592());
    Value::Mapping(values)
}

fn node_592() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("include"), node_593());
    Value::Mapping(values)
}

fn node_593() -> Value {
    let mut values = Vec::new();
    values.push(node_594());
    values.push(node_595());
    Value::Sequence(values)
}

fn node_595() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("x64"));
    values.insert(text("runner"), text("macos-15-intel"));
    Value::Mapping(values)
}

fn node_594() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("arm64"));
    values.insert(text("runner"), text("macos-15"));
    Value::Mapping(values)
}

fn node_369() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("github.event.deleted != true"));
    values.insert(text("name"), text("native / ${{ matrix.id }}"));
    values.insert(text("strategy"), node_370());
    values.insert(text("runs-on"), text("${{ matrix.runner }}"));
    values.insert(text("timeout-minutes"), Value::Number(276.into()));
    values.insert(text("steps"), node_379());
    values.insert(text("env"), node_589());
    Value::Mapping(values)
}

fn node_589() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("CARGO_HOME"),
        text("${{ github.workspace }}/target/ci-cargo-home"),
    );
    Value::Mapping(values)
}

fn node_379() -> Value {
    let mut values = Vec::new();
    values.push(node_380());
    values.push(node_381());
    values.push(node_383());
    values.push(node_384());
    values.push(node_385());
    values.push(node_387());
    values.push(node_389());
    values.push(node_390());
    values.push(node_391());
    values.push(node_393());
    values.push(node_394());
    values.push(node_396());
    values.push(node_398());
    values.push(node_400());
    values.push(node_402());
    values.push(node_404());
    values.push(node_405());
    values.push(node_407());
    values.push(node_409());
    values.push(node_411());
    values.push(node_413());
    values.push(node_415());
    values.push(node_417());
    values.push(node_419());
    values.push(node_421());
    values.push(node_423());
    values.push(node_425());
    values.push(node_427());
    values.push(node_428());
    values.push(node_429());
    values.push(node_430());
    values.push(node_432());
    values.push(node_434());
    values.push(node_436());
    values.push(node_438());
    values.push(node_440());
    values.push(node_442());
    values.push(node_443());
    values.push(node_444());
    values.push(node_446());
    values.push(node_447());
    values.push(node_448());
    values.push(node_450());
    values.push(node_451());
    values.push(node_453());
    values.push(node_455());
    values.push(node_457());
    values.push(node_459());
    values.push(node_461());
    values.push(node_462());
    values.push(node_464());
    values.push(node_466());
    values.push(node_468());
    values.push(node_470());
    values.push(node_472());
    values.push(node_474());
    values.push(node_476());
    values.push(node_478());
    values.push(node_480());
    values.push(node_482());
    values.push(node_484());
    values.push(node_485());
    values.push(node_486());
    values.push(node_487());
    values.push(node_489());
    values.push(node_491());
    values.push(node_493());
    values.push(node_495());
    values.push(node_497());
    values.push(node_499());
    values.push(node_500());
    values.push(node_501());
    values.push(node_502());
    values.push(node_504());
    values.push(node_506());
    values.push(node_508());
    values.push(node_509());
    values.push(node_511());
    values.push(node_513());
    values.push(node_515());
    values.push(node_517());
    values.push(node_518());
    values.push(node_519());
    values.push(node_521());
    values.push(node_523());
    values.push(node_525());
    values.push(node_526());
    values.push(node_528());
    values.push(node_530());
    values.push(node_532());
    values.push(node_534());
    values.push(node_535());
    values.push(node_536());
    values.push(node_538());
    values.push(node_540());
    values.push(node_541());
    values.push(node_543());
    values.push(node_545());
    values.push(node_547());
    values.push(node_548());
    values.push(node_549());
    values.push(node_551());
    values.push(node_553());
    values.push(node_554());
    values.push(node_556());
    values.push(node_558());
    values.push(node_560());
    values.push(node_561());
    values.push(node_562());
    values.push(node_564());
    values.push(node_566());
    values.push(node_567());
    values.push(node_569());
    values.push(node_571());
    values.push(node_573());
    values.push(node_574());
    values.push(node_575());
    values.push(node_577());
    values.push(node_579());
    values.push(node_580());
    values.push(node_582());
    values.push(node_584());
    values.push(node_586());
    values.push(node_587());
    Value::Sequence(values)
}

fn node_587() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Retain passive Win32 module evidence"));
    values.insert(text("if"), text("!cancelled() && runner.os == 'Windows'"));
    values.insert(text("uses"), text("./.github/actions/upload-artifact"));
    values.insert(text("with"), node_588());
    values.insert(text("timeout-minutes"), Value::Number(6.into()));
    Value::Mapping(values)
}

fn node_588() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("namespace-win32-${{ github.job }}-${{ runner.arch }}-${{ strategy.job-index }}-${{ github.run_id }}-${{ github.run_attempt }}"));
    values.insert(text("path"), text("target/ci/reports/namespace-win32"));
    values.insert(text("if-no-files-found"), text("ignore"));
    values.insert(text("retention-days"), Value::Number(7.into()));
    Value::Mapping(values)
}

fn node_586() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("native-run-windows-cleanup"));
    values.insert(text("if"), text("always() && (steps.native-run-windows.outcome == 'success' || steps.native-run-windows.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers native-execute"),
    );
    Value::Mapping(values)
}

fn node_584() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("native-run-windows-auxiliary-profiles-partial-save"),
    );
    values.insert(text("if"), text("always() && steps.native-run-windows.outputs.auxiliary-profiles-partial-save == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_585());
    Value::Mapping(values)
}

fn node_585() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.native-run-windows.outputs.auxiliary-profiles-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.native-run-windows.outputs.auxiliary-profiles-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_582() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("native-run-windows-auxiliary-profiles-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.native-run-windows.outputs.auxiliary-profiles-complete-save == 'true' && steps.native-run-windows-auxiliary-profiles-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_583());
    Value::Mapping(values)
}

fn node_583() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.native-run-windows.outputs.auxiliary-profiles-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.native-run-windows.outputs.auxiliary-profiles-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_580() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("native-run-windows-auxiliary-profiles-complete-probe"),
    );
    values.insert(text("if"), text("!cancelled() && steps.native-run-windows.outputs.auxiliary-profiles-complete-save == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_581());
    Value::Mapping(values)
}

fn node_581() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.native-run-windows.outputs.auxiliary-profiles-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.native-run-windows.outputs.auxiliary-profiles-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_579() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Run native suite"));
    values.insert(text("id"), text("native-run-windows"));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci.exe ci segment native-execute"),
    );
    values.insert(text("if"), text("runner.os == 'Windows'"));
    values.insert(text("timeout-minutes"), Value::Number(40.into()));
    Value::Mapping(values)
}

fn node_577() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("native-run-windows-request-auxiliary-profiles-partial-restore"),
    );
    values.insert(
        text("if"),
        text(
            "steps.native-run-windows-request.outputs.auxiliary-profiles-partial-restore == 'true'",
        ),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.native-run-windows-request.outputs.auxiliary-profiles-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.native-run-windows-request.outputs.auxiliary-profiles-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.native-run-windows-request.outputs.auxiliary-profiles-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_575() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("native-run-windows-request-auxiliary-profiles-complete-restore"),
    );
    values.insert(text("if"), text("steps.native-run-windows-request.outputs.auxiliary-profiles-complete-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_576());
    Value::Mapping(values)
}

fn node_576() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.native-run-windows-request.outputs.auxiliary-profiles-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.native-run-windows-request.outputs.auxiliary-profiles-complete-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.native-run-windows-request.outputs.auxiliary-profiles-complete-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_574() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("native-run-windows-request"));
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci.exe ci cache-requests native-execute"),
    );
    values.insert(text("if"), text("runner.os == 'Windows'"));
    Value::Mapping(values)
}

fn node_573() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("native-run-cleanup"));
    values.insert(text("if"), text("always() && (steps.native-run.outcome == 'success' || steps.native-run.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cleanup-transfers native-execute"),
    );
    Value::Mapping(values)
}

fn node_571() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("native-run-auxiliary-profiles-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.native-run.outputs.auxiliary-profiles-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_572());
    Value::Mapping(values)
}

fn node_572() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.native-run.outputs.auxiliary-profiles-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.native-run.outputs.auxiliary-profiles-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_569() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("native-run-auxiliary-profiles-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.native-run.outputs.auxiliary-profiles-complete-save == 'true' && steps.native-run-auxiliary-profiles-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("key"),
        text("${{ steps.native-run.outputs.auxiliary-profiles-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.native-run.outputs.auxiliary-profiles-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_567() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("native-run-auxiliary-profiles-complete-probe"),
    );
    values.insert(
        text("if"),
        text("!cancelled() && steps.native-run.outputs.auxiliary-profiles-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_568());
    Value::Mapping(values)
}

fn node_568() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.native-run.outputs.auxiliary-profiles-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.native-run.outputs.auxiliary-profiles-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_566() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Run native suite"));
    values.insert(text("id"), text("native-run"));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci segment native-execute"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("timeout-minutes"), Value::Number(40.into()));
    Value::Mapping(values)
}

fn node_564() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("native-run-request-auxiliary-profiles-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.native-run-request.outputs.auxiliary-profiles-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_565());
    Value::Mapping(values)
}

fn node_565() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.native-run-request.outputs.auxiliary-profiles-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.native-run-request.outputs.auxiliary-profiles-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.native-run-request.outputs.auxiliary-profiles-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_562() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("native-run-request-auxiliary-profiles-complete-restore"),
    );
    values.insert(
        text("if"),
        text("steps.native-run-request.outputs.auxiliary-profiles-complete-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_563());
    Value::Mapping(values)
}

fn node_563() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.native-run-request.outputs.auxiliary-profiles-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.native-run-request.outputs.auxiliary-profiles-complete-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.native-run-request.outputs.auxiliary-profiles-complete-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_561() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("native-run-request"));
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cache-requests native-execute"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    Value::Mapping(values)
}

fn node_560() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("native-compile-windows-cleanup"));
    values.insert(text("if"), text("always() && (steps.native-compile-windows.outcome == 'success' || steps.native-compile-windows.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers native-compile"),
    );
    Value::Mapping(values)
}

fn node_558() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("native-compile-windows-native-tests-partial-save"),
    );
    values.insert(
        text("if"),
        text(
            "always() && steps.native-compile-windows.outputs.native-tests-partial-save == 'true'",
        ),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_559());
    Value::Mapping(values)
}

fn node_559() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.native-compile-windows.outputs.native-tests-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.native-compile-windows.outputs.native-tests-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_556() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("native-compile-windows-native-tests-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.native-compile-windows.outputs.native-tests-complete-save == 'true' && steps.native-compile-windows-native-tests-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_557());
    Value::Mapping(values)
}

fn node_557() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.native-compile-windows.outputs.native-tests-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.native-compile-windows.outputs.native-tests-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_554() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("native-compile-windows-native-tests-complete-probe"),
    );
    values.insert(text("if"), text("!cancelled() && steps.native-compile-windows.outputs.native-tests-complete-save == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_555());
    Value::Mapping(values)
}

fn node_555() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.native-compile-windows.outputs.native-tests-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.native-compile-windows.outputs.native-tests-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_553() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("native-compile-windows"));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci.exe ci segment native-compile"),
    );
    values.insert(text("if"), text("runner.os == 'Windows'"));
    values.insert(text("timeout-minutes"), Value::Number(35.into()));
    Value::Mapping(values)
}

fn node_551() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("native-compile-windows-request-native-tests-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.native-compile-windows-request.outputs.native-tests-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_552());
    Value::Mapping(values)
}

fn node_552() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.native-compile-windows-request.outputs.native-tests-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.native-compile-windows-request.outputs.native-tests-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.native-compile-windows-request.outputs.native-tests-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_549() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("native-compile-windows-request-native-tests-complete-restore"),
    );
    values.insert(
        text("if"),
        text(
            "steps.native-compile-windows-request.outputs.native-tests-complete-restore == 'true'",
        ),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_550());
    Value::Mapping(values)
}

fn node_550() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.native-compile-windows-request.outputs.native-tests-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.native-compile-windows-request.outputs.native-tests-complete-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.native-compile-windows-request.outputs.native-tests-complete-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_548() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("native-compile-windows-request"));
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci.exe ci cache-requests native-compile"),
    );
    values.insert(text("if"), text("runner.os == 'Windows'"));
    Value::Mapping(values)
}

fn node_547() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("native-compile-cleanup"));
    values.insert(text("if"), text("always() && (steps.native-compile.outcome == 'success' || steps.native-compile.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cleanup-transfers native-compile"),
    );
    Value::Mapping(values)
}

fn node_545() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("native-compile-native-tests-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.native-compile.outputs.native-tests-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_546());
    Value::Mapping(values)
}

fn node_546() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.native-compile.outputs.native-tests-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.native-compile.outputs.native-tests-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_543() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("native-compile-native-tests-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.native-compile.outputs.native-tests-complete-save == 'true' && steps.native-compile-native-tests-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_544());
    Value::Mapping(values)
}

fn node_544() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.native-compile.outputs.native-tests-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.native-compile.outputs.native-tests-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_541() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("native-compile-native-tests-complete-probe"),
    );
    values.insert(
        text("if"),
        text("!cancelled() && steps.native-compile.outputs.native-tests-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
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
        text("key"),
        text("${{ steps.native-compile.outputs.native-tests-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.native-compile.outputs.native-tests-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_540() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("native-compile"));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci segment native-compile"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("timeout-minutes"), Value::Number(35.into()));
    Value::Mapping(values)
}

fn node_538() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("native-compile-request-native-tests-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.native-compile-request.outputs.native-tests-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_539());
    Value::Mapping(values)
}

fn node_539() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.native-compile-request.outputs.native-tests-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.native-compile-request.outputs.native-tests-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.native-compile-request.outputs.native-tests-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_536() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("native-compile-request-native-tests-complete-restore"),
    );
    values.insert(
        text("if"),
        text("steps.native-compile-request.outputs.native-tests-complete-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_537());
    Value::Mapping(values)
}

fn node_537() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.native-compile-request.outputs.native-tests-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.native-compile-request.outputs.native-tests-complete-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.native-compile-request.outputs.native-tests-complete-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_535() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("native-compile-request"));
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cache-requests native-compile"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    Value::Mapping(values)
}

fn node_534() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-windows-cleanup"));
    values.insert(text("if"), text("always() && (steps.workspace-fetch-windows.outcome == 'success' || steps.workspace-fetch-windows.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers workspace-fetch"),
    );
    Value::Mapping(values)
}

fn node_532() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("workspace-fetch-windows-index-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.workspace-fetch-windows.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("key"),
        text("${{ steps.workspace-fetch-windows.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch-windows.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_530() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("workspace-fetch-windows-archives-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.workspace-fetch-windows.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_531());
    Value::Mapping(values)
}

fn node_531() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch-windows.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch-windows.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_528() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("workspace-fetch-windows-source-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.workspace-fetch-windows.outputs.source-complete-save == 'true' && steps.workspace-fetch-windows-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.workspace-fetch-windows.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch-windows.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_526() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("workspace-fetch-windows-source-complete-probe"),
    );
    values.insert(
        text("if"),
        text(
            "!cancelled() && steps.workspace-fetch-windows.outputs.source-complete-save == 'true'",
        ),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
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
        text("${{ steps.workspace-fetch-windows.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch-windows.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_525() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-windows"));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci.exe ci segment workspace-fetch"),
    );
    values.insert(text("if"), text("runner.os == 'Windows'"));
    values.insert(text("timeout-minutes"), Value::Number(25.into()));
    Value::Mapping(values)
}

fn node_523() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("workspace-fetch-windows-request-index-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.workspace-fetch-windows-request.outputs.index-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_524());
    Value::Mapping(values)
}

fn node_524() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch-windows-request.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch-windows-request.outputs.index-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-fetch-windows-request.outputs.index-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_521() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("workspace-fetch-windows-request-archives-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.workspace-fetch-windows-request.outputs.archives-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_522());
    Value::Mapping(values)
}

fn node_522() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch-windows-request.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch-windows-request.outputs.archives-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-fetch-windows-request.outputs.archives-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_519() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("workspace-fetch-windows-request-source-restore"),
    );
    values.insert(
        text("if"),
        text("steps.workspace-fetch-windows-request.outputs.source-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_520());
    Value::Mapping(values)
}

fn node_520() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch-windows-request.outputs.source-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch-windows-request.outputs.source-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-fetch-windows-request.outputs.source-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_518() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-windows-request"));
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci.exe ci cache-requests workspace-fetch"),
    );
    values.insert(text("if"), text("runner.os == 'Windows'"));
    Value::Mapping(values)
}

fn node_517() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-cleanup"));
    values.insert(text("if"), text("always() && (steps.workspace-fetch.outcome == 'success' || steps.workspace-fetch.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cleanup-transfers workspace-fetch"),
    );
    Value::Mapping(values)
}

fn node_515() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-index-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.workspace-fetch.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_516());
    Value::Mapping(values)
}

fn node_516() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_513() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-archives-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.workspace-fetch.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_514());
    Value::Mapping(values)
}

fn node_514() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_511() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-source-complete-save"));
    values.insert(text("if"), text("always() && steps.workspace-fetch.outputs.source-complete-save == 'true' && steps.workspace-fetch-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_512());
    Value::Mapping(values)
}

fn node_512() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_509() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-source-complete-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.workspace-fetch.outputs.source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_510());
    Value::Mapping(values)
}

fn node_510() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_508() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci segment workspace-fetch"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("timeout-minutes"), Value::Number(25.into()));
    Value::Mapping(values)
}

fn node_506() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("workspace-fetch-request-index-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.workspace-fetch-request.outputs.index-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_507());
    Value::Mapping(values)
}

fn node_507() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch-request.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch-request.outputs.index-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-fetch-request.outputs.index-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_504() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("workspace-fetch-request-archives-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.workspace-fetch-request.outputs.archives-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.workspace-fetch-request.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch-request.outputs.archives-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-fetch-request.outputs.archives-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_502() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-request-source-restore"));
    values.insert(
        text("if"),
        text("steps.workspace-fetch-request.outputs.source-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_503());
    Value::Mapping(values)
}

fn node_503() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch-request.outputs.source-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch-request.outputs.source-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-fetch-request.outputs.source-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_501() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-request"));
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cache-requests workspace-fetch"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    Value::Mapping(values)
}

fn node_500() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-workflows-check-windows"));
    values.insert(text("if"), text("runner.os == 'Windows'"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci.exe ci workflows --check"),
    );
    Value::Mapping(values)
}

fn node_499() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-cleanup-windows"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt-windows.outcome == 'success'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci.exe ci driver-cleanup"),
    );
    Value::Mapping(values)
}

fn node_497() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-cold-adopt-windows-index-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt-windows.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_498());
    Value::Mapping(values)
}

fn node_498() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt-windows.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt-windows.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_495() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-cold-adopt-windows-archives-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt-windows.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_496());
    Value::Mapping(values)
}

fn node_496() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt-windows.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt-windows.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_493() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-cold-adopt-windows-source-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-cold-adopt-windows.outputs.source-complete-save == 'true' && steps.driver-cold-adopt-windows-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_494());
    Value::Mapping(values)
}

fn node_494() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt-windows.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt-windows.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_491() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-cold-adopt-windows-source-complete-probe"),
    );
    values.insert(text("if"), text("!cancelled() && steps.driver-cold-adopt-windows.outputs.source-complete-save == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_492());
    Value::Mapping(values)
}

fn node_492() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt-windows.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt-windows.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_489() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-windows-bootstrap-save"));
    values.insert(text("if"), text("always() && steps.driver-cold-adopt-windows.outputs.bootstrap-save == 'true' && steps.driver-cold-adopt-windows-bootstrap-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_490());
    Value::Mapping(values)
}

fn node_490() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt-windows.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt-windows.outputs.bootstrap-path }}"),
    );
    Value::Mapping(values)
}

fn node_487() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-cold-adopt-windows-bootstrap-probe"),
    );
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-cold-adopt-windows.outputs.bootstrap-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_488());
    Value::Mapping(values)
}

fn node_488() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt-windows.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt-windows.outputs.bootstrap-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_486() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-windows"));
    values.insert(
        text("if"),
        text("steps.driver-cold-build-windows.outcome == 'success'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    values.insert(
        text("run"),
        text("./target/ci-driver-cold/release/memcordon-ci.exe ci driver-adopt-cold"),
    );
    Value::Mapping(values)
}

fn node_485() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-build-windows"));
    values.insert(text("if"), text("runner.os == 'Windows' && steps.driver-bootstrap-windows.outputs.bootstrap-ready != 'true'"));
    values.insert(text("timeout-minutes"), Value::Number(30.into()));
    values.insert(text("run"), text("rustup run 1.97.1 cargo build --locked --release --target-dir target/ci-driver-cold -p memcordon-ci --bin memcordon-ci"));
    Value::Mapping(values)
}

fn node_484() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-cleanup-windows"));
    values.insert(text("if"), text("always() && (steps.driver-managed-build-windows.outcome == 'success' || steps.driver-managed-build-windows.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci.exe ci driver-cleanup"),
    );
    Value::Mapping(values)
}

fn node_482() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-windows-index-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build-windows.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_483());
    Value::Mapping(values)
}

fn node_483() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build-windows.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build-windows.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_480() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-windows-archives-partial-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-managed-build-windows.outputs.archives-partial-save == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.driver-managed-build-windows.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build-windows.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_478() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-windows-source-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-managed-build-windows.outputs.source-complete-save == 'true' && steps.driver-managed-build-windows-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_479());
    Value::Mapping(values)
}

fn node_479() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build-windows.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build-windows.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_476() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-windows-source-complete-probe"),
    );
    values.insert(text("if"), text("!cancelled() && steps.driver-managed-build-windows.outputs.source-complete-save == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_477());
    Value::Mapping(values)
}

fn node_477() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build-windows.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build-windows.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_474() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-windows-compiled-partial-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-managed-build-windows.outputs.compiled-partial-save == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.driver-managed-build-windows.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build-windows.outputs.compiled-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_472() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-windows-compiled-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-managed-build-windows.outputs.compiled-complete-save == 'true' && steps.driver-managed-build-windows-compiled-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_473());
    Value::Mapping(values)
}

fn node_473() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build-windows.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build-windows.outputs.compiled-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_470() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-windows-compiled-complete-probe"),
    );
    values.insert(text("if"), text("!cancelled() && steps.driver-managed-build-windows.outputs.compiled-complete-save == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_471());
    Value::Mapping(values)
}

fn node_471() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build-windows.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build-windows.outputs.compiled-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_468() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-windows-image-save"));
    values.insert(text("if"), text("always() && steps.driver-managed-build-windows.outputs.image-save == 'true' && steps.driver-managed-build-windows-image-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_469());
    Value::Mapping(values)
}

fn node_469() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build-windows.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build-windows.outputs.image-path }}"),
    );
    Value::Mapping(values)
}

fn node_466() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-windows-image-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build-windows.outputs.image-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_467());
    Value::Mapping(values)
}

fn node_467() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build-windows.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build-windows.outputs.image-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_464() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-windows-bootstrap-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-managed-build-windows.outputs.bootstrap-save == 'true' && steps.driver-managed-build-windows-bootstrap-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_465());
    Value::Mapping(values)
}

fn node_465() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build-windows.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build-windows.outputs.bootstrap-path }}"),
    );
    Value::Mapping(values)
}

fn node_462() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-windows-bootstrap-probe"),
    );
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build-windows.outputs.bootstrap-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_463());
    Value::Mapping(values)
}

fn node_463() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build-windows.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build-windows.outputs.bootstrap-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_461() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-windows"));
    values.insert(
        text("if"),
        text("steps.driver-selection-windows.outputs.build-required == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(50.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci.exe ci driver-build"),
    );
    Value::Mapping(values)
}

fn node_459() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-context-windows-compiled-partial-restore"),
    );
    values.insert(text("if"), text("steps.driver-selection-windows.outputs.build-required == 'true' && steps.driver-context-windows.outputs.compiled-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_460());
    Value::Mapping(values)
}

fn node_460() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context-windows.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context-windows.outputs.compiled-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context-windows.outputs.compiled-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_457() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-context-windows-compiled-complete-restore"),
    );
    values.insert(text("if"), text("steps.driver-selection-windows.outputs.build-required == 'true' && steps.driver-context-windows.outputs.compiled-complete-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_458());
    Value::Mapping(values)
}

fn node_458() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context-windows.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context-windows.outputs.compiled-complete-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context-windows.outputs.compiled-complete-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_455() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-context-windows-index-partial-restore"),
    );
    values.insert(text("if"), text("steps.driver-selection-windows.outputs.build-required == 'true' && steps.driver-context-windows.outputs.index-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_456());
    Value::Mapping(values)
}

fn node_456() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context-windows.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context-windows.outputs.index-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context-windows.outputs.index-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_453() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-context-windows-archives-partial-restore"),
    );
    values.insert(text("if"), text("steps.driver-selection-windows.outputs.build-required == 'true' && steps.driver-context-windows.outputs.archives-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("key"),
        text("${{ steps.driver-context-windows.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context-windows.outputs.archives-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context-windows.outputs.archives-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_451() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-windows-source-restore"));
    values.insert(text("if"), text("steps.driver-selection-windows.outputs.build-required == 'true' && steps.driver-context-windows.outputs.source-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_452());
    Value::Mapping(values)
}

fn node_452() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context-windows.outputs.source-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context-windows.outputs.source-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context-windows.outputs.source-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_450() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-selection-windows"));
    values.insert(
        text("if"),
        text("steps.driver-bootstrap-windows.outputs.bootstrap-ready == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(4.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci.exe ci driver-select"),
    );
    Value::Mapping(values)
}

fn node_448() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-windows-image-restore"));
    values.insert(
        text("if"),
        text("steps.driver-context-windows.outputs.image-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_449());
    Value::Mapping(values)
}

fn node_449() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context-windows.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context-windows.outputs.image-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context-windows.outputs.image-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_447() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-windows"));
    values.insert(
        text("if"),
        text("steps.driver-bootstrap-windows.outputs.bootstrap-ready == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci.exe ci driver-context"),
    );
    Value::Mapping(values)
}

fn node_446() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-bootstrap-windows"));
    values.insert(text("if"), text("runner.os == 'Windows' && steps.driver-bootstrap-cache-windows.outcome == 'success' && steps.driver-bootstrap-cache-windows.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-bootstrap-in/memcordon-ci.exe ci driver-bootstrap"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_444() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-bootstrap-cache-windows"));
    values.insert(text("if"), text("runner.os == 'Windows'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_445());
    Value::Mapping(values)
}

fn node_445() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-bootstrap-in"));
    values.insert(text("key"), text("mc-ci-bootstrap-v3-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/driver-bootstrap.toml', 'ci/toolchains.toml') }}-lookup"));
    values.insert(text("restore-keys"), text("mc-ci-bootstrap-v3-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/driver-bootstrap.toml', 'ci/toolchains.toml') }}-"));
    Value::Mapping(values)
}

fn node_443() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-workflows-check"));
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci workflows --check"),
    );
    Value::Mapping(values)
}

fn node_442() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-cleanup"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt.outcome == 'success'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci driver-cleanup"),
    );
    Value::Mapping(values)
}

fn node_440() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-index-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_441());
    Value::Mapping(values)
}

fn node_441() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_438() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-archives-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_439());
    Value::Mapping(values)
}

fn node_439() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_436() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-source-complete-save"));
    values.insert(text("if"), text("always() && steps.driver-cold-adopt.outputs.source-complete-save == 'true' && steps.driver-cold-adopt-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_437());
    Value::Mapping(values)
}

fn node_437() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_434() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-source-complete-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-cold-adopt.outputs.source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_435());
    Value::Mapping(values)
}

fn node_435() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_432() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-bootstrap-save"));
    values.insert(text("if"), text("always() && steps.driver-cold-adopt.outputs.bootstrap-save == 'true' && steps.driver-cold-adopt-bootstrap-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_433());
    Value::Mapping(values)
}

fn node_433() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-path }}"),
    );
    Value::Mapping(values)
}

fn node_430() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-bootstrap-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-cold-adopt.outputs.bootstrap-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_431());
    Value::Mapping(values)
}

fn node_431() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_429() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt"));
    values.insert(
        text("if"),
        text("steps.driver-cold-build.outcome == 'success'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    values.insert(
        text("run"),
        text("./target/ci-driver-cold/release/memcordon-ci ci driver-adopt-cold"),
    );
    Value::Mapping(values)
}

fn node_428() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-build"));
    values.insert(
        text("if"),
        text("runner.os != 'Windows' && steps.driver-bootstrap.outputs.bootstrap-ready != 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(30.into()));
    values.insert(text("run"), text("rustup run 1.97.1 cargo build --locked --release --target-dir target/ci-driver-cold -p memcordon-ci --bin memcordon-ci"));
    Value::Mapping(values)
}

fn node_427() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-cleanup"));
    values.insert(text("if"), text("always() && (steps.driver-managed-build.outcome == 'success' || steps.driver-managed-build.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-cleanup"),
    );
    Value::Mapping(values)
}

fn node_425() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-index-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_426());
    Value::Mapping(values)
}

fn node_426() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_423() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-archives-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.driver-managed-build.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_421() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-source-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.source-complete-save == 'true' && steps.driver-managed-build-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_422());
    Value::Mapping(values)
}

fn node_422() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_419() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-source-complete-probe"),
    );
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_420());
    Value::Mapping(values)
}

fn node_420() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_417() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-compiled-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build.outputs.compiled-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("key"),
        text("${{ steps.driver-managed-build.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.compiled-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_415() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-compiled-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.compiled-complete-save == 'true' && steps.driver-managed-build-compiled-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_416());
    Value::Mapping(values)
}

fn node_416() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_413() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-compiled-complete-probe"),
    );
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.compiled-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_414());
    Value::Mapping(values)
}

fn node_414() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_411() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-image-save"));
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.image-save == 'true' && steps.driver-managed-build-image-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_412());
    Value::Mapping(values)
}

fn node_412() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.image-path }}"),
    );
    Value::Mapping(values)
}

fn node_409() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-image-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.image-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
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
        text("key"),
        text("${{ steps.driver-managed-build.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.image-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_407() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-bootstrap-save"));
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.bootstrap-save == 'true' && steps.driver-managed-build-bootstrap-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_408());
    Value::Mapping(values)
}

fn node_408() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-path }}"),
    );
    Value::Mapping(values)
}

fn node_405() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-bootstrap-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.bootstrap-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_406());
    Value::Mapping(values)
}

fn node_406() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_404() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build"));
    values.insert(
        text("if"),
        text("steps.driver-selection.outputs.build-required == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(50.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-build"),
    );
    Value::Mapping(values)
}

fn node_402() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-compiled-partial-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.compiled-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.driver-context.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.compiled-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.compiled-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_400() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-compiled-complete-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.compiled-complete-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.driver-context.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.compiled-complete-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.compiled-complete-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_398() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-index-partial-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.index-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_399());
    Value::Mapping(values)
}

fn node_399() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.index-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.index-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_396() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-archives-partial-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.archives-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_397());
    Value::Mapping(values)
}

fn node_397() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.archives-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.archives-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_394() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-source-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.source-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.driver-context.outputs.source-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.source-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.source-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_393() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-selection"));
    values.insert(
        text("if"),
        text("steps.driver-bootstrap.outputs.bootstrap-ready == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(4.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-select"),
    );
    Value::Mapping(values)
}

fn node_391() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-image-restore"));
    values.insert(
        text("if"),
        text("steps.driver-context.outputs.image-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("key"),
        text("${{ steps.driver-context.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.image-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.image-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_390() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context"));
    values.insert(
        text("if"),
        text("steps.driver-bootstrap.outputs.bootstrap-ready == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-context"),
    );
    Value::Mapping(values)
}

fn node_389() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-bootstrap"));
    values.insert(text("if"), text("runner.os != 'Windows' && steps.driver-bootstrap-cache.outcome == 'success' && steps.driver-bootstrap-cache.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-bootstrap-in/memcordon-ci ci driver-bootstrap"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_387() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-bootstrap-cache"));
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_388());
    Value::Mapping(values)
}

fn node_388() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-bootstrap-in"));
    values.insert(text("key"), text("mc-ci-bootstrap-v3-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/driver-bootstrap.toml', 'ci/toolchains.toml') }}-lookup"));
    values.insert(text("restore-keys"), text("mc-ci-bootstrap-v3-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/driver-bootstrap.toml', 'ci/toolchains.toml') }}-"));
    Value::Mapping(values)
}

fn node_385() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("public-source-seed-restore"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(text("with"), node_386());
    Value::Mapping(values)
}

fn node_386() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-cargo-home/registry/cache/index.crates.io-1949cf8c6b5b557f/*.crate\ntarget/ci-cargo-home/registry/cache/index.crates.io-6f17d22bba15001f/*.crate\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/.cache\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/config.json"));
    values.insert(text("key"), text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-${{ hashFiles('Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', 'tools/*/Cargo.toml', '.cargo/**') }}"));
    values.insert(
        text("restore-keys"),
        text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-"),
    );
    Value::Mapping(values)
}

fn node_384() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("name"),
        text("Initialize genuine auxiliary Cargo target"),
    );
    values.insert(
        text("run"),
        text("rustup run 1.97.1 cargo clean --locked --package memcordon-ci --target-dir target"),
    );
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    Value::Mapping(values)
}

fn node_383() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Install pinned Rust"));
    values.insert(
        text("run"),
        text("rustup toolchain install 1.97.1 --profile minimal"),
    );
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    Value::Mapping(values)
}

fn node_381() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Check out repository"));
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_382());
    values.insert(text("timeout-minutes"), Value::Number(6.into()));
    Value::Mapping(values)
}

fn node_382() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_380() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Configure checkout line endings"));
    values.insert(text("run"), text("git config --global core.autocrlf false"));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    Value::Mapping(values)
}

fn node_370() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("fail-fast"), Value::Bool(false));
    values.insert(text("matrix"), node_371());
    Value::Mapping(values)
}

fn node_371() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("include"), node_372());
    Value::Mapping(values)
}

fn node_372() -> Value {
    let mut values = Vec::new();
    values.push(node_373());
    values.push(node_374());
    values.push(node_375());
    values.push(node_376());
    values.push(node_377());
    values.push(node_378());
    Value::Sequence(values)
}

fn node_378() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("windows-arm64"));
    values.insert(text("runner"), text("windows-11-arm"));
    Value::Mapping(values)
}

fn node_377() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("windows-x64"));
    values.insert(text("runner"), text("windows-2025"));
    Value::Mapping(values)
}

fn node_376() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("macos-x64"));
    values.insert(text("runner"), text("macos-15-intel"));
    Value::Mapping(values)
}

fn node_375() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("macos-arm64"));
    values.insert(text("runner"), text("macos-15"));
    Value::Mapping(values)
}

fn node_374() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("linux-arm64"));
    values.insert(text("runner"), text("ubuntu-24.04-arm"));
    Value::Mapping(values)
}

fn node_373() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("linux-x64"));
    values.insert(text("runner"), text("ubuntu-24.04"));
    Value::Mapping(values)
}

fn node_273() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("github.event_name != 'push'"));
    values.insert(text("name"), text("quality / documentation"));
    values.insert(text("runs-on"), text("ubuntu-24.04"));
    values.insert(text("timeout-minutes"), Value::Number(279.into()));
    values.insert(text("steps"), node_274());
    values.insert(text("env"), node_368());
    Value::Mapping(values)
}

fn node_368() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("CARGO_HOME"),
        text("${{ github.workspace }}/target/ci-cargo-home"),
    );
    Value::Mapping(values)
}

fn node_274() -> Value {
    let mut values = Vec::new();
    values.push(node_275());
    values.push(node_276());
    values.push(node_278());
    values.push(node_279());
    values.push(node_281());
    values.push(node_283());
    values.push(node_284());
    values.push(node_285());
    values.push(node_287());
    values.push(node_288());
    values.push(node_290());
    values.push(node_292());
    values.push(node_294());
    values.push(node_296());
    values.push(node_298());
    values.push(node_299());
    values.push(node_301());
    values.push(node_303());
    values.push(node_305());
    values.push(node_307());
    values.push(node_309());
    values.push(node_311());
    values.push(node_313());
    values.push(node_315());
    values.push(node_317());
    values.push(node_319());
    values.push(node_321());
    values.push(node_322());
    values.push(node_323());
    values.push(node_324());
    values.push(node_326());
    values.push(node_328());
    values.push(node_330());
    values.push(node_332());
    values.push(node_334());
    values.push(node_336());
    values.push(node_337());
    values.push(node_338());
    values.push(node_339());
    values.push(node_341());
    values.push(node_343());
    values.push(node_345());
    values.push(node_346());
    values.push(node_348());
    values.push(node_350());
    values.push(node_352());
    values.push(node_354());
    values.push(node_355());
    values.push(node_356());
    values.push(node_358());
    values.push(node_360());
    values.push(node_361());
    values.push(node_363());
    values.push(node_365());
    values.push(node_367());
    Value::Sequence(values)
}

fn node_367() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("quality-run-cleanup"));
    values.insert(text("if"), text("always() && (steps.quality-run.outcome == 'success' || steps.quality-run.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cleanup-transfers quality-documentation"),
    );
    Value::Mapping(values)
}

fn node_365() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("quality-run-compiled-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.quality-run.outputs.compiled-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_366());
    Value::Mapping(values)
}

fn node_366() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.quality-run.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.quality-run.outputs.compiled-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_363() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("quality-run-compiled-complete-save"));
    values.insert(text("if"), text("always() && steps.quality-run.outputs.compiled-complete-save == 'true' && steps.quality-run-compiled-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_364());
    Value::Mapping(values)
}

fn node_364() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.quality-run.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.quality-run.outputs.compiled-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_361() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("quality-run-compiled-complete-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.quality-run.outputs.compiled-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
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
        text("${{ steps.quality-run.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.quality-run.outputs.compiled-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_360() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Run quality suite"));
    values.insert(text("id"), text("quality-run"));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci segment quality-documentation"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("timeout-minutes"), Value::Number(100.into()));
    Value::Mapping(values)
}

fn node_358() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("quality-run-request-compiled-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.quality-run-request.outputs.compiled-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.quality-run-request.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.quality-run-request.outputs.compiled-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.quality-run-request.outputs.compiled-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_356() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("quality-run-request-compiled-complete-restore"),
    );
    values.insert(
        text("if"),
        text("steps.quality-run-request.outputs.compiled-complete-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_357());
    Value::Mapping(values)
}

fn node_357() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.quality-run-request.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.quality-run-request.outputs.compiled-complete-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.quality-run-request.outputs.compiled-complete-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_355() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("quality-run-request"));
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cache-requests quality-documentation"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    Value::Mapping(values)
}

fn node_354() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-cleanup"));
    values.insert(text("if"), text("always() && (steps.workspace-fetch.outcome == 'success' || steps.workspace-fetch.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cleanup-transfers workspace-fetch"),
    );
    Value::Mapping(values)
}

fn node_352() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-index-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.workspace-fetch.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_353());
    Value::Mapping(values)
}

fn node_353() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_350() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-archives-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.workspace-fetch.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_351());
    Value::Mapping(values)
}

fn node_351() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_348() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-source-complete-save"));
    values.insert(text("if"), text("always() && steps.workspace-fetch.outputs.source-complete-save == 'true' && steps.workspace-fetch-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_349());
    Value::Mapping(values)
}

fn node_349() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_346() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-source-complete-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.workspace-fetch.outputs.source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_347());
    Value::Mapping(values)
}

fn node_347() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_345() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci segment workspace-fetch"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("timeout-minutes"), Value::Number(25.into()));
    Value::Mapping(values)
}

fn node_343() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("workspace-fetch-request-index-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.workspace-fetch-request.outputs.index-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_344());
    Value::Mapping(values)
}

fn node_344() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch-request.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch-request.outputs.index-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-fetch-request.outputs.index-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_341() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("workspace-fetch-request-archives-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.workspace-fetch-request.outputs.archives-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_342());
    Value::Mapping(values)
}

fn node_342() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch-request.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch-request.outputs.archives-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-fetch-request.outputs.archives-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_339() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-request-source-restore"));
    values.insert(
        text("if"),
        text("steps.workspace-fetch-request.outputs.source-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.workspace-fetch-request.outputs.source-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch-request.outputs.source-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-fetch-request.outputs.source-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_338() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-request"));
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cache-requests workspace-fetch"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    Value::Mapping(values)
}

fn node_337() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-workflows-check"));
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci workflows --check"),
    );
    Value::Mapping(values)
}

fn node_336() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-cleanup"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt.outcome == 'success'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci driver-cleanup"),
    );
    Value::Mapping(values)
}

fn node_334() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-index-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_332() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-archives-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_333());
    Value::Mapping(values)
}

fn node_333() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_330() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-source-complete-save"));
    values.insert(text("if"), text("always() && steps.driver-cold-adopt.outputs.source-complete-save == 'true' && steps.driver-cold-adopt-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_331());
    Value::Mapping(values)
}

fn node_331() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_328() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-source-complete-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-cold-adopt.outputs.source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_329());
    Value::Mapping(values)
}

fn node_329() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_326() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-bootstrap-save"));
    values.insert(text("if"), text("always() && steps.driver-cold-adopt.outputs.bootstrap-save == 'true' && steps.driver-cold-adopt-bootstrap-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_327());
    Value::Mapping(values)
}

fn node_327() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-path }}"),
    );
    Value::Mapping(values)
}

fn node_324() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-bootstrap-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-cold-adopt.outputs.bootstrap-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_325());
    Value::Mapping(values)
}

fn node_325() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_323() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt"));
    values.insert(
        text("if"),
        text("steps.driver-cold-build.outcome == 'success'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    values.insert(
        text("run"),
        text("./target/ci-driver-cold/release/memcordon-ci ci driver-adopt-cold"),
    );
    Value::Mapping(values)
}

fn node_322() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-build"));
    values.insert(
        text("if"),
        text("runner.os != 'Windows' && steps.driver-bootstrap.outputs.bootstrap-ready != 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(30.into()));
    values.insert(text("run"), text("rustup run 1.97.1 cargo build --locked --release --target-dir target/ci-driver-cold -p memcordon-ci --bin memcordon-ci"));
    Value::Mapping(values)
}

fn node_321() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-cleanup"));
    values.insert(text("if"), text("always() && (steps.driver-managed-build.outcome == 'success' || steps.driver-managed-build.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-cleanup"),
    );
    Value::Mapping(values)
}

fn node_319() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-index-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("key"),
        text("${{ steps.driver-managed-build.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_317() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-archives-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_318());
    Value::Mapping(values)
}

fn node_318() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_315() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-source-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.source-complete-save == 'true' && steps.driver-managed-build-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_316());
    Value::Mapping(values)
}

fn node_316() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_313() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-source-complete-probe"),
    );
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_314());
    Value::Mapping(values)
}

fn node_314() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_311() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-compiled-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build.outputs.compiled-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_312());
    Value::Mapping(values)
}

fn node_312() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.compiled-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_309() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-compiled-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.compiled-complete-save == 'true' && steps.driver-managed-build-compiled-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_310());
    Value::Mapping(values)
}

fn node_310() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_307() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-compiled-complete-probe"),
    );
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.compiled-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_308());
    Value::Mapping(values)
}

fn node_308() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_305() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-image-save"));
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.image-save == 'true' && steps.driver-managed-build-image-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_306());
    Value::Mapping(values)
}

fn node_306() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.image-path }}"),
    );
    Value::Mapping(values)
}

fn node_303() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-image-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.image-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
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
        text("key"),
        text("${{ steps.driver-managed-build.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.image-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_301() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-bootstrap-save"));
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.bootstrap-save == 'true' && steps.driver-managed-build-bootstrap-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("key"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-path }}"),
    );
    Value::Mapping(values)
}

fn node_299() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-bootstrap-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.bootstrap-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_300());
    Value::Mapping(values)
}

fn node_300() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_298() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build"));
    values.insert(
        text("if"),
        text("steps.driver-selection.outputs.build-required == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(50.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-build"),
    );
    Value::Mapping(values)
}

fn node_296() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-compiled-partial-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.compiled-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_297());
    Value::Mapping(values)
}

fn node_297() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.compiled-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.compiled-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_294() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-compiled-complete-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.compiled-complete-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.driver-context.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.compiled-complete-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.compiled-complete-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_292() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-index-partial-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.index-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_293());
    Value::Mapping(values)
}

fn node_293() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.index-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.index-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_290() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-archives-partial-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.archives-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_291());
    Value::Mapping(values)
}

fn node_291() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.archives-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.archives-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_288() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-source-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.source-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("key"),
        text("${{ steps.driver-context.outputs.source-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.source-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.source-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_287() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-selection"));
    values.insert(
        text("if"),
        text("steps.driver-bootstrap.outputs.bootstrap-ready == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(4.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-select"),
    );
    Value::Mapping(values)
}

fn node_285() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-image-restore"));
    values.insert(
        text("if"),
        text("steps.driver-context.outputs.image-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_286());
    Value::Mapping(values)
}

fn node_286() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.image-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.image-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_284() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context"));
    values.insert(
        text("if"),
        text("steps.driver-bootstrap.outputs.bootstrap-ready == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-context"),
    );
    Value::Mapping(values)
}

fn node_283() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-bootstrap"));
    values.insert(text("if"), text("runner.os != 'Windows' && steps.driver-bootstrap-cache.outcome == 'success' && steps.driver-bootstrap-cache.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-bootstrap-in/memcordon-ci ci driver-bootstrap"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_281() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-bootstrap-cache"));
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_282());
    Value::Mapping(values)
}

fn node_282() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-bootstrap-in"));
    values.insert(text("key"), text("mc-ci-bootstrap-v3-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/driver-bootstrap.toml', 'ci/toolchains.toml') }}-lookup"));
    values.insert(text("restore-keys"), text("mc-ci-bootstrap-v3-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/driver-bootstrap.toml', 'ci/toolchains.toml') }}-"));
    Value::Mapping(values)
}

fn node_279() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("public-source-seed-restore"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(text("with"), node_280());
    Value::Mapping(values)
}

fn node_280() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-cargo-home/registry/cache/index.crates.io-1949cf8c6b5b557f/*.crate\ntarget/ci-cargo-home/registry/cache/index.crates.io-6f17d22bba15001f/*.crate\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/.cache\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/config.json"));
    values.insert(text("key"), text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-${{ hashFiles('Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', 'tools/*/Cargo.toml', '.cargo/**') }}"));
    values.insert(
        text("restore-keys"),
        text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-"),
    );
    Value::Mapping(values)
}

fn node_278() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Install quality Rust"));
    values.insert(text("run"), text("rustup toolchain install 1.97.1 --profile minimal --component clippy --component rustfmt"));
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    Value::Mapping(values)
}

fn node_276() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Check out repository"));
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_277());
    values.insert(text("timeout-minutes"), Value::Number(6.into()));
    Value::Mapping(values)
}

fn node_277() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_275() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Configure checkout line endings"));
    values.insert(text("run"), text("git config --global core.autocrlf false"));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    Value::Mapping(values)
}

fn node_176() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("github.event_name != 'push'"));
    values.insert(text("name"), text("MSRV 1.85.0"));
    values.insert(text("runs-on"), text("ubuntu-24.04"));
    values.insert(text("timeout-minutes"), Value::Number(294.into()));
    values.insert(text("steps"), node_177());
    values.insert(text("env"), node_272());
    Value::Mapping(values)
}

fn node_272() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("CARGO_HOME"),
        text("${{ github.workspace }}/target/ci-cargo-home"),
    );
    Value::Mapping(values)
}

fn node_177() -> Value {
    let mut values = Vec::new();
    values.push(node_178());
    values.push(node_179());
    values.push(node_181());
    values.push(node_182());
    values.push(node_183());
    values.push(node_185());
    values.push(node_187());
    values.push(node_188());
    values.push(node_189());
    values.push(node_191());
    values.push(node_192());
    values.push(node_194());
    values.push(node_196());
    values.push(node_198());
    values.push(node_200());
    values.push(node_202());
    values.push(node_203());
    values.push(node_205());
    values.push(node_207());
    values.push(node_209());
    values.push(node_211());
    values.push(node_213());
    values.push(node_215());
    values.push(node_217());
    values.push(node_219());
    values.push(node_221());
    values.push(node_223());
    values.push(node_225());
    values.push(node_226());
    values.push(node_227());
    values.push(node_228());
    values.push(node_230());
    values.push(node_232());
    values.push(node_234());
    values.push(node_236());
    values.push(node_238());
    values.push(node_240());
    values.push(node_241());
    values.push(node_242());
    values.push(node_243());
    values.push(node_245());
    values.push(node_247());
    values.push(node_249());
    values.push(node_250());
    values.push(node_252());
    values.push(node_254());
    values.push(node_256());
    values.push(node_258());
    values.push(node_259());
    values.push(node_260());
    values.push(node_262());
    values.push(node_264());
    values.push(node_265());
    values.push(node_267());
    values.push(node_269());
    values.push(node_271());
    Value::Sequence(values)
}

fn node_271() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("msrv-run-cleanup"));
    values.insert(text("if"), text("always() && (steps.msrv-run.outcome == 'success' || steps.msrv-run.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cleanup-transfers msrv"),
    );
    Value::Mapping(values)
}

fn node_269() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("msrv-run-compiled-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.msrv-run.outputs.compiled-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_270());
    Value::Mapping(values)
}

fn node_270() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.msrv-run.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.msrv-run.outputs.compiled-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_267() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("msrv-run-compiled-complete-save"));
    values.insert(text("if"), text("always() && steps.msrv-run.outputs.compiled-complete-save == 'true' && steps.msrv-run-compiled-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_268());
    Value::Mapping(values)
}

fn node_268() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.msrv-run.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.msrv-run.outputs.compiled-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_265() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("msrv-run-compiled-complete-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.msrv-run.outputs.compiled-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
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
        text("key"),
        text("${{ steps.msrv-run.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.msrv-run.outputs.compiled-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_264() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Run MSRV suite"));
    values.insert(text("id"), text("msrv-run"));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci segment msrv"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("timeout-minutes"), Value::Number(100.into()));
    Value::Mapping(values)
}

fn node_262() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("msrv-run-request-compiled-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.msrv-run-request.outputs.compiled-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_263());
    Value::Mapping(values)
}

fn node_263() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.msrv-run-request.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.msrv-run-request.outputs.compiled-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.msrv-run-request.outputs.compiled-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_260() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("msrv-run-request-compiled-complete-restore"),
    );
    values.insert(
        text("if"),
        text("steps.msrv-run-request.outputs.compiled-complete-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_261());
    Value::Mapping(values)
}

fn node_261() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.msrv-run-request.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.msrv-run-request.outputs.compiled-complete-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.msrv-run-request.outputs.compiled-complete-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_259() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("msrv-run-request"));
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cache-requests msrv"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    Value::Mapping(values)
}

fn node_258() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-cleanup"));
    values.insert(text("if"), text("always() && (steps.workspace-fetch.outcome == 'success' || steps.workspace-fetch.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cleanup-transfers workspace-fetch"),
    );
    Value::Mapping(values)
}

fn node_256() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-index-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.workspace-fetch.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_257());
    Value::Mapping(values)
}

fn node_257() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_254() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-archives-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.workspace-fetch.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_255());
    Value::Mapping(values)
}

fn node_255() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_252() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-source-complete-save"));
    values.insert(text("if"), text("always() && steps.workspace-fetch.outputs.source-complete-save == 'true' && steps.workspace-fetch-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.workspace-fetch.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_250() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-source-complete-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.workspace-fetch.outputs.source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
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
        text("${{ steps.workspace-fetch.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_249() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci segment workspace-fetch"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("timeout-minutes"), Value::Number(25.into()));
    Value::Mapping(values)
}

fn node_247() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("workspace-fetch-request-index-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.workspace-fetch-request.outputs.index-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_248());
    Value::Mapping(values)
}

fn node_248() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch-request.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch-request.outputs.index-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-fetch-request.outputs.index-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_245() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("workspace-fetch-request-archives-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.workspace-fetch-request.outputs.archives-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.workspace-fetch-request.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch-request.outputs.archives-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-fetch-request.outputs.archives-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_243() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-request-source-restore"));
    values.insert(
        text("if"),
        text("steps.workspace-fetch-request.outputs.source-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.workspace-fetch-request.outputs.source-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch-request.outputs.source-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-fetch-request.outputs.source-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_242() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-request"));
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cache-requests workspace-fetch"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    Value::Mapping(values)
}

fn node_241() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-workflows-check"));
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci workflows --check"),
    );
    Value::Mapping(values)
}

fn node_240() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-cleanup"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt.outcome == 'success'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci driver-cleanup"),
    );
    Value::Mapping(values)
}

fn node_238() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-index-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_236() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-archives-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_234() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-source-complete-save"));
    values.insert(text("if"), text("always() && steps.driver-cold-adopt.outputs.source-complete-save == 'true' && steps.driver-cold-adopt-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_235());
    Value::Mapping(values)
}

fn node_235() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_232() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-source-complete-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-cold-adopt.outputs.source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_233());
    Value::Mapping(values)
}

fn node_233() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_230() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-bootstrap-save"));
    values.insert(text("if"), text("always() && steps.driver-cold-adopt.outputs.bootstrap-save == 'true' && steps.driver-cold-adopt-bootstrap-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-path }}"),
    );
    Value::Mapping(values)
}

fn node_228() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-bootstrap-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-cold-adopt.outputs.bootstrap-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_229());
    Value::Mapping(values)
}

fn node_229() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_227() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt"));
    values.insert(
        text("if"),
        text("steps.driver-cold-build.outcome == 'success'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    values.insert(
        text("run"),
        text("./target/ci-driver-cold/release/memcordon-ci ci driver-adopt-cold"),
    );
    Value::Mapping(values)
}

fn node_226() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-build"));
    values.insert(
        text("if"),
        text("runner.os != 'Windows' && steps.driver-bootstrap.outputs.bootstrap-ready != 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(30.into()));
    values.insert(text("run"), text("rustup run 1.97.1 cargo build --locked --release --target-dir target/ci-driver-cold -p memcordon-ci --bin memcordon-ci"));
    Value::Mapping(values)
}

fn node_225() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-cleanup"));
    values.insert(text("if"), text("always() && (steps.driver-managed-build.outcome == 'success' || steps.driver-managed-build.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-cleanup"),
    );
    Value::Mapping(values)
}

fn node_223() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-index-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_224());
    Value::Mapping(values)
}

fn node_224() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_221() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-archives-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_222());
    Value::Mapping(values)
}

fn node_222() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_219() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-source-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.source-complete-save == 'true' && steps.driver-managed-build-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_220());
    Value::Mapping(values)
}

fn node_220() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_217() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-source-complete-probe"),
    );
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
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
        text("${{ steps.driver-managed-build.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_215() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-compiled-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build.outputs.compiled-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_216());
    Value::Mapping(values)
}

fn node_216() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.compiled-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_213() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-compiled-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.compiled-complete-save == 'true' && steps.driver-managed-build-compiled-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_214());
    Value::Mapping(values)
}

fn node_214() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_211() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-compiled-complete-probe"),
    );
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.compiled-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_212());
    Value::Mapping(values)
}

fn node_212() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_209() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-image-save"));
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.image-save == 'true' && steps.driver-managed-build-image-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_210());
    Value::Mapping(values)
}

fn node_210() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.image-path }}"),
    );
    Value::Mapping(values)
}

fn node_207() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-image-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.image-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_208());
    Value::Mapping(values)
}

fn node_208() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.image-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_205() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-bootstrap-save"));
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.bootstrap-save == 'true' && steps.driver-managed-build-bootstrap-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_206());
    Value::Mapping(values)
}

fn node_206() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-path }}"),
    );
    Value::Mapping(values)
}

fn node_203() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-bootstrap-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.bootstrap-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_204());
    Value::Mapping(values)
}

fn node_204() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_202() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build"));
    values.insert(
        text("if"),
        text("steps.driver-selection.outputs.build-required == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(50.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-build"),
    );
    Value::Mapping(values)
}

fn node_200() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-compiled-partial-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.compiled-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_201());
    Value::Mapping(values)
}

fn node_201() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.compiled-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.compiled-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_198() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-compiled-complete-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.compiled-complete-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_199());
    Value::Mapping(values)
}

fn node_199() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.compiled-complete-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.compiled-complete-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_196() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-index-partial-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.index-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_197());
    Value::Mapping(values)
}

fn node_197() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.index-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.index-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_194() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-archives-partial-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.archives-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.driver-context.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.archives-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.archives-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_192() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-source-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.source-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.driver-context.outputs.source-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.source-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.source-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_191() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-selection"));
    values.insert(
        text("if"),
        text("steps.driver-bootstrap.outputs.bootstrap-ready == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(4.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-select"),
    );
    Value::Mapping(values)
}

fn node_189() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-image-restore"));
    values.insert(
        text("if"),
        text("steps.driver-context.outputs.image-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_190());
    Value::Mapping(values)
}

fn node_190() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.image-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.image-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_188() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context"));
    values.insert(
        text("if"),
        text("steps.driver-bootstrap.outputs.bootstrap-ready == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-context"),
    );
    Value::Mapping(values)
}

fn node_187() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-bootstrap"));
    values.insert(text("if"), text("runner.os != 'Windows' && steps.driver-bootstrap-cache.outcome == 'success' && steps.driver-bootstrap-cache.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-bootstrap-in/memcordon-ci ci driver-bootstrap"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_185() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-bootstrap-cache"));
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_186());
    Value::Mapping(values)
}

fn node_186() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-bootstrap-in"));
    values.insert(text("key"), text("mc-ci-bootstrap-v3-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/driver-bootstrap.toml', 'ci/toolchains.toml') }}-lookup"));
    values.insert(text("restore-keys"), text("mc-ci-bootstrap-v3-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/driver-bootstrap.toml', 'ci/toolchains.toml') }}-"));
    Value::Mapping(values)
}

fn node_183() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("public-source-seed-restore"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(text("with"), node_184());
    Value::Mapping(values)
}

fn node_184() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-cargo-home/registry/cache/index.crates.io-1949cf8c6b5b557f/*.crate\ntarget/ci-cargo-home/registry/cache/index.crates.io-6f17d22bba15001f/*.crate\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/.cache\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/config.json"));
    values.insert(text("key"), text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-${{ hashFiles('Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', 'tools/*/Cargo.toml', '.cargo/**') }}"));
    values.insert(
        text("restore-keys"),
        text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-"),
    );
    Value::Mapping(values)
}

fn node_182() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Install declared MSRV"));
    values.insert(
        text("run"),
        text("rustup toolchain install 1.85.0 --profile minimal"),
    );
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    Value::Mapping(values)
}

fn node_181() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Install CI driver Rust"));
    values.insert(
        text("run"),
        text("rustup toolchain install 1.97.1 --profile minimal"),
    );
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    Value::Mapping(values)
}

fn node_179() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Check out repository"));
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_180());
    values.insert(text("timeout-minutes"), Value::Number(6.into()));
    Value::Mapping(values)
}

fn node_180() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_178() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Configure checkout line endings"));
    values.insert(text("run"), text("git config --global core.autocrlf false"));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    Value::Mapping(values)
}

fn node_80() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("github.event_name != 'push'"));
    values.insert(text("name"), text("quality / check and Clippy"));
    values.insert(text("runs-on"), text("ubuntu-24.04"));
    values.insert(text("timeout-minutes"), Value::Number(279.into()));
    values.insert(text("steps"), node_81());
    values.insert(text("env"), node_175());
    Value::Mapping(values)
}

fn node_175() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("CARGO_HOME"),
        text("${{ github.workspace }}/target/ci-cargo-home"),
    );
    Value::Mapping(values)
}

fn node_81() -> Value {
    let mut values = Vec::new();
    values.push(node_82());
    values.push(node_83());
    values.push(node_85());
    values.push(node_86());
    values.push(node_88());
    values.push(node_90());
    values.push(node_91());
    values.push(node_92());
    values.push(node_94());
    values.push(node_95());
    values.push(node_97());
    values.push(node_99());
    values.push(node_101());
    values.push(node_103());
    values.push(node_105());
    values.push(node_106());
    values.push(node_108());
    values.push(node_110());
    values.push(node_112());
    values.push(node_114());
    values.push(node_116());
    values.push(node_118());
    values.push(node_120());
    values.push(node_122());
    values.push(node_124());
    values.push(node_126());
    values.push(node_128());
    values.push(node_129());
    values.push(node_130());
    values.push(node_131());
    values.push(node_133());
    values.push(node_135());
    values.push(node_137());
    values.push(node_139());
    values.push(node_141());
    values.push(node_143());
    values.push(node_144());
    values.push(node_145());
    values.push(node_146());
    values.push(node_148());
    values.push(node_150());
    values.push(node_152());
    values.push(node_153());
    values.push(node_155());
    values.push(node_157());
    values.push(node_159());
    values.push(node_161());
    values.push(node_162());
    values.push(node_163());
    values.push(node_165());
    values.push(node_167());
    values.push(node_168());
    values.push(node_170());
    values.push(node_172());
    values.push(node_174());
    Value::Sequence(values)
}

fn node_174() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("quality-run-cleanup"));
    values.insert(text("if"), text("always() && (steps.quality-run.outcome == 'success' || steps.quality-run.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cleanup-transfers quality-compiler"),
    );
    Value::Mapping(values)
}

fn node_172() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("quality-run-compiled-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.quality-run.outputs.compiled-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_173());
    Value::Mapping(values)
}

fn node_173() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.quality-run.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.quality-run.outputs.compiled-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_170() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("quality-run-compiled-complete-save"));
    values.insert(text("if"), text("always() && steps.quality-run.outputs.compiled-complete-save == 'true' && steps.quality-run-compiled-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.quality-run.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.quality-run.outputs.compiled-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_168() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("quality-run-compiled-complete-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.quality-run.outputs.compiled-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
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
        text("${{ steps.quality-run.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.quality-run.outputs.compiled-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_167() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Run quality suite"));
    values.insert(text("id"), text("quality-run"));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci segment quality-compiler"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("timeout-minutes"), Value::Number(100.into()));
    Value::Mapping(values)
}

fn node_165() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("quality-run-request-compiled-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.quality-run-request.outputs.compiled-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_166());
    Value::Mapping(values)
}

fn node_166() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.quality-run-request.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.quality-run-request.outputs.compiled-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.quality-run-request.outputs.compiled-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_163() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("quality-run-request-compiled-complete-restore"),
    );
    values.insert(
        text("if"),
        text("steps.quality-run-request.outputs.compiled-complete-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_164());
    Value::Mapping(values)
}

fn node_164() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.quality-run-request.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.quality-run-request.outputs.compiled-complete-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.quality-run-request.outputs.compiled-complete-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_162() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("quality-run-request"));
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cache-requests quality-compiler"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    Value::Mapping(values)
}

fn node_161() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-cleanup"));
    values.insert(text("if"), text("always() && (steps.workspace-fetch.outcome == 'success' || steps.workspace-fetch.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cleanup-transfers workspace-fetch"),
    );
    Value::Mapping(values)
}

fn node_159() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-index-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.workspace-fetch.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_160());
    Value::Mapping(values)
}

fn node_160() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_157() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-archives-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.workspace-fetch.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_158());
    Value::Mapping(values)
}

fn node_158() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_155() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-source-complete-save"));
    values.insert(text("if"), text("always() && steps.workspace-fetch.outputs.source-complete-save == 'true' && steps.workspace-fetch-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_156());
    Value::Mapping(values)
}

fn node_156() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_153() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-source-complete-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.workspace-fetch.outputs.source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
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
        text("key"),
        text("${{ steps.workspace-fetch.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_152() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch"));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci segment workspace-fetch"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("timeout-minutes"), Value::Number(25.into()));
    Value::Mapping(values)
}

fn node_150() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("workspace-fetch-request-index-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.workspace-fetch-request.outputs.index-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_151());
    Value::Mapping(values)
}

fn node_151() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch-request.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch-request.outputs.index-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-fetch-request.outputs.index-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_148() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("workspace-fetch-request-archives-partial-restore"),
    );
    values.insert(
        text("if"),
        text("steps.workspace-fetch-request.outputs.archives-partial-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.workspace-fetch-request.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch-request.outputs.archives-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-fetch-request.outputs.archives-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_146() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-request-source-restore"));
    values.insert(
        text("if"),
        text("steps.workspace-fetch-request.outputs.source-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_147());
    Value::Mapping(values)
}

fn node_147() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.workspace-fetch-request.outputs.source-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.workspace-fetch-request.outputs.source-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.workspace-fetch-request.outputs.source-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_145() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("workspace-fetch-request"));
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci cache-requests workspace-fetch"),
    );
    values.insert(text("if"), text("runner.os != 'Windows'"));
    Value::Mapping(values)
}

fn node_144() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-workflows-check"));
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci workflows --check"),
    );
    Value::Mapping(values)
}

fn node_143() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-cleanup"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt.outcome == 'success'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci driver-cleanup"),
    );
    Value::Mapping(values)
}

fn node_141() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-index-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.driver-cold-adopt.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_139() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-archives-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_140());
    Value::Mapping(values)
}

fn node_140() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_137() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-source-complete-save"));
    values.insert(text("if"), text("always() && steps.driver-cold-adopt.outputs.source-complete-save == 'true' && steps.driver-cold-adopt-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_138());
    Value::Mapping(values)
}

fn node_138() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_135() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-source-complete-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-cold-adopt.outputs.source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_136());
    Value::Mapping(values)
}

fn node_136() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_133() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-bootstrap-save"));
    values.insert(text("if"), text("always() && steps.driver-cold-adopt.outputs.bootstrap-save == 'true' && steps.driver-cold-adopt-bootstrap-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_134());
    Value::Mapping(values)
}

fn node_134() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-path }}"),
    );
    Value::Mapping(values)
}

fn node_131() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-bootstrap-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-cold-adopt.outputs.bootstrap-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_132());
    Value::Mapping(values)
}

fn node_132() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_130() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt"));
    values.insert(
        text("if"),
        text("steps.driver-cold-build.outcome == 'success'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    values.insert(
        text("run"),
        text("./target/ci-driver-cold/release/memcordon-ci ci driver-adopt-cold"),
    );
    Value::Mapping(values)
}

fn node_129() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-build"));
    values.insert(
        text("if"),
        text("runner.os != 'Windows' && steps.driver-bootstrap.outputs.bootstrap-ready != 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(30.into()));
    values.insert(text("run"), text("rustup run 1.97.1 cargo build --locked --release --target-dir target/ci-driver-cold -p memcordon-ci --bin memcordon-ci"));
    Value::Mapping(values)
}

fn node_128() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-cleanup"));
    values.insert(text("if"), text("always() && (steps.driver-managed-build.outcome == 'success' || steps.driver-managed-build.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-cleanup"),
    );
    Value::Mapping(values)
}

fn node_126() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-index-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.driver-managed-build.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_124() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-archives-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_125());
    Value::Mapping(values)
}

fn node_125() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_122() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-source-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.source-complete-save == 'true' && steps.driver-managed-build-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_123());
    Value::Mapping(values)
}

fn node_123() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_120() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-source-complete-probe"),
    );
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_121());
    Value::Mapping(values)
}

fn node_121() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_118() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-compiled-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build.outputs.compiled-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_119());
    Value::Mapping(values)
}

fn node_119() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.compiled-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_116() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-compiled-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.compiled-complete-save == 'true' && steps.driver-managed-build-compiled-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.driver-managed-build.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_114() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-compiled-complete-probe"),
    );
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.compiled-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
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
        text("${{ steps.driver-managed-build.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_112() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-image-save"));
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.image-save == 'true' && steps.driver-managed-build-image-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_113());
    Value::Mapping(values)
}

fn node_113() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.image-path }}"),
    );
    Value::Mapping(values)
}

fn node_110() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-image-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.image-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_111());
    Value::Mapping(values)
}

fn node_111() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.image-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_108() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-bootstrap-save"));
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.bootstrap-save == 'true' && steps.driver-managed-build-bootstrap-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_109());
    Value::Mapping(values)
}

fn node_109() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-path }}"),
    );
    Value::Mapping(values)
}

fn node_106() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-bootstrap-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.bootstrap-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_107());
    Value::Mapping(values)
}

fn node_107() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_105() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build"));
    values.insert(
        text("if"),
        text("steps.driver-selection.outputs.build-required == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(50.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-build"),
    );
    Value::Mapping(values)
}

fn node_103() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-compiled-partial-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.compiled-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.driver-context.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.compiled-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.compiled-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_101() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-compiled-complete-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.compiled-complete-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_102());
    Value::Mapping(values)
}

fn node_102() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.compiled-complete-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.compiled-complete-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_99() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-index-partial-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.index-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.driver-context.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.index-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.index-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_97() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-archives-partial-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.archives-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_98());
    Value::Mapping(values)
}

fn node_98() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.archives-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.archives-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_95() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-source-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.source-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_96());
    Value::Mapping(values)
}

fn node_96() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.source-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.source-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.source-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_94() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-selection"));
    values.insert(
        text("if"),
        text("steps.driver-bootstrap.outputs.bootstrap-ready == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(4.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-select"),
    );
    Value::Mapping(values)
}

fn node_92() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-image-restore"));
    values.insert(
        text("if"),
        text("steps.driver-context.outputs.image-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.driver-context.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.image-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.image-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_91() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context"));
    values.insert(
        text("if"),
        text("steps.driver-bootstrap.outputs.bootstrap-ready == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-context"),
    );
    Value::Mapping(values)
}

fn node_90() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-bootstrap"));
    values.insert(text("if"), text("runner.os != 'Windows' && steps.driver-bootstrap-cache.outcome == 'success' && steps.driver-bootstrap-cache.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-bootstrap-in/memcordon-ci ci driver-bootstrap"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_88() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-bootstrap-cache"));
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_89());
    Value::Mapping(values)
}

fn node_89() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-bootstrap-in"));
    values.insert(text("key"), text("mc-ci-bootstrap-v3-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/driver-bootstrap.toml', 'ci/toolchains.toml') }}-lookup"));
    values.insert(text("restore-keys"), text("mc-ci-bootstrap-v3-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/driver-bootstrap.toml', 'ci/toolchains.toml') }}-"));
    Value::Mapping(values)
}

fn node_86() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("public-source-seed-restore"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(text("with"), node_87());
    Value::Mapping(values)
}

fn node_87() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-cargo-home/registry/cache/index.crates.io-1949cf8c6b5b557f/*.crate\ntarget/ci-cargo-home/registry/cache/index.crates.io-6f17d22bba15001f/*.crate\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/.cache\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/config.json"));
    values.insert(text("key"), text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-${{ hashFiles('Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', 'tools/*/Cargo.toml', '.cargo/**') }}"));
    values.insert(
        text("restore-keys"),
        text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-"),
    );
    Value::Mapping(values)
}

fn node_85() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Install quality Rust"));
    values.insert(text("run"), text("rustup toolchain install 1.97.1 --profile minimal --component clippy --component rustfmt"));
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    Value::Mapping(values)
}

fn node_83() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Check out repository"));
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_84());
    values.insert(text("timeout-minutes"), Value::Number(6.into()));
    Value::Mapping(values)
}

fn node_84() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_82() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Configure checkout line endings"));
    values.insert(text("run"), text("git config --global core.autocrlf false"));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    Value::Mapping(values)
}

fn node_15() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("if"), text("github.event_name != 'push'"));
    values.insert(text("name"), text("policy"));
    values.insert(text("runs-on"), text("ubuntu-24.04"));
    values.insert(text("timeout-minutes"), Value::Number(182.into()));
    values.insert(text("steps"), node_16());
    values.insert(text("env"), node_79());
    Value::Mapping(values)
}

fn node_79() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("CARGO_HOME"),
        text("${{ github.workspace }}/target/ci-cargo-home"),
    );
    Value::Mapping(values)
}

fn node_16() -> Value {
    let mut values = Vec::new();
    values.push(node_17());
    values.push(node_18());
    values.push(node_20());
    values.push(node_21());
    values.push(node_23());
    values.push(node_25());
    values.push(node_26());
    values.push(node_27());
    values.push(node_29());
    values.push(node_30());
    values.push(node_32());
    values.push(node_34());
    values.push(node_36());
    values.push(node_38());
    values.push(node_40());
    values.push(node_41());
    values.push(node_43());
    values.push(node_45());
    values.push(node_47());
    values.push(node_49());
    values.push(node_51());
    values.push(node_53());
    values.push(node_55());
    values.push(node_57());
    values.push(node_59());
    values.push(node_61());
    values.push(node_63());
    values.push(node_64());
    values.push(node_65());
    values.push(node_66());
    values.push(node_68());
    values.push(node_70());
    values.push(node_72());
    values.push(node_74());
    values.push(node_76());
    values.push(node_78());
    Value::Sequence(values)
}

fn node_78() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-cleanup"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt.outcome == 'success'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/current/memcordon-ci ci driver-cleanup"),
    );
    Value::Mapping(values)
}

fn node_76() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-index-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.driver-cold-adopt.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_74() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-archives-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.driver-cold-adopt.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_75());
    Value::Mapping(values)
}

fn node_75() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_72() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-source-complete-save"));
    values.insert(text("if"), text("always() && steps.driver-cold-adopt.outputs.source-complete-save == 'true' && steps.driver-cold-adopt-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_73());
    Value::Mapping(values)
}

fn node_73() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_70() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-source-complete-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-cold-adopt.outputs.source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_71());
    Value::Mapping(values)
}

fn node_71() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_68() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-bootstrap-save"));
    values.insert(text("if"), text("always() && steps.driver-cold-adopt.outputs.bootstrap-save == 'true' && steps.driver-cold-adopt-bootstrap-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_69());
    Value::Mapping(values)
}

fn node_69() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-path }}"),
    );
    Value::Mapping(values)
}

fn node_66() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt-bootstrap-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-cold-adopt.outputs.bootstrap-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
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
        text("key"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-cold-adopt.outputs.bootstrap-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_65() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-adopt"));
    values.insert(
        text("if"),
        text("steps.driver-cold-build.outcome == 'success'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(77.into()));
    values.insert(text("run"), text("./target/ci-driver-cold/release/memcordon-ci ci driver-adopt-cold --feedback repository-policy"));
    Value::Mapping(values)
}

fn node_64() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-cold-build"));
    values.insert(
        text("if"),
        text("runner.os != 'Windows' && steps.driver-bootstrap.outputs.bootstrap-ready != 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(30.into()));
    values.insert(text("run"), text("rustup run 1.97.1 cargo build --locked --release --target-dir target/ci-driver-cold -p memcordon-ci --bin memcordon-ci"));
    Value::Mapping(values)
}

fn node_63() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-cleanup"));
    values.insert(text("if"), text("always() && (steps.driver-managed-build.outcome == 'success' || steps.driver-managed-build.outcome == 'failure')"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-cleanup"),
    );
    Value::Mapping(values)
}

fn node_61() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-index-partial-save"));
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build.outputs.index-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_62());
    Value::Mapping(values)
}

fn node_62() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.index-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_59() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-archives-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build.outputs.archives-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_60());
    Value::Mapping(values)
}

fn node_60() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.archives-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_57() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-source-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.source-complete-save == 'true' && steps.driver-managed-build-source-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_58());
    Value::Mapping(values)
}

fn node_58() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.source-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_55() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-source-complete-probe"),
    );
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.source-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_56());
    Value::Mapping(values)
}

fn node_56() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.source-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.source-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_53() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-compiled-partial-save"),
    );
    values.insert(
        text("if"),
        text("always() && steps.driver-managed-build.outputs.compiled-partial-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.driver-managed-build.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.compiled-partial-path }}"),
    );
    Value::Mapping(values)
}

fn node_51() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-compiled-complete-save"),
    );
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.compiled-complete-save == 'true' && steps.driver-managed-build-compiled-complete-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.driver-managed-build.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-path }}"),
    );
    Value::Mapping(values)
}

fn node_49() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("id"),
        text("driver-managed-build-compiled-complete-probe"),
    );
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.compiled-complete-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
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
        text("${{ steps.driver-managed-build.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.compiled-complete-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_47() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-image-save"));
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.image-save == 'true' && steps.driver-managed-build-image-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_48());
    Value::Mapping(values)
}

fn node_48() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.image-path }}"),
    );
    Value::Mapping(values)
}

fn node_45() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-image-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.image-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_46());
    Value::Mapping(values)
}

fn node_46() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.image-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_43() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-bootstrap-save"));
    values.insert(text("if"), text("always() && steps.driver-managed-build.outputs.bootstrap-save == 'true' && steps.driver-managed-build-bootstrap-probe.outputs.cache-hit != 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_44());
    Value::Mapping(values)
}

fn node_44() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-path }}"),
    );
    Value::Mapping(values)
}

fn node_41() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build-bootstrap-probe"));
    values.insert(
        text("if"),
        text("!cancelled() && steps.driver-managed-build.outputs.bootstrap-save == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_42());
    Value::Mapping(values)
}

fn node_42() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-managed-build.outputs.bootstrap-path }}"),
    );
    values.insert(text("lookup-only"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_40() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-managed-build"));
    values.insert(
        text("if"),
        text("steps.driver-selection.outputs.build-required == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(112.into()));
    values.insert(text("run"), text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-build --feedback repository-policy"));
    Value::Mapping(values)
}

fn node_38() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-compiled-partial-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.compiled-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.driver-context.outputs.compiled-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.compiled-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.compiled-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_36() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-compiled-complete-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.compiled-complete-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.driver-context.outputs.compiled-complete-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.compiled-complete-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.compiled-complete-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_34() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-index-partial-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.index-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.driver-context.outputs.index-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.index-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.index-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_32() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-archives-partial-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.archives-partial-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_33());
    Value::Mapping(values)
}

fn node_33() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(
        text("key"),
        text("${{ steps.driver-context.outputs.archives-partial-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.archives-partial-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.archives-partial-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_30() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-source-restore"));
    values.insert(text("if"), text("steps.driver-selection.outputs.build-required == 'true' && steps.driver-context.outputs.source-restore == 'true'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("${{ steps.driver-context.outputs.source-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.source-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.source-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_29() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-selection"));
    values.insert(
        text("if"),
        text("steps.driver-bootstrap.outputs.bootstrap-ready == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(66.into()));
    values.insert(text("run"), text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-select --feedback repository-policy"));
    Value::Mapping(values)
}

fn node_27() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context-image-restore"));
    values.insert(
        text("if"),
        text("steps.driver-context.outputs.image-restore == 'true'"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
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
        text("key"),
        text("${{ steps.driver-context.outputs.image-key }}"),
    );
    values.insert(
        text("path"),
        text("${{ steps.driver-context.outputs.image-path }}"),
    );
    values.insert(
        text("restore-keys"),
        text("${{ steps.driver-context.outputs.image-prefix }}"),
    );
    Value::Mapping(values)
}

fn node_26() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-context"));
    values.insert(
        text("if"),
        text("steps.driver-bootstrap.outputs.bootstrap-ready == 'true'"),
    );
    values.insert(text("timeout-minutes"), Value::Number(5.into()));
    values.insert(
        text("run"),
        text("./target/ci-runtime/bootstrap/memcordon-ci ci driver-context"),
    );
    Value::Mapping(values)
}

fn node_25() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-bootstrap"));
    values.insert(text("if"), text("runner.os != 'Windows' && steps.driver-bootstrap-cache.outcome == 'success' && steps.driver-bootstrap-cache.outputs.cache-matched-key != ''"));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("run"),
        text("./target/ci-bootstrap-in/memcordon-ci ci driver-bootstrap"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    Value::Mapping(values)
}

fn node_23() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("driver-bootstrap-cache"));
    values.insert(text("if"), text("runner.os != 'Windows'"));
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("with"), node_24());
    Value::Mapping(values)
}

fn node_24() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-bootstrap-in"));
    values.insert(text("key"), text("mc-ci-bootstrap-v3-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/driver-bootstrap.toml', 'ci/toolchains.toml') }}-lookup"));
    values.insert(text("restore-keys"), text("mc-ci-bootstrap-v3-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/driver-bootstrap.toml', 'ci/toolchains.toml') }}-"));
    Value::Mapping(values)
}

fn node_21() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("id"), text("public-source-seed-restore"));
    values.insert(
        text("uses"),
        text("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"),
    );
    values.insert(text("continue-on-error"), Value::Bool(true));
    values.insert(text("timeout-minutes"), Value::Number(2.into()));
    values.insert(text("with"), node_22());
    Value::Mapping(values)
}

fn node_22() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("path"), text("target/ci-cargo-home/registry/cache/index.crates.io-1949cf8c6b5b557f/*.crate\ntarget/ci-cargo-home/registry/cache/index.crates.io-6f17d22bba15001f/*.crate\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/.cache\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/config.json"));
    values.insert(text("key"), text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-${{ hashFiles('Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', 'tools/*/Cargo.toml', '.cargo/**') }}"));
    values.insert(
        text("restore-keys"),
        text("mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-"),
    );
    Value::Mapping(values)
}

fn node_20() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Install pinned Rust"));
    values.insert(
        text("run"),
        text("rustup toolchain install 1.97.1 --profile minimal"),
    );
    values.insert(text("timeout-minutes"), Value::Number(15.into()));
    Value::Mapping(values)
}

fn node_18() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Check out repository"));
    values.insert(
        text("uses"),
        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
    );
    values.insert(text("with"), node_19());
    values.insert(text("timeout-minutes"), Value::Number(6.into()));
    Value::Mapping(values)
}

fn node_19() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("persist-credentials"), Value::Bool(false));
    Value::Mapping(values)
}

fn node_17() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("name"), text("Configure checkout line endings"));
    values.insert(text("run"), text("git config --global core.autocrlf false"));
    values.insert(text("timeout-minutes"), Value::Number(1.into()));
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

fn node_12() -> Value {
    let mut values = serde_yaml::Mapping::new();
    values.insert(text("contents"), text("read"));
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
