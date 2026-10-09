//! Compiler-vector regressions are distinct from native kernel attachment.
use crate::*;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxFilterReceipt {
    pub format: String,
    pub revision: u32,
    pub run_id: String,
    pub recipe_id: String,
    pub test_name: String,
    pub native_target: String,
    pub executable_sha256: String,
    pub challenge_sha256: String,
    pub operation: String,
    pub vectors: Vec<FilterVector>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilterVector {
    pub abi: String,
    pub program: Vec<Instruction>,
    pub program_sha256: String,
    pub observations: Vec<FilterObservation>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Instruction {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilterObservation {
    pub case: String,
    pub architecture: u32,
    pub syscall: u32,
    pub arguments: [u64; 3],
    pub actual_bpf_return: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxJournalReceipt {
    pub format: String,
    pub revision: u32,
    pub run_id: String,
    pub recipe_id: String,
    pub test_name: String,
    pub native_target: String,
    pub executable_sha256: String,
    pub challenge_sha256: String,
    pub operation: String,
    pub attempt_id: String,
    pub frontend: JournalProcess,
    pub boot_id: String,
    pub record_before: String,
    pub record_after_refusal: String,
    pub canonical_device: u64,
    pub canonical_inode: u64,
    pub canonical_unchanged: bool,
    pub release_refusal: String,
    pub journal_refusal: String,
    pub native_publication_errno: i32,
    pub owned_competing_device: u64,
    pub owned_competing_inode: u64,
    pub owned_competing_unlinked: bool,
    pub unallocated_record_retired: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JournalProcess {
    pub pid: u32,
    pub start_time: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxVersionReceipt {
    pub format: String,
    pub revision: u32,
    pub run_id: String,
    pub recipe_id: String,
    pub native_target: String,
    pub test_name: String,
    pub executable_sha256: String,
    pub challenge_sha256: String,
    pub operation: String,
    pub fixture_resource_claims: bool,
    pub v1_canonical: String,
    pub v2_request: String,
    pub v2_canonical: String,
    pub v3_request: String,
    pub v3_canonical: String,
    pub projection: String,
    pub projection_refusal: String,
    pub old_parser_refusal: String,
}

fn pinned_v2_bytes() -> VerificationResult<Vec<u8>> {
    // Frozen protocol-vector tags and values, independently encoded here.
    fn id(bytes: &mut Vec<u8>, value: &str) {
        bytes.extend((value.len() as u16).to_be_bytes());
        bytes.extend(value.as_bytes());
    }
    let mut bytes = b"memcordon-workload-contract-v2\0\0\x01".to_vec();
    bytes.extend([0x11; 32]);
    id(&mut bytes, "linux-unix-create-v1");
    bytes.extend(
        hex::decode("6a8a4c2a8003371ea0c7cd8e3a2c340fb86a33c5980538d806783848578099bb")
            .map_err(|error| error.to_string())?,
    );
    id(&mut bytes, "grant-a");
    bytes.extend(1u64.to_be_bytes());
    bytes.extend([0x11; 32]);
    bytes.extend([1, 2, 2, 2, 1]);
    bytes.extend(2u16.to_be_bytes());
    bytes.push(2);
    id(&mut bytes, "a-pair");
    bytes.push(2);
    bytes.push(1);
    id(&mut bytes, "z-create");
    bytes.push(1);
    bytes.extend(0u16.to_be_bytes());
    bytes.extend([3; 16]);
    bytes.extend(1u64.to_be_bytes());
    bytes.push(1);
    Ok(bytes)
}

pub fn validate_linux_version_vector(
    receipt: &LinuxVersionReceipt,
    key: &CaseKey,
    v1: &[u8],
    v2_request: &[u8],
    v2: &[u8],
) -> VerificationResult<()> {
    header(
        &receipt.format,
        receipt.revision,
        "memcordon.linux-version-component",
    )?;
    if key.evidence_class != EvidenceClass::NativeComponentRegression
        || key.channel.is_some()
        || key.family != "L-VER-01"
        || !["v1-vectors", "v2-vectors"].contains(&key.scenario.as_str())
        || !key.target.ends_with("linux-gnu")
        || receipt.native_target != key.target
        || receipt.test_name
            != "native_versions::native_version_vectors_emit_actual_component_receipts"
        || receipt.operation != "actual-version-codec-and-projection-vectors"
        || !receipt.fixture_resource_claims
        || receipt.projection_refusal.is_empty()
        || receipt.projection_refusal.len() > 4096
        || receipt.old_parser_refusal.is_empty()
        || receipt.old_parser_refusal.len() > 4096
    {
        return Err("version-vector native protocol-fixture applicability differs".into());
    }
    identifier(&receipt.run_id)?;
    identifier(&receipt.recipe_id)?;
    digest(&receipt.executable_sha256)?;
    digest(&receipt.challenge_sha256)?;
    let fixed = include_str!(
        "../../../crates/memcordon-core/tests/fixtures/workload_independent/contract.hex"
    );
    let expected = hex::decode(fixed.split_whitespace().collect::<String>())
        .map_err(|error| error.to_string())?;
    let expected_request: serde_json::Value = wire::decode(include_bytes!(
        "../../../fuzz/corpus/workload-request/baseline-v2.json"
    ))?;
    let actual_request: serde_json::Value = wire::decode(v2_request)?;
    if v1 != expected || actual_request != expected_request || v2 != pinned_v2_bytes()? {
        return Err("committed V1/V2 canonical protocol vector changed".into());
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "Compare each versioned request/result byte vector independently with its native receipt"
)]
pub fn validate_linux_mixed_version_vector(
    receipt: &LinuxVersionReceipt,
    key: &CaseKey,
    v1: &[u8],
    v2_request: &[u8],
    v2: &[u8],
    v3_request: &[u8],
    v3: &[u8],
    projection: &[u8],
) -> VerificationResult<()> {
    if !["v3-vectors", "projection-mutation"].contains(&key.scenario.as_str()) {
        return Err("mixed version-vector applicability differs".into());
    }
    let mut baseline = key.clone();
    baseline.scenario = "v2-vectors".into();
    validate_linux_version_vector(receipt, &baseline, v1, v2_request, v2)?;
    fn id(bytes: &mut Vec<u8>, value: &str) {
        bytes.extend((value.len() as u16).to_be_bytes());
        bytes.extend(value.as_bytes());
    }
    let mut expected = b"memcordon.workload-contract/version3\0\0\x01".to_vec();
    expected.extend(3u16.to_be_bytes());
    expected.extend([1; 32]);
    id(&mut expected, "linux-tcp4-unix-private-v1");
    expected.extend([2; 32]);
    id(&mut expected, "combined-grant");
    expected.extend(1u64.to_be_bytes());
    expected.extend([1; 32]);
    expected.push(1);
    for (name, marker) in [
        ("account", 3),
        ("exclusive", 4),
        ("toolchain", 5),
        ("fixture", 6),
        ("build-root", 7),
    ] {
        id(&mut expected, name);
        expected.extend([marker; 32]);
    }
    id(&mut expected, "build-driver");
    id(&mut expected, "work");
    expected.extend([8; 16]);
    expected.extend(1u64.to_be_bytes());
    expected.extend(2u16.to_be_bytes());
    id(&mut expected, "tcp");
    expected.extend([1, 1, 1]);
    id(&mut expected, "unix");
    expected.push(2);
    let object =
        |name: &str, marker: u8| serde_json::json!({"id":name,"digest":hex::encode([marker;32])});
    let expected_request = serde_json::json!({"schema_version":3,"workload_plan_digest":hex::encode([1u8;32]),
        "authorized_profile":{"id":"linux-tcp4-unix-private-v1","semantic_digest":hex::encode([2u8;32])},
        "authorization":{"grant_id":"combined-grant","grant_revision":1,"approved_plan_digest":hex::encode([1u8;32])},
        "ceiling":"fresh_root_ipv4_tcp_unix_streams_intra_attempt_no_gain",
        "requirements":[{"kind":"tcp_listener","id":"tcp","local_port":{"kind":"kernel_assigned"},"peer":{"kind":"dynamic_loopback_within_this_attempt"}},{"kind":"unix_stream_pair","id":"unix"}],
        "execution_identity":{"identity":object("account",3),"exclusive_use_policy":object("exclusive",4)},
        "runtime_image":object("toolchain",5),"input_image":object("fixture",6),"root_layout":object("build-root",7),
        "launch":{"entrypoint":"build-driver","working_directory":"work"},"expected_epoch":{"service_instance":vec![8u8;16],"revision":1}});
    let actual_request: serde_json::Value = wire::decode(v3_request)?;
    let actual_projection: serde_json::Value = wire::decode(projection)?;
    let mut expected_projection = expected_request.clone();
    expected_projection["schema_version"] = 2.into();
    if expected.len() != 463
        || v3 != expected
        || actual_request != expected_request
        || actual_projection != expected_projection
    {
        return Err("mixed canonical/request/projection fixed vector changed".into());
    }
    Ok(())
}

pub fn validate_linux_journal_receipt(
    receipt: &LinuxJournalReceipt,
    key: &CaseKey,
    before: &[u8],
    after: &[u8],
) -> VerificationResult<()> {
    header(
        &receipt.format,
        receipt.revision,
        "memcordon.linux-journal-component",
    )?;
    if key.evidence_class != EvidenceClass::NativeComponentRegression
        || key.channel.is_some()
        || key.family != "L-VER-01"
        || key.scenario != "journal-barrier"
        || !key.target.ends_with("linux-gnu")
        || receipt.native_target != key.target
        || receipt.test_name
            != "private_attempt::durable_journal_barriers_emit_actual_component_receipts"
        || receipt.operation != "durable-preboundary-journal-barriers"
        || !receipt.canonical_unchanged
        || !receipt.owned_competing_unlinked
        || !receipt.unallocated_record_retired
        || receipt.frontend.pid == 0
        || receipt.frontend.start_time == 0
        || receipt.boot_id.is_empty()
        || receipt.boot_id.len() > 128
        || receipt.canonical_inode == 0
        || receipt.owned_competing_inode == 0
        || (receipt.canonical_device, receipt.canonical_inode)
            == (
                receipt.owned_competing_device,
                receipt.owned_competing_inode,
            )
        || receipt.native_publication_errno != 17
        || receipt.release_refusal != "private release requires durable gated observations"
        || receipt.journal_refusal != "File exists (os error 17)"
        || before != after
        || before.len() > 1024 * 1024
    {
        return Err("native preboundary journal barrier observation differs".into());
    }
    identifier(&receipt.run_id)?;
    identifier(&receipt.recipe_id)?;
    identifier(&receipt.attempt_id)?;
    digest(&receipt.executable_sha256)?;
    digest(&receipt.challenge_sha256)?;
    let text = std::str::from_utf8(before).map_err(|error| error.to_string())?;
    let (body, checksum) = text
        .rsplit_once("digest=")
        .ok_or("journal checksum absent")?;
    if checksum != format!("{}\n", sha256(body.as_bytes())) {
        return Err("journal native bytes checksum differs".into());
    }
    let mut lines = body.lines();
    if lines.next() != Some("format=memcordon.private-native-journal")
        || lines.next() != Some("revision=1")
        || lines.next() != Some(format!("cgroup={}", receipt.attempt_id).as_str())
    {
        return Err("journal native envelope association differs".into());
    }
    let payload = lines
        .next()
        .and_then(|line| line.strip_prefix("payload="))
        .ok_or("journal payload absent")?;
    if lines.next().is_some() {
        return Err("journal envelope has unexpected fields".into());
    }
    let record: serde_json::Value = wire::decode(payload.as_bytes())?;
    let fields = [
        "attempt_id",
        "boot_identity",
        "frontend",
        "caller_envelope_digest",
        "admission_metadata",
        "phase",
        "release_knowledge",
        "binding",
        "guardian",
        "namespace_init",
        "target",
        "network_namespace_inode",
        "checkpoint",
        "checkpoint_digest",
        "gated_facts",
        "cleanup_error",
    ];
    if record.as_object().is_none_or(|object| {
        object.len() != fields.len() || object.keys().any(|field| !fields.contains(&field.as_str()))
    }) {
        return Err("allocated journal payload schema differs".into());
    }
    digest(
        record["caller_envelope_digest"]
            .as_str()
            .ok_or("journal caller digest absent")?,
    )?;
    if record["frontend"].as_object().is_none_or(|object| {
        object.len() != 2 || !object.contains_key("pid") || !object.contains_key("start_time")
    }) {
        return Err("journal frontend identity schema differs".into());
    }
    if record["attempt_id"] != receipt.attempt_id
        || record["boot_identity"] != receipt.boot_id
        || record["frontend"]["pid"] != receipt.frontend.pid
        || record["frontend"]["start_time"] != receipt.frontend.start_time
        || record["phase"] != "allocated"
        || record["release_knowledge"] != "not-released"
        || [
            "admission_metadata",
            "binding",
            "guardian",
            "namespace_init",
            "target",
            "network_namespace_inode",
            "checkpoint",
            "checkpoint_digest",
            "gated_facts",
            "cleanup_error",
        ]
        .iter()
        .any(|field| !record[*field].is_null())
        || record
            .as_object()
            .is_none_or(|object| object.keys().any(|field| field.starts_with("mixed_")))
    {
        return Err("journal barrier fabricated target/admission/release authority".into());
    }
    Ok(())
}

fn program_valid(program: &[Instruction]) -> VerificationResult<()> {
    if program.is_empty()
        || program.len() > 4096
        || program.last().is_none_or(|word| word.code != 6)
    {
        return Err("BPF instruction count/final return differs".into());
    }
    for (index, word) in program.iter().enumerate() {
        let targets: Vec<usize> = match word.code {
            0x20 => {
                if word.jt != 0 || word.jf != 0 || word.k % 4 != 0 || word.k > 60 {
                    return Err("BPF absolute scalar load differs".into());
                }
                Vec::new()
            }
            0x15 | 0x45 => vec![
                index + 1 + usize::from(word.jt),
                index + 1 + usize::from(word.jf),
            ],
            0x05 => {
                if word.jt != 0 || word.jf != 0 {
                    return Err("BPF unconditional branch flags differ".into());
                }
                vec![index + 1 + usize::try_from(word.k).map_err(|error| error.to_string())?]
            }
            0x54 | 0x06 => {
                if word.jt != 0 || word.jf != 0 {
                    return Err("BPF scalar/return branch flags differ".into());
                }
                Vec::new()
            }
            _ => return Err("unknown BPF vector opcode".into()),
        };
        if targets.iter().any(|target| *target >= program.len()) {
            return Err("BPF branch exceeds retained program".into());
        }
    }
    Ok(())
}

fn evaluate(
    program: &[Instruction],
    arch: u32,
    syscall: u32,
    args: [u64; 3],
) -> VerificationResult<u32> {
    let mut data = [0u8; 64];
    data[..4].copy_from_slice(&syscall.to_le_bytes());
    data[4..8].copy_from_slice(&arch.to_le_bytes());
    for (index, value) in args.into_iter().enumerate() {
        data[16 + index * 8..24 + index * 8].copy_from_slice(&value.to_le_bytes());
    }
    let mut accumulator = 0u32;
    let mut pc = 0usize;
    for _ in 0..program.len() {
        let word = program
            .get(pc)
            .ok_or("BPF evaluation fell outside program")?;
        pc += 1;
        match word.code {
            0x20 => {
                let offset = word.k as usize;
                accumulator = u32::from_le_bytes(
                    data[offset..offset + 4]
                        .try_into()
                        .map_err(|_| "BPF load width differs")?,
                );
            }
            0x15 => {
                pc += usize::from(if accumulator == word.k {
                    word.jt
                } else {
                    word.jf
                })
            }
            0x45 => {
                pc += usize::from(if accumulator & word.k != 0 {
                    word.jt
                } else {
                    word.jf
                })
            }
            0x05 => pc += word.k as usize,
            0x54 => accumulator &= word.k,
            0x06 => return Ok(word.k),
            _ => return Err("BPF evaluator unknown opcode".into()),
        }
    }
    Err("BPF evaluation did not return within forward program".into())
}

pub fn validate_linux_filter_receipt(
    receipt: &LinuxFilterReceipt,
    key: &CaseKey,
) -> VerificationResult<()> {
    header(
        &receipt.format,
        receipt.revision,
        "memcordon.linux-filter-component",
    )?;
    if key.evidence_class != EvidenceClass::NativeComponentRegression
        || key.channel.is_some()
        || key.family != "L-VER-01"
        || !["filter-x64", "filter-arm64"].contains(&key.scenario.as_str())
        || !key.target.ends_with("linux-gnu")
        || receipt.native_target != key.target
        || receipt.test_name
            != "native_private_tcp::mixed_filter_vectors_emit_actual_component_receipts"
        || receipt.operation != "mixed-filter-compiler-bpf-vectors"
        || receipt.vectors.len() != 2
    {
        return Err("filter component source/ABI-vector applicability differs".into());
    }
    identifier(&receipt.run_id)?;
    identifier(&receipt.recipe_id)?;
    digest(&receipt.executable_sha256)?;
    digest(&receipt.challenge_sha256)?;
    let mut abis = BTreeSet::new();
    for vector in &receipt.vectors {
        if !abis.insert(vector.abi.as_str()) {
            return Err("duplicate BPF ABI vector".into());
        }
        let (arch, socket, pair) = match vector.abi.as_str() {
            "x86_64" => (0xc000003e, 41, 53),
            "aarch64" => (0xc00000b7, 198, 199),
            _ => return Err("unexpected BPF ABI".into()),
        };
        program_valid(&vector.program)?;
        let mut bytes = Vec::with_capacity(vector.program.len() * 8);
        for word in &vector.program {
            bytes.extend(word.code.to_le_bytes());
            bytes.extend([word.jt, word.jf]);
            bytes.extend(word.k.to_le_bytes());
        }
        if sha256(&bytes) != vector.program_sha256 {
            return Err("actual BPF instruction bytes/digest differ".into());
        }
        let expected = frozen_linux_filter_program(&vector.abi)?;
        if vector.program.len() != expected.len()
            || vector
                .program
                .iter()
                .zip(&expected)
                .any(|(actual, expected)| {
                    (actual.code, actual.jt, actual.jf, actual.k)
                        != (expected.code, expected.jt, expected.jf, expected.k)
                })
        {
            return Err(
                "complete BPF program differs from fixed GNU syscall/scalar catalogue".into(),
            );
        }
        let cases = [
            ("tcp-positive", arch, socket, [2, 1, 0], 0x7fff0000),
            ("unix-positive", arch, socket, [1, 1, 0], 0x7fff0000),
            ("unix-pair-positive", arch, pair, [1, 1, 0], 0x7fff0000),
            (
                "wrong-architecture",
                arch ^ 1,
                socket,
                [2, 1, 0],
                0x80000000,
            ),
            ("udp-denied", arch, socket, [2, 2, 0], 0x0005005d),
            ("unix-protocol-denied", arch, socket, [1, 1, 1], 0x0005005d),
        ];
        if vector.observations.len() != cases.len() {
            return Err("BPF observation set narrowed".into());
        }
        let mut observed = BTreeSet::new();
        for observation in &vector.observations {
            let expected = cases
                .iter()
                .find(|case| case.0 == observation.case)
                .ok_or("unexpected BPF observation")?;
            if !observed.insert(observation.case.as_str())
                || (
                    observation.architecture,
                    observation.syscall,
                    observation.arguments,
                    observation.actual_bpf_return,
                ) != (expected.1, expected.2, expected.3, expected.4)
                || evaluate(
                    &vector.program,
                    observation.architecture,
                    observation.syscall,
                    observation.arguments,
                )? != observation.actual_bpf_return
            {
                return Err("actual BPF compiler/evaluator observation differs from independently pinned vector".into());
            }
        }
        // Extra fixed probes preserve neighboring closed socket controls.
        for (number, args, expected) in [
            (socket, [10, 1, 0], 0x00050061),
            (socket, [17, 3, 0], 0x00050061),
            (socket, [16, 3, 0], 0x00050061),
            (socket, [2, 3, 0], 0x0005005d),
            (pair, [2, 1, 0], 0x00050061),
        ] {
            if evaluate(&vector.program, arch, number, args)? != expected {
                return Err("BPF neighboring denied socket operation changed".into());
            }
        }
    }
    if abis != ["x86_64", "aarch64"].into_iter().collect() {
        return Err("BPF ABI inventory narrowed".into());
    }
    Ok(())
}
