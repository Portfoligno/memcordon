//! Independent compiler/filter vectors used by the current native component.
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
    pub profile: String,
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
            != "native_current_filter::current_filter_vectors_emit_actual_component_receipts"
        || receipt.operation != "current-filter-compiler-bpf-vectors"
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
        if vector.profile != "linux-private-workload-v1"
            || !abis.insert((vector.abi.as_str(), vector.profile.as_str()))
        {
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
        let expected = crate::filter_anchor::frozen_linux_filter_program(&vector.abi)?;
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
                "seqpacket-pair-positive-or-denied",
                arch,
                pair,
                [1, 5 | 0x80000, 0],
                0x7fff0000,
            ),
            (
                "named-seqpacket-denied",
                arch,
                socket,
                [1, 5, 0],
                0x0005005d,
            ),
            (
                "seqpacket-protocol-denied",
                arch,
                pair,
                [1, 5, 1],
                0x0005005d,
            ),
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
    if abis
        != ["x86_64", "aarch64"]
            .into_iter()
            .flat_map(|abi| {
                ["linux-private-workload-v1"]
                    .into_iter()
                    .map(move |profile| (abi, profile))
            })
            .collect()
    {
        return Err("BPF ABI inventory narrowed".into());
    }
    Ok(())
}
