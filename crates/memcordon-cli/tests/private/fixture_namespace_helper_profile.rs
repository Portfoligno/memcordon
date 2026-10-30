//! Fixed same-image checkpoint catalog; these static facts are not runtime evidence.
use serde::Deserialize;
use std::sync::OnceLock;

#[derive(Clone, Debug)]
pub struct Checkpoint {
    pub rva: u32,
    pub bytes: Vec<u8>,
    pub kind: String,
    pub successors: Vec<u32>,
}

#[derive(Deserialize)]
struct Catalog {
    max_checkpoint_stops: usize,
    nodes: Vec<Node>,
}
#[derive(Deserialize)]
struct Node {
    id: String,
    bytes: Vec<u8>,
    kind: String,
    successors: Vec<String>,
}

pub const MAX_CHECKPOINT_STOPS: usize = 93;

pub fn checkpoints() -> &'static [Checkpoint] {
    static CATALOG: OnceLock<Vec<Checkpoint>> = OnceLock::new();
    CATALOG.get_or_init(|| {
        let source: Catalog =
            serde_json::from_str(include_str!("fixture_namespace_helper_checkpoints.json"))
                .expect("fixed helper catalog must decode");
        assert_eq!(source.max_checkpoint_stops, MAX_CHECKPOINT_STOPS);
        let rva = |value: &str| {
            u32::from_str_radix(value.strip_prefix("0x").expect("catalog RVA prefix"), 16)
                .expect("catalog RVA")
        };
        let nodes: Vec<_> = source
            .nodes
            .into_iter()
            .map(|node| Checkpoint {
                rva: rva(&node.id),
                bytes: node.bytes,
                kind: node.kind.clone(),
                successors: node
                    .successors
                    .iter()
                    .filter_map(|value| {
                        if value == "helper-return" {
                            assert_eq!(node.kind, "selected-ebx");
                            None
                        } else {
                            Some(rva(value))
                        }
                    })
                    .collect(),
            })
            .collect();
        for node in &nodes {
            assert!(!node.bytes.is_empty());
            assert!(node.successors.len() <= 2);
            assert_eq!(
                nodes.iter().filter(|other| other.rva == node.rva).count(),
                1
            );
            assert!(
                node.successors
                    .iter()
                    .all(|next| nodes.iter().any(|other| other.rva == *next))
            );
        }
        nodes
    })
}

pub fn checkpoint(rva: u32) -> Option<&'static Checkpoint> {
    checkpoints().iter().find(|node| node.rva == rva)
}

#[derive(Deserialize)]
pub struct ByteExtent {
    pub rva: u32,
    pub length: usize,
    pub bytes: Vec<u8>,
}
#[derive(Deserialize)]
struct ByteCatalog {
    image_sha256: String,
    ranges: Vec<ByteExtent>,
}
pub fn byte_extents() -> &'static [ByteExtent] {
    static RANGES: OnceLock<Vec<ByteExtent>> = OnceLock::new();
    RANGES.get_or_init(|| {
        let catalog: ByteCatalog =
            serde_json::from_str(include_str!("fixture_namespace_helper_byte_extents.json"))
                .expect("fixed helper byte catalog");
        assert_eq!(catalog.image_sha256, super::IMAGE_SHA256);
        for range in &catalog.ranges {
            assert_eq!(range.length, range.bytes.len());
        }
        catalog.ranges
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub enum CallKind {
    TokenQuery,
    DirectoryOpen,
    Status,
    Other,
}

pub fn call_kind(rva: u32) -> CallKind {
    match rva {
        0x8653f | 0x8656d | 0x8659c | 0x86808 | 0x868f2 | 0x199c23 | 0x199d4a => {
            CallKind::TokenQuery
        }
        0x867cf | 0x8687a | 0x86a0f | 0x86aaa | 0x86b2d | 0x86ba9 | 0x86c1b | 0x199d96
        | 0x199ecd => CallKind::DirectoryOpen,
        0x8685f | 0x86927 | 0x199e76 | 0x86a38 | 0x86a63 | 0x199c44 | 0x199ddd | 0x86c70 => {
            CallKind::Status
        }
        _ => CallKind::Other,
    }
}

pub fn paired_call(return_rva: u32) -> Option<&'static Checkpoint> {
    checkpoints()
        .iter()
        .find(|node| node.kind == "call-entry" && node.successors.as_slice() == [return_rva])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub enum Source {
    Call { call: u32, returned: u32 },
    Synthetic { checkpoint: u32 },
    Unknown,
}

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct Selected {
    pub raw_rbx: u64,
    pub status: i32,
    pub source: Source,
}

#[derive(Clone, Debug)]
pub struct Machine {
    pub frontier: Vec<u32>,
    pub selected: Option<Selected>,
    pub stops: usize,
    previous: Option<(u32, u64, u64)>,
    source: Source,
}
impl Default for Machine {
    fn default() -> Self {
        Self {
            frontier: vec![0x86450],
            selected: None,
            stops: 0,
            previous: None,
            source: Source::Unknown,
        }
    }
}
impl Machine {
    pub fn hit(
        &mut self,
        rva: u32,
        slot: usize,
        rax: u64,
        rbx: u64,
    ) -> Result<Option<i32>, &'static str> {
        if self.stops >= MAX_CHECKPOINT_STOPS || self.frontier.get(slot) != Some(&rva) {
            return Err("helper checkpoint frontier or budget mismatch");
        }
        let node = checkpoint(rva).expect("frontier references admitted node");
        if let Some((previous, previous_rax, previous_rbx)) = self.previous {
            if let Some(source) = transfer_source(previous, rva, previous_rax, rbx) {
                self.source = source;
            } else if previous_rbx != rbx {
                self.source = Source::Unknown;
            }
        }
        if node.kind == "copy-status" {
            self.source = Source::Synthetic { checkpoint: rva };
        }
        if node.kind == "selected-ebx" {
            if self.source == Source::Unknown {
                return Err("selected helper result has incomplete status lineage");
            }
            self.selected = Some(Selected {
                raw_rbx: rbx,
                status: rbx as u32 as i32,
                source: self.source,
            });
        }
        let status = paired_call(rva)
            .filter(|call| call_kind(call.rva) != CallKind::Other)
            .map(|_| rax as u32 as i32);
        self.stops += 1;
        self.frontier.clone_from(&node.successors);
        self.previous = Some((rva, rax, rbx));
        Ok(status)
    }
}

fn transfer_source(previous: u32, _next: u32, rax: u64, rbx: u64) -> Option<Source> {
    // Validated non-status EBX writes invalidate lineage even if values coincide.
    if matches!(previous, 0x868a4 | 0x199e31) {
        return Some(Source::Unknown);
    }
    // These return spans contain an unconditional mov EAX,EBX before their frontier.
    const MOV_EAX_EBX_RETURNS: &[u32] = &[
        0x86546, 0x86574, 0x865a3, 0x867d6, 0x8680f, 0x86864, 0x86881, 0x868f9, 0x8692c, 0x86a16,
        0x86a3f, 0x86a6a, 0x86ab1, 0x86b34, 0x86bb0, 0x86c22, 0x86c77, 0x199c2a, 0x199c4b,
        0x199d51, 0x199d9d, 0x199de4, 0x199e7b, 0x199ed4,
    ];
    if MOV_EAX_EBX_RETURNS.contains(&previous) {
        if rbx != u64::from(rax as u32) {
            return Some(Source::Unknown);
        }
        return paired_call(previous).map(|call| Source::Call {
            call: call.rva,
            returned: previous,
        });
    }
    if previous == 0x86cbb {
        if rbx != 0xc000009a {
            return Some(Source::Unknown);
        }
        return Some(Source::Synthetic {
            checkpoint: previous,
        });
    }
    None
}
