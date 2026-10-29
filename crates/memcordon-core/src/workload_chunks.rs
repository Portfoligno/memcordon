//! Bounded metadata for each streamed manifest/member. Native ownership is not encoded.
use std::mem::size_of;

pub const CHUNK_HEADER_BYTES: usize = size_of::<u8>() + size_of::<u32>() + size_of::<u64>() * 2;
pub const CHUNK_DATA_BYTES: usize = crate::workload_bundle::STREAM_BYTES - CHUNK_HEADER_BYTES;
pub const OUTPUT_CHUNK_HEADER_BYTES: usize = size_of::<u32>() + size_of::<u64>() * 2;
pub const OUTPUT_CHUNK_DATA_BYTES: usize =
    crate::workload_bundle::STREAM_BYTES - OUTPUT_CHUNK_HEADER_BYTES;

#[derive(Debug, Eq, PartialEq)]
pub struct WorkloadOutputChunkV1<'a> {
    pub file_index: u32,
    pub total: u64,
    pub offset: u64,
    pub bytes: &'a [u8],
}
impl<'a> WorkloadOutputChunkV1<'a> {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(OUTPUT_CHUNK_HEADER_BYTES + self.bytes.len());
        bytes.extend_from_slice(&self.file_index.to_be_bytes());
        bytes.extend_from_slice(&self.total.to_be_bytes());
        bytes.extend_from_slice(&self.offset.to_be_bytes());
        bytes.extend_from_slice(self.bytes);
        Ok(bytes)
    }
    pub fn decode(bytes: &'a [u8]) -> Result<Self, String> {
        fn take<const N: usize>(remaining: &mut &[u8]) -> Result<[u8; N], String> {
            let (head, tail) = remaining
                .split_at_checked(N)
                .ok_or("truncated output chunk")?;
            *remaining = tail;
            head.try_into()
                .map_err(|_| "invalid output chunk word".into())
        }
        let mut remaining = bytes;
        let value = Self {
            file_index: u32::from_be_bytes(take(&mut remaining)?),
            total: u64::from_be_bytes(take(&mut remaining)?),
            offset: u64::from_be_bytes(take(&mut remaining)?),
            bytes: remaining,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), String> {
        let end = self
            .offset
            .checked_add(
                u64::try_from(self.bytes.len()).map_err(|_| "output chunk length overflow")?,
            )
            .ok_or("output chunk offset overflow")?;
        if self.bytes.is_empty() || self.bytes.len() > OUTPUT_CHUNK_DATA_BYTES || end > self.total {
            return Err("empty or excessive output chunk".into());
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SnapshotRoleV1 {
    Runtime = 1,
    Input = 2,
}
#[derive(Debug, Eq, PartialEq)]
pub struct WorkloadChunkV1<'a> {
    pub role: SnapshotRoleV1,
    pub member_index: u32,
    pub total: u64,
    pub offset: u64,
    pub bytes: &'a [u8],
}
impl<'a> WorkloadChunkV1<'a> {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(CHUNK_HEADER_BYTES + self.bytes.len());
        bytes.push(self.role as u8);
        bytes.extend_from_slice(&self.member_index.to_be_bytes());
        bytes.extend_from_slice(&self.total.to_be_bytes());
        bytes.extend_from_slice(&self.offset.to_be_bytes());
        bytes.extend_from_slice(self.bytes);
        Ok(bytes)
    }
    pub fn decode(bytes: &'a [u8]) -> Result<Self, String> {
        fn take<'b, const N: usize>(remaining: &mut &'b [u8]) -> Result<[u8; N], String> {
            let (head, tail) = remaining
                .split_at_checked(N)
                .ok_or("truncated workload chunk")?;
            *remaining = tail;
            head.try_into()
                .map_err(|_| "workload chunk word differs".into())
        }
        let mut remaining = bytes;
        let role = match take::<{ size_of::<u8>() }>(&mut remaining)?[0] {
            1 => SnapshotRoleV1::Runtime,
            2 => SnapshotRoleV1::Input,
            _ => return Err("unknown snapshot role".into()),
        };
        let value = Self {
            role,
            member_index: u32::from_be_bytes(take(&mut remaining)?),
            total: u64::from_be_bytes(take(&mut remaining)?),
            offset: u64::from_be_bytes(take(&mut remaining)?),
            bytes: remaining,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), String> {
        let end = self
            .offset
            .checked_add(u64::try_from(self.bytes.len()).map_err(|_| "chunk length overflow")?)
            .ok_or("chunk offset overflow")?;
        if self.bytes.is_empty() || self.bytes.len() > CHUNK_DATA_BYTES || end > self.total {
            return Err("empty or excessive workload chunk".into());
        }
        Ok(())
    }
}
