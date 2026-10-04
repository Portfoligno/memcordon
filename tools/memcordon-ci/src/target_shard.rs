use std::num::NonZeroUsize;

use crate::{CiError, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShardSpec {
    index: usize,
    count: NonZeroUsize,
}

impl ShardSpec {
    pub fn new(index: usize, count: NonZeroUsize) -> Result<Self> {
        if index >= count.get() {
            return Err(CiError::Message("shard index is outside its count".into()));
        }
        Ok(Self { index, count })
    }

    pub fn selects(self, ordinal: usize) -> bool {
        ordinal % self.count.get() == self.index
    }

    pub fn index(self) -> usize {
        self.index
    }

    pub fn count(self) -> usize {
        self.count.get()
    }
}
