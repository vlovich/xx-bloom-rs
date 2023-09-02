use std::hash::Hash;

use crate::{BloomBuildHasher, BloomFingerprint, BloomHasher};
// utilities for hashing

#[derive(Copy, Clone)]
pub struct HashIter {
    fp: BloomFingerprint,
    i: u32,
    count: u32,
}

impl Iterator for HashIter {
    type Item = u64;

    fn next(&mut self) -> Option<u64> {
        if self.i == self.count {
            return None;
        }
        let r = match self.i {
            0 => self.fp.h1,
            1 => self.fp.h2,
            _ => {
                let p1 = self.fp.h1.wrapping_add(self.i as u64);
                p1.wrapping_mul(self.fp.h2)
            }
        };
        self.i += 1;
        Some(r)
    }
}

impl HashIter {
    #[inline(always)]
    pub fn from<T: Hash, H: BloomBuildHasher>(item: T, count: u32, build_hasher: &H) -> Self {
        let mut hasher = build_hasher.build_hasher();
        item.hash(&mut hasher);
        Self {
            fp: hasher.finish_128(),
            i: 0,
            count,
        }
    }

    #[inline(always)]
    pub fn from_slice<H: BloomBuildHasher>(item: &[u8], count: u32, build_hasher: &H) -> Self {
        Self {
            fp: build_hasher.hash_one_128(item),
            i: 0,
            count,
        }
    }

    #[inline(always)]
    pub fn from_fingerprint(fp: BloomFingerprint, count: u32) -> Self {
        Self { fp, i: 0, count }
    }
}
