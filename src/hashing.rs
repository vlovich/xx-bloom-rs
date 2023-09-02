use std::hash::Hash;

use crate::{BloomBuildHasher, BloomHasher};
// utilities for hashing

pub struct HashIter {
    h1: u64,
    h2: u64,
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
            0 => self.h1,
            1 => self.h2,
            _ => {
                let p1 = self.h1.wrapping_add(self.i as u64);
                p1.wrapping_mul(self.h2)
            }
        };
        self.i += 1;
        Some(r)
    }
}

impl HashIter {
    #[inline(always)]
    pub fn from<T: Hash, H: BloomBuildHasher>(item: T, count: u32, build_hasher: &H) -> HashIter {
        let mut hasher = build_hasher.build_hasher();
        item.hash(&mut hasher);
        let (h1, h2) = hasher.finish_128();
        HashIter {
            h1: h1,
            h2: h2,
            i: 0,
            count: count,
        }
    }

    #[inline(always)]
    pub fn from_slice<H: BloomBuildHasher>(item: &[u8], count: u32, build_hasher: &H) -> HashIter {
        let (h1, h2) = build_hasher.hash_one_128(item);
        HashIter {
            h1: h1,
            h2: h2,
            i: 0,
            count: count,
        }
    }
}
