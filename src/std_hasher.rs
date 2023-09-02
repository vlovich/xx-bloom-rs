use std::{
    collections::hash_map::RandomState,
    hash::{BuildHasher, Hasher},
};

use crate::{BloomBuildHasher, BloomFingerprint, BloomHasher};

pub struct Hasher128Adapter<R, S>
where
    R: Hasher,
    S: Hasher,
{
    h1: R,
    h2: S,
}

impl<R, S> Hasher for Hasher128Adapter<R, S>
where
    R: Hasher,
    S: Hasher,
{
    fn finish(&self) -> u64 {
        unimplemented!("64-finish cannot be called on a BloomHasher. Use finish_128");
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        self.h1.write(bytes);
        self.h2.write(bytes);
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.h1.write_u8(i);
        self.h2.write_u8(i);
    }

    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.h1.write_u16(i);
        self.h2.write_u16(i);
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.h1.write_u32(i);
        self.h2.write_u32(i);
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.h1.write_u64(i);
        self.h2.write_u64(i);
    }

    #[inline]
    fn write_u128(&mut self, i: u128) {
        self.h1.write_u128(i);
        self.h2.write_u128(i);
    }

    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.h1.write_usize(i);
        self.h2.write_usize(i);
    }

    #[inline]
    fn write_i8(&mut self, i: i8) {
        self.h1.write_i8(i);
        self.h2.write_i8(i);
    }

    #[inline]
    fn write_i16(&mut self, i: i16) {
        self.h1.write_i16(i);
        self.h2.write_i16(i);
    }

    #[inline]
    fn write_i32(&mut self, i: i32) {
        self.h1.write_i32(i);
        self.h2.write_i32(i);
    }

    #[inline]
    fn write_i64(&mut self, i: i64) {
        self.h1.write_i64(i);
        self.h2.write_i64(i);
    }

    #[inline]
    fn write_i128(&mut self, i: i128) {
        self.h1.write_i128(i);
        self.h2.write_i128(i);
    }

    #[inline]
    fn write_isize(&mut self, i: isize) {
        self.h1.write_isize(i);
        self.h2.write_isize(i);
    }
}

impl<R, S> BloomHasher for Hasher128Adapter<R, S>
where
    R: Hasher,
    S: Hasher,
{
    #[inline]
    fn finish_128(&self) -> BloomFingerprint {
        BloomFingerprint::new(self.h1.finish(), self.h2.finish())
    }
}

/// Convenience utility to generate a 128-bit digest from 2 64-bit digests (defaulting to using
/// the std hasher).RR
#[derive(Default, Clone)]
pub struct BuildHasher128Adapter<R = RandomState, S = RandomState>
where
    R: Clone + BuildHasher,
    S: Clone + BuildHasher,
{
    h1: R,
    h2: S,
}

impl BuildHasher128Adapter<RandomState, RandomState> {
    #[inline]
    pub fn new() -> Self {
        Self {
            h1: RandomState::new(),
            h2: RandomState::new(),
        }
    }
}

impl<R, S> BuildHasher128Adapter<R, S>
where
    R: Clone + BuildHasher,
    S: Clone + BuildHasher,
{
    #[inline]
    pub fn with_hashers(h1: R, h2: S) -> Self {
        Self { h1, h2 }
    }
}

impl<R, S> BloomBuildHasher for BuildHasher128Adapter<R, S>
where
    R: Clone + BuildHasher,
    S: Clone + BuildHasher,
{
    type Hasher = Hasher128Adapter<R::Hasher, S::Hasher>;

    #[inline(always)]
    fn build_hasher(&self) -> Self::Hasher {
        Hasher128Adapter {
            h1: self.h1.build_hasher(),
            h2: self.h2.build_hasher(),
        }
    }

    #[inline(always)]
    fn hash_one_128(&self, k: &[u8]) -> BloomFingerprint {
        BloomFingerprint::new(self.h1.hash_one(k), self.h2.hash_one(k))
    }
}
