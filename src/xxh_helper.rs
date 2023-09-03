use std::mem::MaybeUninit;

use xxhash_rust::xxh3::{Xxh3, Xxh3Builder};

use crate::{BloomBuildHasher, BloomFingerprint, BloomHasher};

pub(crate) const DEFAULT_SECRET_SIZE: usize = 192;

impl BloomHasher for Xxh3 {
    fn finish_128(&self) -> BloomFingerprint {
        BloomFingerprint::new_128(self.digest128())
    }
}

#[derive(Clone, Copy)]
pub struct RandomXxh3State {
    secret: [u8; DEFAULT_SECRET_SIZE],
}

fn random_secret() -> [u8; DEFAULT_SECRET_SIZE] {
    let mut v =
        unsafe { MaybeUninit::<[MaybeUninit<u8>; DEFAULT_SECRET_SIZE]>::uninit().assume_init() };
    getrandom::getrandom_uninit(&mut v)
        .unwrap()
        .try_into()
        .unwrap()
}

impl RandomXxh3State {
    #[inline(always)]
    ///Creates new instance with default params.
    pub fn new() -> Self {
        // From Rust's internals for RandomState
        thread_local!(static SECRET: std::cell::RefCell<[u8; DEFAULT_SECRET_SIZE]> = {
            std::cell::RefCell::new(random_secret())
        });

        Self {
            secret: SECRET.with(|cell| {
                let mut secret = cell.borrow_mut();
                let randomized_u64_bytes = secret.split_at_mut(8).0;
                let randomized_u64 =
                    u64::from_ne_bytes(randomized_u64_bytes.try_into().unwrap()).wrapping_add(1);
                randomized_u64_bytes.copy_from_slice(&randomized_u64.to_ne_bytes());
                secret.clone()
            }),
        }
    }

    #[inline(always)]
    ///Creates `Xxh3` instance
    pub const fn build(self) -> Xxh3 {
        Xxh3Builder::new().with_secret(self.secret).build()
    }

    #[inline(always)]
    pub const fn secret(&self) -> &[u8] {
        &self.secret
    }
}

impl Default for RandomXxh3State {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

impl BloomBuildHasher for RandomXxh3State {
    type Hasher = Xxh3;

    #[inline(always)]
    fn build_hasher(&self) -> Self::Hasher {
        Xxh3::with_secret(self.secret)
    }

    #[inline(always)]
    fn hash_one_128(&self, k: &[u8]) -> BloomFingerprint {
        let h = xxhash_rust::xxh3::xxh3_128_with_secret(k, &self.secret);
        BloomFingerprint::new_128(h)
    }
}

#[derive(Copy, Clone)]
pub struct SecretBasedXxh3Builder {
    secret: [u8; DEFAULT_SECRET_SIZE],
}

impl SecretBasedXxh3Builder {
    #[inline(always)]
    pub const fn with_secret(secret: [u8; DEFAULT_SECRET_SIZE]) -> Self {
        Self { secret }
    }

    #[inline(always)]
    pub const fn build(&self) -> Xxh3 {
        Xxh3::with_secret(self.secret)
    }
}

impl BloomBuildHasher for SecretBasedXxh3Builder {
    type Hasher = Xxh3;

    #[inline(always)]
    fn build_hasher(&self) -> Self::Hasher {
        self.build()
    }

    #[inline(always)]
    fn hash_one_128(&self, k: &[u8]) -> BloomFingerprint {
        let h = xxhash_rust::xxh3::xxh3_128_with_secret(k, &self.secret);
        BloomFingerprint::new_128(h)
    }
}
