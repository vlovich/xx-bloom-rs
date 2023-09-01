use std::{hash::BuildHasher, mem::MaybeUninit};

use xxhash_rust::xxh3::{Xxh3, Xxh3Builder};

#[derive(Clone, Copy, Default)]
pub struct RandomXxh3State(Xxh3Builder);

const DEFAULT_SECRET_SIZE: usize = 192;

fn random_secret() -> [u8; DEFAULT_SECRET_SIZE] {
    let mut v =
        unsafe { MaybeUninit::<[MaybeUninit<u8>; DEFAULT_SECRET_SIZE]>::uninit().assume_init() };
    getrandom::getrandom_uninit(&mut v).unwrap().try_into().unwrap()
}

impl RandomXxh3State {
    #[inline(always)]
    ///Creates new instance with default params.
    pub fn new() -> Self {
        // From Rust's internals for RandomState
        thread_local!(static SECRET: std::cell::RefCell<[u8; DEFAULT_SECRET_SIZE]> = {
            std::cell::RefCell::new(random_secret())
        });

        Self(SECRET.with(|cell| {
            let mut secret = cell.borrow_mut();
            let randomized_u64_bytes = secret.split_at_mut(8).0;
            let randomized_u64 = u64::from_ne_bytes(randomized_u64_bytes.try_into().unwrap()).wrapping_add(1);
            randomized_u64_bytes.copy_from_slice(&randomized_u64.to_ne_bytes());
            Xxh3Builder::new().with_secret(secret.clone())
        }))
    }

    #[inline(always)]
    ///Sets `seed` for `xxh3` algorithm
    pub const fn with_seed(self, seed: u64) -> Self {
        self.0.with_seed(seed);
        self
    }

    #[inline(always)]
    ///Sets custom `secret` for `xxh3` algorithm
    pub const fn with_secret(self, secret: [u8; 192]) -> Self {
        self.0.with_secret(secret);
        self
    }

    #[inline(always)]
    ///Creates `Xxh3` instance
    pub const fn build(self) -> Xxh3 {
        self.0.build()
    }
}

impl BuildHasher for RandomXxh3State {
    type Hasher = Xxh3;

    #[inline(always)]
    fn build_hasher(&self) -> Self::Hasher {
        self.0.build_hasher()
    }
}
