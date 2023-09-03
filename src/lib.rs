// A Rust BloomFilter implementation.
// Copywrite (c) 2016 Nick Lanham

// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License as
// published by the Free Software Foundation; either version 2 of the
// License, or (at your option) any later version.

// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
// 02110-1301, USA.

//! An implementation of various Approximate Set Membership structures
//! in Rust.  Currently included are a standard Bloom Filter, and the
//! simplest kind of Counting Bloom Filter.
//!
//! # Usage
//!
//! This crate is [on crates.io](https://crates.io/crates/rand) and
//! can be used by adding `bloom` to the dependencies in your
//! project's `Cargo.toml`.
//!
//! ```toml
//! [dependencies]
//! xx-bloom = "0.4.0"
//! ```
//!
//! add this to your crate root:
//!
//! ```rust
//! extern crate xx_bloom;
//! ```
//!
//! # Bloom Filters
//!
//! A Bloom Filter is an Approximate Set Membership structure, which
//! means it can track a set of items and check if an item is a member
//! of the set it is tracking.  It is able to do this using a much
//! smaller amount of memory than storing the actual items, at the
//! cost of an occasionally indicating that an item is in the set even
//! though it is not.  This occurence is called a "False Positive".  A
//! traditional Bloom Filter will never have a "False Negative"
//! however, which would be indicating that an item is *not* in the
//! set, when in fact it is.  The frequency of false positives can be
//! preciecly bounded by setting the size of the filter, and is called
//! the False Positive Rate.  Their small memory footprint and absence
//! of false negatives makes BloomFilters suitable for many
//! applications.
//!
//! # Example Usage
//!
//! ```rust
//! use xx_bloom::{ASMS,BloomFilter};
//!
//! let expected_num_items = 1000;
//!
//! // out of 100 items that are not inserted, expect 1 to return true for contain
//! let false_positive_rate = 0.01;
//!
//! let mut filter = BloomFilter::with_rate(false_positive_rate,expected_num_items);
//! filter.insert(&1);
//! filter.contains(&1); /* true */
//! filter.contains(&2); /* probably false */
//! ```
//!
//! # Counting Bloom Filters
//!
//! Counting filters allow removal from a Bloom filter without
//! recreating the filter afresh. A counting filter uses an n-bit
//! counter where a standard Bloom Filter uses a single bit.  Counting
//! filters can also provide an upper bound on the number of times a
//! particular element has been inserted into the filter.  In general
//! 4 bits per element is considered a good size.  This will cause the
//! filter to use 4 times as much memory as compared to standard Bloom
//! Filter.
//!
//! # Example Usage
//!
//! ```rust
//! use xx_bloom::{ASMS,CountingBloomFilter};
//! // Create a counting filter that uses 4 bits per element and has a false positive rate
//! // of 0.01 when 100 items have been inserted
//! let mut cbf:CountingBloomFilter = CountingBloomFilter::with_rate(4,0.01,100);
//! cbf.insert(&1);
//! cbf.insert(&2);
//! assert_eq!(cbf.estimate_count(&1),1);
//! assert_eq!(cbf.estimate_count(&2),1);
//! assert_eq!(cbf.insert_get_count(&1),1);
//! assert_eq!(cbf.estimate_count(&1),2);
//! assert_eq!(cbf.remove(&1),2);
//! assert_eq!(cbf.estimate_count(&1),1);
//! ```

#![crate_name = "xx_bloom"]
#![crate_type = "rlib"]
#![cfg_attr(feature = "do-bench", feature(test))]

extern crate bit_vec;
extern crate core;
use std::hash::{Hash, Hasher};

mod hashing;
mod std_hasher;
mod xxh_helper;

pub mod bloom;
pub use crate::bloom::{needed_bits, optimal_num_hashes, BloomFilter};

pub mod counting;
pub use crate::counting::CountingBloomFilter;

pub mod valuevec;
pub use crate::valuevec::ValueVec;
pub use std_hasher::*;
pub use xxh_helper::*;
pub const XXH3_SECRET_SIZE: usize = xxh_helper::DEFAULT_SECRET_SIZE;

/// This is an opaque container of the raw underlying information for a key.
/// If you have a bunch of filters with the exact BloomBuildHasher being used,
/// then you can quickly check the fingerprint in all of them without needing to
/// rehash your key constantly.
#[derive(Copy, Clone)]
pub struct BloomFingerprint {
    pub(crate) h1: u64,
    pub(crate) h2: u64,
}

impl BloomFingerprint {
    #[inline(always)]
    pub fn new(h1: u64, h2: u64) -> Self {
        Self { h1, h2 }
    }

    #[inline(always)]
    pub fn new_128(h: u128) -> Self {
        Self::new((h >> 64) as u64, h as u64)
    }
}

/// Extends Hasher so that we can get the full underlying 128-bit digest if
/// it's implemented natively as such.
pub trait BloomHasher: Hasher {
    fn finish_128(&self) -> BloomFingerprint;
}

/// Like BuildHasher, except bloom filters use 128-bit hashes which can be more efficiently
/// obtained sometimes rather than using the std hash api.
pub trait BloomBuildHasher: Clone {
    type Hasher: BloomHasher;

    fn build_hasher(&self) -> Self::Hasher;
    fn hash_one_128(&self, k: &[u8]) -> BloomFingerprint;
}

/// Stanard filter functions
pub trait ASMS {
    fn insert<T: Hash>(&mut self, item: &T);
    fn insert_slice(&mut self, item: &[u8]);
    fn insert_fingerprint(&mut self, fingerprint: BloomFingerprint);
    fn contains<T: Hash>(&self, item: &T) -> bool;
    fn contains_slice(&self, item: &[u8]) -> bool;
    fn contains_fingerprint(&self, fingerprint: BloomFingerprint) -> bool;
    fn clear(&mut self);
}

/// Filters that implement this trait can be intersected with filters
/// of the same type to produce a filter that contains the
/// items that have been inserted into *both* filters.
///
/// Both filters MUST be the same size and be using the same hash
/// functions for this to work.  Will panic if the filters are not the
/// same size, but will simply produce incorrect (meaningless) results
/// if the filters are using different hash functions.
pub trait Intersectable {
    fn intersect(&mut self, other: &Self);
}

/// Filters that implement this trait can be unioned with filters
/// of the same type to produce a filter that contains the
/// items that have been inserted into *either* filter.
///
/// Both filters MUST be the same size and be using the same hash
/// functions for this to work.  Will panic if the filters are not the
/// same size, but will simply produce incorrect (meaningless) results
/// if the filters are using different hash functions.
pub trait Unionable {
    fn union(&mut self, other: &Self);
}

/// Filters than are Combineable can be unioned and intersected
pub trait Combineable: Intersectable + Unionable {}
impl<T> Combineable for T where T: Intersectable + Unionable {}
