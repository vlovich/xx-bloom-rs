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

extern crate bit_vec;
extern crate core;
extern crate xxhash_rust;

use bit_vec::BitVec;
use std::cmp::{max, min};
use std::hash::Hash;

use crate::xxh_helper::RandomXxh3State;
use crate::BloomBuildHasher;

use super::hashing::HashIter;
use super::{Intersectable, Unionable, ASMS};

/// A standard BloomFilter.  If an item is instered then `contains`
/// is guaranteed to return `true` for that item.  For items not
/// inserted `contains` will probably return false.  The probability
/// that `contains` returns `true` for an item that was not inserted
/// is called the False Positive Rate.
///
/// # False Positive Rate
/// The false positive rate is specified as a float in the range
/// (0,1).  If indicates that out of `X` probes, `X * rate` should
/// return a false positive.  Higher values will lead to smaller (but
/// more inaccurate) filters.
///
/// # Example Usage
///
/// ```rust
/// use xx_bloom::{ASMS,BloomFilter};
///
/// let expected_num_items = 1000;
///
/// // out of 100 items that are not inserted, expect 1 to return true for contain
/// let false_positive_rate = 0.01;
///
/// let mut filter = BloomFilter::with_rate(false_positive_rate,expected_num_items);
/// filter.insert(&1);
/// filter.contains(&1); /* true */
/// filter.contains(&2); /* false */
/// ```
pub struct BloomFilter<H = RandomXxh3State>
where
    H: BloomBuildHasher,
{
    bits: BitVec,
    num_hashes: u32,
    hash_builder: H,
}

impl BloomFilter<RandomXxh3State> {
    /// Create a new BloomFilter with the specified number of bits,
    /// and hashes
    pub fn with_size(num_bits: usize, num_hashes: u32) -> BloomFilter<RandomXxh3State> {
        BloomFilter {
            bits: BitVec::from_elem(num_bits, false),
            num_hashes,
            hash_builder: RandomXxh3State::new(),
        }
    }

    /// create a BloomFilter that expects to hold
    /// `expected_num_items`.  The filter will be sized to have a
    /// false positive rate of the value specified in `rate`.
    pub fn with_rate(rate: f32, expected_num_items: u32) -> BloomFilter<RandomXxh3State> {
        let bits = needed_bits(rate, expected_num_items);
        BloomFilter::with_size(bits, optimal_num_hashes(bits, expected_num_items))
    }
}

impl<H> BloomFilter<H>
where
    H: BloomBuildHasher,
{
    /// Create a new BloomFilter with the exact same parameters as the other.
    /// These two filters can be safely intersected and unioned with one another.
    /// Otherwise you have to be careful that not only the number of bits and number of hashes
    /// is the same, but also that the hash algorithms used have the same parameters (the default
    /// hash functions use random state).
    pub fn combinable_with(other: &BloomFilter<H>) -> Self {
        BloomFilter {
            bits: BitVec::from_elem(other.bits.len(), false),
            num_hashes: other.num_hashes,
            hash_builder: other.hash_builder.clone(),
        }
    }
}

impl<H> BloomFilter<H>
where
    H: BloomBuildHasher,
{
    /// Create a new BloomFilter with the specified number of bits,
    /// hashes, and the two specified HashBuilders.  Note the the
    /// HashBuilders MUST provide independent hash values.  Passing
    /// two HashBuilders that produce the same or correlated hash
    /// values will break the false positive guarantees of the
    /// BloomFilter.
    pub fn with_size_and_hasher(
        num_bits: usize,
        num_hashes: u32,
        hash_builder: H,
    ) -> BloomFilter<H> {
        BloomFilter {
            bits: BitVec::from_elem(num_bits, false),
            num_hashes,
            hash_builder,
        }
    }

    /// Create a BloomFilter that expects to hold
    /// `expected_num_items`.  The filter will be sized to have a
    /// false positive rate of the value specified in `rate`.  Items
    /// will be hashed using the Hashers produced by
    /// `hash_builder` and `hash_builder_two`.  Note the the
    /// HashBuilders MUST provide independent hash values.  Passing
    /// two HashBuilders that produce the same or correlated hash
    /// values will break the false positive guarantees of the
    /// BloomFilter.
    pub fn with_rate_and_hasher(
        rate: f32,
        expected_num_items: u32,
        hash_builder: H,
    ) -> BloomFilter<H> {
        let bits = needed_bits(rate, expected_num_items);
        BloomFilter::with_size_and_hasher(
            bits,
            optimal_num_hashes(bits, expected_num_items),
            hash_builder,
        )
    }

    /// Get the number of bits this BloomFilter is using
    pub fn num_bits(&self) -> usize {
        self.bits.len()
    }

    /// Get the number of hash functions this BloomFilter is using
    pub fn num_hashes(&self) -> u32 {
        self.num_hashes
    }

    fn insert_hash_iter(&mut self, h_iter: HashIter) -> bool {
        let mut contained = true;
        for h in h_iter {
            let idx = (h % self.bits.len() as u64) as usize;
            match self.bits.get(idx) {
                Some(b) => {
                    if !b {
                        contained = false;
                    }
                }
                None => {
                    panic!("Hash mod failed in insert");
                }
            }
            self.bits.set(idx, true)
        }
        !contained
    }

    fn contains_hash_iter(&self, h_iter: HashIter) -> bool {
        for h in h_iter {
            let idx = (h % self.bits.len() as u64) as usize;
            match self.bits.get(idx) {
                Some(b) => {
                    if !b {
                        return false;
                    }
                }
                None => {
                    panic!("Hash mod failed");
                }
            }
        }
        true
    }
}

impl<H> ASMS for BloomFilter<H>
where
    H: BloomBuildHasher,
{
    /// Insert item into this BloomFilter.
    ///
    /// If the BloomFilter did not have this value present, `true` is returned.
    ///
    /// If the BloomFilter did have this value present, `false` is returned.
    #[inline]
    fn insert<T: Hash>(&mut self, item: &T) -> bool {
        self.insert_hash_iter(HashIter::from(item, self.num_hashes, &self.hash_builder))
    }

    /// Like `insert` but more optimized path.
    #[inline]
    fn insert_slice(&mut self, item: &[u8]) -> bool {
        self.insert_hash_iter(HashIter::from_slice(
            item,
            self.num_hashes,
            &self.hash_builder,
        ))
    }

    /// Check if the item has been inserted into this bloom filter.
    /// This function can return false positives, but not false
    /// negatives.
    #[inline]
    fn contains<T: Hash>(&self, item: &T) -> bool {
        self.contains_hash_iter(HashIter::from(item, self.num_hashes, &self.hash_builder))
    }

    #[inline]
    fn contains_slice(&self, item: &[u8]) -> bool {
        self.contains_hash_iter(HashIter::from_slice(
            item,
            self.num_hashes,
            &self.hash_builder,
        ))
    }

    /// Remove all values from this BloomFilter
    #[inline]
    fn clear(&mut self) {
        self.bits.clear();
    }
}

impl Intersectable for BloomFilter {
    /// Calculates the intersection of two BloomFilters.  Only items inserted into both filters will still be present in `self`.
    ///
    /// Both BloomFilters must be using the same number of
    /// bits. Returns true if self changed.
    ///
    /// # Panics
    /// Panics if the BloomFilters are not using the same number of bits
    fn intersect(&mut self, other: &BloomFilter) -> bool {
        self.bits.and(&other.bits)
    }
}

impl Unionable for BloomFilter {
    /// Calculates the union of two BloomFilters.  Items inserted into
    /// either filters will be present in `self`.
    ///
    /// Both BloomFilters must be using the same number of
    /// bits. Returns true if self changed.
    ///
    /// # Panics
    /// Panics if the BloomFilters are not using the same number of bits
    fn union(&mut self, other: &BloomFilter) -> bool {
        self.bits.or(&other.bits)
    }
}

/// Return the optimal number of hashes to use for the given number of
/// bits and items in a filter
pub fn optimal_num_hashes(num_bits: usize, num_items: u32) -> u32 {
    min(
        max(
            (num_bits as f32 / num_items as f32 * core::f32::consts::LN_2).round() as u32,
            2,
        ),
        200,
    )
}

/// Return the number of bits needed to satisfy the specified false
/// positive rate, if the filter will hold `num_items` items.
pub fn needed_bits(false_pos_rate: f32, num_items: u32) -> usize {
    let ln22 = core::f32::consts::LN_2 * core::f32::consts::LN_2;
    (num_items as f32 * ((1.0 / false_pos_rate).ln() / ln22)).round() as usize
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use super::{needed_bits, optimal_num_hashes, BloomFilter};
    use crate::{Intersectable, Unionable, ASMS};
    use std::collections::HashSet;

    #[test]
    fn simple() {
        let mut b: BloomFilter = BloomFilter::with_rate(0.01, 100);
        b.insert(&1);
        assert!(b.contains(&1));
        assert!(!b.contains(&2));
        b.clear();
        assert!(!b.contains(&1));
    }

    #[test]
    fn intersect() {
        let mut b1 = BloomFilter::with_rate(0.01, 20);
        b1.insert(&1);
        b1.insert(&2);
        let mut b2 = BloomFilter::combinable_with(&b1);
        b2.insert(&1);

        b1.intersect(&b2);

        assert!(b1.contains(&1));
        assert!(!b1.contains(&2));
    }

    #[test]
    fn union() {
        let mut b1 = BloomFilter::with_rate(0.01, 20);
        b1.insert(&1);
        let mut b2 = BloomFilter::combinable_with(&b1);
        b2.insert(&2);

        b1.union(&b2);

        assert!(b1.contains(&1));
        assert!(b1.contains(&2));
    }

    #[test]
    fn fpr_test() {
        let cnt = 500000;
        let rate = 0.01 as f32;

        let bits = needed_bits(rate, cnt);
        assert_eq!(bits, 4792529);
        let hashes = optimal_num_hashes(bits, cnt);
        assert_eq!(hashes, 7);

        let mut b: BloomFilter = BloomFilter::with_rate(rate, cnt);
        let mut set: HashSet<i32> = HashSet::new();
        let mut rng = rand::thread_rng();

        let mut i = 0;

        while i < cnt {
            let v = rng.gen::<i32>();
            set.insert(v);
            b.insert(&v);
            i += 1;
        }

        i = 0;
        let mut false_positives = 0;
        while i < cnt {
            let v = rng.gen::<i32>();
            match (b.contains(&v), set.contains(&v)) {
                (true, false) => {
                    false_positives += 1;
                }
                (false, true) => {
                    assert!(false);
                } // should never happen
                _ => {}
            }
            i += 1;
        }

        // make sure we're not too far off
        let actual_rate = false_positives as f32 / cnt as f32;
        assert!(actual_rate > (rate - 0.001));
        assert!(actual_rate < (rate + 0.001));
    }
}
