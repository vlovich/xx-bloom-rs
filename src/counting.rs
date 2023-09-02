use crate::xxh_helper::RandomXxh3State;
use crate::BloomBuildHasher;
use crate::BloomFingerprint;

use super::hashing::HashIter;
use super::ValueVec;
use super::ASMS;
use std::hash::Hash;

/// A standard counting bloom filter that uses a fixed number of bits
/// per counter, supports remove, and estimating the count of the
/// number of items inserted.
pub struct CountingBloomFilter<H = RandomXxh3State> {
    counters: ValueVec,
    num_entries: u64,
    num_hashes: u32,
    hash_builder: H,
}

impl CountingBloomFilter<RandomXxh3State> {
    /// Create a new CountingBloomFilter that will hold `num_entries`
    /// items, uses `bits_per_entry` per item, and `num_hashes` hashes
    pub fn with_size(
        num_entries: usize,
        bits_per_entry: usize,
        num_hashes: u32,
    ) -> CountingBloomFilter<RandomXxh3State> {
        CountingBloomFilter {
            counters: ValueVec::new(bits_per_entry, num_entries),
            num_entries: num_entries as u64,
            num_hashes: num_hashes,
            hash_builder: RandomXxh3State::new(),
        }
    }

    /// create a CountingBloomFilter that uses `bits_per_entry`
    /// entries and expects to hold `expected_num_items`.  The filter
    /// will be sized to have a false positive rate of the value
    /// specified in `rate`.
    pub fn with_rate(
        bits_per_entry: usize,
        rate: f32,
        expected_num_items: u32,
    ) -> CountingBloomFilter<RandomXxh3State> {
        let entries = super::bloom::needed_bits(rate, expected_num_items);
        CountingBloomFilter::with_size(
            entries,
            bits_per_entry,
            super::bloom::optimal_num_hashes(entries, expected_num_items),
        )
    }

    /// Return the number of bits needed to hold values up to and
    /// including `max`
    ///
    /// # Example
    ///
    /// ```rust
    /// use xx_bloom::CountingBloomFilter;
    /// // Create a CountingBloomFilter that can count up to 10 on each entry, and with 1000
    /// // items will have a false positive rate of 0.01
    /// let cfb = CountingBloomFilter::with_rate(CountingBloomFilter::bits_for_max(10),
    ///                                          0.01,
    ///                                          1000);
    /// ```
    pub fn bits_for_max(max: u32) -> usize {
        let mut bits_per_val = 0;
        let mut cur = max;
        while cur > 0 {
            bits_per_val += 1;
            cur >>= 1;
        }
        bits_per_val
    }
}

impl<H> CountingBloomFilter<H>
where
    H: BloomBuildHasher,
{
    /// Create a new CountingBloomFilter with the specified number of
    /// bits, hashes, and the two specified HashBuilders.  Note the
    /// the HashBuilders MUST provide independent hash values.
    /// Passing two HashBuilders that produce the same or correlated
    /// hash values will break the false positive guarantees of the
    /// CountingBloomFilter.
    pub fn with_size_and_hasher(
        num_entries: usize,
        bits_per_entry: usize,
        num_hashes: u32,
        hash_builder: H,
    ) -> CountingBloomFilter<H> {
        CountingBloomFilter {
            counters: ValueVec::new(bits_per_entry, num_entries),
            num_entries: num_entries as u64,
            num_hashes,
            hash_builder,
        }
    }

    /// Create a CountingBloomFilter that expects to hold
    /// `expected_num_items`.  The filter will be sized to have a
    /// false positive rate of the value specified in `rate`.  Items
    /// will be hashed using the Hasher produced by
    /// `hash_builder`.  Note the the
    /// HashBuilders MUST provide independent hash values.  Passing
    /// two HashBuilders that produce the same or correlated hash
    /// values will break the false positive guarantees of the
    /// CountingBloomFilter.
    pub fn with_rate_and_hasher(
        bits_per_entry: usize,
        rate: f32,
        expected_num_items: u32,
        hash_builder: H,
    ) -> CountingBloomFilter<H> {
        let entries = super::bloom::needed_bits(rate, expected_num_items);
        CountingBloomFilter::with_size_and_hasher(
            entries,
            bits_per_entry,
            super::bloom::optimal_num_hashes(entries, expected_num_items),
            hash_builder,
        )
    }

    fn remove_hash_iter(&mut self, h_iter: HashIter) -> u32 {
        if !(self as &CountingBloomFilter<H>).contains_hash_iter(h_iter) {
            return 0;
        }
        let mut min = u32::max_value();
        for h in h_iter {
            let idx = (h % self.num_entries) as usize;
            let cur = self.counters.get(idx);
            if cur < min {
                min = cur;
            }
            if cur > 0 {
                self.counters.set(idx, cur - 1);
            } else {
                panic!("Contains returned true but a counter is 0");
            }
        }
        min
    }
    /// Remove an item.  Returns an upper bound of the number of times
    /// this item had been inserted previously (i.e. the count before
    /// this remove).  Returns 0 if item was never inserted.
    #[inline(always)]
    pub fn remove<T: Hash>(&mut self, item: &T) -> u32 {
        self.remove_hash_iter(HashIter::from(item, self.num_hashes, &self.hash_builder))
    }

    /// Remove an item.  Returns an upper bound of the number of times
    /// this item had been inserted previously (i.e. the count before
    /// this remove).  Returns 0 if item was never inserted.
    /// This is a fast path when the items you're dealing with are byte slices.
    #[inline(always)]
    pub fn remove_slice(&mut self, item: &[u8]) -> u32 {
        self.remove_hash_iter(HashIter::from_slice(
            item,
            self.num_hashes,
            &self.hash_builder,
        ))
    }

    /// Remove an item.  Returns an upper bound of the number of times
    /// this item had been inserted previously (i.e. the count before
    /// this remove).  Returns 0 if item was never inserted.
    /// This is a fast path when you have a set of filters that share the same
    /// BloomBuildHasher where you can amortize the key hash across all your
    /// filters.
    #[inline(always)]
    pub fn remove_fingerprint(&mut self, fingerprint: BloomFingerprint) -> u32 {
        self.remove_hash_iter(HashIter::from_fingerprint(fingerprint, self.num_hashes))
    }

    fn estimate_count_hash_iter(&self, h_iter: HashIter) -> u32 {
        let mut min = u32::max_value();
        for h in h_iter {
            let idx = (h % self.num_entries) as usize;
            let cur = self.counters.get(idx);
            if cur < min {
                min = cur;
            }
        }
        min
    }

    /// Return an estimate of the number of times `item` has been
    /// inserted into the filter.  Estimate is a upper bound on the
    /// count, meaning the item has been inserted *at most* this many
    /// times, but possibly fewer.
    #[inline(always)]
    pub fn estimate_count<T: Hash>(&self, item: &T) -> u32 {
        self.estimate_count_hash_iter(HashIter::from(item, self.num_hashes, &self.hash_builder))
    }

    /// Return an estimate of the number of times `item` has been
    /// inserted into the filter.  Estimate is a upper bound on the
    /// count, meaning the item has been inserted *at most* this many
    /// times, but possibly fewer.
    /// This is a fast-path for when your item is a byte slice.
    #[inline(always)]
    pub fn estimate_count_slice(&self, item: &[u8]) -> u32 {
        self.estimate_count_hash_iter(HashIter::from_slice(item, self.num_hashes, &self.hash_builder))
    }

    /// Return an estimate of the number of times `item` has been
    /// inserted into the filter.  Estimate is a upper bound on the
    /// count, meaning the item has been inserted *at most* this many
    /// times, but possibly fewer.
    /// This is a fast-path for when you want to amortize the lookup
    /// across multiple filters sharing the same hash algorithm.
    #[inline(always)]
    pub fn estimate_count_fingerprint(&self, fp: BloomFingerprint) -> u32 {
        self.estimate_count_hash_iter(HashIter::from_fingerprint(fp, self.num_hashes))
    }

    fn insert_get_count_hash_iter(&mut self, h_iter: HashIter) -> u32 {
        let mut min = u32::max_value();
        for h in h_iter {
            let idx = (h % self.num_entries) as usize;
            let cur = self.counters.get(idx);
            if cur < min {
                min = cur;
            }
            if cur < self.counters.max_value() {
                self.counters.set(idx, cur + 1);
            }
        }
        min
    }

    /// Inserts an item, returns the estimated count of the number of
    /// times this item had previously been inserted (not counting
    /// this insertion)
    #[inline(always)]
    pub fn insert_get_count<T: Hash>(&mut self, item: &T) -> u32 {
        self.insert_get_count_hash_iter(HashIter::from(item, self.num_hashes, &self.hash_builder))
    }

    /// Inserts an item, returns the estimated count of the number of
    /// times this item had previously been inserted (not counting
    /// this insertion).
    /// This is a fast-path for when the item is a byte slice.
    #[inline(always)]
    pub fn insert_get_count_slice(&mut self, item: &[u8]) -> u32 {
        self.insert_get_count_hash_iter(HashIter::from_slice(item, self.num_hashes, &self.hash_builder))
    }

    /// Inserts an item, returns the estimated count of the number of
    /// times this item had previously been inserted (not counting
    /// this insertion)
    /// This is a fast-path that lets you want to amortize this across
    /// multiple filters sharing the same hash algorithm.
    #[inline(always)]
    pub fn insert_get_count_fingerprint(&mut self, fp: BloomFingerprint) -> u32 {
        self.insert_get_count_hash_iter(HashIter::from_fingerprint(fp, self.num_hashes))
    }

    fn insert_hash_iter(&mut self, h_iter: HashIter) -> bool {
        let mut min = u32::max_value();
        for h in h_iter {
            let idx = (h % self.num_entries) as usize;
            let cur = self.counters.get(idx);
            if cur < min {
                min = cur;
            }
            if cur < self.counters.max_value() {
                self.counters.set(idx, cur + 1);
            }
        }
        min > 0
    }

    fn contains_hash_iter(&self, h_iter: HashIter) -> bool {
        for h in h_iter {
            let idx = (h % self.num_entries) as usize;
            let cur = self.counters.get(idx);
            if cur == 0 {
                return false;
            }
        }
        true
    }
}

impl<H> ASMS for CountingBloomFilter<H>
where
    H: BloomBuildHasher,
{
    /// Inserts an item, returns true if this item was already in the
    /// filter any number of times
    #[inline(always)]
    fn insert<T: Hash>(&mut self, item: &T) -> bool {
        self.insert_hash_iter(HashIter::from(item, self.num_hashes, &self.hash_builder))
    }

    #[inline(always)]
    fn insert_slice(&mut self, item: &[u8]) -> bool {
        self.insert_hash_iter(HashIter::from_slice(
            item,
            self.num_hashes,
            &self.hash_builder,
        ))
    }

    #[inline(always)]
    fn insert_fingerprint(&mut self, fingerprint: crate::BloomFingerprint) -> bool {
        self.insert_hash_iter(HashIter::from_fingerprint(fingerprint, self.num_hashes))
    }

    /// Check if the item has been inserted into this
    /// CountingBloomFilter.  This function can return false
    /// positives, but not false negatives.
    #[inline(always)]
    fn contains<T: Hash>(&self, item: &T) -> bool {
        self.contains_hash_iter(HashIter::from(item, self.num_hashes, &self.hash_builder))
    }

    #[inline(always)]
    fn contains_slice(&self, item: &[u8]) -> bool {
        // TODO: optimize
        self.contains_hash_iter(HashIter::from_slice(
            item,
            self.num_hashes,
            &self.hash_builder,
        ))
    }

    #[inline(always)]
    fn contains_fingerprint(&self, fingerprint: crate::BloomFingerprint) -> bool {
        self.contains_hash_iter(HashIter::from_fingerprint(fingerprint, self.num_hashes))
    }

    /// Remove all values from this CountingBloomFilter
    fn clear(&mut self) {
        self.counters.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::CountingBloomFilter;
    use crate::ASMS;

    #[test]
    fn simple() {
        let mut cbf: CountingBloomFilter = CountingBloomFilter::with_rate(4, 0.01, 100);
        assert_eq!(cbf.insert(&1), false);
        assert!(cbf.contains(&1));
        assert!(!cbf.contains(&2));
    }

    #[test]
    fn remove() {
        let mut cbf: CountingBloomFilter =
            CountingBloomFilter::with_rate(CountingBloomFilter::bits_for_max(10), 0.01, 100);
        assert_eq!(cbf.insert_get_count(&1), 0);
        cbf.insert(&2);
        assert!(cbf.contains(&1));
        assert!(cbf.contains(&2));
        assert_eq!(cbf.remove(&2), 1);
        assert_eq!(cbf.remove(&3), 0);
        assert!(cbf.contains(&1));
        assert!(!cbf.contains(&2));
    }

    #[test]
    fn estimate_count() {
        let mut cbf: CountingBloomFilter = CountingBloomFilter::with_rate(4, 0.01, 100);
        cbf.insert(&1);
        cbf.insert(&2);
        assert_eq!(cbf.estimate_count(&1), 1);
        assert_eq!(cbf.estimate_count(&2), 1);
        assert_eq!(cbf.insert_get_count(&1), 1);
        assert_eq!(cbf.estimate_count(&1), 2);
    }
}
