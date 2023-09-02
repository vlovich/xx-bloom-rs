use std::{collections::hash_map::RandomState, hint::black_box};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::Rng;
use xx_bloom::{BloomFilter, BuildHasher128Adapter, ASMS, RandomXxh3State, BloomBuildHasher};

// Since no way to get this value cross-platform, manually set it to larger than reasonable.
// Most tests just reuse the same slice over and over again, but that's not representative of
// realistic workloads where the slice fed into the filter is in a different memory location
// each time.
const GUARANTEED_LARGER_THAN_CACHE: usize = 512 * 1024 * 1024;

#[inline(always)]
fn get_random_key<'a>(large_buffer: &'a [u8], offset: &mut usize, size: usize) -> &'a [u8] {
    let key: &[u8] = unsafe { large_buffer.get_unchecked(*offset..*offset + size) };
    *offset = (*offset + size) % GUARANTEED_LARGER_THAN_CACHE;
    key
}

fn benchmark(c: &mut Criterion) {
    let mut rng = rand::thread_rng();

    let key_buffer = Vec::from_iter(
        std::iter::from_fn(|| Some(rng.gen::<u8>())).take(GUARANTEED_LARGER_THAN_CACHE),
    );

    {
        let mut group = c.benchmark_group("Insertion");
        let num_keys = 1_000_000;
        for key_size in [5, 7, 17, 31, 47, 97, 127, 257, 521] {
            group.throughput(criterion::Throughput::Bytes(key_size.try_into().unwrap()));
            group.bench_with_input(
                BenchmarkId::new("std::collections::hash_map::RandomState", key_size),
                &key_size,
                |b, _| {
                    let mut offset = 0;
                    let mut filter = BloomFilter::with_rate_and_hasher(
                        0.01,
                        num_keys + 300_000,
                        BuildHasher128Adapter::with_hashers(RandomState::new(), RandomState::new()),
                    );
                    b.iter(|| {
                        let key = get_random_key(&key_buffer, &mut offset, key_size);
                        black_box(filter.insert(&key));
                    });
                },
            );
            group.bench_with_input(BenchmarkId::new("xxh3", key_size), &key_size, |b, _| {
                let mut offset = 0;
                let mut filter = BloomFilter::with_rate(0.01, num_keys + 300_000);
                b.iter(|| {
                    let key = get_random_key(&key_buffer, &mut offset, key_size);
                    black_box(filter.insert_slice(&key));
                });
            });
        }
    }

    {
        let mut group: criterion::BenchmarkGroup<'_, criterion::measurement::WallTime> =
            c.benchmark_group("Contains");
        let num_keys = 1_000_000;
        for key_size in [5, 7, 17, 31, 47, 97, 127, 257, 521] {
            group.throughput(criterion::Throughput::Bytes(key_size.try_into().unwrap()));
            group.bench_with_input(
                BenchmarkId::new("std::collections::hash_map::RandomState", key_size),
                &key_size,
                |b, _| {
                    let mut offset = 0;
                    let mut filter = BloomFilter::with_rate_and_hasher(
                        0.01,
                        num_keys + 300_000,
                        BuildHasher128Adapter::with_hashers(RandomState::new(), RandomState::new()),
                    );
                    b.iter(|| {
                        let key = get_random_key(&key_buffer, &mut offset, key_size);
                        black_box(filter.contains(&key));
                    });
                },
            );
            group.bench_with_input(BenchmarkId::new("xxh3", key_size), &key_size, |b, _| {
                let mut offset = 0;
                let mut filter = BloomFilter::with_rate(0.01, num_keys + 300_000);
                b.iter(|| {
                    let key = get_random_key(&key_buffer, &mut offset, key_size);
                    black_box(filter.contains_slice(&key));
                });
            });
        }
    }

    {
        let num_keys = 1_000_000;

        let mut group: criterion::BenchmarkGroup<'_, criterion::measurement::WallTime> =
            c.benchmark_group("Containership of 10 filters");
        for key_size in [5, 7, 17, 31, 47, 97, 127, 257, 521] {
            group.throughput(criterion::Throughput::Bytes(key_size.try_into().unwrap()));
            group.bench_with_input(
                BenchmarkId::new("naiive", key_size),
                &key_size,
                |b, _| {
                    let mut offset = 0;
                    let builder = RandomXxh3State::new();
                    let mut filters: Vec<BloomFilter> = (0..10).map(|_| BloomFilter::with_rate_and_hasher(
                        0.01,
                        num_keys + 300_000,
                        builder,
                    )).collect();
                    b.iter(|| {
                        let key = get_random_key(&key_buffer, &mut offset, key_size);
                        for filter in &filters {
                            black_box(filter.contains_slice(&key));
                        }
                    });
                },
            );
            group.bench_with_input(BenchmarkId::new("fingerprint", key_size), &key_size, |b, _| {
                let mut offset = 0;
                let builder = RandomXxh3State::new();
                let mut filters: Vec<BloomFilter> = (0..10).map(|_| BloomFilter::with_rate_and_hasher(
                    0.01,
                    num_keys + 300_000,
                    builder,
                )).collect();
                b.iter(|| {
                    let key = get_random_key(&key_buffer, &mut offset, key_size);
                    let fp = builder.hash_one_128(key);
                    for filter in &filters {
                        black_box(filter.contains_fingerprint(fp));
                    }
                });
            });
        }
    }
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
