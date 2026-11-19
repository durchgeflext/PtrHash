//! Benchmarks query throughput for the fast, default, and compact PtrHash
//! configurations at several input sizes. It compares identity hashing on
//! random integer keys with the library's fast integer hasher.

use ptr_hash::{
    CompactPtrHash, DefaultPtrHash, FastPtrHash, PtrHashParams,
    hash::{FastIntHash, NoHash, Murmur32, XxHash32},
    util::generate_keys64,
};
use std::hint::black_box;
use ptr_hash::util::generate_keys32;

fn time(n: usize, name: &str, f: impl FnOnce()) {
    let start = std::time::Instant::now();
    f();
    let time = start.elapsed().as_secs_f64() / n as f64 * 1e9;
    eprintln!("{name:<40}: {time:.1} ns/key");
}

fn main() {
    env_logger::init();
    for n in [100_000, 1_000_000/*, 10_000_000, 100_000_000*/] {
        eprintln!("Testing n = {}", n);
        let keys = generate_keys64(n);

        let ptr_hash = FastPtrHash::<NoHash, _>::new(&keys, PtrHashParams::default_fast());
        time(n, "FastPtrHash<NoHash>", || {
            for key in &keys {
                black_box(ptr_hash.index(key));
            }
        });

        let ptr_hash = DefaultPtrHash::<NoHash, _>::new(&keys, PtrHashParams::default());
        time(n, "DefaultPtrHash<NoHash>", || {
            for key in &keys {
                black_box(ptr_hash.index(key));
            }
        });

        let ptr_hash = CompactPtrHash::<NoHash, _>::new(&keys, PtrHashParams::default_compact());
        time(n, "CompactPtrHash<NoHash>", || {
            for key in &keys {
                black_box(ptr_hash.index(key));
            }
        });

        let ptr_hash = FastPtrHash::<FastIntHash, _>::new(&keys, PtrHashParams::default_fast());
        time(n, "FastPtrHash<FxHash>", || {
            for key in &keys {
                black_box(ptr_hash.index(key));
            }
        });

        let ptr_hash = DefaultPtrHash::<FastIntHash, _>::new(&keys, PtrHashParams::default());
        time(n, "DefaultPtrHash<FxHash>", || {
            for key in &keys {
                black_box(ptr_hash.index(key));
            }
        });

        let ptr_hash =
            CompactPtrHash::<FastIntHash, _>::new(&keys, PtrHashParams::default_compact());
        time(n, "CompactPtrHash<FxHash>", || {
            for key in &keys {
                black_box(ptr_hash.index(key));
            }
        });

        let keys = generate_keys32(n);

        let ptr_hash = DefaultPtrHash::<Murmur32, u32>::new(&keys, PtrHashParams::default());
        time(n, "DefaultPtrHash<Murmur32>", || {
            for key in &keys {
                black_box(ptr_hash.index(key));
            }
        });

        let ptr_hash = DefaultPtrHash::<XxHash32, u32>::new(&keys, PtrHashParams::default());
        time(n, "DefaultPtrHash<XxHash32>", || {
            for key in &keys {
                black_box(ptr_hash.index(key));
            }
        });

        eprintln!();
    }
}
