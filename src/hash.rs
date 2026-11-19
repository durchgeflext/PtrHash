//! Implementations of various hashers to use with PtrHash.
//!
//! ## Integer keys
//!
//! We provide:
//! - [`NoHash`]: does nothing -- only use on truly random keys.
//! - [`FastIntHash`] = [`FxHash`], which does a single wrapping multiplication and should be good enough most of the time.
//! - [`StrongerIntHash`]: Use this when the input keys are very regular, eg `0..1000`. (But then why do you need an MPHF anyway?)
//!                Does a `u128` multiplication, and xors the high and low word together, like xxh3. Then does one more multiplication. Not very scientific but 'it works'.
//! - [`GxInt`]: GxHash, but with the type 'inlined' so that it optimized better.
//! - [`Xxh3Int`]: Xxh3, but with the type 'inlined' so that it optimized better.
//! - [`Murmur32`] and [`XxHash32`]: 32-bit hash functions for `u32` keys only.
//!
//! In practice, prefer [`FastIntHash`] if it's good enough.
//! Otherwise, fall back to [`StrongerIntHash`].
//! If that still fails (which probably shouldn't happen) fall back to one of the two remaining
//!
//! If [`StrongerIntHash`] lacks sufficient randomness, use [`Xxh3Int`] instead, which is considerably slower but much stronger.
//!
//! ## String keys
//!
//! For string keys, use [`StringHash`] for 64-bit hashes and [`StringHash128`] for 128-bit hashes.
//! These are aliases for 64bit and 128bit versions of gxhash, respectively.
//!
//! Another option is to use [`FxHash`] instead.
//!
//! In general any type implementing `Hasher` can be used, but it may be more
//! efficient to implement [`KeyHasher`] yourself for your key type, to directly
//! call specialized functions rather than going through the generic `Hasher`
//! interface.
//!

use std::arch::x86_64::*;
#[cfg(feature = "gxhash")]
use gxhash::GxBuildHasher;

use crate::KeyT;
use std::fmt::Debug;

/// The [`KeyHasher`] trait returns a 64 or 128-bit `Hash`. From this, two `u64` values are extracted.
///
/// When 64-bit hashes are enough, we simply return the same hash (the `u64`
/// `Self` value) as the low and high part.
///
/// When 128-bit hashes are needed, the two functions return the low/high half of bits.
///
/// Our method never needs the full hash value, and instead uses the two hashes
/// in different places to extract sufficient entropy.
pub trait Hash: Copy + Debug + Default + Send + Sync + Eq + rdst::RadixKey {
    /// Returns the low 64bits of the hash.
    fn low(&self) -> u64;
    /// Returns the high 64bits of the hash.
    fn high(&self) -> u64;
}

impl Hash for u64 {
    fn low(&self) -> u64 {
        *self
    }
    fn high(&self) -> u64 {
        *self
    }
}

impl Hash for u128 {
    fn low(&self) -> u64 {
        *self as u64
    }
    fn high(&self) -> u64 {
        (*self >> 64) as u64
    }
}

/// Wrapper trait for various hash functions.
pub trait KeyHasher<Key: ?Sized>: Clone + Sync {
    type H: Hash;
    fn hash(x: &Key, seed: u64) -> Self::H;
}

/// All external hashers work.
impl<Key: KeyT + ?Sized, H: core::hash::Hasher + Default + Clone + Sync> KeyHasher<Key> for H {
    type H = u64;
    #[inline(always)]
    fn hash(x: &Key, seed: u64) -> u64 {
        let mut hasher = H::default();
        Key::hash(x, &mut hasher);
        hasher.finish() ^ seed
    }
}

// Aliases

/// A slightly faster but weaker hash for sufficiently random integers. Uses [`fxhash::FxHasher64`].
pub type FastIntHash = fxhash::FxHasher64;
pub type FxHash = fxhash::FxHasher64;
/// Type alias for xxhash (XXH3) hasher.
///
/// Prefer [`Xxh3Int`] for integers, which avoids some overhead of the default hasher.
pub type Xxh3 = xxhash_rust::xxh3::Xxh3Default;
#[cfg(feature = "gxhash")]
pub type Gx = gxhash::GxHasher;

/// Use gxhash for 64-bit string hashing.
#[cfg(feature = "gxhash")]
pub type StringHash = Gx;
/// Use gxhash for 128-bit string hashing.
#[cfg(feature = "gxhash")]
pub type StringHash128 = Gx128;

// Implementations

/// 128-bit version of XXH3.
#[cfg_attr(feature = "epserde", derive(epserde::prelude::Epserde))]
#[derive(Clone)]
pub struct Xxh3_128;
impl<Key: KeyT + ?Sized> KeyHasher<Key> for Xxh3_128 {
    type H = u128;
    #[inline(always)]
    fn hash(x: &Key, seed: u64) -> u128 {
        let mut hasher = xxhash_rust::xxh3::Xxh3Default::default();
        x.hash(&mut hasher);
        hasher.digest128() ^ (seed as u128 | (seed as u128) << 64)
    }
}

/// 128-bit version of XXH3.
#[cfg(feature = "gxhash")]
#[cfg_attr(feature = "epserde", derive(epserde::prelude::Epserde))]
#[derive(Clone)]
pub struct Gx128;
#[cfg(feature = "gxhash")]
impl<Key: KeyT + ?Sized> KeyHasher<Key> for Gx128 {
    type H = u128;
    #[inline(always)]
    fn hash(x: &Key, seed: u64) -> u128 {
        use std::hash::BuildHasher;
        let mut hasher = GxBuildHasher::with_seed(seed as i64).build_hasher();
        x.hash(&mut hasher);
        hasher.finish_u128()
    }
}

/// A sufficiently good hash for non-random integers. Inspired by Xxh3, with one extra multiplication:
/// FIXME: IS THAT NEEDED?
///
/// ```ignore
/// let (hi, lo) = (value ^ seed) as u128 * C as u128;
/// return (hi ^ lo).wrapping_mul(C);
/// ```
#[cfg_attr(feature = "epserde", derive(epserde::prelude::Epserde))]
#[derive(Clone)]
pub struct StrongerIntHash;

/// Mixing constant.
pub const C: u64 = 0x517cc1b727220a95;

/// No hash at all; just `value ^ seed`. Use with caution. Mostly for benchmarking.
#[cfg_attr(feature = "epserde", derive(epserde::prelude::Epserde))]
#[derive(Clone)]
pub struct NoHash;

/// Inlined version of Xxh3 for integer keys.
#[cfg_attr(feature = "epserde", derive(epserde::prelude::Epserde))]
#[derive(Clone)]
pub struct Xxh3Int;

/// Inlined version of Xxh3 for integer keys.
#[cfg(feature = "gxhash")]
#[cfg_attr(feature = "epserde", derive(epserde::prelude::Epserde))]
#[derive(Clone)]
pub struct GxInt;

/// MurmurHash3 32-bit hashing for `u32` keys.
#[cfg_attr(feature = "epserde", derive(epserde::prelude::Epserde))]
#[derive(Clone)]
pub struct Murmur32;

/// xxHash32 hashing for `u32` keys.
#[cfg_attr(feature = "epserde", derive(epserde::prelude::Epserde))]
#[derive(Clone)]
pub struct XxHash32;

// Macro to implement hashes for all integer types.
macro_rules! int_hashers {
    ($($t:ty),*) => {
        $(
            impl KeyHasher<$t> for NoHash {
                type H = u64;
                #[inline(always)]
                fn hash(x: &$t, seed: u64) -> u64 {
                    *x as u64 ^ seed
                }
            }

            impl KeyHasher<$t> for StrongerIntHash {
                type H = u64;
                #[inline(always)]
                fn hash(x: &$t, seed: u64) -> u64 {
                    let r = (*x as u64 ^ seed) as u128 * C as u128;
                    let low = r as u64;
                    let high = (r >> 64) as u64;
                    (low ^ high).wrapping_mul(C)
                }
            }

            impl KeyHasher<$t> for Xxh3Int {
                type H = u64;
                #[inline(always)]
                fn hash(x: &$t, seed: u64) -> u64 {
                    xxhash_rust::xxh3::xxh3_64_with_seed(&(*x as u64).to_le_bytes(), seed)
                }
            }

            #[cfg(feature = "gxhash")]
            impl KeyHasher<$t> for GxInt {
                type H = u64;
                #[inline(always)]
                fn hash(x: &$t, seed: u64) -> u64 {
                    gxhash::gxhash64(&(*x as u64).to_le_bytes(), seed as i64)
                }
            }
        )*
    };
}
int_hashers!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize);

impl KeyHasher<u32> for Murmur32 {
    type H = u64;

    //https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp
    #[inline(always)]
    fn hash(x: &u32, seed: u64) -> u64 {
        const C1 : u32= 0xcc9e2d51;
        const C2 : u32 = 0x1b873593;
        const C3 : u32 = 0xe6546b64;
        const C4 : u32 = 0x85ebca6b;
        const C5 : u32 = 0xc2b2ae35;
        let mut h1 : u32 = seed as u32;

        let mut k1 = *x;
        k1 = k1.wrapping_mul(C1);
        k1 = rotl32(k1, 15);
        k1 = k1.wrapping_mul(C2);

        h1 ^= k1;
        h1 = rotl32(h1, 13);
        h1 = h1.wrapping_mul(5).wrapping_add(C3);

        //finalization, fmix32
        h1 ^= h1 >> 16;
        h1 = h1.wrapping_mul(C4);
        h1 ^= h1 >> 13;
        h1 = h1.wrapping_mul(C5);
        h1 ^= h1 >> 16;

        h1 as u64
    }
}

impl KeyHasher<u32> for XxHash32 {
    type H = u64;

    //https://github.com/Cyan4973/xxHash/blob/dev/lib/xxh32_impl.h
    #[inline(always)]
    fn hash(a: &u32, seed: u64) -> u64 {
        //xxhash_32(*x, seed as u32) as u64
        const XXH_2 : u32 = 0x85EBCA77u32;
        const XXH_3 : u32 = 0xC2B2AE3Du32;
        const XXH_4 : u32 = 0x27D4EB2Fu32;
        const XXH_5 : u32 = 0x165667B1u32;

        let mut h32 : u32 = seed as u32 + XXH_5;
        //finalize (h32, input : *char, 4, XXH_aligned)

        //Process4 ONCE
        h32 = h32.wrapping_add((*a).wrapping_mul(XXH_3));
        h32 = rotl32(h32, 17).wrapping_mul(XXH_4);
        //XXH32_avalanche (h32)
        h32 ^= h32 >> 15;
        h32 = h32.wrapping_mul(XXH_2);
        h32 ^= h32 >> 13;
        h32 = h32.wrapping_mul(XXH_3);

        (h32 ^ (h32 >> 16)) as u64
    }
}

#[inline]
pub fn rotl32(word : u32, shift: u32) -> u32 {
    (word << shift) | (word >> (32 - shift))
}

#[inline]
pub fn rotr32(word : u32, shift: u32) -> u32 {
    (word >> shift) | (word << (32 - shift))
}
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn simd_murmur_32(a : &[u32; 8], seed: u32) -> [u32; 8] { unsafe {
    let c1 : __m256i = _mm256_set1_epi32(0xcc9e2d51u32.cast_signed());
    let c2 : __m256i = _mm256_set1_epi32(0x1b873593);
    let c3 : __m256i = _mm256_set1_epi32(0xe6546b64u32.cast_signed());
    let c4 : __m256i = _mm256_set1_epi32(0x85ebca6bu32.cast_signed());
    let c5 : __m256i = _mm256_set1_epi32(0xc2b2ae35u32.cast_signed());
    let five : __m256i = _mm256_set1_epi32(5);

    let mut k1 : __m256i = _mm256_loadu_si256(a.as_ptr() as *const __m256i);
    let mut h1 : __m256i = _mm256_set1_epi32(seed.cast_signed());

    //TODO: Check if multiplication breaks because of the signed integers inside __m256i
    //TODO: Does rust also break when multiplication overflows?
    k1 = _mm256_mullo_epi32(k1, c1);
    k1 = _mm256_or_si256(_mm256_slli_epi32::<15>(k1), _mm256_srli_epi32::<{ 32 - 15 }>(k1));
    k1 = _mm256_mullo_epi32(k1, c2);

    h1 = _mm256_xor_si256(h1, k1);
    h1 = _mm256_or_si256(_mm256_slli_epi32::<13>(h1), _mm256_srli_epi32::<{ 32 - 13 }>(h1));
    h1 = _mm256_mullo_epi32(h1, five);
    h1 = _mm256_add_epi32(h1, c3);
    //finalization
    h1 = _mm256_xor_si256(h1, _mm256_srli_epi32::<16>(h1));
    h1 = _mm256_mullo_epi32(h1, c4);
    h1 = _mm256_xor_si256(h1, _mm256_srli_epi32::<13>(h1));
    h1 = _mm256_mullo_epi32(h1, c5);
    h1 = _mm256_xor_si256(h1, _mm256_srli_epi32::<16>(h1));

    std::mem::transmute(h1)
}}

#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn simd_xxhash_32(a : &[u32; 8], seed : u32) -> [u32; 8] { unsafe {

    let xxh2 : __m256i = _mm256_set1_epi32(0x85EBCA77u32.cast_signed());
    let xxh3 : __m256i = _mm256_set1_epi32(0xC2B2AE3Du32.cast_signed());
    let xxh4 : __m256i = _mm256_set1_epi32(0x27D4EB2F);
    let xxh5 : __m256i = _mm256_set1_epi32(0x165667B1);

    let mut h : __m256i = _mm256_set1_epi32(seed.cast_signed());
    let mut k : __m256i = _mm256_loadu_si256(a.as_ptr() as *const __m256i);

    h = _mm256_add_epi32(h, xxh5);
    // Process 4
    k = _mm256_mullo_epi32(k, xxh3);
    h = _mm256_add_epi32(h, k);
    h = _mm256_or_si256(_mm256_slli_epi32::<17>(h), _mm256_srli_epi32::<{32 - 17}>(h));
    h = _mm256_mullo_epi32(h, xxh4);

    //avalanche
    h = _mm256_xor_si256(h, _mm256_srli_epi32::<15>(h));
    h = _mm256_mullo_epi32(h, xxh2);
    h = _mm256_xor_si256(h, _mm256_srli_epi32::<13>(h));
    h = _mm256_mullo_epi32(h, xxh3);
    h = _mm256_xor_si256(h, _mm256_srli_epi32::<16>(h));

    std::mem::transmute(h)
}}
