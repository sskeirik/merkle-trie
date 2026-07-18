//! Operations on bitstrings.
use std::borrow::Borrow;
use std::fmt::Debug;
use crate::utils::{Allocator, Box, copy_slice_into_box};
#[allow(unused_imports)] // used for debug purposes
use {
    tracing::instrument,
    crate::utils::{to_ascii, to_bin, to_hex},
};

/// Given a bit index `i` in a byte, create a mask that selects indices `j` s.t. `0 <= j <= i`
#[inline]
pub(crate) fn isolate_prefix_mask(bits: usize) -> u8 {
    (1u8 << (bits as u8)) - 1
}

/// Given a bit index `i` in a byte, create a mask that selects indices `j` s.t. `i < j <= 7``
#[inline]
pub(crate) fn isolate_suffix_mask(bits: usize) -> u8 {
    ! isolate_prefix_mask(bits)
}

/// Given a source bitmask, create a bitmask that selects the leading zeroes of the source mask
#[inline]
pub(crate) fn lz_mask(mask: u8) -> u8 {
    let non_leading = 8 - mask.leading_zeros();
    if non_leading >= 8 {
        0
    } else {
        isolate_suffix_mask(non_leading as usize)
    }
}

/// Given a source bitmask, create a bitmask that selects the trailing zeroes of the source mask
#[inline]
pub(crate) fn tz_mask(mask: u8) -> u8 {
    let trailing = mask.trailing_zeros();
    if trailing >= 8 {
        0xff
    } else {
        isolate_prefix_mask(trailing as usize)
    }
}

/// Bit position in a byte string
#[derive(Default)]
pub struct BitPosition {
    /// index of a whole byte
    pub index: usize,
    /// bit index inside a byte
    pub bits: usize,
}

impl Debug for BitPosition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{{}:{}}}", self.index, self.bits)
    }
}

/// The location of the first bit that distinguishes two bit strings
#[derive(Debug)]
pub struct BitDiff {
    /// The first bit position that distinguishes two bitstrings
    pub pos: BitPosition,
    /// The index of the prefix bitstring (if it exists)
    pub prefix: Option<usize>,
}

/// Return the index of the first bit, after the offset bits, that distinguishes the two input strings.
/// If one bit string is a prefix of the other, the extra bits are considered to be distinct.
pub fn find_first_distinct_bits(a: &[u8], b: &[u8], offset: usize, a_bits: Option<usize>, b_bits: Option<usize>) -> Option<BitDiff> {

    // set default length
    let a_bits = a_bits.unwrap_or(a.len()*8 - offset);
    let b_bits = b_bits.unwrap_or(b.len()*8 - offset);

    // check wanted vs. actual bits
    let actual_bits = (a.len()*8).min(b.len()*8);
    let wanted_bits = a_bits.min(b_bits);
    debug_assert!(offset + wanted_bits <= actual_bits, "requested bits would overflow underlying buffer");

    // get start byte
    let mut i = offset / 8;

    // if needed, check offset, increment start byte
    let offset_bits = offset % 8;
    if offset_bits != 0 {
        let isolate_suffix = !((1 << offset_bits) - 1);
        let v = (a[i] ^ b[i]) & isolate_suffix;
        if v != 0 {
            return Some(BitDiff { pos: BitPosition { index: i, bits: v.trailing_zeros() as usize % 8 }, prefix: None });
        }
        i += 1;
    }

    // get byte-aligned wanted bits and bytes
    let aligned_wanted_bits = wanted_bits - offset_bits;
    let aligned_wanted_bytes = aligned_wanted_bits / 8;
    let extra_bits = aligned_wanted_bits % 8;
    let isolate_extra_bits: u8 = (1 << extra_bits) - 1;

    // get end byte
    let n = aligned_wanted_bytes;

    tracing::debug!("Splitting up to {n} bytes, {extra_bits} bits, from a:{}:{} and b:{}:{}", a_bits, to_bin::<false>(a), b_bits, to_bin::<false>(b));

    // Process 8-byte chunks
    while i + 8 <= n {
        let xa = u64::from_le_bytes(a[i..i+8].try_into().unwrap());
        let xb = u64::from_le_bytes(b[i..i+8].try_into().unwrap());
        let v = xa ^ xb;
        if v != 0 {
            let trailing = v.trailing_zeros() as usize; // 0..63
            let extra_bytes = trailing / 8;
            return Some(BitDiff { pos: BitPosition { index: i + extra_bytes, bits: trailing % 8 }, prefix: None });
        }
        i += 8;
    }

    // Remainder bytes
    while i < n {
        let v = a[i] ^ b[i];
        if v != 0 {
            return Some(BitDiff { pos: BitPosition { index: i, bits: v.trailing_zeros() as usize % 8 }, prefix: None });
        }
        i += 1;
    }

    // Final bits
    if isolate_extra_bits != 0 {
        tracing::debug!("Extra bits mask: {}", to_bin::<false>(&[isolate_extra_bits]));
        let v = (a[i] ^ b[i]) & isolate_extra_bits;
        if v != 0 {
            return Some(BitDiff { pos: BitPosition { index: i, bits: v.trailing_zeros() as usize % 8 }, prefix: None });
        }
    }

    // If lengths differ, the extra bits are "different"
    if a_bits != b_bits {
        tracing::debug!("Split aux returned prefix: {i}");
        return Some(BitDiff { pos: BitPosition { index: i, bits: (offset + wanted_bits) % 8 }, prefix: Some((a_bits > b_bits) as usize) });
    }

    // Otherwise, they are identical
    return None;
}

impl BitDiff {
    /// Given a bit diff, find the unique bitmask of length log2(K),
    /// aligned on a log2(K) bit offset, that contains diff.bits
    pub fn mask<const K: usize>(&self) -> u8 {
        BitSeqOps::<K>::mask(self.pos.bits)
    }

    /// Given a bit diff and src buffer, find the unique
    /// [0, 2^K)-valued integer obtained from applying the
    /// diff-derived bitmask to src at the diff's position
    pub fn mask_value<const K: usize>(&self, src: &[u8]) -> usize {
        BitSeqOps::<K>::mask_value(src, self.pos.index, self.pos.bits)
    }

    /// Given a bit diff and src bitstring, copy the bits from src in the range [0,align(log2(K),diff.pos)).
    /// In order to account for non-byte-aligned bitlengths, we write an extra final byte.
    /// Any bits in this final byte which are not contained in the prefix will be zeroed out.
    pub fn write_prefix<const K: usize, A: Allocator + Clone>(&self, src: &[u8], alloc: A) -> Box<[u8], A> {
        BitSeqOps::<K>::write_aligned_prefix(self, src, alloc)
    }

    /// Given a bit diff and src bitstring, copy the bits from src in the range [align(log2(K),diff.pos),src.len()*8).
    pub fn write_suffix<const K: usize, A: Allocator + Clone>(&self, src: &[u8], alloc: A) -> Box<[u8], A> {
        BitSeqOps::<K>::write_aligned_suffix(&self.pos, src, alloc)
    }
}

/// An attachment point for bit-level operations that depend on a constant power-of-two K in the range \[2,256\].
/// This struct is a ZST, is never constructed, and is only used for its const parameter to guide function monomorphization.
pub struct BitSeqOps<const K: usize>;

impl<const K: usize> BitSeqOps<K> {
    const _CHECK: () = assert!(2 <= K && K <= 256 && K.is_power_of_two());
    /// The number of bits needed to encode a K-valued choice
    const K_BITS: usize = K.ilog2() as usize;
    /// The mask (before shifting) used to extract the bit string which defines the split
    const CHUNK_MASK: u8 = (K - 1) as u8;

    /// Given a bit offset in a byte, find the unique bitmask of length log2(K),
    /// aligned on a log2(K) bit offset, that contains the bit offset
    #[inline]
    pub fn mask(bit_index: usize) -> u8 {
        debug_assert!(bit_index < 8, "Invalid bit index");
        Self::CHUNK_MASK << ((bit_index / Self::K_BITS) * Self::K_BITS)
    }

    /// Given a src buffer, a byte index, and a bit offset, find the
    /// unique [0, 2^K)-valued integer obtained from applying the
    /// offset-derived bitmask to src\[index\]
    #[inline]
    pub fn mask_value(src: &[u8], index: usize, bit_index: usize) -> usize {
        let mask = Self::mask(bit_index);
        let value = (src[index] & mask) >> mask.trailing_zeros();
        value as usize
    }

    /// Given a bit diff and src bitstring, copy the bits from src in the range [0,align(log2(K),diff.pos)).
    /// In order to account for non-byte-aligned bitlengths, we write an extra final byte.
    #[instrument(level="debug", skip_all)]
    pub fn write_aligned_prefix<A: Allocator + Clone>(diff: &BitDiff, src: &[u8], alloc: A) -> Box<[u8],A> {
        debug_assert!(diff.prefix.is_none(), "this operation is invalid for bitstrings without a diff");
        let BitDiff { pos: BitPosition { index, bits, }, .. } = diff;
        // since there may be diff bits in the final byte, we must include it
        let mut dst = copy_slice_into_box(&src[..index+1], alloc);
        // we isolate the bits that precede the diff
        dst[*index] &= tz_mask(Self::mask(*bits));
        dst
    }

    /// Given a bit diff and src bitstring, copy the bits from src in the range [align(log2(K),diff.pos),src.len()*8).
    #[instrument(level="debug", skip_all)]
    pub fn write_aligned_suffix<A: Allocator + Clone>(pos: &BitPosition, src: &[u8], alloc: A) -> Box<[u8],A> {
        let suffix_len = src.len() - pos.index;
        if suffix_len == 0 {
            return copy_slice_into_box(&[], alloc);
        }
        let mut dst = copy_slice_into_box(&src[pos.index..], alloc);
        // we isolate the bits that succeed the diff
        dst[0] &= lz_mask(Self::mask(pos.bits));
        dst
    }

    /// Given a prefix, mask, mask_value, and suffix generated by the same [`BitDiff`] and src buffer,
    /// reverse the split to recover a boxed slice whose contents equal the src buffer
    #[instrument(level="debug", skip_all)]
    pub fn recover<A: Allocator + Clone>(prefix: impl Borrow<[u8]>, mask: u8, mask_value: u8, suffix: impl Borrow<[u8]>, alloc: A) -> Box<[u8],A> {
        let prefix = prefix.borrow();
        let suffix = suffix.borrow();
        debug_assert!(prefix.len() > 0 && suffix.len() > 0);
        let merged_key = Box::<[u8],A>::new_uninit_slice_in(prefix.len() + suffix.len() - 1, alloc);
        let mut merged_key = unsafe { merged_key.assume_init() };
        merged_key[0..prefix.len()].copy_from_slice(prefix);
        merged_key[prefix.len()-1] |= mask_value << mask.trailing_zeros();
        merged_key[prefix.len()-1] |= suffix[0];
        if suffix.len() > 1 {
            merged_key[prefix.len()..].copy_from_slice(suffix);
        }
        merged_key
    }
}
#[cfg(test)]
mod test {
    use super::*;
    use allocator_api2::alloc::Global;
    use test_log::test;

    #[test]
    #[rustfmt::skip]
    fn test_mask_shift() {
        let masks: &[u8] = &[0b00000000, 0b00000001, 0b00000010, 0b00000100, 0b00001100, 0b00110000, 0b01000000, 0b10000000];
        let mask_leading: &[u8] = &[0b11111111, 0b11111110, 0b11111100, 0b11111000, 0b11110000, 0b11000000, 0b10000000, 0b00000000];
        let mask_trailing: &[u8] = &[0b11111111, 0b00000000, 0b00000001, 0b00000011, 0b00000011, 0b00001111, 0b00111111, 0b01111111];
        for idx in 0..masks.len() {
            let mask = masks[idx];
            let mask_leading = mask_leading[idx];
            let mask_trailing = mask_trailing[idx];
            println!("{:#010b} leading: {} trailing: {}", mask, mask.leading_zeros(), mask.trailing_zeros());
            println!("{:#010b} Expected Leading\n{:#010b} Actual Leading\n{:#010b} Mask\n{:#010b} Actual Trailing\n{:#010b} Expected Trailing", mask_leading, lz_mask(mask), mask, tz_mask(mask), mask_trailing);
            assert_eq!(mask_leading, lz_mask(mask));
            assert_eq!(mask_trailing, tz_mask(mask));
        }
    }

    #[test]
    fn test_find_first_distinct_bits_diff() {
        // Static byte slices used to build expected splits, i.e., prefix/suffix pairs
        const Z:   &[u8] = &[0u8];
        const O:   &[u8] = &[1u8];
        const H:   &[u8] = &[0b10000000u8];
        const Z8:  &[u8] = &[0u8; 8];

        type BitSplit = (bool, u8, Vec<u8>, Vec<u8>, Vec<u8>, usize, usize);
        fn mk_bit_split<const K: usize>(diff: &BitDiff, a: &[u8], b: &[u8]) -> BitSplit {
            let p = BitSeqOps::<K>::write_aligned_prefix(&diff, a, Global).to_vec();
            let a_s = BitSeqOps::<K>::write_aligned_suffix(&diff.pos, a, Global).to_vec();
            let b_s = BitSeqOps::<K>::write_aligned_suffix(&diff.pos, b, Global).to_vec();
            let (mask, a_i, b_i) = if diff.prefix.is_none() {
                println!("a was {}", to_bin::<false>(a));
                println!("b was {}", to_bin::<false>(b));
                println!("mask was {}", to_bin::<false>(&[BitSeqOps::<K>::mask(diff.pos.bits)]));
                let mask = BitSeqOps::<K>::mask(diff.pos.bits);
                let a_i = BitSeqOps::<K>::mask_value(a, diff.pos.index, diff.pos.bits);
                let b_i = BitSeqOps::<K>::mask_value(b, diff.pos.index, diff.pos.bits);
                // check merge works
                assert_eq!(a, &*BitSeqOps::<K>::recover(p.as_slice(), mask, a_i as u8, a_s.as_slice(), Global));
                assert_eq!(b, &*BitSeqOps::<K>::recover(p.as_slice(), mask, b_i as u8, b_s.as_slice(), Global));
                (mask, a_i, b_i)
            } else {
                (0,0,0)
            };
            (diff.prefix.is_some(), mask, p, a_s, b_s, a_i, b_i)
        }

        fn d(pre: &'static [u8], sa: &'static [u8], sb: &'static [u8], mask: u8, values: [usize; 2]) -> Option<BitSplit> {
            Some((false, mask, pre.to_vec(), sa.to_vec(), sb.to_vec(), values[0], values[1]))
        }

        // inputs contains: bitstring: a, bitstring: b
        #[rustfmt::skip]
        let inputs: [(&[u8], &[u8]); _] = [
            // check for splits using 1-bit diffs
            (&[0b00000001], &[0b00000000]),
            (&[0b00000010], &[0b00000000]),
            (&[0b00000100], &[0b00000000]),
            (&[0b00001000], &[0b00000000]),
            (&[0b00010000], &[0b00000000]),
            (&[0b00100000], &[0b00000000]),
            (&[0b01000000], &[0b00000000]),
            (&[0b10000000], &[0b00000000]),
            // check that bits before/after split are NOT masked out
            (&[0b10010001], &[0b10000001]),
            // check that multi-byte striding works
            (&[0,0,0,0,0,0,0, 0b00100], &[0,0,0,0,0,0,0, 0b00000]),
        ];

        // K=2 (K_BITS=1): each 1-bit chunk is the full mask.
        #[rustfmt::skip]
        let outs_1: [Option<BitSplit>; 10] = [
            d(Z,   Z, Z, 0b00000001, [1, 0]),   // 0
            d(Z,   Z, Z, 0b00000010, [1, 0]),   // 1
            d(Z,   Z, Z, 0b00000100, [1, 0]),   // 2
            d(Z,   Z, Z, 0b00001000, [1, 0]),   // 3
            d(Z,   Z, Z, 0b00010000, [1, 0]),   // 4
            d(Z,   Z, Z, 0b00100000, [1, 0]),   // 5
            d(Z,   Z, Z, 0b01000000, [1, 0]),   // 6
            d(Z,   Z, Z, 0b10000000, [1, 0]),   // 7
            d(O,   H, H, 0b00010000, [1, 0]),   // 8: noise bits survive in prefix/suffix
            d(Z8,  Z, Z, 0b00000100, [1, 0]),   // 9: diff found via 8-byte SIMD stride
        ];

        // K=4 (K_BITS=2): each 2-bit aligned chunk is the mask.
        #[rustfmt::skip]
        let outs_2: [Option<BitSplit>; 10] = [
            d(Z,   Z, Z, 0b00000011, [1, 0]),   // 0
            d(Z,   Z, Z, 0b00000011, [2, 0]),   // 1
            d(Z,   Z, Z, 0b00001100, [1, 0]),   // 2
            d(Z,   Z, Z, 0b00001100, [2, 0]),   // 3
            d(Z,   Z, Z, 0b00110000, [1, 0]),   // 4
            d(Z,   Z, Z, 0b00110000, [2, 0]),   // 5
            d(Z,   Z, Z, 0b11000000, [1, 0]),   // 6
            d(Z,   Z, Z, 0b11000000, [2, 0]),   // 7
            d(O,   H, H, 0b00110000, [1, 0]),   // 8
            d(Z8,  Z, Z, 0b00001100, [1, 0]),   // 9
        ];

        // K=16 (K_BITS=4): each 4-bit aligned chunk is the mask.
        #[rustfmt::skip]
        let outs_4: [Option<BitSplit>; 10] = [
            d(Z,   Z, Z, 0b00001111, [1, 0]),   // 0
            d(Z,   Z, Z, 0b00001111, [2, 0]),   // 1
            d(Z,   Z, Z, 0b00001111, [4, 0]),   // 2
            d(Z,   Z, Z, 0b00001111, [8, 0]),   // 3
            d(Z,   Z, Z, 0b11110000, [1, 0]),   // 4
            d(Z,   Z, Z, 0b11110000, [2, 0]),   // 5
            d(Z,   Z, Z, 0b11110000, [4, 0]),   // 6
            d(Z,   Z, Z, 0b11110000, [8, 0]),   // 7
            d(O,   Z, Z, 0b11110000, [9, 8]),   // 8
            d(Z8,  Z, Z, 0b00001111, [4, 0]),   // 9
        ];

        // K=256 (K_BITS=8): the full byte is always the mask.
        #[rustfmt::skip]
        let outs_8: [Option<BitSplit>; 10] = [
            d(Z,   Z, Z, 0xFF, [  1,   0]),   // 0
            d(Z,   Z, Z, 0xFF, [  2,   0]),   // 1
            d(Z,   Z, Z, 0xFF, [  4,   0]),   // 2
            d(Z,   Z, Z, 0xFF, [  8,   0]),   // 3
            d(Z,   Z, Z, 0xFF, [ 16,   0]),   // 4
            d(Z,   Z, Z, 0xFF, [ 32,   0]),   // 5
            d(Z,   Z, Z, 0xFF, [ 64,   0]),   // 6
            d(Z,   Z, Z, 0xFF, [128,   0]),   // 7
            d(Z,   Z, Z, 0xFF, [145, 129]),   // 8
            d(Z8,  Z, Z, 0xFF, [  4,   0]),   // 9
        ];

        for (idx, (in1, in2)) in inputs.iter().enumerate() {
            println!("Loop Idx: {idx}");

            let bit_diff = find_first_distinct_bits(in1, in2, 0, Some(in1.len()*8), Some(in2.len()*8));
            println!("BitDiff: {:?}", bit_diff);

            let res_1 = bit_diff.as_ref().map(|v| mk_bit_split::<2>(v, in1, in2));
            println!("1: {:?}", res_1);
            assert_eq!(res_1, outs_1[idx]);

            let res_2 = bit_diff.as_ref().map(|v| mk_bit_split::<4>(v, in1, in2));
            println!("2: {:?}", res_2);
            assert_eq!(res_2, outs_2[idx]);

            let res_4 = bit_diff.as_ref().map(|v| mk_bit_split::<16>(v, in1, in2));
            println!("4: {:?}", res_4);
            assert_eq!(res_4, outs_4[idx]);

            let res_8 = bit_diff.as_ref().map(|v| mk_bit_split::<256>(v, in1, in2));
            println!("8: {:?}", res_8);
            assert_eq!(res_8, outs_8[idx]);
        }
    }

    #[test]
    fn test_find_first_distinct_bits_prefix() {
        #[rustfmt::skip]
        let inputs: [(&[u8], &[u8], usize); _] = [
            (&[], &[0], 0),                             // empty prefix
            (&[0,0], &[0b00000001], 0),                 // truncated-to-empty prefix
            (&[0], &[0b00000010], 1),                   // 1-bit prefix
            (&[0,1], &[0,1,1], 16),                     // whole byte prefix
            (&[0,0b00010000], &[0,0b11110000], 12),     // partial byte prefix with no extra bytes
            (&[0,0b00010000], &[0,0b11110000, 1], 12),  // partial byte prefix with extra bytes
        ];

        for (a,b, a_bits) in inputs.into_iter() {
            let diff = find_first_distinct_bits(a, b, 0, Some(a_bits), None).expect("failed to find prefix");
            let expected_bytes =  a_bits / 8;
            let expected_bits = a_bits % 8;
            assert!(diff.prefix.is_some());
            assert_eq!(diff.pos.index, expected_bytes);
            assert_eq!(diff.pos.bits, expected_bits);
        }
    }
}