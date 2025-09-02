// SPDX-License-Identifier: Apache-2.0
#![warn(missing_docs)]

//! Constant-space permutations over integers.
//!
//! This crate provides constant-space, constant-time random access
//! permutations over dense integer ranges. It is built on top of a
//! simple Feistel Network cipher.

mod feistel;
mod permutation;
mod utils;

use num_traits::{FromPrimitive, Num, PrimInt, ToBytes, ToPrimitive};
use std::fmt::Debug;
use std::ops::{AddAssign, BitAnd, BitOr, BitXorAssign, Shl, Shr};

pub trait NumExt:
    Num
    + AddAssign
    + Clone
    + PartialOrd
    + ToPrimitive
    + From<usize>
    + Shl<usize, Output = Self>
    + Shr<usize, Output = Self>
    + BitAnd<Self, Output = Self>
    + BitXorAssign
    + BitOr<Self, Output = Self>
    + ToBytes
    + BitLength
    + std::hash::Hash
    + Debug
{
}

impl<T> NumExt for T where
    T: Num
        + AddAssign
        + Clone
        + PartialOrd
        + ToPrimitive
        + From<usize>
        + Shl<usize, Output = T>
        + Shr<usize, Output = T>
        + BitAnd<T, Output = T>
        + BitXorAssign
        + BitOr<T, Output = T>
        + ToBytes
        + BitLength
        + std::hash::Hash
        + Debug
{
}

///
pub trait BitLength {
    fn bits(&self) -> u64;
}

impl<T: ToBytes> BitLength for T {
    fn bits(&self) -> u64 {
        let bytes = self.to_be_bytes();
        let bytes = bytes.as_ref();

        // Zero is a special case – it needs 0 bits.
        if bytes.iter().all(|&b| b == 0) {
            return 0;
        }

        // Find the first non‑zero byte (most‑significant byte).
        let (msb_index, msb) = bytes
            .iter()
            .enumerate()
            .find(|(_, &b)| b != 0)
            .unwrap(); // safe because we already checked all‑zero above

        // Bits contributed by that byte.
        let msb_bits = 8 - msb.leading_zeros() as u64;

        // Each subsequent byte contributes a full 8 bits.
        let remaining_bits = (bytes.len() - msb_index - 1) as u64 * 8;
        let total = msb_bits + remaining_bits;

        // Round up to an even number of bits.
        total + (total & 1)
    }
}

pub use feistel::*;
pub use permutation::*;
pub use utils::*;
