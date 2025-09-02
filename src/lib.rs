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

use std::fmt::Debug;
use num_bigint::BigUint;
use num_traits::{ToPrimitive, Num, ToBytes};
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

pub trait BitLength {
    fn bits(&self) -> u64;
}

impl BitLength for BigUint {
    fn bits(&self) -> u64 {
        self.bits()
    }
}

impl BitLength for u8 {
    fn bits(&self) -> u64 {
        u8::BITS as u64
    }
}

impl BitLength for u16 {
    fn bits(&self) -> u64 {
        u16::BITS as u64
    }
}

impl BitLength for u32 {
    fn bits(&self) -> u64 {
        u32::BITS as u64
    }
}

impl BitLength for u64 {
    fn bits(&self) -> u64 {
        u64::BITS as u64
    }
}

impl BitLength for u128 {
    fn bits(&self) -> u64 {
        u128::BITS as u64
    }
}

impl BitLength for usize {
    fn bits(&self) -> u64 {
        usize::BITS as u64
    }
}

pub use feistel::*;
pub use permutation::*;
pub use utils::*;
