// SPDX-License-Identifier: Apache-2.0
use crate::NumExt;
use std::hash::{BuildHasher, Hasher};

/// A basic Feistel Network cipher.
///
/// The cipher requires a series of hashes which are built using
/// a supplied [`std::hash::BuildHasher`] (passed with the parameter
/// name `bob`, coz it'z a builder, right?)
pub struct Feistel<N, B>
where
    N: NumExt,
    B: BuildHasher,
{
    bob: B,
    bits: N,
    keys: Vec<N>,
}

impl<N, B> Feistel<N, B>
where
    N: NumExt,
    B: BuildHasher,
{
    /// Construct a new Feistel cipher.
    pub fn new(bob: B, bits: N, keys: &[N]) -> Feistel<N, B> {
        // Insist that there are an even number of bits.
        assert_eq!(bits.clone() & N::one(), N::zero());
        // Insist on encrypting data that fits in an unsigned 64-bit integer.
        assert!(bits <= 64.into());

        Feistel {
            bob,
            bits,
            keys: Vec::from(keys),
        }
    }

    /// Encrypt a value.
    pub fn encrypt(&self, x: N) -> N {
        let (mut l, mut r) = self.split(x);
        for k in self.keys.iter() {
            l ^= self.hash(k.clone(), r.clone());
            (l, r) = (r, l);
        }
        self.combine(r, l)
    }

    /// Decrypt a value.
    pub fn decrypt(&self, x: N) -> N {
        let (mut l, mut r) = self.split(x);
        for k in self.keys.iter().rev() {
            l ^= self.hash(k.clone(), r.clone());
            (l, r) = (r, l);
        }
        self.combine(r, l)
    }

    fn split(&self, x: N) -> (N, N) {
        let n = (self.bits.clone() >> 1).to_usize().unwrap();
        let m = (N::one() << n) - N::one();
        let hi = x.clone() >> n;
        let lo = x & m;
        (hi, lo)
    }

    fn combine(&self, hi: N, lo: N) -> N {
        let n = (self.bits.clone() >> 1).to_usize().unwrap();
        (hi << n) | lo
    }

    fn hash(&self, k: N, x: N) -> N {
        let mut h: <B as BuildHasher>::Hasher = self.bob.build_hasher();
        h.write(k.to_le_bytes().as_ref());
        h.write(x.to_le_bytes().as_ref());
        let res: N = (h.finish() as usize).into();
        let n = (self.bits.clone() >> 1).to_usize().unwrap();
        let m = (N::one() << n) - N::one();
        res & m
    }
}

#[cfg(test)]
mod tests {
    use crate::DefaultBuildHasher;

    use super::*;

    #[test]
    fn test_1a() {
        let bob = DefaultBuildHasher::new();
        let bits = 32usize;
        let keys = [0x1c10usize, 0x8fd6usize, 0x2d5ausize, 0x7363usize, 0x5f70usize];
        let f = Feistel::new(bob, bits, &keys);
        let x = 17;
        let y = f.encrypt(x);
        let z = f.decrypt(y);
        println!("x=0x{x:0x}, y=0x{y:0x}, z=0x{z:0x}");
        assert_eq!(x, z);
    }

    #[test]
    fn test_1b() {
        let bob = DefaultBuildHasher::new();
        let bits = 32;
        let keys = [0x1c10usize, 0x8fd6usize, 0x2d5ausize, 0x7363usize, 0x5f70usize];
        let f = Feistel::new(bob, bits, &keys);
        let x = 234;
        let y = f.encrypt(x);
        let z = f.decrypt(y);
        assert_eq!(x, z);
    }

    #[test]
    fn test_2() {
        let bob = DefaultBuildHasher::new();
        let bits = 56usize;
        let keys = [0x1c10usize, 0x8fd6usize, 0x2d5ausize, 0x7363usize, 0x5f70usize];
        let f = Feistel::new(bob, bits, &keys);
        let x = 17usize;
        let y = f.encrypt(x);
        let z = f.decrypt(y);
        assert_eq!(x, z);
    }

    #[test]
    fn test_minimum_bits() {
        let bob = DefaultBuildHasher::new();
        let bits = 0;
        let keys = [0x1c10usize, 0x8fd6usize, 0x2d5ausize, 0x7363usize, 0x5f70usize];
        let f = Feistel::new(bob, bits, &keys);
        let x = 0;
        let y = f.encrypt(x);
        let z = f.decrypt(y);
        assert_eq!(x, z);
    }

    #[test]
    #[should_panic]
    fn test_odd_bits() {
        let bob = DefaultBuildHasher::new();
        let bits = 1;
        let keys = [0x1c10usize, 0x8fd6usize, 0x2d5ausize, 0x7363usize, 0x5f70usize];
        Feistel::new(bob, bits, &keys);
    }

    #[test]
    #[should_panic]
    fn test_excessive_bits() {
        let bob = DefaultBuildHasher::new();
        let bits = 66;
        let keys = [0x1c10usize, 0x8fd6usize, 0x2d5ausize, 0x7363usize, 0x5f70usize];
        Feistel::new(bob, bits, &keys);
    }
}
