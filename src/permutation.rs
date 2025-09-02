// SPDX-License-Identifier: Apache-2.0
use crate::{DefaultBuildHasher, Feistel, NumExt};
use std::hash::BuildHasher;

/// An object of constructing random access permutations.
pub struct Permutation<N, B = DefaultBuildHasher>
where
    N: NumExt,
    B: BuildHasher,
{
    n: N,
    feistel: Feistel<N, B>,
}

impl<N, B> Permutation<N, B>
where
    N: NumExt,
    B: BuildHasher,
{
    /// Construct a new permutation over the range `0..n`.
    pub fn new(n: N, seed: N, bob: B) -> Permutation<N, B> {
        let mut keys = Vec::new();
        let mut k = seed;
        for _ in 0..5 {
            k = (bob.hash_one(k) as usize).into();
            keys.push(k.clone());
        }
        //println!("keys = {:?}", keys);

        // Code assumes an even number of bits. Rounding up
        // increases the constant factor in [`get`] but doesn't
        // alter the big-O complexity.
        let bits: N = (n.bits() as usize).into();

        Permutation {
            n,
            feistel: Feistel::new(bob, bits, &keys),
        }
    }

    /// Get the xth element of the permutation.
    pub fn get(&self, x: N) -> N {
        assert!(x < self.n);
        let mut res = self.feistel.encrypt(x);
        while res >= self.n {
            res = self.feistel.encrypt(res);
        }
        res
    }

    /// Construct an iterator over the entire permutation.
    pub fn iter(&self) -> PermutationIterator<'_, N, B> {
        let n = self.n.clone();
        PermutationIterator::new(self, N::zero(), n)
    }

    /// Construct an iterator over the subset `begin..end` of the permutation.
    pub fn range(&self, begin: N, end: N) -> PermutationIterator<'_, N, B> {
        assert!(begin <= end);
        assert!(end <= self.n);
        PermutationIterator::new(self, begin, end)
    }

    /// Transform the Permutation into an iterator over the subset `begin..end` of the permutation.
    pub fn into_range(self, begin: N, end: N) -> OwnedPermutationIterator<N, B> {
        assert!(begin <= end);
        assert!(end <= self.n);
        OwnedPermutationIterator::new(self, begin, end)
    }
}

impl<N: NumExt, B: BuildHasher> IntoIterator for Permutation<N, B> {
    type Item = N;

    type IntoIter = OwnedPermutationIterator<N, B>;

    /// Transform the Permutation into an iterator.
    fn into_iter(self) -> Self::IntoIter {
        let end = self.n.clone();
        OwnedPermutationIterator::new(self, N::zero(), end)
    }
}

/// An iterator over a [`Permutation`] object.
pub struct PermutationIterator<'a, N, B>
where
    N: NumExt,
    B: BuildHasher,
{
    source: &'a Permutation<N, B>,
    curr: N,
    end: N,
}

impl<'a, N, B> PermutationIterator<'a, N, B>
where
    N: NumExt,
    B: BuildHasher,
{
    fn new(source: &'a Permutation<N, B>, begin: N, end: N) -> PermutationIterator<'a, N, B> {
        PermutationIterator { source, curr: begin, end }
    }
}

impl<'a, N, B> Iterator for PermutationIterator<'a, N, B>
where
    N: NumExt,
    B: BuildHasher,
{
    type Item = N;

    fn next(&mut self) -> Option<Self::Item> {
        if self.curr == self.end {
            None
        } else {
            let res = self.source.get(self.curr.clone());
            self.curr.add_assign(N::one());
            Some(res)
        }
    }
}

/// An iterator over a [`Permutation`] object that owns the Permutation.
pub struct OwnedPermutationIterator<N, B>
where
    N: NumExt,
    B: BuildHasher,
{
    source: Permutation<N, B>,
    curr: N,
    end: N,
}

impl<N, B> OwnedPermutationIterator<N, B>
where
    N: NumExt,
    B: BuildHasher,
{
    fn new(source: Permutation<N, B>, begin: N, end: N) -> OwnedPermutationIterator<N, B> {
        OwnedPermutationIterator { source, curr: begin, end }
    }
}

impl<N, B> Iterator for OwnedPermutationIterator<N, B>
where
    N: NumExt,
    B: BuildHasher,
{
    type Item = N;

    fn next(&mut self) -> Option<Self::Item> {
        if self.curr == self.end {
            None
        } else {
            let res = self.source.get(self.curr.clone());
            self.curr.add_assign(N::one());
            Some(res)
        }
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use xxhash_rust::xxh64;

    use super::*;

    fn triangular_variance(a: f64, b: f64, c: f64) -> f64 {
        (a * a + b * b + c * c - a * b - a * c - b * c) / 18.0
    }

    fn triangular_sd(a: f64, b: f64, c: f64) -> f64 {
        triangular_variance(a, b, c).sqrt()
    }

    #[test]
    fn test_1() {
        let n = 1000;
        let nf = n as f64;
        let bob = xxh64::Xxh64Builder::new(19);
        let perm = Permutation::new(n, 19, bob);
        let mut xs = Vec::new();
        for i in 0..n {
            let x = perm.get(i);
            //println!("{i}\t{x}");
            xs.push(x);
        }

        // Check the permutation is random.
        let mut sx: f64 = 0.0;
        let mut sx2: f64 = 0.0;
        for i in 0..n as usize {
            let d = (xs[i] as f64) - (i as f64);
            sx += d;
            sx2 += d * d;
        }
        let m_bar = sx / nf;
        assert_eq!(m_bar, 0.0);
        let v_bar = sx2 / nf - m_bar * m_bar;
        let sd_bar = v_bar.sqrt();
        let sd = triangular_sd(-nf, nf, 0.0);
        let std_error = sd / nf.sqrt();
        assert!((sd_bar - sd).abs() < std_error);

        xs.sort();
        for i in 0..n {
            assert_eq!(xs[i as usize], i);
        }
    }

    #[test]
    fn test_2() {
        let n = 1000000;
        let seed = 29;
        let perm = Permutation::new(n, seed, DefaultBuildHasher::new());
        for j in perm.range(100, 200) {
            println!("{}", j);
        }
        for j in perm.iter().take(10) {
            println!("{}", j);
        }
    }

    #[test]
    fn test_3() {
        let n = BigUint::from(1000000u64);
        let seed = 29u64.into();
        let perm = Permutation::new(n, seed, DefaultBuildHasher::new());
        for j in perm.range(100u64.into(), 200u64.into()) {
            println!("{}", j);
        }
        for j in perm.iter().take(10) {
            println!("{}", j);
        }
    }
}
