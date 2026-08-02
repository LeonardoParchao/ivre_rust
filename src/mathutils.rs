// This file is part of IVRE.
// Copyright 2011 - 2024 Pierre LALET <pierre@droids-corp.org>
//
// IVRE is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// IVRE is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
// License for more details.
//
// You should have received a copy of the GNU General Public License
// along with IVRE. If not, see <http://www.gnu.org/licenses/>.

//! This sub-module contains math functions missing from Rust's standard
//! library that might be useful to any other sub-module or script.

use std::collections::HashMap;

/// Yields the sequence of prime numbers via the Sieve of Eratosthenes.
///
/// http://code.activestate.com/recipes/117119/
pub fn genprimes() -> impl Iterator<Item = u64> {
    let mut d: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut q = 2u64;
    
    std::iter::from_fn(move || {
        loop {
            if !d.contains_key(&q) {
                // q is prime
                d.insert(q * q, vec![q]);
                let result = q;
                q += 1;
                return Some(result);
            } else {
                // q is composite
                let witnesses = d.remove(&q).unwrap();
                for p in witnesses {
                    d.entry(p + q).or_insert_with(Vec::new).push(p);
                }
                q += 1;
            }
        }
    })
}

/// Yields the prime factors of the integer n.
pub fn factors(n: u64) -> impl Iterator<Item = u64> {
    let mut primes = genprimes();
    let mut current_n = n;
    
    std::iter::from_fn(move || {
        if current_n == 1 {
            return None;
        }
        
        loop {
            let p = primes.next().unwrap();
            while current_n % p == 0 {
                current_n /= p;
                return Some(p);
            }
            if current_n == 1 {
                return None;
            }
            if p * p > current_n {
                let result = current_n;
                current_n = 1;
                return Some(result);
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genprimes() {
        let primes: Vec<u64> = genprimes().take(10).collect();
        assert_eq!(primes, vec![2, 3, 5, 7, 11, 13, 17, 19, 23, 29]);
    }

    #[test]
    fn test_factors() {
        let factors_vec: Vec<u64> = factors(12).collect();
        assert_eq!(factors_vec, vec![2, 2, 3]);
        
        let factors_vec: Vec<u64> = factors(17).collect();
        assert_eq!(factors_vec, vec![17]);
        
        let factors_vec: Vec<u64> = factors(100).collect();
        assert_eq!(factors_vec, vec![2, 2, 5, 5]);
    }
}
