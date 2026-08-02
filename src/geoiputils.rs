// This file is part of IVRE.
// Copyright 2011 - 2026 Pierre LALET <pierre@droids-corp.org>
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

//! This sub-module contains the classes and functions to handle
//! information about IP addresses (mostly from Maxmind GeoIP files).

use std::collections::HashMap;

/// IP Ranges structure for managing IP address ranges
pub struct IPRanges {
    ranges: HashMap<usize, (u64, u64)>,
    length: u64,
}

impl IPRanges {
    /// Create a new IPRanges instance
    pub fn new() -> Self {
        IPRanges {
            ranges: HashMap::new(),
            length: 0,
        }
    }

    /// Append a range to the collection
    pub fn append(&mut self, start: u64, stop: u64) {
        let length = stop - start + 1;
        self.ranges.insert(self.length as usize, (start, length));
        self.length += length;
    }

    /// Get the total length (number of IP addresses)
    pub fn len(&self) -> u64 {
        self.length
    }

    /// Get the IP address at a specific index
    pub fn get(&self, item: u64) -> Option<u64> {
        let rangeindex = self.ranges.keys()
            .filter(|&&k| k <= item as usize)
            .max()
            .copied()?;
        
        let item = item - rangeindex as u64;
        let rnge = self.ranges.get(&rangeindex)?;
        
        if item < rnge.1 {
            Some(rnge.0 + item)
        } else {
            None
        }
    }
}

impl Default for IPRanges {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipranges_new() {
        let ranges = IPRanges::new();
        assert_eq!(ranges.len(), 0);
    }

    #[test]
    fn test_ipranges_append() {
        let mut ranges = IPRanges::new();
        ranges.append(100, 200);
        assert_eq!(ranges.len(), 101);
    }

    #[test]
    fn test_ipranges_get() {
        let mut ranges = IPRanges::new();
        ranges.append(100, 200);
        assert_eq!(ranges.get(0), Some(100));
        assert_eq!(ranges.get(50), Some(150));
        assert_eq!(ranges.get(100), Some(200));
        assert_eq!(ranges.get(101), None);
    }
}
