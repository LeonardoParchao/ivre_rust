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

//! This sub-module contains functions used for flow.

use std::collections::HashMap;

pub const SCHEMA_VERSION: i32 = 1;

/// Field descriptions for flow data
pub fn get_fields() -> HashMap<&'static str, &'static str> {
    let mut fields = HashMap::new();
    fields.insert("src.addr", "Source IP Address");
    fields.insert("dst.addr", "Destination IP Address");
    fields.insert("proto", "Transport protocol");
    fields.insert("dport", "Destination port (if relevant)");
    fields.insert("sports", "Source ports (list) (if relevant)");
    fields.insert("type", "ICMP type (if relevant)");
    fields.insert("codes", "ICMP codes (list) (if relevant)");
    fields.insert("count", "Number of occurrences of the flow");
    fields.insert("csbytes", "Number of bytes sent by client (src) to server (dst)");
    fields.insert("scbytes", "Number of bytes sent by server (dst) to client (src)");
    fields.insert("cspkts", "Number of packets sent by client (src) to server (dst)");
    fields.insert("scpkts", "Number of packets sent by server (dst) to client (src)");
    fields.insert("firstseen", "First time the flow has been observed");
    fields.insert("lastseen", "Last time the flow has been observed");
    fields.insert("times", "Time periods during which the flow has been observed (list) (MongoDB backend only)");
    fields.insert("times.duration", "Time period duration (MongoDB backend only)");
    fields.insert("times.start", "Time period beginning (MongoDB backend only)");
    fields
}

/// Meta description arrays (fields containing lists of values)
pub fn get_meta_desc_arrays() -> Vec<&'static str> {
    vec!["dns.keys.answers"]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_fields() {
        let fields = get_fields();
        assert!(fields.contains_key("src.addr"));
        assert_eq!(fields.get("src.addr"), Some(&"Source IP Address"));
    }

    #[test]
    fn test_meta_desc_arrays() {
        let arrays = get_meta_desc_arrays();
        assert!(arrays.contains(&"dns.keys.answers"));
    }
}
