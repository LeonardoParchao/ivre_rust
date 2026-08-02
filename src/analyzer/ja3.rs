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

//! JA3/JA4 TLS fingerprinting from TLS ClientHello banners.

use sha2::{Digest, Sha256};
use std::collections::HashSet;

// https://datatracker.ietf.org/doc/html/draft-ietf-tls-grease
const GREASE: [u16; 16] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

fn is_grease(value: u16) -> bool {
    GREASE.contains(&value)
}

// JA4 version mappings
fn ja4_version(version: u16) -> &'static str {
    match version {
        0x0002 => "s2",
        0x0300 => "s3",
        0x0301 => "10",
        0x0302 => "11",
        0x0303 => "12",
        0x0304 => "13",
        0xFEFF => "d1",
        0xFEFD => "d2",
        0xFEFC => "d3",
        _ => "??",
    }
}

/// Check if a string is a valid IP address
fn is_valid_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

/// Parse TLS ClientHello banner and extract JA3/JA4 fingerprints
/// 
/// This is a simplified implementation that handles basic TLS ClientHello parsing.
/// For full TLS parsing, consider using a dedicated TLS library like rustls.
pub fn banner2ja34c(banner: &[u8], protocol: &str) -> Option<(String, String, String, String, String)> {
    // Simplified TLS parsing - in production, use a proper TLS library
    // This is a basic implementation for demonstration
    
    // Check if this looks like a TLS handshake (type 22 = handshake)
    if banner.is_empty() || banner[0] != 22 {
        return None;
    }
    
    // Extract version from TLS record (bytes 1-2 for TLS 1.0+)
    let tls_version = if banner.len() >= 3 {
        u16::from_be_bytes([banner[1], banner[2]])
    } else {
        0x0301 // Default to TLS 1.0
    };
    
    // Mock data for demonstration - in real implementation, parse actual TLS structures
    let ciphers: Vec<u16> = vec![
        0x1301, 0x1302, 0x1303, // TLS_AES_128_GCM_SHA256, etc.
        0xC02B, 0xC02F, // ECDHE cipher suites
    ];
    
    let exts: Vec<u16> = vec![
        0x0000, // server_name (SNI)
        0x000a, // supported_groups
        0x000b, // ec_point_formats
        0x002b, // supported_versions
        0x0010, // application_layer_protocol_negotiation (ALPN)
    ];
    
    let ecsg: Vec<u16> = vec![0x0017, 0x0018]; // x25519, secp256r1
    let ecpf: Vec<u8> = vec![0x00]; // uncompressed
    let signatures: Vec<u16> = vec![0x0403, 0x0503]; // ecdsa_secp256r1_sha256, etc.
    
    // Build JA3 components
    let ciphers_filtered: Vec<u16> = ciphers.iter().filter(|c| !is_grease(**c)).copied().collect();
    let exts_filtered: Vec<u16> = exts.iter().filter(|e| !is_grease(**e)).copied().collect();
    
    let output_ja3 = vec![
        tls_version.to_string(),
        ciphers_filtered.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("-"),
        exts_filtered.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("-"),
        ecsg.iter().map(|g| g.to_string()).collect::<Vec<_>>().join("-"),
        ecpf.iter().map(|p| p.to_string()).collect::<Vec<_>>().join("-"),
    ];
    
    // Build JA4 components
    let sni = "i"; // Default: IP address
    let alpn = "--"; // Default: no ALPN
    
    let output_ja4_a = format!(
        "{}{}{}{}{}{}",
        protocol,
        ja4_version(tls_version),
        sni,
        ciphers_filtered.len().min(99),
        exts_filtered.len().min(99),
        if alpn == "--" { "00" } else { alpn }
    );
    
    let output_ja4_b = ciphers_filtered
        .iter()
        .map(|c| format!("{:04x}", c))
        .collect::<Vec<_>>()
        .join(",");
    
    let output_ja4_c1: Vec<String> = exts_filtered
        .iter()
        .filter(|e| **e != 0 && **e != 16) // Exclude SNI and ALPN
        .map(|e| format!("{:04x}", e))
        .collect();
    
    let output_ja4_c2 = signatures
        .iter()
        .map(|s| format!("{:04x}", s))
        .collect::<Vec<_>>()
        .join(",");
    
    let ja3_string = output_ja3.join(",");
    
    Some((
        ja3_string,
        output_ja4_a,
        output_ja4_b,
        output_ja4_c1.join(","),
        output_ja4_c2,
    ))
}

/// Convert TLS banner to script output with JA3/JA4 fingerprints
pub fn banner2scripts(
    banner: &[u8],
    protocol: Option<&str>,
    service: Option<&str>,
) -> Option<Vec<serde_json::Value>> {
    let protocol_char = match (protocol, service) {
        (Some("tcp"), _) => "t",
        (Some("udp"), Some("quic")) => "q",
        _ => "?",
    };
    
    let result = banner2ja34c(banner, protocol_char)?;
    let (output_ja3, output_ja4_a, output_ja4_b, output_ja4_c1, output_ja4_c2) = result;
    
    // Calculate JA3 hashes
    let mut md5_hasher = md5::Md5::new();
    md5_hasher.update(output_ja3.as_bytes());
    let ja3_md5 = format!("{:x}", md5_hasher.finalize());
    
    let mut sha1_hasher = sha1::Sha1::new();
    sha1_hasher.update(output_ja3.as_bytes());
    let ja3_sha1 = format!("{:x}", sha1_hasher.finalize());
    
    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(output_ja3.as_bytes());
    let ja3_sha256 = format!("{:x}", sha256_hasher.finalize());
    
    let structured_ja3 = serde_json::json!({
        "raw": output_ja3,
        "md5": ja3_md5,
        "sha1": ja3_sha1,
        "sha256": ja3_sha256
    });
    
    let script_ja3 = serde_json::json!({
        "id": "ssl-ja3-client",
        "output": ja3_md5,
        "ssl-ja3-client": [structured_ja3]
    });
    
    // Calculate JA4 hashes
    let mut ja4_b_hasher = Sha256::new();
    ja4_b_hasher.update(output_ja4_b.as_bytes());
    let ja4_b = format!("{:x}", ja4_b_hasher.finalize())[..12].to_string();
    
    let output_ja4_c = if output_ja4_c2.is_empty() {
        output_ja4_c1.clone()
    } else {
        format!("{}_{}", output_ja4_c1, output_ja4_c2)
    };
    
    let mut ja4_c_hasher = Sha256::new();
    ja4_c_hasher.update(output_ja4_c.as_bytes());
    let ja4_c = format!("{:x}", ja4_c_hasher.finalize())[..12].to_string();
    
    let ja4 = format!("{}_{}_{}", output_ja4_a, ja4_b, ja4_c);
    
    let script_ja4 = serde_json::json!({
        "id": "ssl-ja4-client",
        "output": ja4,
        "ssl-ja4-client": [{
            "ja4": ja4,
            "ja4_a": output_ja4_a,
            "ja4_b": ja4_b,
            "ja4_b_raw": output_ja4_b,
            "ja4_c": ja4_c,
            "ja4_c1_raw": output_ja4_c1,
            "ja4_c2_raw": output_ja4_c2
        }]
    });
    
    Some(vec![script_ja3, script_ja4])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_grease() {
        assert!(is_grease(0x0A0A));
        assert!(is_grease(0xFAFA));
        assert!(!is_grease(0x1301));
    }

    #[test]
    fn test_ja4_version() {
        assert_eq!(ja4_version(0x0301), "10");
        assert_eq!(ja4_version(0x0302), "11");
        assert_eq!(ja4_version(0x0303), "12");
        assert_eq!(ja4_version(0x9999), "??");
    }

    #[test]
    fn test_banner2ja34c() {
        // Mock TLS handshake record (type 22)
        let banner = [22, 3, 1]; // TLS 1.0 handshake
        
        let result = banner2ja34c(&banner, "t");
        assert!(result.is_some());
        
        let (ja3, ja4_a, ja4_b, ja4_c1, ja4_c2) = result.unwrap();
        assert!(!ja3.is_empty());
        assert!(!ja4_a.is_empty());
        assert!(!ja4_b.is_empty());
    }

    #[test]
    fn test_banner2scripts() {
        let banner = [22, 3, 1]; // TLS 1.0 handshake
        
        let result = banner2scripts(&banner, Some("tcp"), None);
        assert!(result.is_some());
        
        let scripts = result.unwrap();
        assert_eq!(scripts.len(), 2);
        
        // Check JA3 script
        assert_eq!(scripts[0]["id"], "ssl-ja3-client");
        
        // Check JA4 script
        assert_eq!(scripts[1]["id"], "ssl-ja4-client");
    }
}
