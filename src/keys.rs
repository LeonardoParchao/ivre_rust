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

//! Tools to look for (public) keys in the database.

use log::warn;
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a cryptographic key found in the database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Key {
    pub ip: String,
    pub port: u16,
    pub service: String,
    pub key_type: String,
    pub size: u32,
    pub key: String,
    pub md5: String,
}

/// Regular expression to clean modulus data
lazy_static::lazy_static! {
    static ref MODULUS_BADCHARS: Regex = Regex::new(b"[ :\n]+").unwrap();
}

/// Construct an RSA public key from exponent and modulus
/// 
/// This is a placeholder - in production, use a proper cryptography library
/// like openssl or rustls to handle RSA key operations.
pub fn rsa_construct(exp: u64, mod_hex: &str) -> Result<String, String> {
    // Clean the modulus string
    let clean_mod = MODULUS_BADCHARS.replace_all(mod_hex.as_bytes(), b"");
    let clean_mod_str = String::from_utf8(clean_mod.to_vec())
        .map_err(|e| format!("Invalid UTF-8 in modulus: {}", e))?;
    
    // Parse the modulus as hex
    let modulus = u128::from_str_radix(&clean_mod_str, 16)
        .map_err(|e| format!("Invalid modulus hex: {}", e))?;
    
    // In a real implementation, this would construct an actual RSA key
    // For now, return a placeholder representation
    Ok(format!("RSA(exp={}, mod={})", exp, modulus))
}

/// Base class for key lookup tools
pub struct DbKey {
    pub base_filter: Option<String>,
}

impl DbKey {
    pub fn new(base_filter: Option<String>) -> Self {
        DbKey { base_filter }
    }

    /// Get the condition filter for key lookups
    pub fn cond(&self) -> Option<String> {
        self.base_filter.clone()
    }
}

/// Base class for Nmap key lookup tools
pub struct NmapKey {
    pub base: DbKey,
    pub script_id: Option<String>,
}

impl NmapKey {
    pub fn new(base_filter: Option<String>) -> Self {
        NmapKey {
            base: DbKey::new(base_filter),
            script_id: None,
        }
    }

    /// Get scripts from a host record
    pub fn get_scripts(&self, _host: &serde_json::Value) -> Vec<ScriptResult> {
        // Placeholder implementation
        Vec::new()
    }
}

#[derive(Debug, Clone)]
pub struct ScriptResult {
    pub port: u16,
    pub script: serde_json::Value,
}

/// Base class for passive key lookup tools
pub struct PassiveKey {
    pub base: DbKey,
}

impl PassiveKey {
    pub fn new(base_filter: Option<String>) -> Self {
        PassiveKey {
            base: DbKey::new(base_filter),
        }
    }
}

/// Base class for SSL certificate key lookup
pub struct SslKey {
    pub key_type: String,
    pub dbc: Option<String>,
}

impl SslKey {
    pub fn new(key_type: String) -> Self {
        SslKey {
            key_type,
            dbc: None,
        }
    }

    /// Read PEM certificate and extract key information
    pub fn read_pem(&self, pem: &[u8]) -> Result<Vec<u8>, String> {
        // Remove PEM borders
        let pem_borders = Regex::new(b"^-*(BEGIN|END) CERTIFICATE-*$")
            .map_err(|e| format!("Regex error: {}", e))?;
        
        let clean_pem = pem_borders.replace_all(pem, b"");
        
        // In a real implementation, this would use openssl to parse the certificate
        // For now, return the cleaned data
        Ok(clean_pem.to_vec())
    }

    /// Convert PEM to key data
    pub fn pem2key(&self, pem: &[u8]) -> Option<HashMap<String, Vec<u8>>> {
        let pem_parsed = self.read_pem(pem).ok()?;
        
        // In a real implementation, this would extract key information from the certificate
        // For now, return a placeholder
        let mut result = HashMap::new();
        result.insert("modulus".to_string(), vec![]);
        result.insert("exponent".to_string(), vec![]);
        Some(result)
    }

    /// Read DER certificate and extract key information
    pub fn read_der(&self, der: &[u8]) -> Result<Vec<u8>, String> {
        // In a real implementation, this would use openssl to parse the DER certificate
        // For now, return the data as-is
        Ok(der.to_vec())
    }

    /// Convert DER to key data
    pub fn der2key(&self, der: &[u8]) -> Option<HashMap<String, Vec<u8>>> {
        let der_parsed = self.read_der(der).ok()?;
        
        // In a real implementation, this would extract key information from the certificate
        // For now, return a placeholder
        let mut result = HashMap::new();
        result.insert("modulus".to_string(), vec![]);
        result.insert("exponent".to_string(), vec![]);
        Some(result)
    }
}

/// SSL key lookup for Nmap database
pub struct SslNmapKey {
    pub nmap: NmapKey,
    pub ssl: SslKey,
}

impl SslNmapKey {
    pub fn new(base_filter: Option<String>) -> Self {
        let mut nmap = NmapKey::new(base_filter);
        nmap.script_id = Some("ssl-cert".to_string());
        
        SslNmapKey {
            nmap,
            ssl: SslKey::new("rsa".to_string()),
        }
    }

    /// Get keys from a record
    pub fn get_keys(&self, record: &serde_json::Value) -> Vec<Key> {
        let mut keys = Vec::new();
        
        let addr = record.get("addr").and_then(|v| v.as_str()).unwrap_or("");
        
        for script_result in self.nmap.get_scripts(record) {
            if let Some(script_data) = script_result.script.get("ssl-cert") {
                if let Some(pubkey) = script_data.get("pubkey") {
                    let key_type = pubkey.get("type").and_then(|v| v.as_str()).unwrap_or("unknown");
                    let bits = pubkey.get("bits").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    
                    if let Some(pem) = script_data.get("pem").and_then(|v| v.as_str()) {
                        let key_data = self.ssl.pem2key(pem.as_bytes());
                        
                        let md5 = script_data.get("md5").and_then(|v| v.as_str()).unwrap_or("");
                        
                        keys.push(Key {
                            ip: addr.to_string(),
                            port: script_result.port,
                            service: "ssl".to_string(),
                            key_type: key_type.to_string(),
                            size: bits,
                            key: key_data.map(|k| format!("{:?}", k)).unwrap_or_default(),
                            md5: md5.to_string(),
                        });
                    }
                }
            }
        }
        
        keys
    }
}

/// SSL key lookup for passive database
pub struct SslPassiveKey {
    pub passive: PassiveKey,
    pub ssl: SslKey,
}

impl SslPassiveKey {
    pub fn new(base_filter: Option<String>) -> Self {
        SslPassiveKey {
            passive: PassiveKey::new(base_filter),
            ssl: SslKey::new("rsa".to_string()),
        }
    }

    /// Get keys from a passive record
    pub fn get_keys(&self, record: &serde_json::Value) -> Vec<Key> {
        let mut keys = Vec::new();
        
        let addr = record.get("addr").and_then(|v| v.as_str()).unwrap_or("");
        let port = record.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
        
        if let Some(value) = record.get("value").and_then(|v| v.as_str()) {
            // Decode base64 value
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(value) {
                if let Some(certtext) = self.ssl.der2key(&decoded) {
                    let modulus = certtext.get("modulus").and_then(|v| String::from_utf8(v.clone()).ok()).unwrap_or_default();
                    let exponent = certtext.get("exponent").and_then(|v| String::from_utf8(v.clone()).ok()).unwrap_or_default();
                    
                    let exp = exponent.parse::<u64>().unwrap_or(0);
                    
                    if let Ok(key) = rsa_construct(exp, &modulus) {
                        let md5 = record.get("infos")
                            .and_then(|i| i.get("md5"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        
                        let key_type = certtext.get("type")
                            .and_then(|v| String::from_utf8(v.clone()).ok())
                            .unwrap_or_else(|| "rsa".to_string());
                        
                        let len = certtext.get("len")
                            .and_then(|v| String::from_utf8(v.clone()).ok())
                            .and_then(|s| s.parse::<u32>().ok())
                            .unwrap_or(0);
                        
                        keys.push(Key {
                            ip: addr.to_string(),
                            port,
                            service: "ssl".to_string(),
                            key_type,
                            size: len,
                            key,
                            md5: md5.to_string(),
                        });
                    }
                }
            }
        }
        
        keys
    }
}

/// Base class for SSH key lookup
pub struct SshKey {
    pub key_type: String,
    pub dbc: Option<String>,
}

impl SshKey {
    pub fn new(key_type: String) -> Self {
        SshKey {
            key_type,
            dbc: None,
        }
    }
}

/// SSH key lookup for Nmap database
pub struct SshNmapKey {
    pub nmap: NmapKey,
    pub ssh: SshKey,
}

impl SshNmapKey {
    pub fn new(base_filter: Option<String>, key_type: String) -> Self {
        let mut nmap = NmapKey::new(base_filter);
        nmap.script_id = Some("ssh-hostkey".to_string());
        
        SshNmapKey {
            nmap,
            ssh: SshKey::new(key_type),
        }
    }

    /// Convert SSH key data to key representation
    pub fn data2key(&self, data: &[u8]) -> Result<String, String> {
        // In a real implementation, this would parse SSH key format
        // For now, return a placeholder
        Ok(format!("SSH-KEY-{:x?}", data))
    }

    /// Get keys from a record
    pub fn get_keys(&self, record: &serde_json::Value) -> Vec<Key> {
        let mut keys = Vec::new();
        
        let addr = record.get("addr").and_then(|v| v.as_str()).unwrap_or("");
        
        for script_result in self.nmap.get_scripts(record) {
            if let Some(script_data) = script_result.script.get("ssh-hostkey") {
                if let Some(key_array) = script_data.as_array() {
                    for key in key_array {
                        let key_type = key.get("type").and_then(|v| v.as_str()).unwrap_or("");
                        
                        // Check if this matches our key type
                        if key_type.starts_with("ssh-") && key_type[4..] == self.ssh.key_type {
                            let bits = key.get("bits")
                                .and_then(|v| v.as_str())
                                .and_then(|s| s.parse::<f64>().ok())
                                .unwrap_or(0.0) as u32;
                            
                            if let Some(key_data) = key.get("key").and_then(|v| v.as_str()) {
                                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(key_data) {
                                    let data = if decoded.starts_with(b"\x00") {
                                        decoded
                                    } else {
                                        // Handle double encoding
                                        base64::engine::general_purpose::STANDARD.decode(&decoded).unwrap_or(decoded)
                                    };
                                    
                                    if let Ok(key) = self.data2key(&data) {
                                        let fingerprint = key.get("fingerprint").and_then(|v| v.as_str()).unwrap_or("");
                                        
                                        keys.push(Key {
                                            ip: addr.to_string(),
                                            port: script_result.port,
                                            service: "ssh".to_string(),
                                            key_type: key_type[4..].to_string(),
                                            size: bits,
                                            key,
                                            md5: fingerprint.to_string(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        keys
    }
}

/// SSH key lookup for passive database
pub struct SshPassiveKey {
    pub passive: PassiveKey,
    pub ssh: SshKey,
}

impl SshPassiveKey {
    pub fn new(base_filter: Option<String>, key_type: String) -> Self {
        SshPassiveKey {
            passive: PassiveKey::new(base_filter),
            ssh: SshKey::new(key_type),
        }
    }

    /// Get keys from a passive record
    pub fn get_keys(&self, record: &serde_json::Value) -> Vec<Key> {
        let mut keys = Vec::new();
        
        let addr = record.get("addr").and_then(|v| v.as_str()).unwrap_or("");
        let port = record.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
        
        if let Some(infos) = record.get("infos") {
            let algo = infos.get("algo").and_then(|v| v.as_str()).unwrap_or("");
            let key_type = if algo.starts_with("ssh-") { &algo[4..] } else { algo };
            
            if key_type == self.ssh.key_type {
                let bits = infos.get("bits").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                let exponent = infos.get("exponent").and_then(|v| v.as_str()).unwrap_or("0");
                let modulus = infos.get("modulus").and_then(|v| v.as_str()).unwrap_or("0");
                
                let exp = exponent.parse::<u64>().unwrap_or(0);
                
                if let Ok(key) = rsa_construct(exp, modulus) {
                    let md5 = infos.get("md5").and_then(|v| v.as_str()).unwrap_or("");
                    
                    keys.push(Key {
                        ip: addr.to_string(),
                        port,
                        service: "ssh".to_string(),
                        key_type: key_type.to_string(),
                        size: bits,
                        key,
                        md5: md5.to_string(),
                    });
                }
            }
        }
        
        keys
    }
}

/// RSA-specific key implementations
pub struct RsaKey;

impl RsaKey {
    pub fn new() -> Self {
        RsaKey
    }

    /// Convert PEM to RSA key
    pub fn pem2key(pem: &[u8]) -> Option<String> {
        // In a real implementation, this would extract RSA parameters from PEM
        // For now, return a placeholder
        Some(format!("RSA-PEM-KEY"))
    }

    /// Convert SSH key data to RSA key
    pub fn data2key(data: &[u8]) -> Result<String, String> {
        // In a real implementation, this would parse SSH RSA key format
        // For now, return a placeholder
        Ok(format!("RSA-SSH-KEY-{:x?}", data))
    }
}

/// SSL RSA key lookup for Nmap database
pub struct SslRsaNmapKey {
    pub base: SslNmapKey,
}

impl SslRsaNmapKey {
    pub fn new(base_filter: Option<String>) -> Self {
        SslRsaNmapKey {
            base: SslNmapKey::new(base_filter),
        }
    }

    /// Get keys from a record
    pub fn get_keys(&self, record: &serde_json::Value) -> Vec<Key> {
        let mut keys = Vec::new();
        
        let addr = record.get("addr").and_then(|v| v.as_str()).unwrap_or("");
        
        for script_result in self.base.nmap.get_scripts(record) {
            if let Some(script_data) = script_result.script.get("ssl-cert") {
                if let Some(cert_array) = script_data.as_array() {
                    for cert in cert_array {
                        if let Some(pubkey) = cert.get("pubkey") {
                            let key_type = pubkey.get("type").and_then(|v| v.as_str()).unwrap_or("unknown");
                            let bits = pubkey.get("bits").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                            
                            let exponent = pubkey.get("exponent").and_then(|v| v.as_str()).unwrap_or("0");
                            let modulus = pubkey.get("modulus").and_then(|v| v.as_str()).unwrap_or("0");
                            
                            let exp = exponent.parse::<u64>().unwrap_or(0);
                            
                            if let Ok(key) = rsa_construct(exp, modulus) {
                                let md5 = cert.get("md5").and_then(|v| v.as_str()).unwrap_or("");
                                
                                keys.push(Key {
                                    ip: addr.to_string(),
                                    port: script_result.port,
                                    service: "ssl".to_string(),
                                    key_type: key_type.to_string(),
                                    size: bits,
                                    key,
                                    md5: md5.to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
        
        keys
    }
}

/// SSH RSA key lookup for Nmap database
pub struct SshRsaNmapKey {
    pub base: SshNmapKey,
}

impl SshRsaNmapKey {
    pub fn new(base_filter: Option<String>) -> Self {
        SshRsaNmapKey {
            base: SshNmapKey::new(base_filter, "rsa".to_string()),
        }
    }

    /// Get keys from a record
    pub fn get_keys(&self, record: &serde_json::Value) -> Vec<Key> {
        self.base.get_keys(record)
    }
}

/// SSL RSA key lookup for passive database
pub struct SslRsaPassiveKey {
    pub base: SslPassiveKey,
}

impl SslRsaPassiveKey {
    pub fn new(base_filter: Option<String>) -> Self {
        SslRsaPassiveKey {
            base: SslPassiveKey::new(base_filter),
        }
    }

    /// Get keys from a record
    pub fn get_keys(&self, record: &serde_json::Value) -> Vec<Key> {
        self.base.get_keys(record)
    }
}

/// SSH RSA key lookup for passive database
pub struct SshRsaPassiveKey {
    pub base: SshPassiveKey,
}

impl SshRsaPassiveKey {
    pub fn new(base_filter: Option<String>) -> Self {
        SshRsaPassiveKey {
            base: SshPassiveKey::new(base_filter, "rsa".to_string()),
        }
    }

    /// Get keys from a record
    pub fn get_keys(&self, record: &serde_json::Value) -> Vec<Key> {
        self.base.get_keys(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_construct() {
        let result = rsa_construct(65537, "abcd1234");
        assert!(result.is_ok());
    }

    #[test]
    fn test_db_key_new() {
        let key = DbKey::new(Some("test".to_string()));
        assert_eq!(key.base_filter, Some("test".to_string()));
    }

    #[test]
    fn test_nmap_key_new() {
        let key = NmapKey::new(None);
        assert!(key.script_id.is_none());
    }

    #[test]
    fn test_ssl_key_new() {
        let key = SslKey::new("rsa".to_string());
        assert_eq!(key.key_type, "rsa");
    }

    #[test]
    fn test_ssh_key_new() {
        let key = SshKey::new("rsa".to_string());
        assert_eq!(key.key_type, "rsa");
    }
}
