// This file is part of IVRE.
// Copyright 2011 - 2025 Pierre LALET <pierre@droids-corp.org>
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

//! Functions to manipulate documents from the active (nmap & view) purposes.

use log::warn;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use textwrap::wrap;

/// Parsed certificate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedCertificate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<PublicKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub md5": Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub san: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bits: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exponent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modulus: Option<String>,
}

/// Create SSL output from parsed certificate information
pub fn create_ssl_output(info: &ParsedCertificate) -> Vec<String> {
    let mut out = Vec::new();
    
    if let Some(subject) = &info.subject_text {
        out.push(format!("Subject: {}", subject));
    }
    
    if let Some(issuer) = &info.issuer_text {
        out.push(format!("Issuer: {}", issuer));
    }
    
    if let Some(pubkey) = &info.pubkey {
        if let Some(key_type) = &pubkey.key_type {
            out.push(format!("Public Key type: {}", key_type));
        }
        if let Some(bits) = pubkey.bits {
            out.push(format!("Public Key bits: {}", bits));
        }
    }
    
    if let Some(not_before) = &info.not_before {
        out.push(format!("Not valid before: {}", not_before));
    }
    
    if let Some(not_after) = &info.not_after {
        out.push(format!("Not valid after:  {}", not_after));
    }
    
    if let Some(san) = &info.san {
        for san_entry in san {
            out.push(format!("Subject Alternative Name: {}", san_entry));
        }
    }
    
    if let Some(md5) = &info.md5 {
        out.push(format!("MD5:    {}", wrap(md5, 4).join(" ")));
    }
    
    if let Some(sha1) = &info.sha1 {
        out.push(format!("SHA-1:  {}", wrap(sha1, 4).join(" ")));
    }
    
    if let Some(sha256) = &info.sha256 {
        out.push(format!("SHA-256: {}", wrap(sha256, 4).join(" ")));
    }
    
    if let Some(pem) = &info.pem {
        out.push(pem.clone());
    }
    
    out
}

/// Create SSL certificate from data (similar to Nmap's ssl-cert script)
pub fn create_ssl_cert(data: &[u8], b64encoded: bool) -> Result<(String, ParsedCertificate), String> {
    let cert = if b64encoded {
        base64::engine::general_purpose::STANDARD
            .decode(data)
            .map_err(|e| format!("Base64 decode error: {}", e))?
    } else {
        data.to_vec()
    };
    
    let info = get_cert_info(&cert)?;
    
    let b64cert = base64::engine::general_purpose::STANDARD.encode(&cert);
    let mut pem_lines = Vec::new();
    pem_lines.push("-----BEGIN CERTIFICATE-----".to_string());
    pem_lines.extend(wrap(&b64cert, 64));
    pem_lines.push("-----END CERTIFICATE-----".to_string());
    pem_lines.push(String::new());
    
    let mut info_with_pem = info.clone();
    info_with_pem.pem = Some(pem_lines.join("\n"));
    
    let output = create_ssl_output(&info_with_pem).join("\n");
    
    Ok((output, info_with_pem))
}

/// Extract hostname from Subject Alt Name value
pub fn san2hostname(san: &str) -> Option<(String, String)> {
    if san.starts_with("DNS:") {
        return Some(("dns".to_string(), san[4..].to_string()));
    }
    
    if san.starts_with("URI:") {
        let url = san[4..].to_string();
        let parsed_url = if url.starts_with("://") {
            format!("x{}", url) // Add fake scheme for parsing
        } else {
            url.clone()
        };
        
        if let Ok(parsed) = url::Url::parse(&parsed_url) {
            if let Some(hostname) = parsed.host_str() {
                return Some(("uri".to_string(), hostname.to_string()));
            }
        }
        
        warn!("Invalid URL in SAN {:?}", san);
        return None;
    }
    
    if san.starts_with("DirName:") {
        let dir_name = san[8..];
        if let Some((key, value)) = dir_name.split_once('=') {
            if key.trim().to_lowercase() == "cn" {
                return Some(("dirname-cn".to_string(), value.trim().to_string()));
            }
        }
        warn!("Invalid DirName in SAN {:?}", san);
        return None;
    }
    
    if san.starts_with("othername:UPN:") {
        let upn = san[14..];
        if upn.starts_with("S-1-") {
            // SID - skip
            return None;
        }
        
        let hostname = if upn.contains('/') {
            upn.split('/').nth(1).and_then(|s| s.split('@').next())
        } else {
            Some(upn)
        };
        
        if let Some(host) = hostname {
            return Some(("othername-upn".to_string(), host.to_string()));
        }
    }
    
    if san.starts_with("othername:") {
        let name = san[10..];
        if let Some((subtype, hostname)) = name.split_once(':') {
            return Some((format!("othername-{}", subtype.to_lowercase()), hostname.to_string()));
        }
    }
    
    None
}

/// Add certificate hostnames to the hostnames list
pub fn add_cert_hostnames(cert: &ParsedCertificate, hostnames: &mut Vec<Hostname>) {
    if let Some(subject) = &cert.subject {
        if let Some(common_name) = subject.get("commonName") {
            add_hostname(common_name, "cert-subject-cn", hostnames);
        }
    }
    
    if let Some(san) = &cert.san {
        for san_entry in san {
            if let Some((type_hostname, hostname)) = san2hostname(san_entry) {
                add_hostname(&hostname, &format!("cert-san-{}", type_hostname), hostnames);
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hostname {
    pub name: String,
    #[serde(rename = "type")]
    pub hostname_type: String,
    pub domains: Vec<String>,
}

/// Add a hostname to the hostnames list
pub fn add_hostname(name: &str, hostname_type: &str, hostnames: &mut Vec<Hostname>) {
    let domains = get_domains(name);
    
    hostnames.push(Hostname {
        name: name.to_string(),
        hostname_type: hostname_type.to_string(),
        domains,
    });
}

/// Extract domain parts from a hostname
pub fn get_domains(hostname: &str) -> Vec<String> {
    let parts: Vec<&str> = hostname.split('.').collect();
    let mut domains = Vec::new();
    
    for i in 1..parts.len() {
        let domain = parts[i..].join(".");
        if !domain.is_empty() {
            domains.push(domain);
        }
    }
    
    domains
}

/// Get certificate information from raw certificate data
/// This is a placeholder - in production, use a proper certificate parsing library
pub fn get_cert_info(cert: &[u8]) -> Result<ParsedCertificate, String> {
    // In a real implementation, this would use openssl or rustls to parse the certificate
    // For now, return a placeholder
    Ok(ParsedCertificate {
        subject_text: None,
        issuer_text: None,
        pubkey: None,
        not_before: None,
        not_after: None,
        md5: None,
        sha1: None,
        sha256: None,
        pem: None,
        san: None,
        subject: None,
    })
}

/// Merge JA3 scripts
pub fn merge_ja3_scripts(
    curscript: &serde_json::Value,
    script: &serde_json::Value,
    script_id: &str,
) -> serde_json::Value {
    let is_server = script_id == "ssl-ja3-server";
    
    let ja3_equals = |a: &serde_json::Value, b: &serde_json::Value| -> bool {
        if let (Some(a_md5), Some(b_md5)) = (a.get("md5"), b.get("md5")) {
            if a_md5 != b_md5 {
                return false;
            }
            if is_server {
                if let (Some(a_client), Some(b_client)) = (a.get("client"), b.get("client")) {
                    if let (Some(a_client_md5), Some(b_client_md5)) = (a_client.get("md5"), b_client.get("md5")) {
                        return a_client_md5 == b_client_md5;
                    }
                }
            }
            true
        } else {
            false
        }
    };
    
    let ja3_output = |ja3: &serde_json::Value| -> String {
        if let Some(md5) = ja3.get("md5").and_then(|v| v.as_str()) {
            if is_server {
                if let Some(client) = ja3.get("client") {
                    if let Some(client_md5) = client.get("md5").and_then(|v| v.as_str()) {
                        return format!("{} - {}", md5, client_md5);
                    }
                }
            }
            return md5.to_string();
        }
        String::new()
    };
    
    merge_scripts_generic(curscript, script, script_id, &ja3_equals, &ja3_output)
}

/// Merge JA4 scripts
pub fn merge_ja4_scripts(
    curscript: &serde_json::Value,
    script: &serde_json::Value,
    script_id: &str,
) -> serde_json::Value {
    let ja4_equals = |a: &serde_json::Value, b: &serde_json::Value| -> bool {
        if let (Some(a_ja4), Some(b_ja4)) = (a.get("ja4"), b.get("ja4")) {
            a_ja4 == b_ja4
        } else {
            false
        }
    };
    
    let ja4_output = |ja4: &serde_json::Value| -> String {
        ja4.get("ja4")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    
    merge_scripts_generic(curscript, script, script_id, &ja4_equals, &ja4_output)
}

/// Merge HTTP application scripts
pub fn merge_http_app_scripts(
    curscript: &serde_json::Value,
    script: &serde_json::Value,
    script_id: &str,
) -> serde_json::Value {
    let http_app_equals = |a: &serde_json::Value, b: &serde_json::Value| -> bool {
        if let (Some(a_app), Some(b_app)) = (a.get("application"), b.get("application")) {
            if a_app != b_app {
                return false;
            }
        }
        if let (Some(a_path), Some(b_path)) = (a.get("path"), b.get("path")) {
            a_path == b_path
        } else {
            false
        }
    };
    
    let http_app_output = |app: &serde_json::Value| -> String {
        let mut output = Vec::new();
        
        if let Some(application) = app.get("application").and_then(|v| v.as_str()) {
            if let Some(path) = app.get("path").and_then(|v| v.as_str()) {
                output.push(format!("{}: path {}", application, path));
            }
            
            if let Some(version) = app.get("version").and_then(|v| v.as_str()) {
                output.push(format!(", version {}", version));
                
                if let Some(parsed_version) = app.get("parsed_version").and_then(|v| v.as_str()) {
                    output.push(format!(" ({})", parsed_version));
                } else if application == "OWA" {
                    // In a real implementation, look up EXCHANGE_BUILDS
                    output.push(" (unknown build number)".to_string());
                }
            }
        }
        
        output.concat()
    };
    
    merge_scripts_generic(curscript, script, script_id, &http_app_equals, &http_app_output)
}

/// Merge user agent scripts
pub fn merge_ua_scripts(
    curscript: &serde_json::Value,
    script: &serde_json::Value,
    script_id: &str,
) -> serde_json::Value {
    let ua_equals = |a: &serde_json::Value, b: &serde_json::Value| -> bool {
        if let (Some(a_str), Some(b_str)) = (a.as_str(), b.as_str()) {
            a_str == b_str
        } else {
            false
        }
    };
    
    let ua_output = |ua: &serde_json::Value| -> String {
        ua.as_str().unwrap_or("").to_string()
    };
    
    merge_scripts_generic(curscript, script, script_id, &ua_equals, &ua_output)
}

/// Merge SSL certificate scripts
pub fn merge_ssl_cert_scripts(
    curscript: &serde_json::Value,
    script: &serde_json::Value,
    script_id: &str,
) -> serde_json::Value {
    let cert_equals = |a: &serde_json::Value, b: &serde_json::Value| -> bool {
        if let (Some(a_sha256), Some(b_sha256)) = (a.get("sha256"), b.get("sha256")) {
            a_sha256 == b_sha256
        } else {
            false
        }
    };
    
    let cert_output = |cert: &serde_json::Value| -> String {
        // In a real implementation, this would call create_ssl_output
        cert.get("sha256")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    
    merge_scripts_generic_with_sep(
        curscript,
        script,
        script_id,
        &cert_equals,
        &cert_output,
        "\n------------------------------------------------------------\n",
    )
}

/// Generic script merging function
fn merge_scripts_generic<F, G>(
    curscript: &serde_json::Value,
    script: &serde_json::Value,
    script_id: &str,
    equals: &F,
    output: &G,
) -> serde_json::Value
where
    F: Fn(&serde_json::Value, &serde_json::Value) -> bool,
    G: Fn(&serde_json::Value) -> String,
{
    merge_scripts_generic_with_sep(curscript, script, script_id, equals, output, ", ")
}

/// Generic script merging function with custom separator
fn merge_scripts_generic_with_sep<F, G>(
    curscript: &serde_json::Value,
    script: &serde_json::Value,
    script_id: &str,
    equals: &F,
    output: &G,
    outsep: &str,
) -> serde_json::Value
where
    F: Fn(&serde_json::Value, &serde_json::Value) -> bool,
    G: Fn(&serde_json::Value) -> String,
{
    let mut result = curscript.clone();
    
    if let Some(cur_data) = curscript.get(script_id) {
        if let Some(script_data) = script.get(script_id) {
            let cur_array = cur_data.as_array().unwrap_or(&vec![]);
            let script_array = script_data.as_array().unwrap_or(&vec![]);
            
            let mut merged = cur_array.clone();
            
            for item in script_array {
                if !merged.iter().any(|existing| equals(existing, item)) {
                    merged.push(item.clone());
                }
            }
            
            let outputs: Vec<String> = merged.iter().map(output).collect();
            result["output"] = serde_json::Value::String(outputs.join(outsep));
            result[script_id] = serde_json::Value::Array(merged);
        }
    } else {
        result = script.clone();
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_domains() {
        let domains = get_domains("www.example.com");
        assert_eq!(domains, vec!["example.com", "com"]);
    }

    #[test]
    fn test_san2hostname() {
        assert_eq!(
            san2hostname("DNS:example.com"),
            Some(("dns".to_string(), "example.com".to_string()))
        );
        
        assert_eq!(
            san2hostname("DirName:CN=example.com"),
            Some(("dirname-cn".to_string(), "example.com".to_string()))
        );
        
        assert!(san2hostname("othername:UPN:S-1-5-21").is_none());
    }

    #[test]
    fn test_create_ssl_output() {
        let cert = ParsedCertificate {
            subject_text: Some("CN=example.com".to_string()),
            issuer_text: Some("CN=CA".to_string()),
            pubkey: Some(PublicKey {
                key_type: Some("RSA".to_string()),
                bits: Some(2048),
                exponent: None,
                modulus: None,
            }),
            not_before: Some("2024-01-01".to_string()),
            not_after: Some("2025-01-01".to_string()),
            md5: Some("abcd1234".to_string()),
            sha1: Some("efgh5678".to_string()),
            sha256: Some("ijkl9012".to_string()),
            pem: None,
            san: None,
            subject: None,
        };
        
        let output = create_ssl_output(&cert);
        assert!(output.len() > 0);
        assert!(output.iter().any(|line| line.contains("Subject:")));
    }
}
