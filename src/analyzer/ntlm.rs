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

//! NTLM message parsing and information extraction.

use base64::Engine;
use log::warn;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;

// The positions of `Negotiate Version` and `Negotiate Target Info`
// in the NTLM flags
const FLAG_VERSION: u32 = 0x2000000;
const FLAG_TARGETINFO: u32 = 0x800000;
const FLAG_UNICODE: u32 = 0x1;
const FLAG_OEM: u32 = 0x2;

// Target info types
const INFO_NETBIOS_COMPUTER_NAME: u16 = 1;
const INFO_NETBIOS_DOMAIN_NAME: u16 = 2;
const INFO_DNS_COMPUTER_NAME: u16 = 3;
const INFO_DNS_DOMAIN_NAME: u16 = 4;
const INFO_DNS_TREE_NAME: u16 = 5;

#[derive(Debug)]
pub enum NtlmError {
    MessageTooShort(usize),
    InvalidFormat(String),
    DecodeError(String),
}

impl fmt::Display for NtlmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NtlmError::MessageTooShort(size) => write!(f, "NTLM message is too short (size {})", size),
            NtlmError::InvalidFormat(msg) => write!(f, "Invalid NTLM format: {}", msg),
            NtlmError::DecodeError(msg) => write!(f, "Decode error: {}", msg),
        }
    }
}

impl Error for NtlmError {}

/// Extract the string at the given offset and of the given length from an
/// NTLM message
fn extract_substr(ntlm_msg: &[u8], offset: usize, ln: usize, uses_unicode: bool) -> Result<String, NtlmError> {
    if offset + ln > ntlm_msg.len() {
        warn!(
            "Data too small at offset {} [{:?}, size {}]",
            offset, ntlm_msg, ln
        );
        return Err(NtlmError::MessageTooShort(ntlm_msg.len()));
    }
    
    let s = &ntlm_msg[offset..offset + ln];
    
    if uses_unicode {
        // UTF-16LE decoding
        let utf16_data: Vec<u16> = s
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        String::from_utf16(&utf16_data).map_err(|e| NtlmError::DecodeError(e.to_string()))
    } else {
        // Test whether the string is in UTF-16 encoding
        let is_utf16 = s.len() > 1 && s[1..].chunks_exact(2).all(|c| c[0] == 0);
        if is_utf16 {
            let utf16_data: Vec<u16> = s
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect();
            if let Ok(result) = String::from_utf16(&utf16_data) {
                warn!(
                    "NTLM message should use code page encoding but one of its fields ({:?}) is encoded in UTF-16",
                    s
                );
                return Ok(result);
            }
        }
        String::from_utf8(s.to_vec()).map_err(|e| NtlmError::DecodeError(e.to_string()))
    }
}

/// Check if the message uses Unicode encoding based on flags
fn is_unicode(_msg: &[u8], flags: u32) -> bool {
    if flags & FLAG_UNICODE != 0 {
        return true;
    }
    if flags & FLAG_OEM != 0 {
        return false;
    }
    warn!("NTLM message has no encoding specified");
    false
}

/// Extract host information in an NTLMSSP_NEGOTIATE message
pub fn ntlm_negotiate_extract(negotiate: &[u8]) -> Option<HashMap<String, String>> {
    if negotiate.len() < 12 {
        warn!(
            "NTLM message is abnormally short [{:?}, size {}]",
            negotiate,
            negotiate.len()
        );
        return None;
    }

    let mut value = HashMap::new();

    let flags = u32::from_le_bytes([negotiate[12], negotiate[13], negotiate[14], negotiate[15]]);
    value.insert("ntlm-fingerprint".to_string(), format!("0x{:08x}", flags));
    let uses_unicode = is_unicode(negotiate, flags);

    if negotiate.len() > 32 {
        let ln_dom = u16::from_le_bytes([negotiate[16], negotiate[17]]);
        let off_dom = u32::from_le_bytes([negotiate[20], negotiate[21], negotiate[22], negotiate[23]]);
        let ln_work = u16::from_le_bytes([negotiate[24], negotiate[25]]);
        let off_work = u32::from_le_bytes([negotiate[28], negotiate[29], negotiate[30], negotiate[31]]);

        if ln_dom > 0 && off_dom > 0 {
            if let Ok(domain) = extract_substr(negotiate, off_dom as usize, ln_dom as usize, uses_unicode) {
                value.insert("NetBIOS_Domain_Name".to_string(), domain);
            }
        }
        if ln_work > 0 && off_work > 0 {
            if let Ok(workstation) = extract_substr(negotiate, off_work as usize, ln_work as usize, uses_unicode) {
                value.insert("Workstation".to_string(), workstation);
            }
        }
    }

    Some(value)
}

/// Extract host information in an NTLMSSP_CHALLENGE message
pub fn ntlm_challenge_extract(challenge: &[u8]) -> Option<HashMap<String, String>> {
    if challenge.len() < 24 {
        warn!(
            "NTLM message is abnormally short [{:?}, size {}]",
            challenge,
            challenge.len()
        );
        return None;
    }

    let mut value = HashMap::new();
    let flags = u32::from_le_bytes([challenge[20], challenge[21], challenge[22], challenge[23]]);
    value.insert("ntlm-fingerprint".to_string(), format!("0x{:08x}", flags));
    let uses_unicode = is_unicode(challenge, flags);

    // Get target name
    let lntarget = u16::from_le_bytes([challenge[12], challenge[13]]);
    let offset = u16::from_le_bytes([challenge[14], challenge[15]]) as usize;
    
    if let Ok(target_name) = extract_substr(challenge, offset, lntarget as usize, uses_unicode) {
        value.insert("Target_Name".to_string(), target_name);
    }

    // Get OS Version if the version of NTLM handles it
    // and the `Negotiate version` flag is set
    if offset >= 56 && (flags & FLAG_VERSION != 0) {
        if challenge.len() < 56 {
            warn!(
                "NTLM message should contain version info at offset 56 but is too short (size {})",
                challenge.len()
            );
            return Some(value);
        }

        let maj = challenge[48];
        let minor = challenge[49];
        let bld = u16::from_le_bytes([challenge[50], challenge[51]]);
        let ntlm_ver = challenge[55];
        
        value.insert("Product_Version".to_string(), format!("{}.{}.{}", maj, minor, bld));
        value.insert("NTLM_Version".to_string(), ntlm_ver.to_string());
    }

    // Get target information if the version of NTLM handles it
    // and the `Negotiate Target Info` is set
    if offset >= 48 && (flags & FLAG_TARGETINFO != 0) {
        if challenge.len() < 46 {
            warn!(
                "NTLM message should contain target info at offset 48 but is too short (size {})",
                challenge.len()
            );
            return Some(value);
        }

        let ln_info = u16::from_le_bytes([challenge[42], challenge[43]]) as usize;
        let off = u16::from_le_bytes([challenge[44], challenge[45]]) as usize;
        
        if off + ln_info > challenge.len() {
            warn!(
                "NTLM target info should be of size {} but is too short (size {})",
                ln_info,
                challenge.len() - off
            );
            return Some(value);
        }

        let mut target_info = &challenge[off..];
        let mut pos = 0;
        
        while pos + 4 <= ln_info {
            let typ = u16::from_le_bytes([target_info[pos], target_info[pos + 1]]);
            let ln = u16::from_le_bytes([target_info[pos + 2], target_info[pos + 3]]) as usize;
            
            if typ >= INFO_NETBIOS_COMPUTER_NAME && typ <= INFO_DNS_TREE_NAME {
                let key = match typ {
                    INFO_NETBIOS_COMPUTER_NAME => "NetBIOS_Computer_Name",
                    INFO_NETBIOS_DOMAIN_NAME => "NetBIOS_Domain_Name",
                    INFO_DNS_COMPUTER_NAME => "DNS_Computer_Name",
                    INFO_DNS_DOMAIN_NAME => "DNS_Domain_Name",
                    INFO_DNS_TREE_NAME => "DNS_Tree_Name",
                    _ => continue,
                };
                
                if let Ok(info_value) = extract_substr(target_info, pos + 4, ln, uses_unicode) {
                    value.insert(key.to_string(), info_value);
                }
            }
            
            pos += 4 + ln;
            if pos >= target_info.len() {
                break;
            }
            target_info = &target_info[pos..];
            pos = 0;
        }
    }

    Some(value)
}

/// Extract host information in an NTLMSSP_AUTH message
pub fn ntlm_authenticate_info(request: &[u8]) -> Option<HashMap<String, String>> {
    if request.len() < 52 {
        warn!(
            "NTLM message is too short ({}) but should be at least 52 char long",
            request.len()
        );
        return None;
    }

    let mut value = HashMap::new();
    
    // Find minimum offset
    let mut min_offset = usize::MAX;
    for i in (16..49).step_by(8) {
        let off = u32::from_le_bytes([request[i], request[i + 1], request[i + 2], request[i + 3]]) as usize;
        if off > 0 && off < min_offset {
            min_offset = off;
        }
    }
    
    let has_version = min_offset >= 64 && request.len() > 64;
    let flags = if has_version {
        u32::from_le_bytes([request[60], request[61], request[62], request[63]])
    } else {
        0
    };
    
    let uses_unicode = is_unicode(request, flags);
    
    // NetBIOS Domain Name
    let ln = u16::from_le_bytes([request[28], request[29]]) as usize;
    let off = u32::from_le_bytes([request[30], request[31], request[32], request[33]]) as usize;
    if ln > 0 {
        if let Ok(domain) = extract_substr(request, off, ln, uses_unicode) {
            value.insert("NetBIOS_Domain_Name".to_string(), domain);
        }
    }
    
    // User Name
    let ln = u16::from_le_bytes([request[36], request[37]]) as usize;
    let off = u32::from_le_bytes([request[38], request[39], request[40], request[41]]) as usize;
    if ln > 0 {
        if let Ok(user) = extract_substr(request, off, ln, uses_unicode) {
            value.insert("User_Name".to_string(), user);
        }
    }
    
    // Workstation
    let ln = u16::from_le_bytes([request[44], request[45]]) as usize;
    let off = u32::from_le_bytes([request[46], request[47], request[48], request[49]]) as usize;
    if ln > 0 {
        if let Ok(workstation) = extract_substr(request, off, ln, uses_unicode) {
            value.insert("Workstation".to_string(), workstation);
        }
    }

    // Get OS Version if the `Negotiate Version` is set
    if has_version && (flags & FLAG_VERSION != 0) && min_offset >= 72 && request.len() > 72 {
        let maj = request[64];
        let minor = request[65];
        let bld = u16::from_le_bytes([request[66], request[67]]);
        let ntlm_ver = request[71];
        
        value.insert("Product_Version".to_string(), format!("{}.{}.{}", maj, minor, bld));
        value.insert("NTLM_Version".to_string(), ntlm_ver.to_string());
    }

    Some(value)
}

/// Extract valuable host information from an NTLM message
pub fn ntlm_extract_info(value: &[u8]) -> Option<HashMap<String, String>> {
    if value.len() < 12 {
        warn!("NTLM message is too short ({})", value.len());
        return None;
    }
    
    let ntlm_type = u32::from_le_bytes([value[8], value[9], value[10], value[11]]);
    
    match ntlm_type {
        1 => ntlm_negotiate_extract(value),
        2 => ntlm_challenge_extract(value),
        3 => ntlm_authenticate_info(value),
        _ => {
            warn!(
                "The following NTLM message {:?} has an unknown message type: {}",
                value, ntlm_type
            );
            Some(HashMap::new())
        }
    }
}

/// Checks whether the given string is an NTLM message
pub fn is_ntlm_message(message: &str) -> bool {
    let parts: Vec<&str> = message.splitn(2, char::is_whitespace).collect();
    if parts.len() < 2 {
        return false;
    }
    
    let val1 = parts[0].to_lowercase();
    let val2 = parts[1];
    
    if val1 == "ntlm" {
        return true;
    }
    
    if val1 == "negotiate" {
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(val2) {
            return decoded.starts_with(b"NTLMSSP");
        }
    }
    
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ntlm_message() {
        assert!(is_ntlm_message("NTLM TlRMTVNTUAAB"));
        assert!(is_ntlm_message("negotiate TlRMTVNTUAAB"));
        assert!(!is_ntlm_message("not ntlm"));
    }
}
