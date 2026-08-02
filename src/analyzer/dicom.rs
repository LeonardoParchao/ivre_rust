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

//! DICOM message parsing.

use base64::Engine;
use log::{debug, warn};
use std::collections::HashMap;

/// User info item types
const USER_INFO_MAX_PDU_LENGTH: u8 = 0x51;
const USER_INFO_IMPLEMENTATION_CLASS_UID: u8 = 0x52;
const USER_INFO_IMPLEMENTATION_VERSION: u8 = 0x55;
const USER_INFO_USER_INFO: u8 = 0x50;

/// Generate items from DICOM data
fn gen_items(data: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut result = Vec::new();
    let mut pos = 0;
    
    while pos < data.len() {
        if data.len() - pos < 4 {
            debug!(
                "Item too short: maybe a broken DICOM item [{:?}]",
                &data[pos..]
            );
            return result;
        }
        
        let itype = data[pos];
        let pad = data[pos + 1];
        let ilen = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        
        if pad != 0 {
            debug!(
                "Non zero padding: maybe a broken DICOM item [{:?}]",
                &data[pos..]
            );
        }
        
        pos += 4;
        
        if pos + ilen > data.len() {
            debug!(
                "Item too short: maybe a broken DICOM item [{:?}]",
                &data[pos..]
            );
            return result;
        }
        
        result.push((itype, data[pos..pos + ilen].to_vec()));
        pos += ilen;
    }
    
    result
}

/// Parse items from DICOM data
fn parse_items(data: &[u8]) -> HashMap<String, String> {
    let mut res = HashMap::new();
    let items: HashMap<u8, Vec<u8>> = gen_items(data).into_iter().collect();
    
    let user_info = match items.get(&USER_INFO_USER_INFO) {
        Some(data) => data,
        None => {
            warn!("No User Info in items [{:?}]", items);
            return res;
        }
    };
    
    for (itype, ivalue) in gen_items(user_info) {
        let ivalue_parsed = match itype {
            USER_INFO_MAX_PDU_LENGTH => {
                if ivalue.len() >= 4 {
                    let value = u32::from_be_bytes([ivalue[0], ivalue[1], ivalue[2], ivalue[3]]);
                    value.to_string()
                } else {
                    warn!(
                        "Cannot convert max_pdu_length value to an integer [{:?}]",
                        ivalue
                    );
                    base64::engine::general_purpose::STANDARD.encode(&ivalue)
                }
            }
            _ => {
                match std::str::from_utf8(&ivalue) {
                    Ok(s) => s.to_string(),
                    Err(_) => {
                        warn!(
                            "Cannot convert value to an ASCII string [{:?}]",
                            ivalue
                        );
                        base64::engine::general_purpose::STANDARD.encode(&ivalue)
                    }
                }
            }
        };
        
        let itype_parsed = match itype {
            USER_INFO_MAX_PDU_LENGTH => "max_pdu_length",
            USER_INFO_IMPLEMENTATION_CLASS_UID => "implementation_class_uid",
            USER_INFO_IMPLEMENTATION_VERSION => "implementation_version",
            _ => {
                warn!(
                    "Unknown item type in User Info {:02x} [{:?}]",
                    itype, ivalue
                );
                &format!("unknown_{:02x}", itype)
            }
        };
        
        res.insert(itype_parsed.to_string(), ivalue_parsed);
    }
    
    res
}

/// Parse a DICOM message
pub fn parse_message(data: &[u8]) -> HashMap<String, String> {
    let mut res = HashMap::new();
    
    if data.len() < 6 {
        debug!(
            "Message too short: probably not a DICOM message [{:?}]",
            data
        );
        return res;
    }
    
    let rtype = data[0];
    let pad = data[1];
    let rlen = u32::from_be_bytes([data[2], data[3], data[4], data[5]]) as usize;
    
    if pad != 0 {
        debug!(
            "Non zero padding: probably not a DICOM message [{:?}]",
            data
        );
        return res;
    }
    
    if rlen > data.len() - 6 {
        debug!(
            "Message too short: probably not a DICOM message [{:?}]",
            data
        );
        return res;
    }
    
    if rtype == 2 || rtype == 3 {
        // Associate accept / reject
        res.insert("service_name".to_string(), "dicom".to_string());
        
        let (msg, extra_info) = if rtype == 2 {
            let expected = b"\x00\x01\x00\x00ANY-SCP         ECHOSCU         \x00\x00\
                \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                \x00\x00";
            
            if data.len() >= 74 && &data[6..74] == expected {
                ("Any AET is accepted (Insecure)".to_string(), parse_items(&data[74..]))
            } else {
                ("Any AET is accepted (Insecure)".to_string(), {
                    let mut info = HashMap::new();
                    info.insert("info".to_string(), "Unusual accept message".to_string());
                    info
                })
            }
        } else {
            let expected = b"\x03\x00\x00\x00\x00\x04\x00\x01\x01\x07";
            if data == expected {
                ("Called AET check enabled".to_string(), HashMap::new())
            } else {
                ("Called AET check enabled".to_string(), {
                    let mut info = HashMap::new();
                    info.insert("info".to_string(), "Unusual reject message".to_string());
                    info
                })
            }
        };
        
        let mut script_output = vec![
            String::new(),
            "dicom: DICOM Service Provider discovered!".to_string(),
            format!("config: {}", msg),
        ];
        
        let mut script_data: HashMap<String, String> = HashMap::new();
        script_data.insert("dicom".to_string(), "DICOM Service Provider discovered!".to_string());
        script_data.insert("config".to_string(), msg);
        
        for (key, value) in &extra_info {
            script_output.push(format!("{}: {}", key, value));
            script_data.insert(key.clone(), value.clone());
        }
        
        res.insert("script_output".to_string(), script_output.join("\n  "));
        res.insert("script_data".to_string(), format!("{:?}", script_data));
        
        return res;
    }
    
    debug!(
        "Unknown message type [{:?}]: probably not a DICOM message [{:?}]",
        rtype, data
    );
    
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_message_too_short() {
        let data = b"\x02\x00\x00\x00\x00\x10";
        let result = parse_message(data);
        assert!(result.is_empty());
    }
}
