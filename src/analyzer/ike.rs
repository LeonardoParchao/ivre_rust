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

//! IKE (Internet Key Exchange) protocol parsing and analysis.

use std::collections::HashMap;

/// Helper struct to map integers to string names with fallback for unknown values
struct Values {
    mapping: HashMap<u32, &'static str>,
}

impl Values {
    fn new(mapping: HashMap<u32, &'static str>) -> Self {
        Values { mapping }
    }

    fn get(&self, item: u32) -> String {
        self.mapping
            .get(&item)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("UNKNOWN-{}", item))
    }
}

/// Helper struct that returns the numeric value as-is
struct NumValues;

impl NumValues {
    fn get(&self, item: u32) -> u32 {
        item
    }
}

// Internet Key Exchange (IKE) Attributes - ISAKMP Domain of Interpretation (DOI)
// https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-19
fn doi() -> Values {
    let mut mapping = HashMap::new();
    mapping.insert(0, "ISAKMP"); // RFC2408
    mapping.insert(1, "IPSEC"); // RFC2407
    mapping.insert(2, "GDOI"); // RFC3547
    Values::new(mapping)
}

// RFC 2407 - 4.4.1 - IPSEC Security Protocol Identifier
// https://tools.ietf.org/html/rfc2407#section-4.4.1
fn proto() -> Values {
    let mut mapping = HashMap::new();
    mapping.insert(1, "ISAKMP");
    mapping.insert(2, "IPSEC_AH");
    mapping.insert(3, "IPSEC_ESP");
    mapping.insert(4, "IPCOMP");
    Values::new(mapping)
}

// RFC 2408 - 3.14.1 - Notify Message Types
// https://tools.ietf.org/html/rfc2408#section-3.14.1
fn notification() -> Values {
    let mut mapping = HashMap::new();
    mapping.insert(1, "INVALID-PAYLOAD-TYPE");
    mapping.insert(2, "DOI-NOT-SUPPORTED");
    mapping.insert(3, "SITUATION-NOT-SUPPORTED");
    mapping.insert(4, "INVALID-COOKIE");
    mapping.insert(5, "INVALID-MAJOR-VERSION");
    mapping.insert(6, "INVALID-MINOR-VERSION");
    mapping.insert(7, "INVALID-EXCHANGE-TYPE");
    mapping.insert(8, "INVALID-FLAGS");
    mapping.insert(9, "INVALID-MESSAGE-ID");
    mapping.insert(10, "INVALID-PROTOCOL-ID");
    mapping.insert(11, "INVALID-SPI");
    mapping.insert(12, "INVALID-TRANSFORM-ID");
    mapping.insert(13, "ATTRIBUTES-NOT-SUPPORTED");
    mapping.insert(14, "NO-PROPOSAL-CHOSEN");
    mapping.insert(15, "BAD-PROPOSAL-SYNTAX");
    mapping.insert(16, "PAYLOAD-MALFORMED");
    mapping.insert(17, "INVALID-KEY-INFORMATION");
    mapping.insert(18, "INVALID-ID-INFORMATION");
    mapping.insert(19, "INVALID-CERT-ENCODING");
    mapping.insert(20, "INVALID-CERTIFICATE");
    mapping.insert(21, "CERT-TYPE-UNSUPPORTED");
    mapping.insert(22, "INVALID-CERT-AUTHORITY");
    mapping.insert(23, "INVALID-HASH-INFORMATION");
    mapping.insert(24, "AUTHENTICATION-FAILED");
    mapping.insert(25, "INVALID-SIGNATURE");
    mapping.insert(26, "ADDRESS-NOTIFICATION");
    mapping.insert(27, "NOTIFY-SA-LIFETIME");
    mapping.insert(28, "CERTIFICATE-UNAVAILABLE");
    mapping.insert(29, "UNSUPPORTED-EXCHANGE-TYPE");
    mapping.insert(30, "UNEQUAL-PAYLOAD-LENGTHS");
    Values::new(mapping)
}

// https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-2
fn transform_values() -> HashMap<u32, (&'static str, TransformDecoder)> {
    let mut mapping = HashMap::new();

    // Encryption
    let mut encryption = HashMap::new();
    encryption.insert(1, "DES-CBC");
    encryption.insert(2, "IDEA-CBC");
    encryption.insert(3, "Blowfish-CBC");
    encryption.insert(4, "RC5-R16-B64-CBC");
    encryption.insert(5, "3DES-CBC");
    encryption.insert(6, "CAST-CBC");
    encryption.insert(7, "AES-CBC");
    encryption.insert(8, "CAMELLIA-CBC");
    mapping.insert(1, ("Encryption", TransformDecoder::Values(Values::new(encryption))));

    // Hash
    let mut hash = HashMap::new();
    hash.insert(1, "MD5");
    hash.insert(2, "SHA");
    hash.insert(3, "Tiger");
    hash.insert(4, "SHA2-256");
    hash.insert(5, "SHA2-384");
    hash.insert(6, "SHA2-512");
    mapping.insert(2, ("Hash", TransformDecoder::Values(Values::new(hash))));

    // Authentication
    let mut auth = HashMap::new();
    auth.insert(1, "PSK");
    auth.insert(2, "DSS Signature");
    auth.insert(3, "RSA Signature");
    auth.insert(4, "RSA Encryption");
    auth.insert(5, "RSA Revised Encryption");
    auth.insert(6, "ElGamal Encryption");
    auth.insert(7, "ElGamal Revised Encryption");
    auth.insert(8, "ECDSA Signature");
    auth.insert(9, "ECDSA with SHA-256 on the P-256 curve");
    auth.insert(10, "ECDSA with SHA-384 on the P-384 curve");
    auth.insert(11, "ECDSA with SHA-512 on the P-521 curve");
    auth.insert(64221, "HybridInitRSA");
    auth.insert(64222, "HybridRespRSA");
    auth.insert(64223, "HybridInitDSS");
    auth.insert(64224, "HybridRespDSS");
    auth.insert(65001, "XAUTHInitPreShared or GSS-API using Kerberos");
    auth.insert(65002, "XAUTHRespPreShared or Generic GSS-API");
    auth.insert(65003, "XAUTHInitDSS or GSS-API with SPNEGO");
    auth.insert(65004, "XAUTHRespDSS or GSS-API using SPKM");
    auth.insert(65005, "XAUTHInitRSA");
    auth.insert(65006, "XAUTHRespRSA");
    auth.insert(65007, "XAUTHInitRSAEncryption");
    auth.insert(65008, "XAUTHRespRSAEncryption");
    auth.insert(65009, "XAUTHInitRSARevisedEncryption");
    auth.insert(65010, "XAUTHRespRSARevisedEncryptio");
    mapping.insert(3, ("Authentication", TransformDecoder::Values(Values::new(auth))));

    // GroupDesc
    let mut group_desc = HashMap::new();
    group_desc.insert(1, "768MODPgr");
    group_desc.insert(2, "1024MODPgr");
    group_desc.insert(3, "EC2Ngr155");
    group_desc.insert(4, "EC2Ngr185");
    group_desc.insert(5, "1536MODPgr");
    group_desc.insert(14, "2048MODPgr");
    group_desc.insert(15, "3072MODPgr");
    group_desc.insert(16, "4096MODPgr");
    group_desc.insert(17, "6144MODPgr");
    group_desc.insert(18, "8192MODPgr");
    mapping.insert(4, ("GroupDesc", TransformDecoder::Values(Values::new(group_desc))));

    // GroupType
    let mut group_type = HashMap::new();
    group_type.insert(1, "MODP");
    group_type.insert(2, "ECP");
    group_type.insert(3, "EC2N");
    mapping.insert(5, ("GroupType", TransformDecoder::Values(Values::new(group_type))));

    mapping.insert(6, ("GroupPrime", TransformDecoder::NumValues(NumValues)));
    mapping.insert(7, ("GroupGenerator1", TransformDecoder::NumValues(NumValues)));
    mapping.insert(8, ("GroupGenerator2", TransformDecoder::NumValues(NumValues)));
    mapping.insert(9, ("GroupCurveA", TransformDecoder::NumValues(NumValues)));
    mapping.insert(10, ("GroupCurveB", TransformDecoder::NumValues(NumValues)));

    // LifeType
    let mut life_type = HashMap::new();
    life_type.insert(1, "Seconds");
    life_type.insert(2, "Kilobytes");
    mapping.insert(11, ("LifeType", TransformDecoder::Values(Values::new(life_type))));

    mapping.insert(12, ("LifeDuration", TransformDecoder::NumValues(NumValues)));
    mapping.insert(13, ("PRF", TransformDecoder::NumValues(NumValues)));
    mapping.insert(14, ("KeyLength", TransformDecoder::NumValues(NumValues)));
    mapping.insert(15, ("FieldSize", TransformDecoder::NumValues(NumValues)));
    mapping.insert(16, ("GroupOrder", TransformDecoder::NumValues(NumValues)));

    mapping
}

enum TransformDecoder {
    Values(Values),
    NumValues(NumValues),
}

impl TransformDecoder {
    fn decode(&self, value: u32) -> String {
        match self {
            TransformDecoder::Values(v) => v.get(value),
            TransformDecoder::NumValues(_) => value.to_string(),
        }
    }
}

/// Parse notification payload from IKE message
fn info_from_notification(payload: &[u8], output: &mut HashMap<String, String>) {
    let payload_len = payload.len();
    if payload_len < 12 {
        output.insert(
            "protocol".to_string(),
            format!("ISAKMP: Notification payload too short ({} bytes)", payload_len),
        );
        return;
    }

    let doi_val = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    output.insert("DOI".to_string(), doi().get(doi_val));
    output.insert("protocol_id".to_string(), proto().get(payload[8] as u32));
    
    let notif_type = u16::from_be_bytes([payload[10], payload[11]]);
    output.insert("notification_type".to_string(), notification().get(notif_type as u32));
}

/// Parse vendor ID payload from IKE message
fn info_from_vendorid(payload: &[u8], service: &mut HashMap<String, String>, output: &mut HashMap<String, Vec<VendorIdEntry>>) {
    let vendor_id_data = &payload[4..];
    let name = find_ike_vendor_id(vendor_id_data);
    
    if let Some(name) = name {
        let name_str = String::from_utf8_lossy(&name);
        
        if name.starts_with(b"Windows-") {
            service.insert("service_product".to_string(), "Microsoft/Cisco IPsec".to_string());
            service.insert("service_version".to_string(), name_str.replace("-", " "));
            service.insert("service_ostype".to_string(), "Windows".to_string());
        } else if name == b"Windows" {
            service.insert("service_product".to_string(), "Microsoft/Cisco IPsec".to_string());
            service.insert("service_ostype".to_string(), "Windows".to_string());
        } else if name.starts_with(b"Firewall-1 ") {
            service.insert("service_product".to_string(), "Checkpoint VPN-1/Firewall-1".to_string());
            if let Some(version) = name_str.splitn(2, ' ').nth(1) {
                service.insert("service_version".to_string(), version.to_string());
            }
            service.insert("service_devicetype".to_string(), "security-misc".to_string());
        } else if name.starts_with(b"SSH IPSEC Express ") {
            service.insert("service_product".to_string(), "SSH Communications Security IPSec Express".to_string());
            if let Some(version) = name_str.splitn(4, ' ').nth(3) {
                service.insert("service_version".to_string(), version.to_string());
            }
        } else if name.starts_with(b"SSH Sentinel") {
            service.insert("service_product".to_string(), "SSH Communications Security Sentinel".to_string());
            if let Some(version) = name_str.get(13..) {
                if !version.is_empty() {
                    service.insert("service_version".to_string(), version.to_string());
                }
            }
        } else if name.starts_with(b"SSH QuickSec") {
            service.insert("service_product".to_string(), "SSH Communications Security QuickSec".to_string());
            if let Some(version) = name_str.get(13..) {
                if !version.is_empty() {
                    service.insert("service_version".to_string(), version.to_string());
                }
            }
        } else if name.starts_with(b"Cisco VPN Concentrator") {
            service.insert("service_product".to_string(), "Cisco VPN Concentrator".to_string());
            if let Some(version) = name_str.get(24..name.len().saturating_sub(1)) {
                if !version.is_empty() {
                    service.insert("service_version".to_string(), version.to_string());
                }
            }
        } else if name.starts_with(b"SafeNet SoftRemote") {
            service.insert("service_product".to_string(), "SafeNet Remote".to_string());
            if let Some(version) = name_str.get(19..) {
                if !version.is_empty() {
                    service.insert("service_version".to_string(), version.to_string());
                }
            }
        } else if name == b"KAME/racoon" {
            service.insert("service_product".to_string(), "KAME/racoon/IPsec Tools".to_string());
        } else if name == b"Nortel Contivity" {
            service.insert("service_product".to_string(), "Nortel Contivity".to_string());
            service.insert("service_devicetype".to_string(), "firewall".to_string());
        } else if name.starts_with(b"SonicWall-") {
            service.insert("service_product".to_string(), "SonicWall".to_string());
        } else if name.starts_with(b"strongSwan") {
            service.insert("service_product".to_string(), "strongSwan".to_string());
            let version = name_str.get(11..).unwrap_or("4.3.6");
            service.insert("service_version".to_string(), if version.is_empty() { "4.3.6".to_string() } else { version.to_string() });
            service.insert("service_ostype".to_string(), "Unix".to_string());
        } else if name == b"ZyXEL ZyWall USG 100" {
            service.insert("service_product".to_string(), "ZyXEL ZyWALL USG 100".to_string());
            service.insert("service_devicetype".to_string(), "firewall".to_string());
        } else if name.starts_with(b"Linux FreeS/WAN ") {
            service.insert("service_product".to_string(), "FreeS/WAN".to_string());
            if let Some(version) = name_str.splitn(3, ' ').nth(2) {
                service.insert("service_version".to_string(), version.to_string());
            }
            service.insert("service_ostype".to_string(), "Unix".to_string());
        } else if name.starts_with(b"Openswan ") || name.starts_with(b"Linux Openswan ") {
            service.insert("service_product".to_string(), "Openswan".to_string());
            let extra_info = name_str.splitn(2, "Openswan ").nth(1).unwrap_or("");
            let parts: Vec<&str> = extra_info.splitn(2, ' ').collect();
            if !parts.is_empty() {
                service.insert("service_version".to_string(), parts[0].to_string());
            }
            if parts.len() == 2 {
                service.insert("service_extrainfo".to_string(), parts[1].to_string());
            }
            service.insert("service_ostype".to_string(), "Unix".to_string());
        } else if name == b"FreeS/WAN or OpenSWAN" || name == b"FreeS/WAN or OpenSWAN or Libreswan" {
            service.insert("service_product".to_string(), "FreeS/WAN or Openswan or Libreswan".to_string());
            service.insert("service_ostype".to_string(), "Unix".to_string());
        } else if name.starts_with(b"Libreswan ") {
            service.insert("service_product".to_string(), "Libreswan".to_string());
            if let Some(version) = name_str.splitn(2, ' ').nth(1) {
                service.insert("service_version".to_string(), version.to_string());
            }
            service.insert("service_ostype".to_string(), "Unix".to_string());
        } else if name == b"OpenPGP" {
            service.insert("service_product".to_string(), name_str.to_string());
        } else if name == b"FortiGate" || name == b"ZyXEL ZyWALL Router" || name == b"ZyXEL ZyWALL USG 100" {
            service.insert("service_product".to_string(), name_str.to_string());
            service.insert("service_devicetype".to_string(), "firewall".to_string());
        } else if name.starts_with(b"Netscreen-") {
            service.insert("service_product".to_string(), "Juniper".to_string());
            service.insert("service_ostype".to_string(), "NetScreen OS".to_string());
            service.insert("service_devicetype".to_string(), "firewall".to_string());
        } else if name.starts_with(b"StoneGate-") {
            service.insert("service_product".to_string(), "StoneGate".to_string());
            service.insert("service_devicetype".to_string(), "firewall".to_string());
        } else if name.starts_with(b"Symantec-Raptor") {
            service.insert("service_product".to_string(), "Symantec-Raptor".to_string());
            if let Some(version) = name_str.get(16..) {
                if !version.is_empty() {
                    service.insert("service_version".to_string(), version.to_string());
                }
            }
            service.insert("service_devicetype".to_string(), "firewall".to_string());
        } else if name == b"Teldat" {
            service.insert("service_product".to_string(), name_str.to_string());
            service.insert("service_devicetype".to_string(), "broadband router".to_string());
        }
    }

    let mut entry = VendorIdEntry::default();
    entry.value = hex_encode(vendor_id_data);
    if let Some(name) = name {
        entry.name = Some(String::from_utf8_lossy(&name).to_string());
    }
    output.entry("vendor_ids".to_string()).or_insert_with(Vec::new).push(entry);
}

#[derive(Default, Clone)]
struct VendorIdEntry {
    value: String,
    name: Option<String>,
}

/// Parse SA (Security Association) payload from IKE message
fn info_from_sa(payload: &[u8], output: &mut HashMap<String, serde_json::Value>) {
    let payload_len = payload.len();
    if payload_len < 20 {
        output.insert(
            "protocol".to_string(),
            serde_json::Value::String(format!("ISAKMP: SA payload too short ({} bytes)", payload_len)),
        );
        return;
    }

    let doi_val = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    output.insert("DOI".to_string(), serde_json::Value::String(doi().get(doi_val)));

    let mut payload_data = &payload[20..];
    let mut payload_type: u8 = 3;
    let transforms = transform_values();

    while payload_type == 3 && !payload_data.is_empty() {
        let mut transform = HashMap::new();
        payload_type = payload_data[0];
        let payload_length = u16::from_be_bytes([payload_data[2], payload_data[3]]) as usize;
        let data = &payload_data[8..payload_length];
        payload_data = &payload_data[payload_length..];

        let mut data_slice = data;
        while !data_slice.is_empty() {
            if data_slice.len() < 4 {
                break;
            }
            let transf_type = u16::from_be_bytes([data_slice[0], data_slice[1]]);
            let mut value = u16::from_be_bytes([data_slice[2], data_slice[3]]) as u32;
            data_slice = &data_slice[4..];

            if transf_type & 0x8000 != 0 {
                // Value is the actual value
            } else {
                // Value is a length
                let value_length = value as usize;
                if value_length > data_slice.len() {
                    output.insert(
                        "protocol".to_string(),
                        serde_json::Value::String(format!("invalid transform length: {}", value_length)),
                    );
                    break;
                }
                value = 0;
                for val in data_slice.iter().take(value_length) {
                    value = value * 256 + (*val as u32);
                }
                data_slice = &data_slice[value_length..];
            }

            let transf_type_clean = (transf_type & 0x7FFF) as u32;
            let (type_name, decoder) = transforms.get(&transf_type_clean).unwrap_or(&(format!("UNKNOWN-{}", transf_type_clean), TransformDecoder::NumValues(NumValues)));
            let decoded_value = decoder.decode(value);
            transform.insert(type_name.to_string(), decoded_value);
        }

        if !transform.is_empty() {
            output
                .entry("transforms".to_string())
                .or_insert_with(|| serde_json::Value::Array(Vec::new()))
                .as_array_mut()
                .unwrap()
                .push(serde_json::to_value(transform).unwrap_or(serde_json::Value::Null));
        }
    }

    if !payload_data.is_empty() {
        output.insert(
            "protocol".to_string(),
            serde_json::Value::String(format!("unexpected payload in transforms: {:?}", payload_data)),
        );
    }
}

/// Find IKE vendor ID from payload data
fn find_ike_vendor_id(_data: &[u8]) -> Option<Vec<u8>> {
    // This is a placeholder - in the full implementation, this would check
    // against a database of known vendor IDs
    None
}

/// Encode bytes as hex string
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Main function to analyze IKE payload
pub fn analyze_ike_payload(payload: &[u8], probe: &str) -> Option<HashMap<String, serde_json::Value>> {
    let mut service = HashMap::new();
    let mut output = HashMap::new();

    let mut payload_data = payload;
    if probe == "ike-ipsec-nat-t" {
        if payload.starts_with(&[0x00, 0x00, 0x00, 0x00]) {
            payload_data = &payload[4..];
        } else {
            output.insert(
                "protocol".to_string(),
                serde_json::Value::String("ike-ipsec-nat-t: missing non-ESP marker".to_string()),
            );
        }
    }

    let payload_len = payload_data.len();
    if payload_len < 28 {
        return None;
    }

    if !payload_data.starts_with(&[0x00, 0x11, 0x22, 0x33]) {
        return None;
    }

    let payload_len_proto = u32::from_be_bytes([payload_data[24], payload_data[25], payload_data[26], payload_data[27]]) as usize;
    if payload_len < payload_len_proto {
        return None;
    }

    let mut payload_type = payload_data[16];
    payload_data = &payload_data[28..];

    while payload_type != 0 && payload_data.len() >= 4 {
        let payload_length = u16::from_be_bytes([payload_data[2], payload_data[3]]) as usize;

        match payload_type {
            1 => {
                // SA
                output.insert("type".to_string(), serde_json::Value::String("SA".to_string()));
                info_from_sa(&payload_data[..payload_length], &mut output);
            }
            11 => {
                // Notification
                output.insert("type".to_string(), serde_json::Value::String("Notification".to_string()));
                let mut string_output = HashMap::new();
                info_from_notification(&payload_data[..payload_length], &mut string_output);
                for (k, v) in string_output {
                    output.insert(k, serde_json::Value::String(v));
                }
            }
            13 => {
                // Vendor ID
                output.insert("type".to_string(), serde_json::Value::String("Vendor ID".to_string()));
                let mut string_service = HashMap::new();
                let mut vendor_ids = HashMap::new();
                info_from_vendorid(&payload_data[..payload_length], &mut string_service, &mut vendor_ids);
                for (k, v) in string_service {
                    service.insert(k, serde_json::Value::String(v));
                }
                for (k, v) in vendor_ids {
                    output.insert(k, serde_json::to_value(v).unwrap_or(serde_json::Value::Null));
                }
            }
            _ => {}
        }

        payload_type = payload_data[0];
        payload_data = &payload_data[payload_length..];
    }

    if let Some(serde_json::Value::String(version)) = service.get("service_version") {
        if version == "Unknown Vsn" {
            service.remove("service_version");
        }
    }

    if output.is_empty() {
        return None;
    }

    let mut txtoutput = Vec::new();
    if let Some(serde_json::Value::Array(transforms)) = output.get("transforms") {
        txtoutput.push("Transforms:".to_string());
        for tr in transforms {
            if let serde_json::Value::Object(obj) = tr {
                let items: Vec<String> = obj
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect();
                txtoutput.push(format!("  - {}", items.join(", ")));
            }
        }
    }

    if let Some(serde_json::Value::Array(vendor_ids)) = output.get("vendor_ids") {
        txtoutput.push("Vendor IDs:".to_string());
        for vid in vendor_ids {
            if let serde_json::Value::Object(obj) = vid {
                let name = obj.get("name").and_then(|v| v.as_str()).unwrap_or_else(|| {
                    obj.get("value").and_then(|v| v.as_str()).unwrap_or("")
                });
                txtoutput.push(format!("  - {}", name));
            }
        }
    }

    if let Some(serde_json::Value::String(notif_type)) = output.get("notification_type") {
        txtoutput.push(format!("Notification: {}", notif_type));
    }

    let mut result = HashMap::new();
    result.insert("service_name".to_string(), serde_json::Value::String("isakmp".to_string()));

    let mut script = HashMap::new();
    script.insert("id".to_string(), serde_json::Value::String("ike-info".to_string()));
    script.insert("output".to_string(), serde_json::Value::String(txtoutput.join("\n")));
    script.insert("ike-info".to_string(), serde_json::to_value(&output).unwrap_or(serde_json::Value::Null));

    result.insert("scripts".to_string(), serde_json::Value::Array(vec![serde_json::to_value(script).unwrap()]));

    for (k, v) in service {
        result.insert(k, v);
    }

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_ike_payload() {
        // Basic test with minimal valid IKE payload
        let payload = [
            0x00, 0x11, 0x22, 0x33, // Magic bytes
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
            0x00, 0x00, 0x00, 0x00, // Cookie initiator
            0x00, 0x00, 0x00, 0x00, // Cookie responder
            0x01, // Next payload
            0x00, // Version
            0x00, // Exchange type
            0x00, // Flags
            0x00, 0x00, 0x00, 0x00, // Message ID
            0x00, 0x00, 0x00, 0x1c, // Length
        ];

        let result = analyze_ike_payload(&payload, "ike");
        assert!(result.is_some());
    }
}
