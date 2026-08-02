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

//! Support for NetFlow files

use chrono::NaiveDateTime;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::fs::File;
use std::path::Path;

/// NetFlow log parser
pub struct NetFlowParser<R: Read> {
    reader: BufReader<R>,
    fields: Vec<(&'static str, &'static str)>,
    field_idx: HashMap<&'static str, usize>,
    units: HashMap<char, u64>,
    timefmt: &'static str,
}

impl NetFlowParser<BufReader<File>> {
    /// Create a new NetFlowParser from a file path
    pub fn from_path<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Ok(NetFlowParser::new(reader))
    }
}

impl<R: Read> NetFlowParser<R> {
    /// Create a new NetFlowParser from a reader
    pub fn new(reader: R) -> Self {
        let fields = vec![
            ("start_time", "%ts"),
            ("end_time", "%te"),
            ("proto", "%pr"),
            ("addr1", "%sa"),
            ("addr2", "%da"),
            ("port1", "%sp"),
            ("port2", "%dp"),
            ("pkts1", "%opkt"),
            ("pkts2", "%ipkt"),
            ("bytes1", "%obyt"),
            ("bytes2", "%ibyt"),
            ("flags", "%flg"),
        ];
        
        let field_idx: HashMap<&'static str, usize> = fields
            .iter()
            .enumerate()
            .map(|(idx, (name, _))| (*name, idx))
            .collect();
        
        let mut units = HashMap::new();
        units.insert('K', 1_000);
        units.insert('M', 1_000_000);
        units.insert('G', 1_000_000_000);
        units.insert('T', 1_000_000_000_000);
        
        NetFlowParser {
            reader: BufReader::new(reader),
            fields,
            field_idx,
            units,
            timefmt: "%Y-%m-%d %H:%M:%S.%f",
        }
    }

    /// Convert string with units to integer
    fn str2int(&self, val: &str) -> i64 {
        match val.parse::<i64>() {
            Ok(v) => v,
            Err(_) => {
                if val.len() > 1 {
                    let (num_str, unit_char) = val.split_at(val.len() - 1);
                    let num: f64 = num_str.parse().unwrap_or(0.0);
                    let multiplier = self.units.get(&unit_char.chars().next().unwrap_or('\0')).copied().unwrap_or(1);
                    (num * multiplier as f64) as i64
                } else {
                    0
                }
            }
        }
    }

    /// Guess which port is the server port (simplified version)
    fn guess_srv_port(&self, port1: i64, port2: i64, _proto: &str) -> i32 {
        // Simplified logic: lower port is likely server port
        if port1 < port2 { 1 } else { 2 }
    }

    /// Parse a single line
    pub fn parse_line(&self, line: &str) -> Result<HashMap<String, serde_json::Value>, String> {
        let line = line.trim();
        let parts: Vec<&str> = line.split(',').collect();
        
        if parts.len() != self.fields.len() {
            return Err(format!("Expected {} fields, got {}", self.fields.len(), parts.len()));
        }

        let mut result = HashMap::new();

        for (field_info, value) in self.fields.iter().zip(parts.iter()) {
            let field_name = field_info.0;
            let value = value.trim();
            result.insert(field_name.to_string(), serde_json::Value::String(value.to_string()));
        }

        // Lowercase protocol
        if let Some(proto) = result.get_mut("proto") {
            if let Some(s) = proto.as_str() {
                *proto = serde_json::Value::String(s.to_lowercase());
            }
        }

        let mut srv_idx: Option<i32> = None;
        let proto = result.get("proto").and_then(|v| v.as_str()).unwrap_or("");

        // Handle ICMP special case
        if proto == "icmp" {
            if let Some(port2) = result.get_mut("port2") {
                if let Some(s) = port2.as_str() {
                    // Fix nfdump anomaly: "0.8" -> "8.0"
                    let fixed = if s == "0.8" { "8.0" } else { s };
                    let parts: Vec<&str> = fixed.split('.').collect();
                    if parts.len() == 2 {
                        let icmp_type: i64 = parts[0].parse().unwrap_or(0);
                        let icmp_code: i64 = parts[1].parse().unwrap_or(0);
                        
                        result.insert("type".to_string(), serde_json::Value::Number(icmp_type.into()));
                        result.insert("code".to_string(), serde_json::Value::Number(icmp_code.into()));
                        
                        // ICMP 0 is an answer to ICMP 8
                        if icmp_type == 0 {
                            result.insert("type".to_string(), serde_json::Value::Number(8.into()));
                            srv_idx = Some(1);
                        } else {
                            srv_idx = Some(2);
                        }
                    }
                }
            }
            result.remove("port1");
        } else {
            // Parse port fields for non-ICMP
            for field in ["port1", "port2"] {
                if let Some(val) = result.get_mut(field) {
                    if let Some(s) = val.as_str() {
                        result.insert(field.to_string(), serde_json::Value::Number(s.parse::<i64>().unwrap_or(0).into()));
                    }
                }
            }
        }

        // Parse timestamps
        for field in ["start_time", "end_time"] {
            if let Some(val) = result.get(field) {
                if let Some(s) = val.as_str() {
                    match NaiveDateTime::parse_from_str(s, self.timefmt) {
                        Ok(dt) => {
                            result.insert(field.to_string(), serde_json::Value::String(dt.to_string()));
                        }
                        Err(_) => {
                            return Err(format!("Cannot parse timestamp: {}", s));
                        }
                    }
                }
            }
        }

        // Determine server/client indices
        let srv_idx_final = if srv_idx.is_none() {
            let port1 = result.get("port1").and_then(|v| v.as_i64()).unwrap_or(0);
            let port2 = result.get("port2").and_then(|v| v.as_i64()).unwrap_or(0);
            if self.guess_srv_port(port1, port2, proto) >= 0 {
                1
            } else {
                2
            }
        } else {
            srv_idx.unwrap()
        };

        let cli_idx = if srv_idx_final == 2 { 1 } else { 2 };

        // Rename addresses
        if let Some(val) = result.remove(&format!("addr{}", cli_idx)) {
            result.insert("src".to_string(), val);
        }
        if let Some(val) = result.remove(&format!("addr{}", srv_idx_final)) {
            result.insert("dst".to_string(), val);
        }

        // Rename ports
        if let Some(val) = result.remove(&format!("port{}", cli_idx)) {
            result.insert("sport".to_string(), val);
        }
        if let Some(val) = result.remove(&format!("port{}", srv_idx_final)) {
            result.insert("dport".to_string(), val.clone());
            if let Some(s) = val.as_str() {
                result.insert("flow_name".to_string(), serde_json::Value::String(format!("{} {}", proto, s)));
            }
        } else if result.contains_key("type") {
            let icmp_type = result.get("type").and_then(|v| v.as_i64()).unwrap_or(0);
            result.insert("flow_name".to_string(), serde_json::Value::String(format!("{} {}", proto, icmp_type)));
        } else {
            result.insert("flow_name".to_string(), serde_json::Value::String(proto.to_string()));
        }

        // Convert bytes and packets
        if let Some(val) = result.remove(&format!("bytes{}", cli_idx)) {
            if let Some(s) = val.as_str() {
                result.insert("scbytes".to_string(), serde_json::Value::Number(self.str2int(s).into()));
            }
        }
        if let Some(val) = result.remove(&format!("pkts{}", cli_idx)) {
            if let Some(s) = val.as_str() {
                result.insert("scpkts".to_string(), serde_json::Value::Number(self.str2int(s).into()));
            }
        }
        if let Some(val) = result.remove(&format!("bytes{}", srv_idx_final)) {
            if let Some(s) = val.as_str() {
                result.insert("csbytes".to_string(), serde_json::Value::Number(self.str2int(s).into()));
            }
        }
        if let Some(val) = result.remove(&format!("pkts{}", srv_idx_final)) {
            if let Some(s) = val.as_str() {
                result.insert("cspkts".to_string(), serde_json::Value::Number(self.str2int(s).into()));
            }
        }

        Ok(result)
    }

    /// Parse all lines from the reader
    pub fn parse_all(&mut self) -> std::io::Result<Vec<HashMap<String, serde_json::Value>>> {
        let mut results = Vec::new();
        let mut line = String::new();
        
        while self.reader.read_line(&mut line)? > 0 {
            match self.parse_line(&line) {
                Ok(parsed) if !parsed.is_empty() => results.push(parsed),
                _ => {}
            }
            line.clear();
        }
        
        Ok(results)
    }

    /// Get the field format string
    pub fn fmt(&self) -> String {
        let fmt_parts: Vec<&str> = self.fields.iter().map(|(_, fmt)| *fmt).collect();
        format!("fmt:{}", fmt_parts.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_line_tcp() {
        let parser = NetFlowParser::new(std::io::Cursor::new(b""));
        let line = "2024-01-01 12:00:00.000,2024-01-01 12:01:00.000,TCP,192.168.1.1,192.168.1.2,12345,80,100,50,10000,5000,AP";
        let result = parser.parse_line(line);
        
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.get("src").and_then(|v| v.as_str()), Some("192.168.1.1"));
        assert_eq!(parsed.get("dst").and_then(|v| v.as_str()), Some("192.168.1.2"));
        assert_eq!(parsed.get("sport").and_then(|v| v.as_i64()), Some(12345));
        assert_eq!(parsed.get("dport").and_then(|v| v.as_i64()), Some(80));
    }

    #[test]
    fn test_parse_line_icmp() {
        let parser = NetFlowParser::new(std::io::Cursor::new(b""));
        let line = "2024-01-01 12:00:00.000,2024-01-01 12:01:00.000,ICMP,192.168.1.1,192.168.1.2,0,8.0,10,5,1000,500,AP";
        let result = parser.parse_line(line);
        
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.get("type").and_then(|v| v.as_i64()), Some(8));
        assert_eq!(parsed.get("code").and_then(|v| v.as_i64()), Some(0));
    }

    #[test]
    fn test_str2int() {
        let parser = NetFlowParser::new(std::io::Cursor::new(b""));
        assert_eq!(parser.str2int("100"), 100);
        assert_eq!(parser.str2int("1K"), 1000);
        assert_eq!(parser.str2int("1M"), 1_000_000);
    }
}
