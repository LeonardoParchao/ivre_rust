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
//
// Maintainers:
//   - 2018 Francois CHENAIS <francois.chenais@cea.fr>

//! Support for Iptables log from syslog files

use chrono::NaiveDateTime;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::fs::File;
use std::path::Path;

/// Iptables log parser from syslog files
pub struct IptablesParser<R: Read> {
    reader: BufReader<R>,
}

impl IptablesParser<BufReader<File>> {
    /// Create a new IptablesParser from a file path
    pub fn from_path<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Ok(IptablesParser::new(reader))
    }
}

impl<R: Read> IptablesParser<R> {
    /// Create a new IptablesParser from a reader
    pub fn new(reader: R) -> Self {
        IptablesParser {
            reader: BufReader::new(reader),
        }
    }

    /// Parse a single line
    pub fn parse_line(&self, line: &str) -> Result<HashMap<String, serde_json::Value>, String> {
        let line = line.trim();
        
        // Check if this is an iptables log (must contain "IN=")
        let field_idx = match line.find("IN=") {
            Some(idx) => idx,
            None => return Err("Not an iptables log".to_string()),
        };

        // Convert the syslog iptables log into hash
        let mut result = HashMap::new();
        
        for val in line[field_idx..].split_whitespace() {
            if let Some(eq_pos) = val.find('=') {
                let key = &val[..eq_pos];
                let value = &val[eq_pos + 1..];
                result.insert(key.to_lowercase(), serde_json::Value::String(value.to_string()));
            } else {
                result.insert(val.to_lowercase(), serde_json::Value::String("".to_string()));
            }
        }

        // Parse timestamp from the beginning of the line
        let timestamp_str = &line[..15.min(line.len())];
        match NaiveDateTime::parse_from_str(timestamp_str, "%b %d %H:%M:%S") {
            Ok(dt) => {
                result.insert("start_time".to_string(), serde_json::Value::String(dt.to_string()));
            }
            Err(_) => return Err("Bad date format".to_string()),
        }

        // Sanitize protocol
        if let Some(proto) = result.get_mut("proto") {
            if let Some(s) = proto.as_str() {
                *proto = serde_json::Value::String(s.to_lowercase());
            }
        }

        // Rename fields according to flow2db specifications
        let proto = result.get("proto").and_then(|v| v.as_str()).unwrap_or("");
        if proto == "udp" || proto == "tcp" {
            if let Some(spt) = result.remove("spt") {
                if let Some(s) = spt.as_str() {
                    result.insert("sport".to_string(), serde_json::Value::Number(s.parse::<i64>().unwrap_or(0).into()));
                }
            }
            if let Some(dpt) = result.remove("dpt") {
                if let Some(s) = dpt.as_str() {
                    result.insert("dport".to_string(), serde_json::Value::Number(s.parse::<i64>().unwrap_or(0).into()));
                }
            }
        }

        // This data is mandatory but undefined in iptables logs, so make a choice
        result.insert("cspkts".to_string(), serde_json::Value::Number(0.into()));
        result.insert("scpkts".to_string(), serde_json::Value::Number(0.into()));
        result.insert("scbytes".to_string(), serde_json::Value::Number(0.into()));
        result.insert("csbytes".to_string(), serde_json::Value::Number(0.into()));

        // Copy start_time to end_time
        if let Some(start_time) = result.get("start_time") {
            result.insert("end_time".to_string(), start_time.clone());
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_line() {
        let parser = IptablesParser::new(std::io::Cursor::new(b""));
        let line = "Feb  4 05:30:11 pi01 kernel: [3240403.495065] IPTABLES/UDP/IN=enxb827eb8f8a4f OUT= MAC=ff:ff:ff:ff:ff:ff SRC=192.168.0.254 DST=192.168.0.255 LEN=236 TOS=0x00 PREC=0x00 TTL=64 ID=0 DF PROTO=UDP SPT=138 DPT=138 LEN=216";
        let result = parser.parse_line(line);
        
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.get("src").and_then(|v| v.as_str()), Some("192.168.0.254"));
        assert_eq!(parsed.get("dst").and_then(|v| v.as_str()), Some("192.168.0.255"));
        assert_eq!(parsed.get("sport").and_then(|v| v.as_i64()), Some(138));
        assert_eq!(parsed.get("dport").and_then(|v| v.as_i64()), Some(138));
        assert!(parsed.contains_key("start_time"));
        assert!(parsed.contains_key("end_time"));
    }

    #[test]
    fn test_parse_line_not_iptables() {
        let parser = IptablesParser::new(std::io::Cursor::new(b""));
        let line = "Feb  4 05:30:11 pi01 kernel: [3240403.495065] Some other log";
        let result = parser.parse_line(line);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_line_tcp() {
        let parser = IptablesParser::new(std::io::Cursor::new(b""));
        let line = "Feb  4 05:30:11 pi01 kernel: [3240403.495065] PROTO=TCP SPT=12345 DPT=80 SRC=192.168.1.1 DST=192.168.1.2 IN=eth0";
        let result = parser.parse_line(line);
        
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.get("sport").and_then(|v| v.as_i64()), Some(12345));
        assert_eq!(parsed.get("dport").and_then(|v| v.as_i64()), Some(80));
    }
}
