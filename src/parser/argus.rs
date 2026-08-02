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

//! Support for Argus log files

use chrono::NaiveDateTime;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::fs::File;
use std::path::Path;

/// Argus log parser
pub struct ArgusParser<R: Read> {
    reader: BufReader<R>,
    fields: Vec<String>,
    aggregation: Vec<String>,
}

impl ArgusParser<BufReader<File>> {
    /// Create a new ArgusParser from a file path
    pub fn from_path<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Ok(ArgusParser::new(reader))
    }
}

impl<R: Read> ArgusParser<R> {
    /// Create a new ArgusParser from a reader
    pub fn new(reader: R) -> Self {
        let fields = vec![
            "proto".to_string(),
            "dir".to_string(),
            "saddr".to_string(),
            "sport".to_string(),
            "daddr".to_string(),
            "dport".to_string(),
            "spkts".to_string(),
            "dpkts".to_string(),
            "sbytes".to_string(),
            "dbytes".to_string(),
            "stime".to_string(),
            "ltime".to_string(),
        ];
        
        let aggregation = vec![
            "saddr".to_string(),
            "sport".to_string(),
            "daddr".to_string(),
            "dport".to_string(),
            "proto".to_string(),
        ];
        
        ArgusParser {
            reader: BufReader::new(reader),
            fields,
            aggregation,
        }
    }

    /// Parse a single line
    pub fn parse_line(&self, line: &str) -> Result<HashMap<String, serde_json::Value>, String> {
        let line = line.trim();
        let parts: Vec<&str> = line.split(',').collect();
        
        if parts.len() != self.fields.len() {
            return Err(format!("Expected {} fields, got {}", self.fields.len(), parts.len()));
        }

        let mut result = HashMap::new();

        for (field_name, value) in self.fields.iter().zip(parts.iter()) {
            let value = value.trim();
            result.insert(field_name.clone(), serde_json::Value::String(value.to_string()));
        }

        // Parse port fields (sport, dport)
        for fld in ["sport", "dport"] {
            if let Some(val) = result.get(fld) {
                if let Some(s) = val.as_str() {
                    if s.is_empty() {
                        result.remove(fld);
                    } else {
                        let parsed = if s.starts_with("0x") {
                            i64::from_str_radix(&s[2..], 16)
                        } else {
                            s.parse::<i64>()
                        };
                        
                        match parsed {
                            Ok(v) => {
                                result.insert(fld.to_string(), serde_json::Value::Number(v.into()));
                            }
                            Err(_) => {
                                result.remove(fld);
                            }
                        }
                    }
                }
            }
        }

        // Rename fields according to flow2db specifications
        if let Some(val) = result.remove("saddr") {
            result.insert("src".to_string(), val);
        }
        if let Some(val) = result.remove("daddr") {
            result.insert("dst".to_string(), val);
        }

        // Parse and rename byte/packet fields
        if let Some(val) = result.remove("sbytes") {
            if let Some(s) = val.as_str() {
                result.insert("csbytes".to_string(), serde_json::Value::Number(s.parse::<i64>().unwrap_or(0).into()));
            }
        }
        if let Some(val) = result.remove("spkts") {
            if let Some(s) = val.as_str() {
                result.insert("cspkts".to_string(), serde_json::Value::Number(s.parse::<i64>().unwrap_or(0).into()));
            }
        }
        if let Some(val) = result.remove("dbytes") {
            if let Some(s) = val.as_str() {
                result.insert("scbytes".to_string(), serde_json::Value::Number(s.parse::<i64>().unwrap_or(0).into()));
            }
        }
        if let Some(val) = result.remove("dpkts") {
            if let Some(s) = val.as_str() {
                result.insert("scpkts".to_string(), serde_json::Value::Number(s.parse::<i64>().unwrap_or(0).into()));
            }
        }

        // Parse timestamps
        if let Some(val) = result.remove("stime") {
            if let Some(s) = val.as_str() {
                let timestamp = s.parse::<f64>().unwrap_or(0.0);
                let dt = NaiveDateTime::from_timestamp_opt(timestamp as i64, ((timestamp % 1.0) * 1_000_000_000.0) as u32);
                if let Some(dt) = dt {
                    result.insert("start_time".to_string(), serde_json::Value::String(dt.to_string()));
                }
            }
        }
        if let Some(val) = result.remove("ltime") {
            if let Some(s) = val.as_str() {
                let timestamp = s.parse::<f64>().unwrap_or(0.0);
                let dt = NaiveDateTime::from_timestamp_opt(timestamp as i64, ((timestamp % 1.0) * 1_000_000_000.0) as u32);
                if let Some(dt) = dt {
                    result.insert("end_time".to_string(), serde_json::Value::String(dt.to_string()));
                }
            }
        }

        Ok(result)
    }

    /// Parse all lines from the reader
    pub fn parse_all(&mut self) -> std::io::Result<Vec<HashMap<String, serde_json::Value>>> {
        let mut results = Vec::new();
        let mut line = String::new();
        
        // Skip header line
        if self.reader.read_line(&mut line)? > 0 {
            line.clear();
        }
        
        while self.reader.read_line(&mut line)? > 0 {
            match self.parse_line(&line) {
                Ok(parsed) if !parsed.is_empty() => results.push(parsed),
                _ => {}
            }
            line.clear();
        }
        
        Ok(results)
    }

    /// Get the aggregation fields
    pub fn aggregation(&self) -> &[String] {
        &self.aggregation
    }

    /// Get the field names
    pub fn fields(&self) -> &[String] {
        &self.fields
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_line() {
        let parser = ArgusParser::new(std::io::Cursor::new(b""));
        let line = "tcp,->,192.168.1.1,1234,192.168.1.2,80,100,50,10000,5000,1704067200.0,1704067260.0";
        let result = parser.parse_line(line);
        
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.get("src").and_then(|v| v.as_str()), Some("192.168.1.1"));
        assert_eq!(parsed.get("dst").and_then(|v| v.as_str()), Some("192.168.1.2"));
        assert!(parsed.contains_key("start_time"));
        assert!(parsed.contains_key("end_time"));
    }

    #[test]
    fn test_parse_line_hex_port() {
        let parser = ArgusParser::new(std::io::Cursor::new(b""));
        let line = "tcp,->,192.168.1.1,0x4d2,192.168.1.2,80,100,50,10000,5000,1704067200.0,1704067260.0";
        let result = parser.parse_line(line);
        
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.get("sport").and_then(|v| v.as_i64()), Some(1234));
    }

    #[test]
    fn test_parse_line_empty_port() {
        let parser = ArgusParser::new(std::io::Cursor::new(b""));
        let line = "tcp,->,192.168.1.1,,192.168.1.2,80,100,50,10000,5000,1704067200.0,1704067260.0";
        let result = parser.parse_line(line);
        
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert!(!parsed.contains_key("sport"));
    }
}
