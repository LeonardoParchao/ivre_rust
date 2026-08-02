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

//! Support for Airodump CSV files.

use chrono::NaiveDateTime;
use std::collections::HashMap;

const TYPE_INT: u8 = 0;
const TYPE_DATE: u8 = 1;
const TYPE_IP: u8 = 2;
const TYPE_MAC: u8 = 3;

/// Airodump parser for CSV log files
pub struct AirodumpParser {
    fields: Vec<String>,
    cur_types: Vec<Option<u8>>,
    nextline_headers: bool,
}

impl AirodumpParser {
    pub fn new() -> Self {
        let types = Self::get_types();
        let fields = types.keys().cloned().collect();
        let cur_types = fields.iter().map(|f| types.get(f).copied()).collect();
        
        AirodumpParser {
            fields,
            cur_types,
            nextline_headers: false,
        }
    }
    
    fn get_types() -> HashMap<String, u8> {
        let mut types = HashMap::new();
        types.insert("# IV".to_string(), TYPE_INT);
        types.insert("BSSID".to_string(), TYPE_MAC);
        types.insert("ID-length".to_string(), TYPE_INT);
        types.insert("First time seen".to_string(), TYPE_DATE);
        types.insert("Last time seen".to_string(), TYPE_DATE);
        types.insert("LAN IP".to_string(), TYPE_IP);
        types.insert("Power".to_string(), TYPE_INT);
        types.insert("Speed".to_string(), TYPE_INT);
        types.insert("channel".to_string(), TYPE_INT);
        types.insert("# beacons".to_string(), TYPE_INT);
        types
    }
    
    pub fn parse_line(&mut self, line: &str) -> Result<HashMap<String, serde_json::Value>, String> {
        let line = line.trim_end_matches('\r').trim_end_matches('\n');
        
        if line.is_empty() {
            self.nextline_headers = true;
            return Err("Empty line, expecting headers".to_string());
        }
        
        let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
        
        if self.nextline_headers {
            self.fields = parts.iter().map(|s| s.to_string()).collect();
            self.cur_types = self.fields.iter().map(|f| Self::get_types().get(f).copied()).collect();
            self.nextline_headers = false;
            return Err("Headers parsed, expecting data".to_string());
        }
        
        let mut result = HashMap::new();
        
        for (i, val) in parts.iter().enumerate() {
            if i >= self.fields.len() {
                break;
            }
            
            let field = &self.fields[i];
            let type_id = self.cur_types.get(i).copied().flatten();
            
            let converted = match type_id {
                Some(TYPE_INT) => {
                    val.parse::<i64>()
                        .map(|v| serde_json::Value::Number(v.into()))
                        .unwrap_or(serde_json::Value::Null)
                }
                Some(TYPE_DATE) => {
                    NaiveDateTime::parse_from_str(val, "%Y-%m-%d %H:%M:%S")
                        .map(|dt| serde_json::Value::String(dt.to_string()))
                        .unwrap_or(serde_json::Value::Null)
                }
                Some(TYPE_IP) => {
                    // Normalize IP address
                    let normalized: String = val.split('.').map(|s| s.trim()).collect::<Vec<_>>().join(".");
                    serde_json::Value::String(normalized)
                }
                Some(TYPE_MAC) => {
                    serde_json::Value::String(val.to_lowercase())
                }
                None => serde_json::Value::String(val.to_string()),
                _ => serde_json::Value::String(val.to_string()),
            };
            
            result.insert(field.clone(), converted);
        }
        
        Ok(result)
    }
    
    pub fn set_headers(&mut self, headers: Vec<String>) {
        self.fields = headers;
        self.cur_types = self.fields.iter().map(|f| Self::get_types().get(f).copied()).collect();
    }
}

impl Default for AirodumpParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_airodump_parser_new() {
        let parser = AirodumpParser::new();
        assert!(!parser.fields.is_empty());
    }

    #[test]
    fn test_parse_line() {
        let mut parser = AirodumpParser::new();
        // Test with a simple data line
        let line = "1,00:11:22:33:44:55,10,2024-01-01 12:00:00,2024-01-01 12:30:00,192.168.1.1,-50,54,6,100";
        
        // First call will expect headers
        let result = parser.parse_line(line);
        assert!(result.is_err());
        
        // Set headers manually for testing
        parser.set_headers(vec![
            "# IV".to_string(),
            "BSSID".to_string(),
            "ID-length".to_string(),
            "First time seen".to_string(),
            "Last time seen".to_string(),
            "LAN IP".to_string(),
            "Power".to_string(),
            "Speed".to_string(),
            "channel".to_string(),
            "# beacons".to_string(),
        ]);
        
        let result = parser.parse_line(line);
        assert!(result.is_ok());
        
        let parsed = result.unwrap();
        assert!(parsed.contains_key("BSSID"));
    }
}
