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

//! Support for Zeek log files

use chrono::NaiveDateTime;
use regex::Regex;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::fs::File;
use std::path::Path;

lazy_static::lazy_static! {
    static ref CONTAINER_TYPE: Regex = Regex::new(r"^(table|set|vector)\[([a-z]+)\]$").unwrap();
}

/// Zeek log parser
pub struct ZeekParser<R: Read> {
    reader: BufReader<R>,
    sep: Vec<u8>,
    set_sep: Vec<u8>,
    empty_field: Vec<u8>,
    unset_field: Vec<u8>,
    fields: Vec<Vec<u8>>,
    types: Vec<Vec<u8>>,
    path: Option<String>,
    nextlines: Vec<String>,
    int_types: Vec<Vec<u8>>,
    float_types: Vec<Vec<u8>>,
    time_types: Vec<Vec<u8>>,
}

impl ZeekParser<BufReader<File>> {
    /// Create a new ZeekParser from a file path
    pub fn from_path<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut parser = ZeekParser::new(reader);
        parser.parse_headers()?;
        Ok(parser)
    }
}

impl<R: Read> ZeekParser<R> {
    /// Create a new ZeekParser from a reader
    pub fn new(reader: R) -> Self {
        ZeekParser {
            reader: BufReader::new(reader),
            sep: b" ".to_vec(),
            set_sep: b",".to_vec(),
            empty_field: b"(empty)".to_vec(),
            unset_field: b"-".to_vec(),
            fields: Vec::new(),
            types: Vec::new(),
            path: None,
            nextlines: Vec::new(),
            int_types: vec![b"port".to_vec(), b"count".to_vec()],
            float_types: vec![b"interval".to_vec()],
            time_types: vec![b"time".to_vec()],
        }
    }

    /// Parse header lines from the reader
    fn parse_headers(&mut self) -> std::io::Result<()> {
        let mut line = String::new();
        
        while self.reader.read_line(&mut line)? > 0 {
            let line_bytes = line.trim().as_bytes().to_vec();
            
            if !line_bytes.starts_with(b"#") {
                self.nextlines.push(line.trim().to_string());
                break;
            }
            
            self.parse_header_line(&line_bytes);
            line.clear();
        }
        
        Ok(())
    }

    /// Parse a single header line
    fn parse_header_line(&mut self, line: &[u8]) {
        if line.is_empty() {
            return;
        }
        
        if !line.starts_with(b"#") {
            return;
        }

        let line_content = &line[1..];
        
        // Handle special case for separator
        if line.starts_with(b"#separator ") {
            let arg = &line[11..];
            if arg.starts_with(b"\\x") {
                self.sep = self.decode_hex(&arg[2..]);
            } else {
                self.sep = arg.to_vec();
            }
            return;
        }

        let parts: Vec<&[u8]> = line_content.splitn(2, |&c| c == b' ').collect();
        if parts.len() < 2 {
            return;
        }

        let directive = parts[0];
        let arg = parts[1];

        match directive {
            b"set_separator" => self.set_sep = arg.to_vec(),
            b"empty_field" => self.empty_field = arg.to_vec(),
            b"unset_field" => self.unset_field = arg.to_vec(),
            b"path" => self.path = String::from_utf8(arg.to_vec()).ok(),
            b"open" => {}
            b"fields" => self.fields = self.split_bytes(arg, &self.sep),
            b"types" => self.types = self.split_bytes(arg, &self.sep),
            _ => {}
        }
    }

    /// Split bytes by separator
    fn split_bytes(&self, data: &[u8], sep: &[u8]) -> Vec<Vec<u8>> {
        let mut result = Vec::new();
        let mut start = 0;
        
        while let Some(pos) = data[start..].windows(sep.len()).position(|w| w == sep) {
            result.push(data[start..start + pos].to_vec());
            start += pos + sep.len();
        }
        result.push(data[start..].to_vec());
        
        result
    }

    /// Decode hex-encoded bytes
    fn decode_hex(&self, hex: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        for chunk in hex.chunks(2) {
            if chunk.len() == 2 {
                if let Ok(byte) = std::str::from_utf8(chunk) {
                    if let Ok(v) = u8::from_str_radix(byte, 16) {
                        result.push(v);
                    }
                }
            }
        }
        result
    }

    /// Fix a value based on its type
    fn fix_value(&self, val: &[u8], typ: &[u8]) -> serde_json::Value {
        if val == self.unset_field {
            return serde_json::Value::Null;
        }

        if typ == b"bool" {
            return serde_json::Value::Bool(val == b"T");
        }

        // Check for container types
        if let Some(caps) = CONTAINER_TYPE.captures(std::str::from_utf8(typ).unwrap_or("")) {
            if let Some(elt_type) = caps.get(2) {
                if val == self.empty_field {
                    return serde_json::Value::Array(vec![]);
                }
                let elements = self.split_bytes(val, &self.set_sep);
                let values: Vec<serde_json::Value> = elements
                    .iter()
                    .map(|e| self.fix_value(e, elt_type.as_str().as_bytes()))
                    .collect();
                return serde_json::Value::Array(values);
            }
        }

        if self.int_types.iter().any(|t| t == typ) {
            return serde_json::Value::Number(
                std::str::from_utf8(val)
                    .and_then(|s| s.parse::<i64>())
                    .unwrap_or(0)
                    .into(),
            );
        }

        if self.float_types.iter().any(|t| t == typ) {
            return serde_json::Value::Number(
                serde_json::Number::from_f64(
                    std::str::from_utf8(val)
                        .and_then(|s| s.parse::<f64>())
                        .unwrap_or(0.0),
                )
                .unwrap_or(serde_json::Number::from(0)),
            );
        }

        if self.time_types.iter().any(|t| t == typ) {
            return serde_json::Value::String(
                std::str::from_utf8(val)
                    .and_then(|s| s.parse::<f64>())
                    .and_then(|ts| NaiveDateTime::from_timestamp_opt(ts as i64, ((ts % 1.0) * 1_000_000_000.0) as u32))
                    .map(|dt| dt.to_string())
                    .unwrap_or_else(|| String::from_utf8_lossy(val).to_string()),
            );
        }

        if val == self.empty_field {
            return serde_json::Value::String(String::new());
        }

        serde_json::Value::String(String::from_utf8_lossy(val).to_string())
    }

    /// Parse a single data line
    pub fn parse_line(&self, line: &str) -> Result<HashMap<String, serde_json::Value>, String> {
        let line_bytes = line.trim().as_bytes();
        
        if line_bytes.starts_with(b"#") {
            return Err("Header line".to_string());
        }

        let fields = self.split_bytes(line_bytes, &self.sep);
        let mut result = HashMap::new();

        for (field, typ) in self.fields.iter().zip(self.types.iter()) {
            if let Some(val) = fields.get(self.fields.iter().position(|f| f == field).unwrap_or(0)) {
                let field_name = String::from_utf8_lossy(field).replace(".", "_");
                result.insert(field_name, self.fix_value(val, typ));
            }
        }

        Ok(result)
    }

    /// Get the next parsed line
    pub fn next_line(&mut self) -> Option<Result<HashMap<String, serde_json::Value>, String>> {
        if !self.nextlines.is_empty() {
            let line = self.nextlines.remove(0);
            return Some(self.parse_line(&line));
        }

        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => None,
            Ok(_) => Some(self.parse_line(&line)),
            Err(e) => Some(Err(e.to_string())),
        }
    }

    /// Parse all lines from the reader
    pub fn parse_all(&mut self) -> std::io::Result<Vec<HashMap<String, serde_json::Value>>> {
        let mut results = Vec::new();
        
        while let Some(result) = self.next_line() {
            match result {
                Ok(parsed) if !parsed.is_empty() => results.push(parsed),
                Ok(_) => {}
                Err(_) => {}
            }
        }
        
        Ok(results)
    }

    /// Get field types as pairs
    pub fn field_types(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.fields
            .iter()
            .cloned()
            .zip(self.types.iter().cloned())
            .collect()
    }

    /// Get the separator
    pub fn sep(&self) -> &[u8] {
        &self.sep
    }

    /// Get the set separator
    pub fn set_sep(&self) -> &[u8] {
        &self.set_sep
    }

    /// Get the empty field marker
    pub fn empty_field(&self) -> &[u8] {
        &self.empty_field
    }

    /// Get the unset field marker
    pub fn unset_field(&self) -> &[u8] {
        &self.unset_field
    }

    /// Get the fields
    pub fn fields(&self) -> &[Vec<u8>] {
        &self.fields
    }

    /// Get the types
    pub fn types(&self) -> &[Vec<u8>] {
        &self.types
    }

    /// Get the path
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_hex() {
        let parser = ZeekParser::new(std::io::Cursor::new(b""));
        assert_eq!(parser.decode_hex(b"09"), vec![9]);
        assert_eq!(parser.decode_hex(b"ff"), vec![255]);
    }

    #[test]
    fn test_fix_value_bool() {
        let parser = ZeekParser::new(std::io::Cursor::new(b""));
        assert_eq!(
            parser.fix_value(b"T", b"bool"),
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            parser.fix_value(b"F", b"bool"),
            serde_json::Value::Bool(false)
        );
    }

    #[test]
    fn test_fix_value_int() {
        let parser = ZeekParser::new(std::io::Cursor::new(b""));
        assert_eq!(
            parser.fix_value(b"42", b"count"),
            serde_json::Value::Number(42.into())
        );
    }

    #[test]
    fn test_fix_value_unset() {
        let parser = ZeekParser::new(std::io::Cursor::new(b""));
        assert_eq!(
            parser.fix_value(b"-", b"string"),
            serde_json::Value::Null
        );
    }

    #[test]
    fn test_split_bytes() {
        let parser = ZeekParser::new(std::io::Cursor::new(b""));
        let result = parser.split_bytes(b"a,b,c", b",");
        assert_eq!(result, vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
    }
}
