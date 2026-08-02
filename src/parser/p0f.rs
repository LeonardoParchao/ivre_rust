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

//! Support for p0f log files

use chrono::NaiveDateTime;
use regex::Regex;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::fs::File;
use std::path::Path;

lazy_static::lazy_static! {
    static ref LINE_RE: Regex = Regex::new(r"^\[(?P<time>[^\]]+)\] (?P<data>.*)$").unwrap();
}

/// p0f log parser
pub struct P0fParser<R: Read> {
    reader: BufReader<R>,
}

impl P0fParser<BufReader<File>> {
    /// Create a new P0fParser from a file path
    pub fn from_path<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Ok(P0fParser { reader })
    }
}

impl<R: Read> P0fParser<R> {
    /// Create a new P0fParser from a reader
    pub fn new(reader: R) -> Self {
        P0fParser {
            reader: BufReader::new(reader),
        }
    }

    /// Parse a single line
    pub fn parse_line(&self, line: &str) -> HashMap<String, String> {
        let line = line.trim();
        let caps = match LINE_RE.captures(line) {
            Some(c) => c,
            None => return HashMap::new(),
        };

        let mut result = HashMap::new();

        // Parse timestamp
        if let Some(time_str) = caps.name("time") {
            match NaiveDateTime::parse_from_str(time_str.as_str(), "%Y/%m/%d %H:%M:%S") {
                Ok(dt) => {
                    result.insert("ts".to_string(), dt.to_string());
                }
                Err(_) => return HashMap::new(),
            }
        }

        // Parse data entries
        if let Some(data_str) = caps.name("data") {
            for entry in data_str.as_str().split('|') {
                let parts: Vec<&str> = entry.splitn(2, '=').collect();
                if parts.len() == 2 {
                    let key = parts[0].to_string();
                    let value = parts[1].to_string();
                    
                    if result.contains_key(&key) {
                        // Duplicate key - return empty as per Python implementation
                        return HashMap::new();
                    }
                    result.insert(key, value);
                }
            }
        }

        result
    }

    /// Parse all lines from the reader
    pub fn parse_all(&mut self) -> std::io::Result<Vec<HashMap<String, String>>> {
        let mut results = Vec::new();
        let mut line = String::new();
        
        while self.reader.read_line(&mut line)? > 0 {
            let parsed = self.parse_line(&line);
            if !parsed.is_empty() {
                results.push(parsed);
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
        let parser = P0fParser::new(std::io::Cursor::new(b""));
        let line = "[2024/01/01 12:00:00] os=Linux|version=5.0";
        let result = parser.parse_line(line);
        
        assert_eq!(result.get("ts"), Some(&"2024-01-01 12:00:00".to_string()));
        assert_eq!(result.get("os"), Some(&"Linux".to_string()));
        assert_eq!(result.get("version"), Some(&"5.0".to_string()));
    }

    #[test]
    fn test_parse_line_invalid() {
        let parser = P0fParser::new(std::io::Cursor::new(b""));
        let line = "invalid line";
        let result = parser.parse_line(line);
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_line_duplicate_key() {
        let parser = P0fParser::new(std::io::Cursor::new(b""));
        let line = "[2024/01/01 12:00:00] os=Linux|os=Windows";
        let result = parser.parse_line(line);
        assert!(result.is_empty());
    }
}
