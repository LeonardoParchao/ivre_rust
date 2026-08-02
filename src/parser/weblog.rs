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

//! Support for http server log files

use chrono::NaiveDateTime;
use regex::Regex;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::fs::File;
use std::path::Path;

lazy_static::lazy_static! {
    static ref LINE_RE: Regex = Regex::new(
        r'^(?P<addr>[^ ]*) (?P<identity>[^ ]*) (?P<username>[^ ]*) \[(?P<datetime>[^]]*)\] "(?P<request>[^"]*)" (?P<status>[^ ]*) (?P<size>[^ ]*) "(?P<referer>[^"]*)" "(?P<useragent>[^"]*)"(?: "(?P<x_forwarded_for>[^"]*)")?\r?$'
    ).unwrap();
}

/// Http server log parser
pub struct WeblogParser<R: Read> {
    reader: BufReader<R>,
}

impl WeblogParser<BufReader<File>> {
    /// Create a new WeblogParser from a file path
    pub fn from_path<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Ok(WeblogParser { reader })
    }
}

impl<R: Read> WeblogParser<R> {
    /// Create a new WeblogParser from a reader
    pub fn new(reader: R) -> Self {
        WeblogParser {
            reader: BufReader::new(reader),
        }
    }

    /// Parse a single line
    pub fn parse_line(&self, line: &str) -> HashMap<String, String> {
        let caps = match LINE_RE.captures(line) {
            Some(c) => c,
            None => return HashMap::new(),
        };

        let mut result = HashMap::new();

        // Parse timestamp
        if let Some(datetime_str) = caps.name("datetime") {
            let datetime_part = datetime_str.as_str().split_whitespace().next();
            if let Some(dt_str) = datetime_part {
                match NaiveDateTime::parse_from_str(dt_str, "%d/%b/%Y:%H:%M:%S") {
                    Ok(dt) => {
                        result.insert("ts".to_string(), dt.to_string());
                    }
                    Err(_) => return HashMap::new(),
                }
            } else {
                return HashMap::new();
            }
        }

        // Parse host address
        if let Some(addr) = caps.name("addr") {
            result.insert("host".to_string(), addr.as_str().to_string());
        }

        // Parse user-agent (skip if "-")
        if let Some(useragent) = caps.name("useragent") {
            let ua_str = useragent.as_str();
            if ua_str != "-" {
                result.insert("user-agent".to_string(), ua_str.to_string());
            }
        }

        // Parse x-forwarded-for (skip if "-" or missing)
        if let Some(xff) = caps.name("x_forwarded_for") {
            let xff_str = xff.as_str();
            if !xff_str.is_empty() && xff_str != "-" {
                result.insert("x-forwarded-for".to_string(), xff_str.to_string());
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
        let parser = WeblogParser::new(std::io::Cursor::new(b""));
        let line = r#"192.168.1.1 - - [01/Jan/2024:12:00:00 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0""#;
        let result = parser.parse_line(line);
        
        assert_eq!(result.get("host"), Some(&"192.168.1.1".to_string()));
        assert!(result.contains_key("ts"));
        assert_eq!(result.get("user-agent"), Some(&"Mozilla/5.0".to_string()));
    }

    #[test]
    fn test_parse_line_with_xff() {
        let parser = WeblogParser::new(std::io::Cursor::new(b""));
        let line = r#"192.168.1.1 - - [01/Jan/2024:12:00:00 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0" "10.0.0.1""#;
        let result = parser.parse_line(line);
        
        assert_eq!(result.get("x-forwarded-for"), Some(&"10.0.0.1".to_string()));
    }

    #[test]
    fn test_parse_line_invalid() {
        let parser = WeblogParser::new(std::io::Cursor::new(b""));
        let line = "invalid line";
        let result = parser.parse_line(line);
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_line_skip_dash_useragent() {
        let parser = WeblogParser::new(std::io::Cursor::new(b""));
        let line = r#"192.168.1.1 - - [01/Jan/2024:12:00:00 +0000] "GET / HTTP/1.1" 200 1234 "-" "-""#;
        let result = parser.parse_line(line);
        
        assert!(!result.contains_key("user-agent"));
    }
}
