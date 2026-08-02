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

//! This sub-module contains function to convert & display Nmap scan
//! results as they are stored in the database (JSON).

use std::collections::HashMap;
use std::io::Write;

/// Generate script output for display
#[allow(dead_code)]
fn script_output(record: &HashMap<String, serde_json::Value>) -> Vec<String> {
    let mut out = Vec::new();
    
    if let Some(scripts) = record.get("scripts").and_then(|v| v.as_array()) {
        for script in scripts {
            if let Some(script_obj) = script.as_object() {
                let script_id = script_obj.get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                
                if let Some(output) = script_obj.get("output").and_then(|v| v.as_str()) {
                    let lines: Vec<&str> = output
                        .lines()
                        .map(|line| line.trim())
                        .filter(|line| !line.is_empty())
                        .collect();
                    
                    let script_out = if lines.is_empty() {
                        String::new()
                    } else if lines.len() == 1 {
                        format!(" {}", lines[0])
                    } else {
                        format!("\n\t\t\t{}", lines.join("\n\t\t\t"))
                    };
                    
                    out.push(format!("\t\t{}:{}\n", script_id, script_out));
                } else {
                    out.push(format!("\t\t{}:\n", script_id));
                }
            }
        }
    }
    
    out
}

/// Display a host record
pub fn display_host<W: Write>(
    record: &HashMap<String, serde_json::Value>,
    out: &mut W,
    _show_scripts: bool,
    _show_traceroute: bool,
    _show_os: bool,
) -> std::io::Result<()> {
    let addr = record.get("addr")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    
    writeln!(out, "Host {}", addr)?;
    
    // Display hostnames
    if let Some(hostnames) = record.get("hostnames").and_then(|v| v.as_array()) {
        let names: Vec<&str> = hostnames
            .iter()
            .filter_map(|h| h.get("name").and_then(|v| v.as_str()))
            .collect();
        if !names.is_empty() {
            writeln!(out, " ({})", names.join("/"))?;
        }
    }
    
    // Display source
    if let Some(source) = record.get("source") {
        if let Some(src_str) = source.as_str() {
            writeln!(out, " from {}", src_str)?;
        } else if let Some(src_arr) = source.as_array() {
            let sources: Vec<&str> = src_arr
                .iter()
                .filter_map(|v| v.as_str())
                .collect();
            if !sources.is_empty() {
                writeln!(out, " from {}", sources.join("/"))?;
            }
        }
    }
    
    // Display categories
    if let Some(categories) = record.get("categories").and_then(|v| v.as_array()) {
        let cats: Vec<&str> = categories
            .iter()
            .filter_map(|c| c.as_str())
            .filter(|c| !c.starts_with('_'))
            .collect();
        if !cats.is_empty() {
            writeln!(out, " ({})", cats.join(", "))?;
        }
    }
    
    // Display state
    if let Some(state) = record.get("state").and_then(|v| v.as_str()) {
        write!(out, " ({})", state)?;
        if let Some(state_reason) = record.get("state_reason").and_then(|v| v.as_str()) {
            write!(out, ": {}", state_reason)?;
        }
        writeln!(out, ")")?;
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_output_empty() {
        let record: HashMap<String, serde_json::Value> = HashMap::new();
        let output = script_output(&record);
        assert!(output.is_empty());
    }
}
