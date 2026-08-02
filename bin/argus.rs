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

//! Argus parser binary

use std::env;
use std::fs::File;
use std::io::{self, BufRead, Read};
use std::path::Path;

use ivre::parser::argus::ArgusParser;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: {} <input_file>", args[0]);
        std::process::exit(1);
    }

    let input_path = &args[1];
    
    let file = match File::open(input_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error opening file {}: {}", input_path, e);
            std::process::exit(1);
        }
    };

    let mut parser = ArgusParser::new(file);
    
    match parser.parse_all() {
        Ok(results) => {
            for result in results {
                println!("{}", serde_json::to_string(&result).unwrap_or_else(|_| "{}".to_string()));
            }
        }
        Err(e) => {
            eprintln!("Error parsing file: {}", e);
            std::process::exit(1);
        }
    }
}
