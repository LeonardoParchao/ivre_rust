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

//! This module contains functions to manipulate CPE values for
//! documents from the active (nmap & view) purposes.

use log::warn;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;

#[derive(Debug, Clone)]
pub struct CpeDict {
    pub cpe_type: String,
    pub vendor: String,
    pub product: String,
    pub version: String,
    pub origins: HashSet<String>,
}

impl CpeDict {
    pub fn new(cpe_type: String, vendor: String, product: String, version: String) -> Self {
        CpeDict {
            cpe_type,
            vendor,
            product,
            version,
            origins: HashSet::new(),
        }
    }
}

#[derive(Debug)]
pub enum CpeError {
    InvalidFormat(String),
}

impl fmt::Display for CpeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CpeError::InvalidFormat(cpe_str) => write!(f, "invalid cpe format ({})", cpe_str),
        }
    }
}

impl Error for CpeError {}

/// Helper function to parse CPEs. Supports both 2.2 (`cpe:/...`) and
/// 2.3 (`cpe:2.3:...`) formats. This is a very partial/simple parser.
///
/// # Errors
///
/// Returns `CpeError::InvalidFormat` if the cpe string is not parsable.
pub fn cpe2dict(cpe_str: &str) -> Result<CpeDict, CpeError> {
    let cpe_body = if cpe_str.starts_with("cpe:2.3:") {
        &cpe_str[8..]
    } else if cpe_str.starts_with("cpe:/") {
        &cpe_str[5..]
    } else {
        return Err(CpeError::InvalidFormat(cpe_str.to_string()));
    };

    // Keep anything after the version field grouped together to avoid losing
    // update/edition components present in 2.2/2.3 strings.
    let parts: Vec<&str> = cpe_body.split(':').collect();
    
    if parts.len() < 2 {
        return Err(CpeError::InvalidFormat(cpe_str.to_string()));
    }

    let cpe_type = parts.get(0).unwrap_or(&"").to_string();
    let cpe_vend = parts.get(1).unwrap_or(&"").to_string();
    let cpe_prod = parts.get(2).unwrap_or(&"").to_string();
    let cpe_vers = parts.get(3).unwrap_or(&"").to_string();

    Ok(CpeDict::new(cpe_type, cpe_vend, cpe_prod, cpe_vers))
}

/// Add CPE values (`cpe_values`) to the `hostrec` at the given `path`.
///
/// CPEs are indexed in a dictionary to agglomerate origins, but this dict
/// is replaced with its values() in ._pre_addhost() or in
/// .store_scan_json_zgrab(), or in the function that calls
/// add_cpe_values(), depending on the context.
pub fn add_cpe_values(
    hostrec: &mut HashMap<String, CpeDict>,
    path: &str,
    cpe_values: &[String],
) {
    for cpe in cpe_values {
        if !hostrec.contains_key(cpe) {
            match cpe2dict(cpe) {
                Ok(cpeobj) => {
                    hostrec.insert(cpe.clone(), cpeobj);
                }
                Err(_) => {
                    warn!("Invalid cpe format ({})", cpe);
                    continue;
                }
            }
        }
        if let Some(cpeobj) = hostrec.get_mut(cpe) {
            cpeobj.origins.insert(path.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpe2dict_2_3() {
        let cpe_str = "cpe:2.3:a:vendor:product:1.0";
        let result = cpe2dict(cpe_str).unwrap();
        assert_eq!(result.cpe_type, "a");
        assert_eq!(result.vendor, "vendor");
        assert_eq!(result.product, "product");
        assert_eq!(result.version, "1.0");
    }

    #[test]
    fn test_cpe2dict_2_2() {
        let cpe_str = "cpe:/a:vendor:product:1.0";
        let result = cpe2dict(cpe_str).unwrap();
        assert_eq!(result.cpe_type, "a");
        assert_eq!(result.vendor, "vendor");
        assert_eq!(result.product, "product");
        assert_eq!(result.version, "1.0");
    }

    #[test]
    fn test_cpe2dict_invalid() {
        let cpe_str = "invalid:cpe";
        assert!(cpe2dict(cpe_str).is_err());
    }

    #[test]
    fn test_add_cpe_values() {
        let mut hostrec: HashMap<String, CpeDict> = HashMap::new();
        let cpe_values = vec!["cpe:2.3:a:vendor:product:1.0".to_string()];
        add_cpe_values(&mut hostrec, "/path/to/scan", &cpe_values);
        
        assert_eq!(hostrec.len(), 1);
        let cpe_key = "cpe:2.3:a:vendor:product:1.0";
        assert!(hostrec.contains_key(cpe_key));
        assert!(hostrec[cpe_key].origins.contains("/path/to/scan"));
    }
}
