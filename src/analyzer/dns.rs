// This file is part of IVRE.
// Copyright 2011 - 2025 Pierre LALET <pierre@droids-corp.org>
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

//! DNS checking and analysis functionality.
//!
//! This module provides DNS query capabilities and various checkers for
//! DNS consistency, zone transfers, and other DNS-related security checks.

use log::warn;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// DNS record representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NsRecord {
    pub name: String,
    pub ttl: String,
    pub rclass: String,
    pub rtype: String,
    pub data: String,
}

/// Regular expressions for URL and email validation
lazy_static::lazy_static! {
    static ref HTTPS_REGEXP: Regex = Regex::new(
        r"^(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|\
        \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/?|[/?]\S+)$"
    ).unwrap();
    
    static ref MAIL_REGEXP: Regex = Regex::new(r"[^@]+@[^@]+\.[^@]+").unwrap();
}

/// Perform a DNS query using a resolver
/// 
/// This is a simplified implementation. In production, use a proper DNS library
/// like trust-dns-client or async-std's DNS capabilities.
pub fn dns_query(
    name: &str,
    rtype: Option<&str>,
    _srv: Option<&str>,
) -> Vec<NsRecord> {
    // Placeholder implementation
    // In a real implementation, this would use a DNS client library
    // to perform actual DNS queries
    
    warn!("DNS query for {} with type {:?} - placeholder implementation", name, rtype);
    
    Vec::new()
}

/// Perform a DNS query and return only the data field
pub fn dns_query_data(
    name: &str,
    rtype: Option<&str>,
    srv: Option<&str>,
) -> Vec<String> {
    dns_query(name, rtype, srv)
        .into_iter()
        .map(|r| r.data)
        .collect()
}

/// Base checker class for DNS operations
pub struct Checker {
    pub domain: String,
    ns_servers: Option<Vec<String>>,
    ns4_servers: Option<Vec<(String, String)>>,
    ns6_servers: Option<Vec<(String, String)>>,
}

impl Checker {
    pub fn new(domain: String) -> Self {
        Checker {
            domain,
            ns_servers: None,
            ns4_servers: None,
            ns6_servers: None,
        }
    }

    /// Get the list of nameservers for the domain
    pub fn get_ns_servers(&mut self) -> &[String] {
        if self.ns_servers.is_none() {
            self.ns_servers = Some(dns_query_data(&self.domain, Some("NS"), None));
        }
        self.ns_servers.as_ref().unwrap()
    }

    /// Get IPv4 addresses of nameservers
    pub fn get_ns4_servers(&mut self) -> &[(String, String)] {
        if self.ns4_servers.is_none() {
            let mut servers = Vec::new();
            for srv in self.get_ns_servers() {
                for addr in dns_query_data(srv, Some("A"), None) {
                    servers.push((srv.clone(), addr));
                }
            }
            self.ns4_servers = Some(servers);
        }
        self.ns4_servers.as_ref().unwrap()
    }

    /// Get IPv6 addresses of nameservers
    pub fn get_ns6_servers(&mut self) -> &[(String, String)] {
        if self.ns6_servers.is_none() {
            let mut servers = Vec::new();
            for srv in self.get_ns_servers() {
                for addr in dns_query_data(srv, Some("AAAA"), None) {
                    servers.push((srv.clone(), addr));
                }
            }
            self.ns6_servers = Some(servers);
        }
        self.ns6_servers.as_ref().unwrap()
    }

    /// Perform the test (to be implemented by subclasses)
    pub fn test(&mut self, _v4: bool, _v6: bool) -> Vec<DnsHostResult> {
        Vec::new()
    }

    /// Perform the test and return raw results
    pub fn do_test(&mut self, v4: bool, v6: bool) -> Vec<(String, String, Vec<NsRecord>)> {
        let mut results = Vec::new();
        
        if v4 {
            for (srv, addr) in self.get_ns4_servers() {
                results.push((srv.clone(), addr.clone(), self._test(&addr)));
            }
        }
        
        if v6 {
            for (srv, addr) in self.get_ns6_servers() {
                results.push((srv.clone(), addr.clone(), self._test(&addr)));
            }
        }
        
        results
    }

    /// Internal test method (to be implemented by subclasses)
    fn _test(&self, _addr: &str) -> Vec<NsRecord> {
        Vec::new()
    }
}

/// Result of a DNS check on a host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsHostResult {
    pub addr: String,
    pub hostnames: Vec<Hostname>,
    pub schema_version: String,
    pub starttime: String,
    pub endtime: String,
    pub ports: Option<Vec<PortInfo>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hostname {
    pub name: String,
    #[serde(rename = "type")]
    pub hostname_type: String,
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: String,
    pub service_name: Option<String>,
    #[serde(rename = "state_state")]
    pub state: Option<String>,
    pub scripts: Option<Vec<ScriptInfo>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptInfo {
    pub id: String,
    pub output: String,
}

/// Checker for DNS zone transfers (AXFR)
pub struct AxfrChecker {
    base: Checker,
}

impl AxfrChecker {
    pub fn new(domain: String) -> Self {
        AxfrChecker {
            base: Checker::new(domain),
        }
    }

    fn _test(&self, addr: &str) -> Vec<NsRecord> {
        dns_query(&self.base.domain, Some("AXFR"), Some(addr))
    }

    pub fn test(&mut self, v4: bool, v6: bool) -> Vec<DnsHostResult> {
        let mut results = Vec::new();
        
        for (srvname, addr, res) in self.base.do_test(v4, v6) {
            let srvname = srvname.trim_end_matches('.');
            
            if res.is_empty() {
                continue;
            }
            
            if res.len() == 1 && (res[0].rtype == "SOA" || res[0].rtype == "CNAME") {
                // SOA only: transfer failed
                // CNAME only: no transfer actually performed
                continue;
            }
            
            warn!("AXFR success for {} on {}", self.base.domain, addr);
            
            let max_name_len = res.iter().map(|r| r.name.len()).max().unwrap_or(0);
            let max_type_len = res.iter().map(|r| r.rtype.len()).max().unwrap_or(0);
            
            let line_fmt = format!("| %-{}s  %-{}s  %s", max_name_len, max_type_len);
            let output_lines: Vec<String> = res
                .iter()
                .map(|r| format!("{}", line_fmt, r.name, r.rtype, r.data))
                .collect();
            
            let output = format!(
                "\nDomain: {}\n{}\n\\\n",
                self.base.domain,
                output_lines.join("\n")
            );
            
            let port_info = PortInfo {
                port: 53,
                protocol: "tcp".to_string(),
                service_name: Some("domain".to_string()),
                state: Some("open".to_string()),
                scripts: Some(vec![ScriptInfo {
                    id: "dns-zone-transfer".to_string(),
                    output,
                }]),
            };
            
            results.push(DnsHostResult {
                addr: addr.clone(),
                hostnames: vec![Hostname {
                    name: srvname.to_string(),
                    hostname_type: "user".to_string(),
                    domains: get_domains(&srvname),
                }],
                schema_version: "1.0".to_string(),
                starttime: chrono::Utc::now().to_rfc3339(),
                endtime: chrono::Utc::now().to_rfc3339(),
                ports: Some(vec![port_info]),
            });
            
            // Extract hosts from records
            let mut hosts: HashMap<String, Vec<(String, String)>> = HashMap::new();
            for r in res {
                if r.rclass != "IN" {
                    continue;
                }
                if r.rtype == "A" || r.rtype == "AAAA" {
                    let name = r.name.trim_end_matches('.').to_lowercase();
                    hosts
                        .entry(r.data.clone())
                        .or_insert_with(Vec::new)
                        .push((r.rtype.clone(), name));
                }
            }
            
            for (host, records) in hosts {
                results.push(DnsHostResult {
                    addr: host.clone(),
                    hostnames: records
                        .iter()
                        .map(|rec| Hostname {
                            name: rec.1.clone(),
                            hostname_type: rec.0.clone(),
                            domains: get_domains(&rec.1),
                        })
                        .collect(),
                    schema_version: "1.0".to_string(),
                    starttime: chrono::Utc::now().to_rfc3339(),
                    endtime: chrono::Utc::now().to_rfc3339(),
                    ports: None,
                });
            }
        }
        
        results
    }
}

/// Checker for DNS consistency across nameservers
pub struct SameValueChecker {
    base: Checker,
    pub name: Option<String>,
    pub rtype: Option<String>,
}

impl SameValueChecker {
    pub fn new(domain: String) -> Self {
        SameValueChecker {
            base: Checker::new(domain),
            name: None,
            rtype: None,
        }
    }

    fn _sv_test(&self, addr: &str) -> HashSet<String> {
        if let Some(ref name) = self.name {
            dns_query_data(name, self.rtype.as_deref(), Some(addr))
                .into_iter()
                .collect()
        } else {
            HashSet::new()
        }
    }

    pub fn do_sv_test(&mut self, v4: bool, v6: bool) -> Vec<(String, String, HashSet<String>)> {
        let mut results = Vec::new();
        
        if v4 {
            for (srv, addr) in self.base.get_ns4_servers() {
                results.push((srv.clone(), addr.clone(), self._sv_test(addr)));
            }
        }
        
        if v6 {
            for (srv, addr) in self.base.get_ns6_servers() {
                results.push((srv.clone(), addr.clone(), self._sv_test(addr)));
            }
        }
        
        results
    }

    pub fn test(&mut self, v4: bool, v6: bool) -> Vec<DnsHostResult> {
        let results = self.do_sv_test(v4, v6);
        
        let mut value_map: HashMap<HashSet<String>, HashMap<String, Vec<String>>> = HashMap::new();
        
        for (srvname, addr, res) in &results {
            let srvname = srvname.trim_end_matches('.');
            value_map
                .entry(res.clone())
                .or_insert_with(HashMap::new)
                .entry(addr.clone())
                .or_insert_with(Vec::new)
                .push(srvname.to_string());
        }
        
        if value_map.is_empty() {
            return Vec::new();
        }
        
        let good_value = value_map
            .keys()
            .max_by_key(|v| value_map.get(v).map_or(0, |m| m.len()))
            .cloned()
            .unwrap_or_default();
        
        let good_value_repr = good_value
            .iter()
            .map(|r| format!("  {:?}", r))
            .collect::<Vec<_>>()
            .join("\n");
        
        let good_value_sorted: Vec<String> = good_value.iter().cloned().collect();
        let mut good_value_sorted.sort();
        
        let mut host_results = Vec::new();
        
        for (val, servers) in &value_map {
            if val == &good_value {
                continue;
            }
            
            for (addr, names) in servers {
                let val_repr = val.iter().map(|r| format!("  {:?}", r)).collect::<Vec<_>>().join("\n");
                
                let output = format!(
                    "DNS inconsistency\n\n{} ({})\nThis server:\n{}\nMost common answer:\n{}",
                    self.name.as_ref().unwrap_or(&String::new()),
                    self.rtype.as_ref().unwrap_or(&String::new()),
                    val_repr,
                    good_value_repr
                );
                
                let port_info = PortInfo {
                    port: 53,
                    protocol: "udp".to_string(),
                    service_name: Some("domain".to_string()),
                    state: Some("open".to_string()),
                    scripts: Some(vec![ScriptInfo {
                        id: "dns-check-consistency".to_string(),
                        output,
                    }]),
                };
                
                host_results.push(DnsHostResult {
                    addr: addr.clone(),
                    hostnames: names
                        .iter()
                        .map(|name| Hostname {
                            name: name.clone(),
                            hostname_type: "user".to_string(),
                            domains: get_domains(name),
                        })
                        .collect(),
                    schema_version: "1.0".to_string(),
                    starttime: chrono::Utc::now().to_rfc3339(),
                    endtime: chrono::Utc::now().to_rfc3339(),
                    ports: Some(vec![port_info]),
                });
            }
        }
        
        host_results
    }
}

/// Checker for DNS NS records
pub struct DnsSrvChecker {
    base: SameValueChecker,
}

impl DnsSrvChecker {
    pub fn new(domain: String) -> Self {
        let mut checker = SameValueChecker::new(domain.clone());
        checker.name = Some(domain.clone());
        checker.rtype = Some("NS".to_string());
        
        DnsSrvChecker { base: checker }
    }

    pub fn test(&mut self, v4: bool, v6: bool) -> Vec<DnsHostResult> {
        let mut results = self.base.test(v4, v6);
        
        for (srvname, addr, _) in self.base.do_sv_test(v4, v6) {
            let srvname = srvname.trim_end_matches('.');
            
            let port_info = PortInfo {
                port: 53,
                protocol: "udp".to_string(),
                service_name: Some("domain".to_string()),
                state: Some("open".to_string()),
                scripts: Some(vec![ScriptInfo {
                    id: "dns-domains".to_string(),
                    output: format!("Server is authoritative for {}", self.base.base.domain),
                }]),
            };
            
            results.push(DnsHostResult {
                addr: addr.clone(),
                hostnames: vec![Hostname {
                    name: srvname.to_string(),
                    hostname_type: "user".to_string(),
                    domains: get_domains(srvname),
                }],
                schema_version: "1.0".to_string(),
                starttime: chrono::Utc::now().to_rfc3339(),
                endtime: chrono::Utc::now().to_rfc3339(),
                ports: Some(vec![port_info]),
            });
        }
        
        results
    }
}

/// Checker for DNS MX records
pub struct DnsMxChecker {
    base: SameValueChecker,
    name2addr: HashMap<String, Vec<String>>,
}

impl DnsMxChecker {
    pub fn new(domain: String) -> Self {
        let mut checker = SameValueChecker::new(domain.clone());
        checker.name = Some(domain.clone());
        checker.rtype = Some("MX".to_string());
        
        DnsMxChecker {
            base: checker,
            name2addr: HashMap::new(),
        }
    }

    pub fn name2addr(&mut self, name: &str, v4: bool, v6: bool) -> &[String] {
        if !self.name2addr.contains_key(name) {
            let mut addrs = Vec::new();
            
            if v4 {
                addrs.extend(dns_query_data(name, Some("A"), None));
            }
            
            if v6 {
                addrs.extend(dns_query_data(name, Some("AAAA"), None));
            }
            
            addrs.sort();
            self.name2addr.insert(name.to_string(), addrs);
        }
        
        self.name2addr.get(name).unwrap()
    }

    pub fn test(&mut self, v4: bool, v6: bool) -> Vec<DnsHostResult> {
        let mut results = self.base.test(v4, v6);
        
        let all_results: HashSet<String> = self
            .base
            .do_sv_test(v4, v6)
            .into_iter()
            .flat_map(|(_, _, subresults)| subresults)
            .collect();
        
        for result in all_results {
            let parts: Vec<&str> = result.splitn(2, ' ').collect();
            if parts.len() < 2 {
                continue;
            }
            
            let priority = parts[0];
            let srvname = parts[1].trim_end_matches('.');
            
            for addr in self.name2addr(srvname, v4, v6) {
                let port_info = PortInfo {
                    port: 25,
                    protocol: "tcp".to_string(),
                    service_name: None,
                    state: None,
                    scripts: Some(vec![ScriptInfo {
                        id: "dns-domains-mx".to_string(),
                        output: format!(
                            "Server is Mail eXchanger for {} (priority {})",
                            self.base.base.domain, priority
                        ),
                    }]),
                };
                
                results.push(DnsHostResult {
                    addr: addr.clone(),
                    hostnames: vec![Hostname {
                        name: srvname.to_string(),
                        hostname_type: "user".to_string(),
                        domains: get_domains(srvname),
                    }],
                    schema_version: "1.0".to_string(),
                    starttime: chrono::Utc::now().to_rfc3339(),
                    endtime: chrono::Utc::now().to_rfc3339(),
                    ports: Some(vec![port_info]),
                });
            }
        }
        
        results
    }
}

/// Checker for TLS-RPT records
pub struct TlsRptChecker {
    base: SameValueChecker,
}

impl TlsRptChecker {
    pub fn new(domain: String) -> Self {
        let mut checker = SameValueChecker::new(domain.clone());
        checker.name = Some(format!("_smtp._tls.{}", domain));
        checker.rtype = Some("TXT".to_string());
        
        TlsRptChecker { base: checker }
    }

    pub fn test(&mut self, v4: bool, v6: bool) -> Vec<DnsHostResult> {
        let mut results = self.base.test(v4, v6);
        
        for (srvname, addr, raw_res) in self.base.do_sv_test(v4, v6) {
            let srvname = srvname.trim_end_matches('.');
            
            let res: Vec<String> = raw_res.into_iter().collect();
            let res_sorted: Vec<&String> = res.iter().collect();
            let mut res_sorted: Vec<&String> = res_sorted.iter().cloned().collect();
            res_sorted.sort();
            
            let (output, structured) = if res.is_empty() {
                (
                    format!("Domain {} has no TLS-RPT configuration", self.base.base.domain),
                    serde_json::json!({
                        "domain": self.base.base.domain,
                        "warnings": ["Domain has no TLS-RPT configuration"]
                    }),
                )
            } else if res.len() > 1 {
                (
                    format!("Domain {} has more than one TLS-RPT configuration", self.base.base.domain),
                    serde_json::json!({
                        "domain": self.base.base.domain,
                        "value": res.join(" / "),
                        "warnings": ["Domain has more than one TLS-RPT configuration"]
                    }),
                )
            } else {
                let value = &res[0];
                let mut warnings = Vec::new();
                
                if value.starts_with("v=TLSRPTv1;") {
                    if !value[11..].starts_with("rua=") {
                        warnings.push("TLS-RPT configuration should contain 'rua=' after 'v=TLSRPTv1;'".to_string());
                    }
                } else {
                    warnings.push("TLS-RPT configuration should start with 'v=TLSRPTv1;'".to_string());
                    if !value.starts_with("rua=") && !value.contains(";rua=") {
                        warnings.push("TLS-RPT configuration should contain 'rua=' after 'v=TLSRPTv1;'".to_string());
                    }
                }
                
                if value.contains("rua=") {
                    let ruas = value.split("rua=").nth(1).unwrap_or("");
                    for rua_val in ruas.split(',') {
                        if rua_val.starts_with("https://") {
                            if HTTPS_REGEXP.is_match(&rua_val[8..]) {
                                warnings.push(format!("TLS-RPT contains an invalid HTTPS URL: {:?}", rua_val));
                            }
                        } else if rua_val.starts_with("mailto:") {
                            if MAIL_REGEXP.is_match(&rua_val[7..]) {
                                warnings.push(format!("TLS-RPT contains an invalid e-mail URL: {:?}", rua_val));
                            }
                        } else {
                            warnings.push(format!("TLS-RPT contains an invalid URL: {:?}", rua_val));
                        }
                    }
                } else {
                    warnings.push(format!("TLS-RPT does not contain an rua entry: {:?}", value));
                }
                
                let output = if warnings.is_empty() {
                    format!("Domain {} has a valid TLS-RPT configuration", self.base.base.domain)
                } else {
                    format!(
                        "Domain {} has a TLS-RPT configuration with warnings:\n{}",
                        self.base.base.domain,
                        warnings.join("\n")
                    )
                };
                
                let mut structured = serde_json::json!({
                    "domain": self.base.base.domain,
                    "value": value
                });
                
                if !warnings.is_empty() {
                    structured["warnings"] = serde_json::to_value(&warnings).unwrap();
                }
                
                (output, structured)
            }
            
            let port_info = PortInfo {
                port: 53,
                protocol: "udp".to_string(),
                service_name: Some("domain".to_string()),
                state: Some("open".to_string()),
                scripts: Some(vec![ScriptInfo {
                    id: "dns-tls-rpt".to_string(),
                    output,
                }]),
            };
            
            results.push(DnsHostResult {
                addr: addr.clone(),
                hostnames: vec![Hostname {
                    name: srvname.to_string(),
                    hostname_type: "user".to_string(),
                    domains: get_domains(srvname),
                }],
                schema_version: "1.0".to_string(),
                starttime: chrono::Utc::now().to_rfc3339(),
                endtime: chrono::Utc::now().to_rfc3339(),
                ports: Some(vec![port_info]),
            });
        }
        
        results
    }
}

/// Extract domain parts from a hostname
fn get_domains(hostname: &str) -> Vec<String> {
    let parts: Vec<&str> = hostname.split('.').collect();
    let mut domains = Vec::new();
    
    for i in 1..parts.len() {
        let domain = parts[i..].join(".");
        if !domain.is_empty() {
            domains.push(domain);
        }
    }
    
    domains
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_domains() {
        let domains = get_domains("www.example.com");
        assert_eq!(domains, vec!["example.com", "com"]);
    }

    #[test]
    fn test_checker_new() {
        let checker = Checker::new("example.com".to_string());
        assert_eq!(checker.domain, "example.com");
    }

    #[test]
    fn test_axfr_checker_new() {
        let checker = AxfrChecker::new("example.com".to_string());
        assert_eq!(checker.base.domain, "example.com");
    }

    #[test]
    fn test_same_value_checker_new() {
        let checker = SameValueChecker::new("example.com".to_string());
        assert_eq!(checker.base.domain, "example.com");
    }
}
