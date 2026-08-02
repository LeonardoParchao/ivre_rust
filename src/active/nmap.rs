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

//! This submodule contains data needed for Nmap results manipulation.

use std::collections::HashMap;

/// Aliases for Nmap script table elements to unify structured output
pub fn get_aliases_table_elems() -> HashMap<&'static str, &'static str> {
    let mut aliases = HashMap::new();
    
    // Use the same structured output for both ssl-cert and ssl-cacert
    aliases.insert("ssl-cacert", "ssl-cert");
    
    // Use the same structured output for all the Nuclei scripts
    aliases.insert("dns-nuclei", "nuclei");
    aliases.insert("http-nuclei", "nuclei");
    aliases.insert("network-nuclei", "nuclei");
    aliases.insert("ssl-nuclei", "nuclei");
    aliases.insert("tcp-nuclei", "nuclei");
    
    // ls unified output (ls NSE module + ftp-anon)
    aliases.insert("afp-ls", "ls");
    aliases.insert("http-ls", "ls");
    aliases.insert("nfs-ls", "ls");
    aliases.insert("smb-ls", "ls");
    aliases.insert("ftp-anon", "ls");
    
    // vulns unified output (vulns NSE module)
    let vulns_scripts = [
        "afp-path-vuln", "clamav-exec", "distcc-cve2004-2687", "ftp-libopie",
        "ftp-vsftpd-backdoor", "ftp-vuln-cve2010-4221", "http-avaya-ipoffice-users",
        "http-cross-domain-policy", "http-dlink-backdoor", "http-frontpage-login",
        "http-huawei-hg5xx-vuln", "http-iis-short-name-brute", "http-method-tamper",
        "http-phpmyadmin-dir-traversal", "http-phpself-xss", "http-sap-netweaver-leak",
        "http-shellshock", "http-slowloris-check", "http-tplink-dir-traversal",
        "http-vuln-cve2006-3392", "http-vuln-cve2009-3960", "http-vuln-cve2010-2861",
        "http-vuln-cve2011-3192", "http-vuln-cve2011-3368", "http-vuln-cve2012-1823",
        "http-vuln-cve2013-0156", "http-vuln-cve2013-6786", "http-vuln-cve2013-7091",
        "http-vuln-cve2014-2126", "http-vuln-cve2014-2127", "http-vuln-cve2014-2128",
        "http-vuln-cve2014-2129", "http-vuln-cve2014-3704", "http-vuln-cve2014-8877",
        "http-vuln-cve2015-1427", "http-vuln-cve2015-1635", "http-vuln-cve2017-1001000",
        "http-vuln-cve2017-5638", "http-vuln-cve2017-5689", "http-vuln-cve2017-8917",
        "http-vuln-misfortune-cookie", "http-vuln-wnr1000-creds", "ipmi-cipher-zero",
        "mysql-vuln-cve2012-2122", "qconn-exec", "rdp-vuln-ms12-020", "realvnc-auth-bypass",
        "rmi-vuln-classloader", "rsa-vuln-roca", "samba-vuln-cve-2012-1182",
        "smb-double-pulsar-backdoor", "smb-vuln-conficker", "smb-vuln-cve-2017-7494",
        "smb-vuln-cve2009-3103", "smb-vuln-ms06-025", "smb-vuln-ms07-029",
        "smb-vuln-ms08-067", "smb-vuln-ms10-054", "smb-vuln-ms10-061", "smb-vuln-ms17-010",
        "smb-vuln-regsvc-dos", "smb-vuln-webexec", "smb2-vuln-uptime",
        "smtp-vuln-cve2011-1720", "smtp-vuln-cve2011-1764", "ssl-ccs-injection",
        "ssl-dh-params", "ssl-heartbleed", "ssl-poodle", "sslv2-drown",
        "supermicro-ipmi-conf", "tls-ticketbleed",
    ];
    for script in vulns_scripts {
        aliases.insert(script, "vulns");
    }
    
    // ntlm unified output (*-ntlm-info modules)
    let ntlm_scripts = [
        "http-ntlm-info", "imap-ntlm-info", "ms-sql-ntlm-info", "nntp-ntlm-info",
        "pop3-ntlm-info", "rdp-ntlm-info", "smtp-ntlm-info", "telnet-ntlm-info",
    ];
    for script in ntlm_scripts {
        aliases.insert(script, "ntlm-info");
    }
    
    aliases
}

/// Get the alias for a script ID, or return the original ID if no alias exists
pub fn get_script_alias(script_id: &str) -> &str {
    let aliases = get_aliases_table_elems();
    aliases.get(script_id).copied().unwrap_or(script_id)
}
