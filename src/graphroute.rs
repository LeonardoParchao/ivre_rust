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

//! This sub-module builds graphs of traceroute results.

use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::Write;

pub type Graph = HashMap<String, HashSet<String>>;

/// Build a graph from traceroute results
pub fn build_graph(
    cursor: &[HashMap<String, serde_json::Value>],
    include_last_hop: bool,
    include_target: bool,
    only_connected: bool,
) -> (Graph, HashSet<String>) {
    let mut graph: Graph = HashMap::new();
    let mut entry_nodes: HashSet<String> = HashSet::new();
    
    for host in cursor {
        if !host.contains_key("traces") {
            continue;
        }
        
        if let Some(traces) = host.get("traces").and_then(|v| v.as_array()) {
            for trace in traces {
                if let Some(hops) = trace.get("hops").and_then(|v| v.as_array()) {
                    let mut sorted_hops: Vec<&serde_json::Value> = hops
                        .iter()
                        .filter(|h| h.get("ttl").is_some())
                        .collect();
                    
                    sorted_hops.sort_by_key(|h| {
                        h.get("ttl")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0)
                    });
                    
                    if sorted_hops.is_empty() {
                        continue;
                    }
                    
                    if let Some(first_hop) = sorted_hops.first() {
                        if let Some(ipaddr) = first_hop.get("ipaddr").and_then(|v| v.as_str()) {
                            entry_nodes.insert(ipaddr.to_string());
                        }
                    }
                    
                    let mut hops_to_process = sorted_hops.clone();
                    
                    if !include_last_hop && !include_target {
                        if let Some(host_addr) = host.get("addr").and_then(|v| v.as_str()) {
                            if let Some(last_hop) = hops_to_process.last() {
                                if last_hop.get("ipaddr").and_then(|v| v.as_str()) == Some(host_addr) {
                                    hops_to_process.pop();
                                }
                            }
                        }
                        if !include_last_hop && !hops_to_process.is_empty() {
                            hops_to_process.pop();
                        }
                    }
                    
                    for (i, hop) in hops_to_process.iter().skip(1).enumerate() {
                        let prev_hop = &hops_to_process[i];
                        
                        let prev_ttl = prev_hop.get("ttl")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let curr_ttl = hop.get("ttl")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        
                        let prev_ip = prev_hop.get("ipaddr").and_then(|v| v.as_str());
                        let curr_ip = hop.get("ipaddr").and_then(|v| v.as_str());
                        
                        if let (Some(prev_ip), Some(curr_ip)) = (prev_ip, curr_ip) {
                            if !only_connected || curr_ttl - prev_ttl == 1 {
                                graph
                                    .entry(prev_ip.to_string())
                                    .or_insert_with(HashSet::new)
                                    .insert(curr_ip.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    
    (graph, entry_nodes)
}

/// Generate a label for a node using SHA256 hash
pub fn label(node: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(node.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Write a graph in Graphviz DOT format
pub fn write_dot_graph<W: Write>(
    graph: &Graph,
    out: &mut W,
    cluster: Option<&dyn Fn(&str) -> Option<String>>,
) -> std::io::Result<()> {
    writeln!(out, "digraph traceroute {{")?;
    
    let mut nodes: HashSet<String> = HashSet::new();
    let mut edges: HashSet<(String, String)> = HashSet::new();
    
    if cluster.is_none() {
        // Add nodes without clustering
        for (node, node_edges) in graph {
            if !nodes.contains(node) {
                nodes.insert(node.clone());
                writeln!(out, "\t\"{}\" [label=\"{}\"];", label(node), node)?;
            }
            
            for destnode in node_edges {
                if !nodes.contains(destnode) {
                    nodes.insert(destnode.clone());
                    writeln!(out, "\t\"{}\" [label=\"{}\"];", label(destnode), destnode)?;
                }
                
                if !edges.contains(&(node.clone(), destnode.clone())) {
                    writeln!(out, "\t\"{}\" -> \"{}\";", label(node), label(destnode))?;
                    edges.insert((node.clone(), destnode.clone()));
                }
            }
        }
    } else {
        // Add nodes with clustering
        let mut clusters: HashMap<Option<String>, HashSet<String>> = HashMap::new();
        let cluster_fn = cluster.unwrap();
        
        for (node, node_edges) in graph {
            if !nodes.contains(node) {
                nodes.insert(node.clone());
                let cluster_id = cluster_fn(node);
                clusters
                    .entry(cluster_id)
                    .or_insert_with(HashSet::new)
                    .insert(node.clone());
            }
            
            for destnode in node_edges {
                if !nodes.contains(destnode) {
                    nodes.insert(destnode.clone());
                    let cluster_id = cluster_fn(destnode);
                    clusters
                        .entry(cluster_id)
                        .or_insert_with(HashSet::new)
                        .insert(destnode.clone());
                }
                
                if !edges.contains(&(node.clone(), destnode.clone())) {
                    writeln!(out, "\t\"{}\" -> \"{}\";", label(node), label(destnode))?;
                    edges.insert((node.clone(), destnode.clone()));
                }
            }
        }
        
        // Write clusters
        if let Some(None) = clusters.keys().find(|k| k.is_none()) {
            if let Some(nodes) = clusters.remove(&None) {
                for node in nodes {
                    writeln!(out, "\t\"{}\" [label=\"{}\"];", label(&node), node)?;
                }
            }
        }
        
        for (cluster_id, cluster_nodes) in clusters {
            if let Some(cluster_name) = cluster_id {
                writeln!(out, "\tsubgraph cluster_{} {{", cluster_name)?;
                writeln!(out, "\t\tlabel = \"{}\";", cluster_name)?;
                for node in cluster_nodes {
                    writeln!(out, "\t\t\"{}\" [label=\"{}\"];", label(&node), node)?;
                }
                writeln!(out, "\t}}")?;
            }
        }
    }
    
    writeln!(out, "}}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label() {
        let label1 = label("192.168.1.1");
        let label2 = label("192.168.1.1");
        assert_eq!(label1, label2);
        
        let label3 = label("192.168.1.2");
        assert_ne!(label1, label3);
    }

    #[test]
    fn test_build_graph_empty() {
        let cursor: Vec<HashMap<String, serde_json::Value>> = Vec::new();
        let (graph, entry_nodes) = build_graph(&cursor, false, false, true);
        assert!(graph.is_empty());
        assert!(entry_nodes.is_empty());
    }
}
