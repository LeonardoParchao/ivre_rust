// Configuration file for the Sphinx documentation builder.
//
// This file only contains a selection of the most common options. For a full
// list see the documentation:
// http://www.sphinx-doc.org/en/master/config

use std::path::Path;

// -- Path setup --------------------------------------------------------------

// If extensions (or modules to document with autodoc) are in another directory,
// add these directories to sys.path here. If the directory is relative to the
// documentation root, use os.path.abspath to make it absolute, like shown here.
//
// In Rust, this would typically be handled via module paths in Cargo.toml

// -- Project information -----------------------------------------------------

#[derive(Debug, Clone)]
pub struct ProjectInfo {
    pub project: String,
    pub copyright: String,
    pub author: String,
    pub html_logo: String,
    pub master_doc: String,
    pub version: String,
}

impl ProjectInfo {
    pub fn new(version: &str) -> Self {
        // Parse version: split on "dev" and handle trailing "."
        let version = version.split("dev").next().unwrap_or(version).to_string();
        let version = if version.ends_with('.') {
            format!("{}dev", version)
        } else {
            version
        };

        Self {
            project: "IVRE".to_string(),
            copyright: "2011 - 2026, Pierre LALET".to_string(),
            author: "Pierre LALET".to_string(),
            html_logo: "../web/static/logo.png".to_string(),
            master_doc: "index".to_string(),
            version,
        }
    }
}

// -- General configuration ---------------------------------------------------

#[derive(Debug, Clone)]
pub struct SphinxConfig {
    pub extensions: Vec<String>,
    pub autosectionlabel_prefix_document: bool,
    pub templates_path: Vec<String>,
    pub exclude_patterns: Vec<String>,
    pub html_theme: String,
    pub html_static_path: Option<Vec<String>>,
}

impl SphinxConfig {
    pub fn default() -> Self {
        Self {
            extensions: vec![
                // "sphinx.ext.autodoc".to_string(), // TODO
                "sphinx.ext.autosectionlabel".to_string(),
                "sphinx.ext.graphviz".to_string(),
                // "sphinx.ext.napoleon".to_string(), // TODO
                "sphinxcontrib.autohttp.bottle".to_string(),
            ],
            autosectionlabel_prefix_document: true,
            templates_path: vec!["_templates".to_string()],
            exclude_patterns: vec!["_build".to_string(), "Thumbs.db".to_string(), ".DS_Store".to_string()],
            html_theme: "sphinx_rtd_theme".to_string(),
            html_static_path: None, // ['_static']
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub project: ProjectInfo,
    pub sphinx: SphinxConfig,
}

impl Config {
    pub fn new(version: &str) -> Self {
        Self {
            project: ProjectInfo::new(version),
            sphinx: SphinxConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parsing() {
        let info = ProjectInfo::new("1.0.0dev");
        assert_eq!(info.version, "1.0.0");

        let info = ProjectInfo::new("1.0.0");
        assert_eq!(info.version, "1.0.0");

        let info = ProjectInfo::new("1.0.0.");
        assert_eq!(info.version, "1.0.0.dev");
    }

    #[test]
    fn test_default_config() {
        let config = Config::new("1.0.0");
        assert_eq!(config.project.project, "IVRE");
        assert_eq!(config.sphinx.html_theme, "sphinx_rtd_theme");
        assert!(config.sphinx.autosectionlabel_prefix_document);
    }
}
