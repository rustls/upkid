use serde::{Deserialize, Serialize};

/// Details about intermediate preloading.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct IntermediatesConfig {
    /// Whether to fetch things at all.
    pub enabled: bool,
    /// Where to fetch intermediate certificates.
    pub fetch_url: String,
}

impl Default for IntermediatesConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            fetch_url: "https://upki.rustls.dev/intermediates/".into(),
        }
    }
}
