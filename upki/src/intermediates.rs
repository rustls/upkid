use core::ops::Deref;

use serde::{Deserialize, Serialize};
#[cfg(feature = "__fetch")]
use tracing::info;

#[cfg(feature = "__fetch")]
use crate::Config;
use crate::data;
#[cfg(feature = "__fetch")]
use crate::revocation::{Error, FetchContext, FetchType, Plan};

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

/// Update the local intermediates cache by fetching updates over the network.
///
/// `dry_run` means this call fetches the new manifest, but does not fetch any
/// required files; but the necessary files are printed to stdout.
#[cfg(feature = "__fetch")]
pub async fn fetch(dry_run: bool, config: &Config) -> Result<(), Error> {
    let IntermediatesConfig {
        enabled: true,
        fetch_url,
    } = &config.intermediates
    else {
        return Ok(());
    };

    let cache_dir = config.intermediates_cache_dir();
    info!("fetching intermediates from {fetch_url} into {cache_dir:?}...",);

    FetchContext {
        cache_dir,
        fetch_url,
        old_manifest: Manifest::from_config(config)
            .ok()
            .as_deref(),
        typ: FetchType::Intermediates,
    }
    .fetch(dry_run)
    .await
}

/// The structure contained in a manifest.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest(data::Manifest);

impl Manifest {
    /// Load the intermediates manifest from the cache directory specified in the configuration.
    #[cfg(feature = "__fetch")]
    pub fn from_config(config: &Config) -> Result<Self, Error> {
        let mut file_name = config.intermediates_cache_dir();
        file_name.push("manifest.json");
        data::Manifest::from_file(file_name).map(Self)
    }

    /// Verify the current contents of the cache against this manifest.
    ///
    /// This performs disk IO but does not perform network IO.
    #[cfg(feature = "__fetch")]
    pub fn verify(&self, config: &Config) -> Result<(), Error> {
        self.introduce()?;
        let plan = Plan::construct(
            self,
            &FetchContext {
                cache_dir: config.intermediates_cache_dir(),
                fetch_url: "https://.../",
                old_manifest: None,
                typ: FetchType::Intermediates,
            },
        )?;
        match plan.download_bytes() {
            0 => Ok(()),
            bytes => Err(Error::Outdated(bytes)),
        }
    }
}

impl Deref for Manifest {
    type Target = data::Manifest;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
