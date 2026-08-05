//! upki fetcher.
//!
//! This program synchronises a local directory with the crlite files contained on a
//! remote server.  There is a manifest file that gives the names, sizes and hashes of
//! all valid files; this is fetched first. Then a plan is formed by comparing this against
//! the local filesystem contents. Finally, the plan is executed. If that succeeds
//! the remote server contents matches the local filesystem.

use core::fmt;
use core::time::Duration;
use std::collections::HashSet;
use std::env;
#[cfg(target_family = "unix")]
use std::fs::Permissions;
use std::fs::{self, File};
use std::io::{self, Read, Write};
#[cfg(target_family = "unix")]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use tracing::{debug, info};

use super::index::INDEX_BIN;
use super::{Error, Index, Manifest, ManifestFile};
use crate::{Config, sha256};

/// Update the local revocation cache by fetching updates over the network.
///
/// `dry_run` means this call fetches the new manifest, but does not fetch any
/// required files; but the necessary files are printed to stdout.  Therefore
/// such a call is not completely "dry" -- perhaps "moist".
pub async fn fetch(dry_run: bool, config: &Config) -> Result<ExitCode, Error> {
    let cache_dir = config.revocation_cache_dir();
    info!(
        "fetching {} into {:?}...",
        &config.revocation.fetch_url, &cache_dir,
    );
    let old_manifest = Manifest::from_config(config).ok();

    FetchContext {
        cache_dir,
        fetch_url: &config.revocation.fetch_url,
        old_manifest,
    }
    .fetch(dry_run)
    .await
}

pub(crate) struct FetchContext<'a> {
    pub(crate) cache_dir: PathBuf,
    pub(crate) fetch_url: &'a str,
    pub(crate) old_manifest: Option<Manifest>,
}

impl FetchContext<'_> {
    pub(crate) async fn fetch(&self, dry_run: bool) -> Result<ExitCode, Error> {
        let manifest_url = format!("{}{MANIFEST_JSON}", self.fetch_url);
        #[cfg(feature = "fetch")]
        let builder = reqwest::Client::builder().use_rustls_tls();
        #[cfg(all(feature = "fetch-native-tls", not(feature = "fetch")))]
        let builder = reqwest::Client::builder().use_native_tls();

        let client = builder
            .timeout(Duration::from_secs(REQUEST_TIMEOUT))
            .user_agent(format!(
                "{}/{} ({})",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION"),
                env!("CARGO_PKG_REPOSITORY")
            ))
            .build()
            .map_err(|error| Error::HttpFetch {
                error: Box::new(error),
                url: manifest_url.clone(),
            })?;

        let response = client
            .get(&manifest_url)
            .send()
            .await
            .map_err(|error| Error::HttpFetch {
                error: Box::new(error),
                url: manifest_url.clone(),
            })?
            .error_for_status()
            .map_err(|error| Error::HttpFetch {
                error: Box::new(error),
                url: manifest_url.clone(),
            })?;

        let manifest = response
            .json::<Manifest>()
            .await
            .map_err(|error| Error::FileDecode {
                error: Box::new(error),
                path: None,
            })?;

        manifest.introduce()?;

        let plan = Plan::construct(&manifest, self)?;

        if dry_run {
            println!(
                "{} steps required ({} bytes to download)",
                plan.steps.len(),
                plan.download_bytes()
            );
            for step in plan.steps {
                println!("- {step}");
            }
            return Ok(ExitCode::SUCCESS);
        }

        info!(
            "{} steps required ({} bytes to download).",
            plan.steps.len(),
            plan.download_bytes()
        );

        for step in plan.steps {
            step.execute(&client).await?;
        }

        info!("success");
        Ok(ExitCode::SUCCESS)
    }
}

pub(crate) struct Plan {
    steps: Vec<PlanStep>,
}

impl Plan {
    /// Form a plan of how to synchronize with the remote server.
    ///
    /// - `manifest` describes the contents of the remote server.
    pub(crate) fn construct(manifest: &Manifest, ctx: &FetchContext<'_>) -> Result<Self, Error> {
        let mut steps = Vec::new();

        // Collect unwanted files for deletion
        let mut unwanted_files = HashSet::new();

        if ctx.cache_dir.exists() {
            let iter = fs::read_dir(&ctx.cache_dir).map_err(|error| Error::CreateDirectory {
                error,
                path: ctx.cache_dir.to_owned(),
            })?;

            for entry in iter {
                let entry = match entry {
                    Ok(e) => e,
                    Err(error) => return Err(Error::FileRead { error, path: None }),
                };

                let path = Path::new(&entry.file_name()).to_owned();
                let name = path.to_string_lossy();
                if name.ends_with(".filter") || name.ends_with(".delta") {
                    unwanted_files.insert(path);
                }
            }
        } else {
            steps.push(PlanStep::CreateDir(ctx.cache_dir.to_owned()));
        }

        for file in &manifest.files {
            unwanted_files.remove(Path::new(&file.filename));

            let path = ctx.cache_dir.join(&file.filename);
            match hash_file(&path) {
                Ok(digest) if digest.as_ref() == file.hash => continue,
                _ => {}
            }

            steps.push(PlanStep::download(file, ctx.fetch_url, &ctx.cache_dir));
        }

        if let Some(old_manifest) = &ctx.old_manifest {
            for file in &old_manifest.files {
                unwanted_files.remove(Path::new(&file.filename));
            }
        }

        steps.push(PlanStep::SaveIndex {
            manifest: manifest.clone(),
            local_dir: ctx.cache_dir.to_owned(),
        });

        steps.push(PlanStep::SaveManifest {
            manifest: manifest.clone(),
            local_dir: ctx.cache_dir.to_owned(),
        });

        for filename in unwanted_files {
            steps.push(PlanStep::Delete(ctx.cache_dir.join(filename)));
        }

        Ok(Self { steps })
    }

    /// How many bytes will we download?
    pub(crate) fn download_bytes(&self) -> usize {
        self.steps
            .iter()
            .filter_map(|s| match s {
                PlanStep::Download { file, .. } => Some(file.size),
                _ => None,
            })
            .sum()
    }
}

/// One step moving closer to local sync with the remote contents.
enum PlanStep {
    CreateDir(PathBuf),

    /// Download `file` from `remote` to `local`
    Download {
        file: ManifestFile,
        /// URL.
        remote_url: String,
        /// Full path to output file.
        local: PathBuf,
    },

    /// Delete the given single local file.
    Delete(PathBuf),

    /// Build and save the index from filter universe metadata.
    SaveIndex {
        manifest: Manifest,
        local_dir: PathBuf,
    },

    /// Save the manifest structure
    SaveManifest {
        manifest: Manifest,
        local_dir: PathBuf,
    },
}

impl PlanStep {
    async fn execute(self, client: &reqwest::Client) -> Result<(), Error> {
        match self {
            Self::CreateDir(path) => {
                fs::create_dir_all(&path).map_err(|error| Error::CreateDirectory { error, path })?
            }
            Self::Download {
                file,
                remote_url,
                local,
            } => {
                debug!("downloading {:?}", file);

                let response = client
                    .get(&remote_url)
                    .send()
                    .await
                    .map_err(|error| Error::HttpFetch {
                        error: Box::new(error),
                        url: remote_url.clone(),
                    })?
                    .error_for_status()
                    .map_err(|error| Error::HttpFetch {
                        error: Box::new(error),
                        url: remote_url.clone(),
                    })?;

                let bytes = response
                    .bytes()
                    .await
                    .map_err(|error| Error::HttpFetch {
                        error: Box::new(error),
                        url: remote_url.clone(),
                    })?;

                atomic_write(&local, &bytes).map_err(|error| Error::FileWrite {
                    error,
                    path: local.clone(),
                })?;

                match hash_file(&local) {
                    Ok(digest) if digest.as_ref() == file.hash => {}
                    Ok(_) => return Err(Error::HashMismatch(local)),
                    Err(error) => {
                        return Err(Error::FileRead {
                            error,
                            path: Some(local),
                        });
                    }
                }

                debug!("download successful");
            }
            Self::Delete(target) => {
                debug!("deleting unreferenced file {target:?}");
                fs::remove_file(&target).map_err(|error| Error::RemoveFile {
                    error,
                    path: target,
                })?;
            }
            Self::SaveIndex {
                manifest,
                local_dir,
            } => {
                debug!("building index");
                let Some(buf) = Index::write(&manifest, &local_dir) else {
                    return Ok(());
                };

                #[cfg(target_family = "unix")]
                let temp = tempfile::Builder::new()
                    .permissions(Permissions::from_mode(0o644))
                    .suffix(".new")
                    .tempfile_in(&local_dir);
                #[cfg(not(target_family = "unix"))]
                let temp = tempfile::Builder::new()
                    .suffix(".new")
                    .tempfile_in(&local_dir);

                let mut local_temp = temp.map_err(|error| Error::FileWrite {
                    error,
                    path: local_dir.clone(),
                })?;

                local_temp
                    .as_file_mut()
                    .write_all(&buf)
                    .map_err(|error| Error::FileWrite {
                        error,
                        path: local_temp.path().to_owned(),
                    })?;

                let path = local_dir.join(INDEX_BIN);
                local_temp
                    .persist(&path)
                    .map_err(|error| Error::FileWrite {
                        error: error.error,
                        path,
                    })?;
            }
            Self::SaveManifest {
                manifest,
                local_dir,
            } => {
                debug!("saving manifest");
                let path = local_dir.join(MANIFEST_JSON);
                let data =
                    serde_json::to_vec(&manifest).map_err(|error| Error::ManifestEncode {
                        error: Box::new(error),
                        path: path.clone(),
                    })?;
                atomic_write(&path, &data).map_err(|error| Error::FileWrite { error, path })?;
            }
        }

        Ok(())
    }

    fn download(file: &ManifestFile, remote_url: &str, local: &Path) -> Self {
        Self::Download {
            file: file.clone(),
            remote_url: format!("{remote_url}{}", file.filename),
            local: local.join(&file.filename),
        }
    }
}

impl fmt::Display for PlanStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreateDir(path) => write!(f, "create directory {path:?}"),
            Self::Download {
                file,
                remote_url,
                local,
            } => write!(
                f,
                "download {} bytes from {remote_url} to {local:?}",
                file.size
            ),
            Self::Delete(path) => write!(f, "delete stale file {path:?}"),
            Self::SaveIndex { local_dir, .. } => {
                write!(f, "build index from filters into {local_dir:?}")
            }
            Self::SaveManifest { local_dir, .. } => {
                write!(f, "save new manifest into {local_dir:?}")
            }
        }
    }
}

/// Atomically write `data` to `path` via a temporary file and rename.
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), io::Error> {
    let dir = path
        .parent()
        .expect("path must have parent");

    #[cfg(target_family = "unix")]
    let temp = tempfile::Builder::new()
        .permissions(Permissions::from_mode(0o644))
        .tempfile_in(dir);
    #[cfg(not(target_family = "unix"))]
    let temp = tempfile::Builder::new().tempfile_in(dir);

    let mut temp = temp?;
    temp.write_all(data)?;
    temp.persist(path)
        .map_err(|error| error.error)?;
    Ok(())
}

fn hash_file(path: &Path) -> Result<sha256::Digest, io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = sha256::Context::new();
    let mut buffer = [0; 4096];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }

        hasher.update(&buffer[..n]);
    }

    Ok(hasher.finish())
}

const MANIFEST_JSON: &str = "manifest.json";
const REQUEST_TIMEOUT: u64 = 30;
