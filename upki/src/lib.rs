#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

use core::error::Error as StdError;
#[cfg(target_os = "windows")]
use std::env;
use std::path::{Path, PathBuf};
use std::{fmt, fs, io};

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

pub(crate) mod sha256;

/// Determining revocation status of publicly trusted certificates.
pub mod revocation;

/// Fetching intermediate certificates to assist chain building.
pub mod intermediates;

/// Common data storage formats.
pub mod data;

use crate::intermediates::IntermediatesConfig;
use crate::revocation::RevocationConfig;

/// Foreign function interface.
#[cfg(feature = "capi")]
pub mod ffi;

/// `upki` configuration.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    /// Where to store cache files.
    cache_dir: PathBuf,

    /// Configuration for crlite-style revocation.
    pub revocation: RevocationConfig,

    /// Configuration for intermediate preloading.
    #[serde(default)]
    pub intermediates: IntermediatesConfig,
}

impl Config {
    /// Load the configuration data from a file at `path`.
    ///
    /// If no file exists at `path`, a default configuration is returned.
    pub fn from_file_or_user_default(path: &ConfigPath) -> Result<Self, Error> {
        match path {
            ConfigPath::Default(path) if path.exists() => Self::from_file(path),
            ConfigPath::Default(_) => Self::try_default(),
            ConfigPath::Specified(path) => Self::from_file(path),
        }
    }

    /// Load the configuration data from a file at `path`.
    pub fn from_file(path: &Path) -> Result<Self, Error> {
        let config_content = fs::read_to_string(path).map_err(|error| Error::FileRead {
            error,
            path: path.to_owned(),
        })?;

        toml::from_str(&config_content).map_err(|error| Error::ConfigError {
            error: Box::new(error),
            path: path.to_owned(),
        })
    }

    /// Return a sensible default configuration.
    pub fn try_default() -> Result<Self, Error> {
        let user_cache = project_dirs()?.cache_dir().to_owned();
        Ok(Self {
            cache_dir: match user_cache.exists() {
                true => user_cache,
                false => {
                    let system_cache = platform::system_cache_dir()?;
                    match system_cache.exists() {
                        true => system_cache,
                        false => user_cache,
                    }
                }
            },
            revocation: RevocationConfig::default(),
            intermediates: IntermediatesConfig::default(),
        })
    }

    pub(crate) fn revocation_cache_dir(&self) -> PathBuf {
        self.cache_dir.join("revocation")
    }

    pub(crate) fn intermediates_cache_dir(&self) -> PathBuf {
        self.cache_dir.join("intermediates")
    }
}

/// How the path to a configuration file was decided upon.
pub enum ConfigPath {
    /// The path was directly specified by a user.
    Specified(PathBuf),
    /// The path was determined automatically.
    Default(PathBuf),
}

impl ConfigPath {
    /// Return the path of a configuration file.
    ///
    /// If `specified` is supplied, this path is returned -- no searching is performed
    /// and this function does not return an error.
    ///
    /// This function prefers to return paths to existing files.  If no files exist
    /// according to the (platform-specific) search logic, then a suggested location
    /// is returned where a configuration file can be created if desired.
    ///
    /// This function fails for platform-specific reasons, typically if `$HOME` is not
    /// set, or another XDG environment variable is malformed.
    pub fn new(specified: Option<PathBuf>) -> Result<Self, Error> {
        if let Some(f) = specified {
            return Ok(Self::Specified(f));
        }

        // Search for an existing configuration file.
        //
        // The search order is:
        //
        // - user-specific files, following XDG
        // - a system-level file
        //
        // If no files are found, the user-specific file location is returned.
        let user = project_dirs()?
            .config_dir()
            .join(CONFIG_FILE);
        if user.exists() {
            return Ok(Self::Default(user));
        }

        let system = platform::system_config_dir()?.join(CONFIG_FILE);
        if system.exists() {
            return Ok(Self::Default(system.to_owned()));
        }

        Ok(Self::Default(user))
    }
}

impl AsRef<Path> for ConfigPath {
    fn as_ref(&self) -> &Path {
        match self {
            Self::Specified(path) => path.as_ref(),
            Self::Default(path) => path.as_ref(),
        }
    }
}

#[cfg(target_vendor = "apple")]
mod platform {
    use super::*;

    pub(super) fn system_config_dir() -> Result<PathBuf, Error> {
        Ok(PathBuf::from("/Library/Application Support").join(PREFIX))
    }

    pub(super) fn system_cache_dir() -> Result<PathBuf, Error> {
        Ok(PathBuf::from("/Library/Caches").join(BUNDLE_ID))
    }
}

#[cfg(all(unix, not(target_vendor = "apple")))]
mod platform {
    use super::*;

    pub(super) fn system_config_dir() -> Result<PathBuf, Error> {
        Ok(PathBuf::from("/etc").join(PREFIX))
    }

    pub(super) fn system_cache_dir() -> Result<PathBuf, Error> {
        Ok(PathBuf::from("/var/cache").join(PREFIX))
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::*;

    pub(super) fn system_config_dir() -> Result<PathBuf, Error> {
        Ok(match env::var_os("ProgramData") {
            Some(base) => PathBuf::from(base),
            None => PathBuf::from("C:\\ProgramData"),
        }
        .join(VENDOR)
        .join(PREFIX))
    }

    pub(super) fn system_cache_dir() -> Result<PathBuf, Error> {
        Ok(match env::var_os("ProgramData") {
            Some(base) => PathBuf::from(base),
            None => PathBuf::from("C:\\ProgramData"),
        }
        .join(VENDOR)
        .join(PREFIX)
        .join("cache"))
    }
}

/// Errors for the upki library API.
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// Failed to decode configuration file at `path`.
    ConfigError {
        /// Underlying error.
        error: Box<dyn StdError + Send + Sync>,
        /// Path to the configuration file.
        path: PathBuf,
    },
    /// Failed to read configuration file at `path`.
    FileRead {
        /// Underlying error.
        error: io::Error,
        /// Path to the configuration file.
        path: PathBuf,
    },
    /// No cache directory could be found.
    NoCacheDirectoryFound,
    /// No configuration directory could be found.
    NoConfigDirectoryFound,
    /// The user's home directory could not be determined.
    NoValidHomeDirectory,
    /// Error from the revocation API.
    Revocation(revocation::Error),
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::ConfigError { error, .. } => Some(error.as_ref()),
            Self::FileRead { error, .. } => Some(error),
            Self::NoCacheDirectoryFound
            | Self::NoConfigDirectoryFound
            | Self::NoValidHomeDirectory => None,
            Self::Revocation(err) => Some(err),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigError { path, .. } => {
                write!(f, "failed to parse config file at {}", path.display())
            }
            Self::FileRead { path, .. } => {
                write!(f, "failed to read config file at {}", path.display())
            }
            Self::NoCacheDirectoryFound => write!(f, "no cache directory could be found"),
            Self::NoConfigDirectoryFound => write!(f, "no configuration directory could be found"),
            Self::NoValidHomeDirectory => write!(f, "could not determine user's home directory"),
            Self::Revocation(_) => write!(f, "revocation error"),
        }
    }
}

impl From<revocation::Error> for Error {
    fn from(value: revocation::Error) -> Self {
        Self::Revocation(value)
    }
}

fn project_dirs() -> Result<ProjectDirs, Error> {
    ProjectDirs::from("dev", "rustls", PREFIX).ok_or(Error::NoValidHomeDirectory)
}

#[cfg(target_vendor = "apple")]
const BUNDLE_ID: &str = "dev.rustls.upki";
#[cfg(target_os = "windows")]
const VENDOR: &str = "rustls";
const PREFIX: &str = "upki";
const CONFIG_FILE: &str = "config.toml";
