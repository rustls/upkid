#[cfg(feature = "__fetch")]
use std::{fs::File, io::BufReader, path::PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::revocation::Error;

/// The structure contained in a manifest.json
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Manifest {
    /// When this file was generated.
    ///
    /// UNIX timestamp in seconds.
    pub generated_at: u64,

    /// Some human-readable text.
    pub comment: String,

    /// List of required files.
    #[serde(alias = "filters")]
    pub files: Vec<ManifestFile>,
}

impl Manifest {
    #[cfg(feature = "__fetch")]
    pub(crate) fn from_file(file_name: PathBuf) -> Result<Self, Error> {
        let file = match File::open(&file_name) {
            Ok(f) => f,
            Err(error) => {
                return Err(Error::FileRead {
                    error,
                    path: Some(file_name),
                });
            }
        };

        serde_json::from_reader(BufReader::new(file)).map_err(|error| Error::FileDecode {
            error: Box::new(error),
            path: Some(file_name),
        })
    }

    /// Logs metadata fields in this manifest.
    pub fn introduce(&self) -> Result<(), Error> {
        let dt = match DateTime::<Utc>::from_timestamp(self.generated_at as i64, 0) {
            Some(dt) => dt.to_rfc3339(),
            None => {
                return Err(Error::InvalidTimestamp {
                    input: self.generated_at.to_string(),
                    context: "manifest generated (in s)",
                });
            }
        };

        info!(comment = self.comment, date = dt, "parsed manifest");
        Ok(())
    }
}

/// Manifest data for a single manifest file.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ManifestFile {
    /// Relative filename.
    ///
    /// This is also the suggested local filename.
    pub filename: String,

    /// File size, indicative.  Allows a fetcher to predict data usage.
    pub size: usize,

    /// SHA256 hash of file contents.
    #[serde(with = "hex::serde")]
    pub hash: Vec<u8>,
}
