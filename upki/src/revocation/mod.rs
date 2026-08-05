use core::error::Error as StdError;
use core::ops::Deref;
use core::str::FromStr;
use core::{fmt, str};
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use clubcard_crlite::CRLiteKey;
pub use clubcard_crlite::IssuerSpkiHash;
use rustls_pki_types::{CertificateDer, TrustAnchor};
use serde::{Deserialize, Serialize};

#[cfg(feature = "__fetch")]
use crate::Config;
use crate::{data, sha256};

#[cfg(feature = "__fetch")]
mod fetch;
#[cfg(feature = "__fetch")]
pub use fetch::fetch;
#[cfg(feature = "__fetch")]
use fetch::{FetchContext, FetchType, Plan};

mod index;
pub use index::Index;

/// The structure contained in a manifest.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest(data::Manifest);

impl Manifest {
    /// Load the revocation manifest from the cache directory specified in the configuration.
    #[cfg(feature = "__fetch")]
    pub fn from_config(config: &Config) -> Result<Self, Error> {
        let mut file_name = config.revocation_cache_dir();
        file_name.push("manifest.json");
        data::Manifest::from_file(file_name).map(Self)
    }

    /// Verify the current contents of the cache against this manifest.
    ///
    /// This performs disk IO but does not perform network IO.
    #[cfg(feature = "__fetch")]
    pub fn verify(&self, config: &Config) -> Result<ExitCode, Error> {
        self.introduce()?;
        let plan = Plan::construct(
            self,
            &FetchContext {
                cache_dir: config.revocation_cache_dir(),
                fetch_url: "https://.../",
                old_manifest: None,
                typ: FetchType::Revocation,
            },
        )?;
        match plan.download_bytes() {
            0 => Ok(ExitCode::SUCCESS),
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

/// Input parameters for a revocation check.
#[derive(Debug)]
pub struct RevocationCheckInput {
    /// Big-endian bytes encoding of the end-entity certificate serial number.
    pub cert_serial: CertSerial,
    /// SHA256 hash of the `SubjectPublicKeyInfo` of the issuer of the end-entity certificate.
    pub issuer_spki_hash: IssuerSpkiHash,
    /// CT log IDs and inclusion timestamps present in the end-entity certificate.
    pub sct_timestamps: Vec<CtTimestamp>,
    issuer_serial_hash: [u8; 32],
}

impl RevocationCheckInput {
    /// Construct a `RevocationCheckInput` from a sequence of DER-encoded certificates.
    ///
    /// The first element in `certificates` **must** be the end-entity certificate.  The
    /// end-entity certificate's issuer **must** be present in the other certificates
    /// (but does not need to be in any specific position).
    ///
    /// Note this interface **only** checks the end-entity certificate for revocation.  It does
    /// **not** check any of the certificates for validity: it assumes the caller has done any
    /// required checks before calling this interface (path building, naming validation,
    /// expiry checking, etc.).
    pub fn from_certificates(certificates: &[CertificateDer<'_>]) -> Result<Self, Error> {
        let (end_entity, rest) = certificates
            .split_first()
            .ok_or(Error::TooFewCertificates)?;
        let end_entity = webpki::EndEntityCert::try_from(end_entity)
            .map_err(|error| Error::InvalidEndEntityCertificate(Box::new(error)))?;

        let issuer = find_issuer(end_entity.issuer(), rest.iter())?;
        let issuer_spki_hash = IssuerSpkiHash(
            sha256::Digest::from(&[webpki::spki_for_anchor(&issuer).as_ref()][..]).0,
        );

        let mut sct_timestamps = vec![];
        let iter = end_entity
            .sct_log_timestamps()
            .map_err(|e| Error::InvalidEndEntityCertificate(Box::new(e)))?;

        for ts in iter {
            let ts = ts.map_err(|e| Error::InvalidSctInCertificate(Box::new(e)))?;
            sct_timestamps.push(CtTimestamp {
                log_id: ts.log_id,
                timestamp: ts.timestamp_ms,
            });
        }

        Ok(Self::new(
            CertSerial(end_entity.serial().to_vec()),
            issuer_spki_hash,
            sct_timestamps,
        ))
    }

    /// Construct a `RevocationCheckInput` from its constituent parts.
    pub fn new(
        cert_serial: CertSerial,
        issuer_spki_hash: IssuerSpkiHash,
        sct_timestamps: Vec<CtTimestamp>,
    ) -> Self {
        let mut issuer_serial_context = sha256::Context::new();
        issuer_serial_context.update(&issuer_spki_hash.0);
        issuer_serial_context.update(&cert_serial.0);
        let issuer_serial_hash = issuer_serial_context.finish().0;

        Self {
            cert_serial,
            issuer_spki_hash,
            sct_timestamps,
            issuer_serial_hash,
        }
    }

    fn key(&self) -> CRLiteKey<'_> {
        CRLiteKey::with_hash(
            &self.issuer_spki_hash,
            &self.cert_serial.0,
            self.issuer_serial_hash,
        )
    }
}

/// A certificate serial number.
#[derive(Clone, Debug)]
pub struct CertSerial(pub Vec<u8>);

impl FromStr for CertSerial {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match BASE64_STANDARD.decode(value) {
            Ok(bytes) => Ok(Self(bytes)),
            Err(e) => Err(Error::InvalidBase64 {
                error: Box::new(e),
                context: "certificate serial",
            }),
        }
    }
}

/// An issuance timestamp established in certificate transparency.
#[derive(Clone, Debug)]
pub struct CtTimestamp {
    /// CT log ID
    pub log_id: [u8; 32],
    /// Issuance timestamp
    pub timestamp: u64,
}

impl FromStr for CtTimestamp {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some((log_id, issuance_timestamp)) = value.split_once(":") else {
            return Err(Error::InvalidSctEncoding);
        };

        Ok(Self {
            log_id: BASE64_STANDARD
                .decode(log_id)
                .map_err(|e| Error::InvalidBase64 {
                    error: Box::new(e),
                    context: "CT log ID",
                })?
                .try_into()
                .map_err(|wrong: Vec<u8>| Error::InvalidLength {
                    expected: 32,
                    actual: wrong.len(),
                    context: "CT log ID",
                })?,
            timestamp: u64::from_str(issuance_timestamp).map_err(|_| Error::InvalidTimestamp {
                input: issuance_timestamp.to_string(),
                context: "CT timestamp (in ms)",
            })?,
        })
    }
}

/// The successful outcome of a revocation check.
///
/// Look at a value of this type to determine whether a certificate was revoked or not.
#[derive(Debug, PartialEq)]
#[must_use]
pub enum RevocationStatus {
    /// We couldn't determine the revocation status.
    ///
    /// Most likely, this certificate is very new and is not covered by the current filter dataset.
    NotCoveredByRevocationData,

    /// This certificate has been revoked.
    CertainlyRevoked,

    /// This certificate was covered by revocation data, and it is not currently revoked.
    NotRevoked,
}

impl RevocationStatus {
    /// Convert this revocation status to an exit code for the CLI.
    ///
    /// Also print the status to stdout.
    pub fn to_cli(&self) -> ExitCode {
        println!("{self:?}");
        match self {
            Self::NotRevoked | Self::NotCoveredByRevocationData => ExitCode::SUCCESS,
            Self::CertainlyRevoked => ExitCode::from(Self::EXIT_CODE_REVOCATION_REVOKED),
        }
    }

    const EXIT_CODE_REVOCATION_REVOKED: u8 = 2;
}

/// Details about crlite-style revocation.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct RevocationConfig {
    /// Where to fetch revocation data files.
    fetch_url: String,
}

impl Default for RevocationConfig {
    fn default() -> Self {
        Self {
            fetch_url: "https://upki.rustls.dev/revocation/".into(),
        }
    }
}

fn find_issuer<'a>(
    name: &[u8],
    candidates: impl Iterator<Item = &'a CertificateDer<'a>>,
) -> Result<TrustAnchor<'a>, Error> {
    for (i, c) in candidates.enumerate() {
        // nb. do not copy this code. it is not correct to treat intermediate certificates
        // as trust anchors.
        let root = webpki::anchor_from_trusted_cert(c).map_err(|error| {
            Error::InvalidIntermediateCertificate {
                error: Box::new(error),
                index: i,
            }
        })?;

        if root.subject.as_ref() == name {
            return Ok(root);
        }
    }

    Err(Error::NoIssuer)
}

/// Errors for the revocation API.
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// Failed to create a directory.
    CreateDirectory {
        /// Underlying error.
        error: io::Error,
        /// Path to the directory being created.
        path: PathBuf,
    },
    /// Failed to write a file.
    FileWrite {
        /// Underlying error.
        error: io::Error,
        /// Path to the file being written.
        path: PathBuf,
    },
    /// Failed to decode a file.
    FileDecode {
        /// Underlying error.
        error: Box<dyn StdError + Send + Sync>,
        /// Path to the file.
        path: Option<PathBuf>,
    },
    /// Failed to read a file.
    FileRead {
        /// Underlying error.
        error: io::Error,
        /// Path to the file.
        path: Option<PathBuf>,
    },
    /// A downloaded file did not match the expected hash.
    HashMismatch(PathBuf),
    /// Failed to decode the index file.
    IndexDecode(Box<dyn StdError + Send + Sync>),
    /// Failed to fetch a file over HTTP.
    HttpFetch {
        /// Underlying error.
        error: Box<dyn StdError + Send + Sync>,
        /// URL being accessed.
        url: String,
    },
    /// Invalid base64 encoding.
    InvalidBase64 {
        /// Underlying error.
        error: Box<dyn StdError + Send + Sync>,
        /// Context in which the base64 was being parsed.
        context: &'static str,
    },
    /// The end-entity certificate was invalid and could not be parsed.
    InvalidEndEntityCertificate(Box<dyn StdError + Send + Sync>),
    /// An intermediate certificate was invalid and could not be parsed.
    InvalidIntermediateCertificate {
        /// Underlying error.
        error: Box<dyn StdError + Send + Sync>,
        /// Index of the intermediate certificate in the provided chain.
        index: usize,
    },
    /// A base64-decoded value did not have the expected length.
    InvalidLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
        /// Context in which the hash was being parsed.
        context: &'static str,
    },
    /// No ':' found in [`CtTimestamp`] string representation.
    InvalidSctEncoding,
    /// An SCT in the end-entity certificate could not be parsed.
    InvalidSctInCertificate(Box<dyn StdError + Send + Sync>),
    /// A timestamp could not be parsed.
    InvalidTimestamp {
        /// Input value that failed to parse as a timestamp.
        input: String,
        /// Context in which the timestamp was being parsed.
        context: &'static str,
    },
    /// Failed to encode a manifest file.
    ManifestEncode {
        /// Underlying error.
        error: Box<dyn StdError + Send + Sync>,
        /// Path to the manifest file.
        path: PathBuf,
    },
    /// No issuer found for the end-entity certificate in the provided chain.
    NoIssuer,
    /// Number of bytes that need to be downloaded to update the local cache.
    Outdated(usize),
    /// Failed to remove a file.
    RemoveFile {
        /// Underlying error.
        error: io::Error,
        /// Path to the file being removed.
        path: PathBuf,
    },
    /// Certificate chains must contain at least 2 certificates.
    TooFewCertificates,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreateDirectory { path, .. } => {
                write!(f, "cannot create directory {path:?}")
            }
            Self::FileWrite { path, .. } => write!(f, "cannot write file {path:?}"),
            Self::FileDecode { path, .. } => match path {
                Some(path) => write!(f, "cannot decode file {path:?}"),
                None => write!(f, "cannot decode file"),
            },
            Self::FileRead { path, .. } => match path {
                Some(path) => write!(f, "cannot read file {path:?}"),
                None => write!(f, "cannot read file"),
            },
            Self::HashMismatch(path) => write!(f, "hash mismatch for file {path:?}"),
            Self::IndexDecode(_) => write!(f, "cannot decode index file"),
            Self::HttpFetch { url, .. } => write!(f, "HTTP fetch error for URL {url}"),
            Self::InvalidBase64 { context, .. } => {
                write!(f, "invalid base64 for {context}")
            }
            Self::InvalidEndEntityCertificate(_) => {
                write!(f, "invalid end-entity certificate")
            }
            Self::InvalidIntermediateCertificate { index, .. } => {
                write!(f, "invalid intermediate certificate at index {index}")
            }
            Self::InvalidLength {
                expected,
                actual,
                context,
            } => write!(
                f,
                "invalid length for {context}: expected {expected}, got {actual}"
            ),
            Self::InvalidSctEncoding => write!(f, "invalid SCT encoding: no ':' found"),
            Self::InvalidSctInCertificate(_) => {
                write!(f, "invalid SCT in certificate")
            }
            Self::InvalidTimestamp { input, context } => {
                write!(f, "invalid timestamp for {context}: '{input}'")
            }
            Self::ManifestEncode { path, .. } => {
                write!(f, "cannot encode manifest file at {path:?}")
            }
            Self::NoIssuer => write!(f, "no issuer found for end-entity certificate"),
            Self::Outdated(bytes) => write!(f, "cache is outdated, {bytes} bytes need downloading"),
            Self::RemoveFile { path, .. } => write!(f, "cannot remove file {path:?}"),
            Self::TooFewCertificates => {
                write!(f, "certificate chain must contain at least 2 certificates")
            }
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::CreateDirectory { error, .. } => Some(error),
            Self::FileWrite { error, .. } => Some(error),
            Self::FileDecode { error, .. } => Some(&**error),
            Self::FileRead { error, .. } => Some(error),
            Self::HashMismatch(_) => None,
            Self::IndexDecode(error) => Some(&**error),
            Self::HttpFetch { error, .. } => Some(&**error),
            Self::InvalidBase64 { error, .. } => Some(&**error),
            Self::InvalidEndEntityCertificate(error) => Some(&**error),
            Self::InvalidIntermediateCertificate { error, .. } => Some(&**error),
            Self::InvalidLength { .. } => None,
            Self::InvalidSctEncoding => None,
            Self::InvalidSctInCertificate(error) => Some(&**error),
            Self::InvalidTimestamp { .. } => None,
            Self::ManifestEncode { error, .. } => Some(&**error),
            Self::NoIssuer => None,
            Self::Outdated(_) => None,
            Self::RemoveFile { error, .. } => Some(error),
            Self::TooFewCertificates => None,
        }
    }
}
