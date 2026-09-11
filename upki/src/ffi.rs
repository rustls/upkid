#![allow(non_camel_case_types)]

use core::ffi::c_char;
use std::ffi::CStr;
use std::panic::catch_unwind;
use std::path::Path;
use std::slice;

use rustls_pki_types::CertificateDer;

use crate::revocation::{self, Index, RevocationCheckInput, RevocationStatus};
use crate::{Config, ConfigPath, Error};

/// Check the revocation status of a certificate.
///
/// The `certificates` array should contain the end-entity certificate first,
/// followed by any intermediate certificates needed to find the issuer.
///
/// Returns a `upki_result` indicating success (with revocation status) or an error.
///
/// # Safety
///
/// - `config` must be a valid pointer returned by `upki_config_new`.
/// - `certificates` must point to `certificates_len` `upki_certificate` values.
/// - Each `upki_certificate` must have a valid `data` pointer to `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn upki_check_revocation(
    config: *const upki_config,
    certificates: *const upki_certificate_der,
    certificates_len: usize,
) -> upki_result {
    catch_unwind(|| {
        if config.is_null() || certificates.is_null() {
            return upki_result::UPKI_ERR_NULL_POINTER;
        }

        let config = unsafe { &(*config).0 };
        let certificates = unsafe { slice::from_raw_parts(certificates, certificates_len) };

        let certs = certificates
            .iter()
            .map(|c| CertificateDer::from(unsafe { slice::from_raw_parts(c.data, c.len) }))
            .collect::<Vec<_>>();

        let input = match RevocationCheckInput::from_certificates(&certs) {
            Ok(input) => input,
            Err(err) => return Error::Revocation(err).into(),
        };

        let mut index = match Index::from_cache(config) {
            Ok(index) => index,
            Err(err) => return Error::Revocation(err).into(),
        };

        match index.check(&input) {
            Ok(status) => match status {
                RevocationStatus::NotCoveredByRevocationData => {
                    upki_result::UPKI_REVOCATION_NOT_COVERED
                }
                RevocationStatus::CertainlyRevoked => upki_result::UPKI_REVOCATION_REVOKED,
                RevocationStatus::NotRevoked => upki_result::UPKI_REVOCATION_NOT_REVOKED,
            },
            Err(err) => Error::Revocation(err).into(),
        }
    })
    .unwrap_or(upki_result::UPKI_ERR_PANICKED)
}

/// Opaque type representing a `upki::Config`.
pub struct upki_config(Config);

/// Create a new `upki_config` by loading it from the file at `path`.
///
/// If `path` is `NULL`, the file is found by searching for a configuration
/// file in a series of places (depending on the platform.) This is
/// exposed by the `upki` command-line tool: run `upki show-config-path`
/// so see where the current configuration file is being found.
///
/// On success, writes the config pointer to `out` and returns `UPKI_OK`.
/// The caller is responsible for freeing the config with `upki_config_free`.
///
/// # Safety
///
/// - `out` must be a pointer to writable, properly-aligned storage for a pointer.
///   Returns `UPKI_ERR_NULL_POINTER` if `out` is `NULL`.
/// - `path` must be a valid pointer to a null-terminated UTF-8 string, or `NULL`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn upki_config_new(
    path: *const c_char,
    out: *mut *mut upki_config,
) -> upki_result {
    catch_unwind(|| {
        if out.is_null() {
            return upki_result::UPKI_ERR_NULL_POINTER;
        }

        let path = match path.is_null() {
            true => match ConfigPath::new(None) {
                Ok(path) => path,
                Err(e) => return e.into(),
            },
            false => {
                let path = unsafe { CStr::from_ptr(path) };
                let Ok(path) = path.to_str() else {
                    return upki_result::UPKI_ERR_CONFIG_PATH;
                };
                ConfigPath::Specified(Path::new(path).to_owned())
            }
        };

        match Config::from_file_or_user_default(&path) {
            Ok(config) => {
                unsafe { *out = Box::into_raw(Box::new(upki_config(config))) };
                upki_result::UPKI_OK
            }
            Err(err) => err.into(),
        }
    })
    .unwrap_or(upki_result::UPKI_ERR_PANICKED)
}

/// Free a `upki_config` created by `upki_config_new`.
///
/// # Safety
///
/// `config` must be a valid pointer returned by `upki_config_new`,
/// or null (in which case this is a no-op).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn upki_config_free(config: *mut upki_config) {
    if !config.is_null() {
        drop(unsafe { Box::from_raw(config) });
    }
}

/// A DER-encoded certificate.
#[repr(C)]
pub struct upki_certificate_der {
    /// Pointer to the DER-encoded certificate data.
    pub data: *const u8,
    /// Length of the certificate data in bytes.
    pub len: usize,
}

/// Result type for upki C API functions.
///
/// Values 0-15 indicate success (with specific status information).
/// Values 16 and above indicate errors.
#[derive(Clone, Copy)]
#[repr(C)]
pub enum upki_result {
    /// Operation succeeded.
    UPKI_OK = 0,
    /// The certificate is not covered by the revocation data.
    UPKI_REVOCATION_NOT_COVERED = 1,
    /// The certificate has been revoked.
    UPKI_REVOCATION_REVOKED = 2,
    /// The certificate is not revoked.
    UPKI_REVOCATION_NOT_REVOKED = 3,

    /// A null pointer was passed where a valid pointer was required.
    UPKI_ERR_NULL_POINTER = 16,
    /// The config path is not valid UTF-8.
    UPKI_ERR_CONFIG_PATH = 17,
    /// An unknown error variant was added to the library.
    UPKI_ERR_UNKNOWN = 18,
    /// An unexpected panic occurred in the library.
    UPKI_ERR_PANICKED = 19,

    // Errors from upki::Error
    /// Failed to decode configuration file.
    UPKI_ERR_CONFIG_DECODE = 32,
    /// Failed to read configuration file.
    UPKI_ERR_CONFIG_READ = 33,
    /// No cache directory could be found.
    UPKI_ERR_NO_CACHE_DIR = 34,
    /// No configuration directory could be found.
    UPKI_ERR_NO_CONFIG_DIR = 35,
    /// The user's home directory could not be determined.
    UPKI_ERR_NO_HOME_DIR = 36,

    // Errors from upki::revocation::Error
    /// Failed to create a directory.
    UPKI_ERR_REVOCATION_CREATE_DIR = 64,
    /// Failed to write a file.
    UPKI_ERR_REVOCATION_FILE_WRITE = 65,
    /// Failed to decode a file.
    UPKI_ERR_REVOCATION_FILE_DECODE = 66,
    /// Failed to read a file.
    UPKI_ERR_REVOCATION_FILE_READ = 67,
    /// A downloaded file did not match the expected hash.
    UPKI_ERR_REVOCATION_HASH_MISMATCH = 68,
    /// Failed to fetch a file over HTTP.
    UPKI_ERR_REVOCATION_HTTP_FETCH = 69,
    /// Invalid base64 encoding.
    UPKI_ERR_REVOCATION_INVALID_BASE64 = 70,
    /// The end-entity certificate was invalid.
    UPKI_ERR_REVOCATION_INVALID_END_ENTITY_CERT = 71,
    /// An intermediate certificate was invalid.
    UPKI_ERR_REVOCATION_INVALID_INTERMEDIATE_CERT = 72,
    /// A base64-decoded value did not have the expected length.
    UPKI_ERR_REVOCATION_INVALID_LENGTH = 73,
    /// Invalid SCT encoding.
    UPKI_ERR_REVOCATION_INVALID_SCT_ENCODING = 74,
    /// An SCT in the end-entity certificate could not be parsed.
    UPKI_ERR_REVOCATION_INVALID_SCT_IN_CERT = 75,
    /// A timestamp could not be parsed.
    UPKI_ERR_REVOCATION_INVALID_TIMESTAMP = 76,
    /// Failed to encode a manifest file.
    UPKI_ERR_REVOCATION_MANIFEST_ENCODE = 77,
    /// No issuer found for the end-entity certificate.
    UPKI_ERR_REVOCATION_NO_ISSUER = 78,
    /// Cache is outdated.
    UPKI_ERR_REVOCATION_OUTDATED = 79,
    /// Failed to remove a file.
    UPKI_ERR_REVOCATION_REMOVE_FILE = 80,
    /// Certificate chain must contain at least 2 certificates.
    UPKI_ERR_REVOCATION_TOO_FEW_CERTS = 81,
}

impl upki_result {
    /// Convert an error into a static C string
    pub const fn c_str(&self) -> &'static CStr {
        match self {
            Self::UPKI_OK => c"operation succeeded",
            Self::UPKI_REVOCATION_NOT_COVERED => {
                c"the certificate is not covered by the revocation data"
            }
            Self::UPKI_REVOCATION_REVOKED => c"the certificate has been revoked",
            Self::UPKI_REVOCATION_NOT_REVOKED => c"the certificate is not revoked",
            Self::UPKI_ERR_NULL_POINTER => {
                c"a null pointer was passed where a valid pointer was required"
            }
            Self::UPKI_ERR_CONFIG_PATH => c"the config path is not valid utf-8",
            Self::UPKI_ERR_UNKNOWN => c"an unknown error variant was added to the library",
            Self::UPKI_ERR_PANICKED => c"an unexpected panic occurred in the library",
            Self::UPKI_ERR_CONFIG_DECODE => c"failed to decode configuration file",
            Self::UPKI_ERR_CONFIG_READ => c"failed to read configuration file",
            Self::UPKI_ERR_NO_CACHE_DIR => c"no cache directory could be found",
            Self::UPKI_ERR_NO_CONFIG_DIR => c"no configuration directory could be found",
            Self::UPKI_ERR_NO_HOME_DIR => c"the user's home directory could not be determined",
            Self::UPKI_ERR_REVOCATION_CREATE_DIR => c"failed to create a directory",
            Self::UPKI_ERR_REVOCATION_FILE_WRITE => c"failed to write a file",
            Self::UPKI_ERR_REVOCATION_FILE_DECODE => c"failed to decode a file",
            Self::UPKI_ERR_REVOCATION_FILE_READ => c"failed to read a file",
            Self::UPKI_ERR_REVOCATION_HASH_MISMATCH => {
                c"a downloaded file did not match the expected hash"
            }
            Self::UPKI_ERR_REVOCATION_HTTP_FETCH => c"failed to fetch a file over http",
            Self::UPKI_ERR_REVOCATION_INVALID_BASE64 => c"invalid base64 encoding",
            Self::UPKI_ERR_REVOCATION_INVALID_END_ENTITY_CERT => {
                c"the end-entity certificate was invalid"
            }
            Self::UPKI_ERR_REVOCATION_INVALID_INTERMEDIATE_CERT => {
                c"an intermediate certificate was invalid"
            }
            Self::UPKI_ERR_REVOCATION_INVALID_LENGTH => {
                c"a base64-decoded value did not have the expected length"
            }
            Self::UPKI_ERR_REVOCATION_INVALID_SCT_ENCODING => c"invalid sct encoding",
            Self::UPKI_ERR_REVOCATION_INVALID_SCT_IN_CERT => {
                c"an sct in the end-entity certificate could not be parsed"
            }
            Self::UPKI_ERR_REVOCATION_INVALID_TIMESTAMP => c"a timestamp could not be parsed",
            Self::UPKI_ERR_REVOCATION_MANIFEST_ENCODE => c"failed to encode a manifest file",
            Self::UPKI_ERR_REVOCATION_NO_ISSUER => {
                c"no issuer found for the end-entity certificate"
            }
            Self::UPKI_ERR_REVOCATION_OUTDATED => c"cache is outdated",
            Self::UPKI_ERR_REVOCATION_REMOVE_FILE => c"failed to remove a file",
            Self::UPKI_ERR_REVOCATION_TOO_FEW_CERTS => {
                c"certificate chain must contain at least 2 certificates"
            }
        }
    }

    /// All known error values.
    pub const ALL: &[Self] = &[
        Self::UPKI_OK,
        Self::UPKI_REVOCATION_NOT_COVERED,
        Self::UPKI_REVOCATION_REVOKED,
        Self::UPKI_REVOCATION_NOT_REVOKED,
        Self::UPKI_ERR_NULL_POINTER,
        Self::UPKI_ERR_CONFIG_PATH,
        Self::UPKI_ERR_UNKNOWN,
        Self::UPKI_ERR_PANICKED,
        Self::UPKI_ERR_CONFIG_DECODE,
        Self::UPKI_ERR_CONFIG_READ,
        Self::UPKI_ERR_NO_CACHE_DIR,
        Self::UPKI_ERR_NO_CONFIG_DIR,
        Self::UPKI_ERR_NO_HOME_DIR,
        Self::UPKI_ERR_REVOCATION_CREATE_DIR,
        Self::UPKI_ERR_REVOCATION_FILE_WRITE,
        Self::UPKI_ERR_REVOCATION_FILE_DECODE,
        Self::UPKI_ERR_REVOCATION_FILE_READ,
        Self::UPKI_ERR_REVOCATION_HASH_MISMATCH,
        Self::UPKI_ERR_REVOCATION_HTTP_FETCH,
        Self::UPKI_ERR_REVOCATION_INVALID_BASE64,
        Self::UPKI_ERR_REVOCATION_INVALID_END_ENTITY_CERT,
        Self::UPKI_ERR_REVOCATION_INVALID_INTERMEDIATE_CERT,
        Self::UPKI_ERR_REVOCATION_INVALID_LENGTH,
        Self::UPKI_ERR_REVOCATION_INVALID_SCT_ENCODING,
        Self::UPKI_ERR_REVOCATION_INVALID_SCT_IN_CERT,
        Self::UPKI_ERR_REVOCATION_INVALID_TIMESTAMP,
        Self::UPKI_ERR_REVOCATION_MANIFEST_ENCODE,
        Self::UPKI_ERR_REVOCATION_NO_ISSUER,
        Self::UPKI_ERR_REVOCATION_OUTDATED,
        Self::UPKI_ERR_REVOCATION_REMOVE_FILE,
        Self::UPKI_ERR_REVOCATION_TOO_FEW_CERTS,
    ];
}

impl From<Error> for upki_result {
    fn from(err: Error) -> Self {
        match err {
            Error::ConfigError { .. } => Self::UPKI_ERR_CONFIG_DECODE,
            Error::FileRead { .. } => Self::UPKI_ERR_CONFIG_READ,
            Error::NoCacheDirectoryFound => Self::UPKI_ERR_NO_CACHE_DIR,
            Error::NoConfigDirectoryFound => Self::UPKI_ERR_NO_CONFIG_DIR,
            Error::NoValidHomeDirectory => Self::UPKI_ERR_NO_HOME_DIR,
            Error::Revocation(revocation::Error::CreateDirectory { .. }) => {
                Self::UPKI_ERR_REVOCATION_CREATE_DIR
            }
            Error::Revocation(revocation::Error::FileWrite { .. }) => {
                Self::UPKI_ERR_REVOCATION_FILE_WRITE
            }
            Error::Revocation(revocation::Error::FileDecode { .. }) => {
                Self::UPKI_ERR_REVOCATION_FILE_DECODE
            }
            Error::Revocation(revocation::Error::FileRead { .. }) => {
                Self::UPKI_ERR_REVOCATION_FILE_READ
            }
            Error::Revocation(revocation::Error::HashMismatch(_)) => {
                Self::UPKI_ERR_REVOCATION_HASH_MISMATCH
            }
            Error::Revocation(revocation::Error::HttpFetch { .. }) => {
                Self::UPKI_ERR_REVOCATION_HTTP_FETCH
            }
            Error::Revocation(revocation::Error::InvalidBase64 { .. }) => {
                Self::UPKI_ERR_REVOCATION_INVALID_BASE64
            }
            Error::Revocation(revocation::Error::InvalidEndEntityCertificate(_)) => {
                Self::UPKI_ERR_REVOCATION_INVALID_END_ENTITY_CERT
            }
            Error::Revocation(revocation::Error::InvalidIntermediateCertificate { .. }) => {
                Self::UPKI_ERR_REVOCATION_INVALID_INTERMEDIATE_CERT
            }
            Error::Revocation(revocation::Error::InvalidLength { .. }) => {
                Self::UPKI_ERR_REVOCATION_INVALID_LENGTH
            }
            Error::Revocation(revocation::Error::InvalidSctEncoding) => {
                Self::UPKI_ERR_REVOCATION_INVALID_SCT_ENCODING
            }
            Error::Revocation(revocation::Error::InvalidSctInCertificate(_)) => {
                Self::UPKI_ERR_REVOCATION_INVALID_SCT_IN_CERT
            }
            Error::Revocation(revocation::Error::InvalidTimestamp { .. }) => {
                Self::UPKI_ERR_REVOCATION_INVALID_TIMESTAMP
            }
            Error::Revocation(revocation::Error::ManifestEncode { .. }) => {
                Self::UPKI_ERR_REVOCATION_MANIFEST_ENCODE
            }
            Error::Revocation(revocation::Error::NoIssuer) => Self::UPKI_ERR_REVOCATION_NO_ISSUER,
            Error::Revocation(revocation::Error::Outdated(_)) => Self::UPKI_ERR_REVOCATION_OUTDATED,
            Error::Revocation(revocation::Error::RemoveFile { .. }) => {
                Self::UPKI_ERR_REVOCATION_REMOVE_FILE
            }
            Error::Revocation(revocation::Error::TooFewCertificates) => {
                Self::UPKI_ERR_REVOCATION_TOO_FEW_CERTS
            }
            _ => Self::UPKI_ERR_UNKNOWN,
        }
    }
}
