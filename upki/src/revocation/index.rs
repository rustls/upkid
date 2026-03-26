use core::cmp::Ordering;
use core::{fmt, str};
#[cfg(feature = "__fetch")]
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
#[cfg(feature = "__fetch")]
use std::path::Path;
use std::path::PathBuf;

#[cfg(feature = "__fetch")]
use clubcard_crlite::TimestampInterval;
use clubcard_crlite::{CRLiteClubcard, CRLiteStatus, LogId, Timestamp};

use super::{Error, RevocationCheckInput, RevocationStatus};
use crate::Config;
#[cfg(feature = "__fetch")]
use crate::data::Manifest;

/// Binary-encoded index of universe metadata for all filters in a manifest.
///
/// This allows the check path to identify which filter file covers a given certificate
/// without loading every filter. Written atomically during fetch, this is the single
/// source of truth for revocation checks.
///
/// # Encoding
///
/// All integers are big-endian. Filenames are fixed 32-byte slots, NULL-padded.
///
/// ```text
/// HEADER (first reads, 14 bytes):
///   magic: [u8; 8]                    "upkiidx1"
///   num_filenames: u16
///   num_log_ids: u32
///
/// TABLES (second read):
///   Per filename:
///     filename: [u8; 32]              UTF-8, NULL-padded
///   Per log_id (sorted lexicographically):
///     log_id: [u8; 32]
///     offset: u64                      byte offset from file start
///     num_entries: u16
///
/// ENTRY SECTIONS (seek + third read):
///   Per entry:
///     filter_index: u16
///     min_timestamp: u64
///     max_timestamp: u64
/// ```
///
/// Indexes with the legacy "upkiidx0" magic encode `num_filenames` and
/// `filter_index` as `u8`. Both versions are read, but writing always produces
/// "upkiidx1".
///
/// This type stores a [`File`] for on-demand reading of entry sections.
pub struct Index {
    cache_dir: PathBuf,
    num_filenames: usize,
    num_logs: usize,
    logs_offset: usize,
    /// Size of one entry section entry, determined by the index magic version.
    entry_size: usize,
    /// Contains the filename table followed by the log table.
    tables: Vec<u8>,
    file: File,
}

impl Index {
    /// Read the index header from the cache directory specified in `config`.
    ///
    /// Only the header (filename table and log-ID directory) is loaded into memory.
    /// Entry sections are read on demand during [`check`](Self::check) via seeking.
    pub fn from_cache(config: &Config) -> Result<Self, Error> {
        let cache_dir = config.revocation_cache_dir();
        let index_path = cache_dir.join(INDEX_BIN);
        let mut file = File::open(&index_path).map_err(|error| Error::FileRead {
            error,
            path: Some(index_path.clone()),
        })?;

        // Read 1: magic, determining the version-dependent header and entry sizes
        let mut magic = [0u8; 8];
        file.read_exact(&mut magic)
            .map_err(|e| Error::IndexDecode(Box::new(e)))?;
        let (header_size, entry_size) = if magic == *INDEX_MAGIC_V1 {
            (HEADER_SIZE_V1, ENTRY_SIZE_V1)
        } else if magic == *INDEX_MAGIC_V0 {
            (HEADER_SIZE_V0, ENTRY_SIZE_V0)
        } else {
            return Err(Error::IndexDecode("invalid index magic".into()));
        };

        // Read 2: num_filenames + num_log_ids
        let mut header = [0u8; HEADER_SIZE_V1 - 8];
        let header = &mut header[..header_size - 8];
        file.read_exact(header)
            .map_err(|e| Error::IndexDecode(Box::new(e)))?;
        let mut data = &*header;
        let num_filenames = match entry_size {
            ENTRY_SIZE_V0 => u8::read_be(&mut data)? as usize,
            _ => u16::read_be(&mut data)? as usize,
        };
        let num_logs = u32::read_be(&mut data)? as usize;

        // Read 3: filename table + log table
        let logs_offset = num_filenames * FILENAME_SIZE;
        let tables_len = logs_offset + num_logs * LOG_DIR_ENTRY_SIZE;

        // A corrupt `num_log_ids` could demand an unreasonable sized allocation. Cap the table
        // allocation to the file's overall size.
        let file_len = file
            .metadata()
            .map_err(|error| Error::FileRead {
                error,
                path: Some(index_path),
            })?
            .len();
        if (header_size + tables_len) as u64 > file_len {
            return Err(Error::IndexDecode("index tables truncated".into()));
        }

        let mut tables = vec![0u8; tables_len];
        file.read_exact(&mut tables)
            .map_err(|e| Error::IndexDecode(Box::new(e)))?;

        Ok(Self {
            cache_dir,
            num_filenames,
            num_logs,
            logs_offset,
            entry_size,
            tables,
            file,
        })
    }

    /// Build index bytes by reading filter files from `dir` and extracting universe metadata.
    ///
    /// Returns `None` if any filter file cannot be read or decoded.
    #[cfg(feature = "__fetch")]
    pub(super) fn write(manifest: &Manifest, dir: &Path) -> Option<Vec<u8>> {
        let mut by_log_id: BTreeMap<LogId, Vec<(u16, TimestampInterval)>> = BTreeMap::new();

        for (filter_idx, filter) in manifest.files.iter().enumerate() {
            if filter.filename.len() > FILENAME_SIZE {
                tracing::warn!(
                    "skipping index: filename {:?} exceeds {FILENAME_SIZE} bytes",
                    filter.filename
                );
                return None;
            }

            let path = dir.join(&filter.filename);
            let bytes = match fs::read(&path) {
                Ok(bytes) => bytes,
                Err(error) => {
                    tracing::warn!("skipping index: cannot read {path:?}: {error}");
                    return None;
                }
            };

            let clubcard = match CRLiteClubcard::from_bytes(&bytes) {
                Ok(c) => c,
                Err(error) => {
                    tracing::warn!("skipping index: cannot decode {path:?}: {error:?}");
                    return None;
                }
            };

            for (log_id, interval) in clubcard.universe().iter() {
                by_log_id
                    .entry(*log_id)
                    .or_default()
                    .push((filter_idx as u16, *interval));
            }
        }

        // Compute header size to determine entry section offsets
        let header_size = HEADER_SIZE_V1
            + manifest.files.len() * FILENAME_SIZE
            + by_log_id.len() * LOG_DIR_ENTRY_SIZE;

        // Write header
        let mut buf = Vec::new();
        buf.extend_from_slice(INDEX_MAGIC_V1);
        buf.extend_from_slice(&(manifest.files.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(by_log_id.len() as u32).to_be_bytes());

        // Write filename table (fixed 32-byte slots, NULL-padded)
        for filter in &manifest.files {
            let filename = filter.filename.as_bytes();
            let mut slot = [0u8; FILENAME_SIZE];
            slot[..filename.len()].copy_from_slice(filename);
            buf.extend_from_slice(&slot);
        }

        // Pre-compute offsets for each log_id's entry section
        let mut current_offset = header_size;
        let mut dir_entries: Vec<(&LogId, u64, u16)> = Vec::new();
        for (log_id, entries) in &by_log_id {
            dir_entries.push((log_id, current_offset as u64, entries.len() as u16));
            current_offset += entries.len() * ENTRY_SIZE_V1;
        }

        // Write log_id directory
        for (log_id, offset, count) in &dir_entries {
            buf.extend_from_slice(&log_id.0);
            buf.extend_from_slice(&offset.to_be_bytes());
            buf.extend_from_slice(&count.to_be_bytes());
        }

        // Write entry sections
        for entries in by_log_id.values() {
            for (filter_idx, interval) in entries {
                buf.extend_from_slice(&filter_idx.to_be_bytes());
                buf.extend_from_slice(&interval.low.0.to_be_bytes());
                buf.extend_from_slice(&interval.high.0.to_be_bytes());
            }
        }

        Some(buf)
    }

    /// Perform a revocation check using the index.
    ///
    /// Uses binary search over the log-ID directory to find relevant entries, then seeks into
    /// the index file to read only those entries. Loads matching filter files and queries
    /// them for the certificate's revocation status. Each distinct filter file is read and
    /// parsed at most once per check.
    pub fn check(&mut self, input: &RevocationCheckInput) -> Result<RevocationStatus, Error> {
        let key = input.key();
        let dir_data = &self.tables[self.logs_offset..];
        let mut maybe_good = false;
        let mut seen = vec![false; self.num_filenames];

        'timestamp: for sct in &input.sct_timestamps {
            // Binary search the sorted log_id directory (stride LOG_DIR_ENTRY_SIZE)
            let mut lo = 0;
            let mut hi = self.num_logs;
            let entry_offset = loop {
                if lo >= hi {
                    continue 'timestamp;
                }

                let mid = lo + (hi - lo) / 2;
                let offset = mid * LOG_DIR_ENTRY_SIZE;
                let log_id = &dir_data[offset..offset + 32];
                match log_id.cmp(sct.log_id.as_slice()) {
                    Ordering::Less => lo = mid + 1,
                    Ordering::Equal => break offset,
                    Ordering::Greater => hi = mid,
                }
            };

            let mut entry_data = &dir_data[entry_offset + 32..];
            let offset = u64::read_be(&mut entry_data)?;
            let count = u16::read_be(&mut entry_data)?;

            self.file
                .seek(SeekFrom::Start(offset))
                .map_err(|e| Error::IndexDecode(Box::new(e)))?;

            let mut buf = vec![0u8; count as usize * self.entry_size];
            self.file
                .read_exact(&mut buf)
                .map_err(|e| Error::IndexDecode(Box::new(e)))?;

            let mut data = &buf[..];
            for _ in 0..count {
                let filter_index = match self.entry_size {
                    ENTRY_SIZE_V0 => u8::read_be(&mut data)? as usize,
                    _ => u16::read_be(&mut data)? as usize,
                };
                let min_ts = u64::read_be(&mut data)?;
                let max_ts = u64::read_be(&mut data)?;
                if min_ts > sct.timestamp || sct.timestamp > max_ts {
                    continue;
                }

                // Errors on `filter_index >= num_filenames`, so the `seen`
                // indexing below is in range.
                let filename = self.filename(filter_index)?;

                // A filter is queried with every SCT timestamp, so consulting it
                // again for a later SCT cannot produce a different answer.
                if seen[filter_index] {
                    continue;
                }
                seen[filter_index] = true;

                let path = self.cache_dir.join(filename);
                let bytes = match fs::read(&path) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        return Err(Error::FileRead {
                            error,
                            path: Some(path),
                        });
                    }
                };

                let filter =
                    CRLiteClubcard::from_bytes(&bytes).map_err(|error| Error::FileDecode {
                        error: format!("cannot decode crlite filter: {error:?}").into(),
                        path: Some(path),
                    })?;

                match filter.contains(
                    &key,
                    input
                        .sct_timestamps
                        .iter()
                        .map(|ct_ts| (LogId(ct_ts.log_id), Timestamp(ct_ts.timestamp))),
                ) {
                    CRLiteStatus::Revoked => return Ok(RevocationStatus::CertainlyRevoked),
                    CRLiteStatus::Good => {
                        maybe_good = true;
                        continue;
                    }
                    CRLiteStatus::NotEnrolled | CRLiteStatus::NotCovered => continue,
                }
            }
        }

        Ok(match maybe_good {
            true => RevocationStatus::NotRevoked,
            false => RevocationStatus::NotCoveredByRevocationData,
        })
    }

    /// Look up the `i`-th filename in the fixed-size filename table.
    fn filename(&self, index: usize) -> Result<&str, Error> {
        if index >= self.num_filenames {
            return Err(Error::IndexDecode("filter index out of bounds".into()));
        }

        let start = index * FILENAME_SIZE;
        let slot = &self.tables[start..start + FILENAME_SIZE];
        let end = slot
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(FILENAME_SIZE);
        str::from_utf8(&slot[..end]).map_err(|e| Error::IndexDecode(Box::new(e)))
    }
}

impl fmt::Debug for Index {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            cache_dir,
            num_filenames,
            num_logs,
            logs_offset,
            entry_size: _,
            tables: _,
            file: _,
        } = self;

        f.debug_struct("Index")
            .field("cache_dir", cache_dir)
            .field("filenames", num_filenames)
            .field("num_logs", num_logs)
            .field("logs_offset", logs_offset)
            .finish_non_exhaustive()
    }
}

impl FromBeBytes<8> for u64 {
    fn from_be_bytes(bytes: &[u8; 8]) -> Self {
        Self::from_be_bytes(*bytes)
    }
}

impl FromBeBytes<4> for u32 {
    fn from_be_bytes(bytes: &[u8; 4]) -> Self {
        Self::from_be_bytes(*bytes)
    }
}

impl FromBeBytes<2> for u16 {
    fn from_be_bytes(bytes: &[u8; 2]) -> Self {
        Self::from_be_bytes(*bytes)
    }
}

impl FromBeBytes<1> for u8 {
    fn from_be_bytes(bytes: &[u8; 1]) -> Self {
        bytes[0]
    }
}

trait FromBeBytes<const N: usize>: Sized {
    fn read_be(data: &mut &[u8]) -> Result<Self, Error> {
        match data.split_first_chunk::<N>() {
            Some((chunk, rest)) => {
                *data = rest;
                Ok(Self::from_be_bytes(chunk))
            }
            None => Err(Error::IndexDecode("unexpected end of index data".into())),
        }
    }

    fn from_be_bytes(bytes: &[u8; N]) -> Self;
}

const HEADER_SIZE_V1: usize = 8 + 2 + 4;
const HEADER_SIZE_V0: usize = 8 + 1 + 4;
const FILENAME_SIZE: usize = 32;
const LOG_DIR_ENTRY_SIZE: usize = 32 + 8 + 2;
const ENTRY_SIZE_V1: usize = 2 + 8 + 8;
const ENTRY_SIZE_V0: usize = 1 + 8 + 8;

pub(super) const INDEX_BIN: &str = "index.bin";
const INDEX_MAGIC_V1: &[u8; 8] = b"upkiidx1";
const INDEX_MAGIC_V0: &[u8; 8] = b"upkiidx0";

#[cfg(test)]
mod tests {
    use core::error::Error as StdError;
    use std::collections::BTreeMap;
    use std::path::Path;

    use base64::Engine;
    use clubcard::builder::{ApproximateRibbon, ClubcardBuilder, ExactRibbon};
    use clubcard_crlite::builder::CRLiteBuilderItem;
    use clubcard_crlite::{CRLiteClubcard, CRLiteCoverage, CRLiteQuery, Encoding};

    use super::*;
    use crate::intermediates::IntermediatesConfig;
    use crate::revocation::{CertSerial, CtTimestamp, IssuerSpkiHash, RevocationConfig};

    #[test]
    fn check_empty_index() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        write_file(dir.path(), INDEX_BIN, &build_index(&[]));
        assert_eq!(
            Index::from_cache(&config)
                .unwrap()
                .check(&test_input())
                .unwrap(),
            RevocationStatus::NotCoveredByRevocationData,
        );
    }

    #[test]
    fn check_no_matching_log_id() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        // Input has log_id [0xbb; 32], index has [0xcc; 32]
        let data = build_index(&[("test.filter", &[([0xcc; 32], 500, 1500)])]);
        write_file(dir.path(), INDEX_BIN, &data);
        assert_eq!(
            Index::from_cache(&config)
                .unwrap()
                .check(&test_input())
                .unwrap(),
            RevocationStatus::NotCoveredByRevocationData,
        );
    }

    #[test]
    fn check_no_matching_timestamp_range() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        // Input has timestamp 1000, index range is 2000..3000
        let data = build_index(&[("test.filter", &[([0xbb; 32], 2000, 3000)])]);
        write_file(dir.path(), INDEX_BIN, &data);
        assert_eq!(
            Index::from_cache(&config)
                .unwrap()
                .check(&test_input())
                .unwrap(),
            RevocationStatus::NotCoveredByRevocationData,
        );
    }

    #[test]
    fn invalid_magic() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        write_file(dir.path(), INDEX_BIN, b"wrongmag\x00\x00\x00\x00\x00");
        let err = Index::from_cache(&config).unwrap_err();
        assert!(matches!(err, Error::IndexDecode(_)));
    }

    #[test]
    fn truncated_after_magic() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        write_file(dir.path(), INDEX_BIN, INDEX_MAGIC_V1);
        let err = Index::from_cache(&config).unwrap_err();
        assert!(matches!(err, Error::IndexDecode(_)));
    }

    #[test]
    fn truncated_before_magic() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        write_file(dir.path(), INDEX_BIN, b"upki");
        let err = Index::from_cache(&config).unwrap_err();
        assert!(matches!(err, Error::IndexDecode(_)));
    }

    // A valid header whose counts imply tables far larger than the file must be
    // rejected before the table allocation is made.
    #[test]
    fn oversized_table_counts() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        let mut data = INDEX_MAGIC_V1.to_vec();
        data.extend_from_slice(&u16::MAX.to_be_bytes());
        data.extend_from_slice(&u32::MAX.to_be_bytes());
        write_file(dir.path(), INDEX_BIN, &data);
        let err = Index::from_cache(&config).unwrap_err();
        assert!(matches!(err, Error::IndexDecode(_)));
    }

    #[test]
    fn missing_index() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        let err = Index::from_cache(&config).unwrap_err();
        assert!(matches!(err, Error::FileRead { .. }));
    }

    #[test]
    fn check_single_filter_revoked() -> Result<(), Box<dyn StdError>> {
        let dir = tempfile::tempdir()?;
        let config = test_config(dir.path());

        // The filter enrolls our issuer and revokes our serial for log [0xbb; 32].
        let filter = build_filter([0xaa; 32], &[SERIAL], &[], &[([0xbb; 32], 0, 2000)]);
        write_file(dir.path(), "f0.filter", &filter);
        write_file(
            dir.path(),
            INDEX_BIN,
            &build_index(&[("f0.filter", &[([0xbb; 32], 0, 2000)])]),
        );

        assert_eq!(
            Index::from_cache(&config)?.check(&test_input())?,
            RevocationStatus::CertainlyRevoked,
        );

        Ok(())
    }

    #[test]
    fn check_single_filter_not_revoked() -> Result<(), Box<dyn StdError>> {
        let dir = tempfile::tempdir()?;
        let config = test_config(dir.path());

        // The filter enrolls our issuer but revokes a different serial, so our
        // serial is definitively not revoked.
        let filter = build_filter(
            [0xaa; 32],
            &[&[9, 9, 9]],
            &[SERIAL],
            &[([0xbb; 32], 0, 2000)],
        );
        write_file(dir.path(), "f0.filter", &filter);
        write_file(
            dir.path(),
            INDEX_BIN,
            &build_index(&[("f0.filter", &[([0xbb; 32], 0, 2000)])]),
        );

        assert_eq!(
            Index::from_cache(&config)?.check(&test_input())?,
            RevocationStatus::NotRevoked,
        );

        Ok(())
    }

    // The certificate has two SCTs. The filter covering the first does not enroll
    // our issuer, while the filter covering the second revokes it. Checking must
    // continue past the first (inconclusive) filter to reach the verdict.
    #[test]
    fn check_continues_past_not_enrolled_to_revoked() -> Result<(), Box<dyn StdError>> {
        let dir = tempfile::tempdir()?;
        let config = test_config(dir.path());

        let (log_a, log_b) = ([0xb1; 32], [0xb2; 32]);
        // f0 covers log_a but enrolls a different issuer -> NotEnrolled for us.
        let f0 = build_filter([0xcc; 32], &[&[7, 7]], &[], &[(log_a, 0, 2000)]);
        // f1 covers log_b and revokes our serial.
        let f1 = build_filter([0xaa; 32], &[SERIAL], &[], &[(log_b, 0, 2000)]);
        write_file(dir.path(), "f0.filter", &f0);
        write_file(dir.path(), "f1.filter", &f1);
        write_file(
            dir.path(),
            INDEX_BIN,
            &build_index(&[
                ("f0.filter", &[(log_a, 0, 2000)]),
                ("f1.filter", &[(log_b, 0, 2000)]),
            ]),
        );

        assert_eq!(
            Index::from_cache(&config)?.check(&multi_sct_input(&[(log_a, 1000), (log_b, 1000)]))?,
            RevocationStatus::CertainlyRevoked,
        );

        Ok(())
    }

    // Same shape as above, but the second filter reports the certificate as not
    // revoked. That verdict must still be reached past the inconclusive first filter.
    #[test]
    fn check_continues_past_not_enrolled_to_not_revoked() -> Result<(), Box<dyn StdError>> {
        let dir = tempfile::tempdir()?;
        let config = test_config(dir.path());

        let (log_a, log_b) = ([0xb1; 32], [0xb2; 32]);
        let f0 = build_filter([0xcc; 32], &[&[7, 7]], &[], &[(log_a, 0, 2000)]);
        // f1 enrolls our issuer but revokes a different serial -> not revoked.
        let f1 = build_filter([0xaa; 32], &[&[9, 9, 9]], &[SERIAL], &[(log_b, 0, 2000)]);
        write_file(dir.path(), "f0.filter", &f0);
        write_file(dir.path(), "f1.filter", &f1);
        write_file(
            dir.path(),
            INDEX_BIN,
            &build_index(&[
                ("f0.filter", &[(log_a, 0, 2000)]),
                ("f1.filter", &[(log_b, 0, 2000)]),
            ]),
        );

        assert_eq!(
            Index::from_cache(&config)?.check(&multi_sct_input(&[(log_a, 1000), (log_b, 1000)]))?,
            RevocationStatus::NotRevoked,
        );

        Ok(())
    }

    // Every covering filter is inconclusive (none enrolls our issuer), so the
    // certificate is reported as not covered.
    #[test]
    fn check_all_filters_not_enrolled() -> Result<(), Box<dyn StdError>> {
        let dir = tempfile::tempdir()?;
        let config = test_config(dir.path());

        let (log_a, log_b) = ([0xb1; 32], [0xb2; 32]);
        let f0 = build_filter([0xcc; 32], &[&[7, 7]], &[], &[(log_a, 0, 2000)]);
        let f1 = build_filter([0xdd; 32], &[&[8, 8]], &[], &[(log_b, 0, 2000)]);
        write_file(dir.path(), "f0.filter", &f0);
        write_file(dir.path(), "f1.filter", &f1);
        write_file(
            dir.path(),
            INDEX_BIN,
            &build_index(&[
                ("f0.filter", &[(log_a, 0, 2000)]),
                ("f1.filter", &[(log_b, 0, 2000)]),
            ]),
        );

        assert_eq!(
            Index::from_cache(&config)?.check(&multi_sct_input(&[(log_a, 1000), (log_b, 1000)]))?,
            RevocationStatus::NotCoveredByRevocationData,
        );

        Ok(())
    }

    // An earlier filter that revokes takes precedence: checking stops at the first
    // conclusive verdict without consulting (or even reading) later filters. Only
    // f0's file exists on disk; if the check tried to load f1 it would error.
    #[test]
    fn check_stops_at_first_revoked() -> Result<(), Box<dyn StdError>> {
        let dir = tempfile::tempdir()?;
        let config = test_config(dir.path());

        let (log_a, log_b) = ([0xb1; 32], [0xb2; 32]);
        // f0 covers log_a and revokes our serial.
        let f0 = build_filter([0xaa; 32], &[SERIAL], &[], &[(log_a, 0, 2000)]);
        write_file(dir.path(), "f0.filter", &f0);
        write_file(
            dir.path(),
            INDEX_BIN,
            &build_index(&[
                ("f0.filter", &[(log_a, 0, 2000)]),
                ("f1.filter", &[(log_b, 0, 2000)]),
            ]),
        );

        assert_eq!(
            Index::from_cache(&config)?.check(&multi_sct_input(&[(log_a, 1000), (log_b, 1000)]))?,
            RevocationStatus::CertainlyRevoked,
        );

        Ok(())
    }

    // A `Good` verdict must not short-circuit the check: the first filter reports
    // the certificate as not revoked, but a later filter revokes it. Revocation
    // wins, so the overall verdict is `CertainlyRevoked`.
    #[test]
    fn check_continues_past_not_revoked_to_revoked() -> Result<(), Box<dyn StdError>> {
        let dir = tempfile::tempdir()?;
        let config = test_config(dir.path());

        let (log_a, log_b) = ([0xb1; 32], [0xb2; 32]);
        // f0 enrolls our issuer but revokes a different serial -> not revoked.
        let f0 = build_filter([0xaa; 32], &[&[9, 9, 9]], &[SERIAL], &[(log_a, 0, 2000)]);
        // f1 covers log_b and revokes our serial.
        let f1 = build_filter([0xaa; 32], &[SERIAL], &[], &[(log_b, 0, 2000)]);
        write_file(dir.path(), "f0.filter", &f0);
        write_file(dir.path(), "f1.filter", &f1);
        write_file(
            dir.path(),
            INDEX_BIN,
            &build_index(&[
                ("f0.filter", &[(log_a, 0, 2000)]),
                ("f1.filter", &[(log_b, 0, 2000)]),
            ]),
        );

        assert_eq!(
            Index::from_cache(&config)?.check(&multi_sct_input(&[(log_a, 1000), (log_b, 1000)]))?,
            RevocationStatus::CertainlyRevoked,
        );

        Ok(())
    }

    // A single log_id can have more than one covering filter. The first does not
    // enroll our issuer, but the second (for the same log and timestamp) revokes
    // our serial. All covering filters for the log must be consulted, not just the
    // first one.
    #[test]
    fn check_multiple_filters_same_log_revoked() -> Result<(), Box<dyn StdError>> {
        let dir = tempfile::tempdir()?;
        let config = test_config(dir.path());

        let log_a = [0xb1; 32];
        // f0 covers log_a but enrolls a different issuer -> NotEnrolled for us.
        let f0 = build_filter([0xcc; 32], &[&[7, 7]], &[], &[(log_a, 0, 2000)]);
        // f1 also covers log_a and revokes our serial.
        let f1 = build_filter([0xaa; 32], &[SERIAL], &[], &[(log_a, 0, 2000)]);
        write_file(dir.path(), "f0.filter", &f0);
        write_file(dir.path(), "f1.filter", &f1);
        write_file(
            dir.path(),
            INDEX_BIN,
            &build_index(&[
                ("f0.filter", &[(log_a, 0, 2000)]),
                ("f1.filter", &[(log_a, 0, 2000)]),
            ]),
        );

        assert_eq!(
            Index::from_cache(&config)?.check(&multi_sct_input(&[(log_a, 1000)]))?,
            RevocationStatus::CertainlyRevoked,
        );

        Ok(())
    }

    // Same shape as above, but the second covering filter for the log reports the
    // certificate as not revoked. Reaching that verdict past the inconclusive first
    // filter yields `NotRevoked` rather than `NotCoveredByRevocationData`.
    #[test]
    fn check_multiple_filters_same_log_not_revoked() -> Result<(), Box<dyn StdError>> {
        let dir = tempfile::tempdir()?;
        let config = test_config(dir.path());

        let log_a = [0xb1; 32];
        let f0 = build_filter([0xcc; 32], &[&[7, 7]], &[], &[(log_a, 0, 2000)]);
        // f1 also covers log_a, enrolls our issuer, but revokes a different serial.
        let f1 = build_filter([0xaa; 32], &[&[9, 9, 9]], &[SERIAL], &[(log_a, 0, 2000)]);
        write_file(dir.path(), "f0.filter", &f0);
        write_file(dir.path(), "f1.filter", &f1);
        write_file(
            dir.path(),
            INDEX_BIN,
            &build_index(&[
                ("f0.filter", &[(log_a, 0, 2000)]),
                ("f1.filter", &[(log_a, 0, 2000)]),
            ]),
        );

        assert_eq!(
            Index::from_cache(&config)?.check(&multi_sct_input(&[(log_a, 1000)]))?,
            RevocationStatus::NotRevoked,
        );

        Ok(())
    }

    // A log has two covering filters whose timestamp ranges do not overlap. The
    // first entry's range does not contain the SCT timestamp, but the second's
    // does and revokes our serial. A non-matching timestamp range must skip only
    // that entry, not abandon the remaining entries for the same log.
    #[test]
    fn check_later_timestamp_entry_same_log_revoked() -> Result<(), Box<dyn StdError>> {
        let dir = tempfile::tempdir()?;
        let config = test_config(dir.path());

        let log_a = [0xb1; 32];
        // f0 covers log_a for 2000..3000, which does not contain the SCT (1000).
        let f0 = build_filter([0xcc; 32], &[&[7, 7]], &[], &[(log_a, 2000, 3000)]);
        // f1 covers log_a for 0..2000, contains the SCT, and revokes our serial.
        let f1 = build_filter([0xaa; 32], &[SERIAL], &[], &[(log_a, 0, 2000)]);
        write_file(dir.path(), "f0.filter", &f0);
        write_file(dir.path(), "f1.filter", &f1);
        write_file(
            dir.path(),
            INDEX_BIN,
            &build_index(&[
                ("f0.filter", &[(log_a, 2000, 3000)]),
                ("f1.filter", &[(log_a, 0, 2000)]),
            ]),
        );

        assert_eq!(
            Index::from_cache(&config)?.check(&multi_sct_input(&[(log_a, 1000)]))?,
            RevocationStatus::CertainlyRevoked,
        );

        Ok(())
    }

    // Same shape as above, but the timestamp-matching entry reports the certificate
    // as not revoked. That verdict must still be reached past the earlier entry
    // whose range does not cover the SCT.
    #[test]
    fn check_later_timestamp_entry_same_log_not_revoked() -> Result<(), Box<dyn StdError>> {
        let dir = tempfile::tempdir()?;
        let config = test_config(dir.path());

        let log_a = [0xb1; 32];
        let f0 = build_filter([0xcc; 32], &[&[7, 7]], &[], &[(log_a, 2000, 3000)]);
        // f1 covers the SCT, enrolls our issuer, but revokes a different serial.
        let f1 = build_filter([0xaa; 32], &[&[9, 9, 9]], &[SERIAL], &[(log_a, 0, 2000)]);
        write_file(dir.path(), "f0.filter", &f0);
        write_file(dir.path(), "f1.filter", &f1);
        write_file(
            dir.path(),
            INDEX_BIN,
            &build_index(&[
                ("f0.filter", &[(log_a, 2000, 3000)]),
                ("f1.filter", &[(log_a, 0, 2000)]),
            ]),
        );

        assert_eq!(
            Index::from_cache(&config)?.check(&multi_sct_input(&[(log_a, 1000)]))?,
            RevocationStatus::NotRevoked,
        );

        Ok(())
    }

    // The SCT timestamp falls in the range of a later entry only; an entry whose
    // range misses must not stop the scan before the covering entry is consulted.
    // The earlier entry's filter file is absent on disk, so the check would error
    // if it wrongly tried to load it.
    #[test]
    fn check_skips_non_matching_entry_without_loading_filter() -> Result<(), Box<dyn StdError>> {
        let dir = tempfile::tempdir()?;
        let config = test_config(dir.path());

        let log_a = [0xb1; 32];
        // f1 covers the SCT and revokes our serial; only its file exists on disk.
        let f1 = build_filter([0xaa; 32], &[SERIAL], &[], &[(log_a, 0, 2000)]);
        write_file(dir.path(), "f1.filter", &f1);
        write_file(
            dir.path(),
            INDEX_BIN,
            &build_index(&[
                ("f0.filter", &[(log_a, 2000, 3000)]),
                ("f1.filter", &[(log_a, 0, 2000)]),
            ]),
        );

        assert_eq!(
            Index::from_cache(&config)?.check(&multi_sct_input(&[(log_a, 1000)]))?,
            RevocationStatus::CertainlyRevoked,
        );

        Ok(())
    }

    // One filter covers both SCT logs but does not enroll our issuer. Its second
    // encounter (for the second SCT) is skipped as already-queried, and that skip
    // must not prevent the second log's other covering filter from being consulted
    // and revoking.
    #[test]
    fn check_skips_queried_filter_but_not_later_filters() -> Result<(), Box<dyn StdError>> {
        let dir = tempfile::tempdir()?;
        let config = test_config(dir.path());

        let (log_a, log_b) = ([0xb1; 32], [0xb2; 32]);
        // f0 covers both logs but enrolls a different issuer -> NotEnrolled for us.
        let f0 = build_filter(
            [0xcc; 32],
            &[&[7, 7]],
            &[],
            &[(log_a, 0, 2000), (log_b, 0, 2000)],
        );
        // f1 covers log_b and revokes our serial.
        let f1 = build_filter([0xaa; 32], &[SERIAL], &[], &[(log_b, 0, 2000)]);
        write_file(dir.path(), "f0.filter", &f0);
        write_file(dir.path(), "f1.filter", &f1);
        write_file(
            dir.path(),
            INDEX_BIN,
            &build_index(&[
                ("f0.filter", &[(log_a, 0, 2000), (log_b, 0, 2000)]),
                ("f1.filter", &[(log_b, 0, 2000)]),
            ]),
        );

        assert_eq!(
            Index::from_cache(&config)?.check(&multi_sct_input(&[(log_a, 1000), (log_b, 1000)]))?,
            RevocationStatus::CertainlyRevoked,
        );

        Ok(())
    }

    // A single filter covers both SCT logs and answers conclusively "not revoked".
    // The verdict from its first (and only) query must survive the deduplicated
    // second encounter.
    #[test]
    fn check_single_filter_covering_multiple_scts_not_revoked() -> Result<(), Box<dyn StdError>> {
        let dir = tempfile::tempdir()?;
        let config = test_config(dir.path());

        let (log_a, log_b) = ([0xb1; 32], [0xb2; 32]);
        // f0 enrolls our issuer but revokes a different serial -> not revoked.
        let f0 = build_filter(
            [0xaa; 32],
            &[&[9, 9, 9]],
            &[SERIAL],
            &[(log_a, 0, 2000), (log_b, 0, 2000)],
        );
        write_file(dir.path(), "f0.filter", &f0);
        write_file(
            dir.path(),
            INDEX_BIN,
            &build_index(&[("f0.filter", &[(log_a, 0, 2000), (log_b, 0, 2000)])]),
        );

        assert_eq!(
            Index::from_cache(&config)?.check(&multi_sct_input(&[(log_a, 1000), (log_b, 1000)]))?,
            RevocationStatus::NotRevoked,
        );

        Ok(())
    }

    // Checking a legacy "upkiidx0" index for a revoked result.
    #[test]
    fn check_v0_index_revoked() -> Result<(), Box<dyn StdError>> {
        let dir = tempfile::tempdir()?;
        let config = test_config(dir.path());

        let (log_a, log_b) = ([0xb1; 32], [0xb2; 32]);
        // f0 covers log_a but enrolls a different issuer -> NotEnrolled for us.
        let f0 = build_filter([0xcc; 32], &[&[7, 7]], &[], &[(log_a, 0, 2000)]);
        // f1 covers log_b and revokes our serial.
        let f1 = build_filter([0xaa; 32], &[SERIAL], &[], &[(log_b, 0, 2000)]);
        write_file(dir.path(), "f0.filter", &f0);
        write_file(dir.path(), "f1.filter", &f1);
        write_file(
            dir.path(),
            INDEX_BIN,
            &build_index_v0(&[
                ("f0.filter", &[(log_a, 0, 2000)]),
                ("f1.filter", &[(log_b, 0, 2000)]),
            ]),
        );

        assert_eq!(
            Index::from_cache(&config)?.check(&multi_sct_input(&[(log_a, 1000), (log_b, 1000)]))?,
            RevocationStatus::CertainlyRevoked,
        );

        Ok(())
    }

    // Checking a legacy "upkiidx0" index for a not revoked result.
    #[test]
    fn check_v0_index_not_revoked() -> Result<(), Box<dyn StdError>> {
        let dir = tempfile::tempdir()?;
        let config = test_config(dir.path());

        let filter = build_filter(
            [0xaa; 32],
            &[&[9, 9, 9]],
            &[SERIAL],
            &[([0xbb; 32], 0, 2000)],
        );
        write_file(dir.path(), "f0.filter", &filter);
        write_file(
            dir.path(),
            INDEX_BIN,
            &build_index_v0(&[("f0.filter", &[([0xbb; 32], 0, 2000)])]),
        );

        assert_eq!(
            Index::from_cache(&config)?.check(&test_input())?,
            RevocationStatus::NotRevoked,
        );

        Ok(())
    }

    // Checking a legacy "upkiidx0" index that's empty should produce not covered.
    #[test]
    fn check_empty_v0_index() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        write_file(dir.path(), INDEX_BIN, &build_index_v0(&[]));
        assert_eq!(
            Index::from_cache(&config)
                .unwrap()
                .check(&test_input())
                .unwrap(),
            RevocationStatus::NotCoveredByRevocationData,
        );
    }

    // Checking a malformed filter that has a filter index beyond the filename table must err.
    #[test]
    fn check_filter_index_out_of_bounds() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());

        let mut data = build_index(&[("f0.filter", &[([0xbb; 32], 0, 2000)])]);
        // Overwrite the sole entry's filter_index (first two bytes of the entry
        // section, which build_index places at the end of the tables).
        let entry_offset = data.len() - ENTRY_SIZE_V1;
        data[entry_offset..entry_offset + 2].copy_from_slice(&500u16.to_be_bytes());
        write_file(dir.path(), INDEX_BIN, &data);

        let err = Index::from_cache(&config)
            .unwrap()
            .check(&test_input())
            .unwrap_err();
        assert!(matches!(err, Error::IndexDecode(_)));
    }

    /// Build a test index with INDEX_MAGIC_V1 with u16 filter indexes.
    #[expect(clippy::type_complexity)]
    fn build_index(filters: &[(&str, &[([u8; 32], u64, u64)])]) -> Vec<u8> {
        build_index_with_magic(INDEX_MAGIC_V1, filters)
    }

    /// Build a test legacy INDEX_MAGIC_V0 index with u8 filter indexes.
    #[expect(clippy::type_complexity)]
    fn build_index_v0(filters: &[(&str, &[([u8; 32], u64, u64)])]) -> Vec<u8> {
        build_index_with_magic(INDEX_MAGIC_V0, filters)
    }

    /// Build a test index with the given magic header bytes.
    ///
    /// The data types used for `num_filenames` and the entry `filter_index` are
    /// determined by the magic bytes, using u8 for INDEX_MAGIC_V0, and u16
    /// otherwise.
    #[expect(clippy::type_complexity)]
    fn build_index_with_magic(
        magic: &[u8; 8],
        filters: &[(&str, &[([u8; 32], u64, u64)])],
    ) -> Vec<u8> {
        let (base_size, entry_size) = match magic {
            INDEX_MAGIC_V0 => (HEADER_SIZE_V0, ENTRY_SIZE_V0),
            _ => (HEADER_SIZE_V1, ENTRY_SIZE_V1),
        };

        // Aggregate by log_id using BTreeMap for sorted order
        let mut by_log_id: BTreeMap<[u8; 32], Vec<(u16, u64, u64)>> = BTreeMap::new();
        for (filter_idx, (_, entries)) in filters.iter().enumerate() {
            for (log_id, min_ts, max_ts) in *entries {
                by_log_id
                    .entry(*log_id)
                    .or_default()
                    .push((filter_idx as u16, *min_ts, *max_ts));
            }
        }

        // Compute header size
        let header_size =
            base_size + filters.len() * FILENAME_SIZE + by_log_id.len() * LOG_DIR_ENTRY_SIZE;

        // Write header
        let mut buf = Vec::new();
        buf.extend_from_slice(magic);
        match entry_size {
            ENTRY_SIZE_V0 => buf.push(filters.len() as u8),
            _ => buf.extend_from_slice(&(filters.len() as u16).to_be_bytes()),
        }
        buf.extend_from_slice(&(by_log_id.len() as u32).to_be_bytes());

        // Write filename table (fixed 32-byte slots, NULL-padded)
        for (filename, _) in filters {
            let bytes = filename.as_bytes();
            let mut slot = [0u8; FILENAME_SIZE];
            slot[..bytes.len()].copy_from_slice(bytes);
            buf.extend_from_slice(&slot);
        }

        // Compute offsets and write directory
        let mut current_offset = header_size;
        let mut entry_counts: Vec<usize> = Vec::new();
        for (log_id, entries) in &by_log_id {
            buf.extend_from_slice(log_id);
            buf.extend_from_slice(&(current_offset as u64).to_be_bytes());
            buf.extend_from_slice(&(entries.len() as u16).to_be_bytes());
            current_offset += entries.len() * entry_size;
            entry_counts.push(entries.len());
        }

        // Write entry sections
        for entries in by_log_id.values() {
            for (filter_idx, min_ts, max_ts) in entries {
                match entry_size {
                    ENTRY_SIZE_V0 => buf.push(*filter_idx as u8),
                    _ => buf.extend_from_slice(&filter_idx.to_be_bytes()),
                }
                buf.extend_from_slice(&min_ts.to_be_bytes());
                buf.extend_from_slice(&max_ts.to_be_bytes());
            }
        }

        buf
    }

    /// Build a serialized CRLite filter that enrolls `issuer`, marks each serial in
    /// `revoked` as revoked, each serial in `not_revoked` as not revoked, and
    /// covers each `(log_id, min_ts, max_ts)` interval.
    ///
    /// The filter is only exact for serials in its universe: a serial whose
    /// verdict a test relies on must be listed in `revoked` or `not_revoked`, or
    /// that verdict is probabilistic (a ~1/256 chance of a false "revoked",
    /// varying per run since clubcard randomizes ribbon solutions).
    fn build_filter(
        issuer: [u8; 32],
        revoked: &[&[u8]],
        unrevoked: &[&[u8]],
        coverage: &[([u8; 32], u64, u64)],
    ) -> Vec<u8> {
        let issuer = IssuerSpkiHash(issuer);
        let universe_size = 1 << 8;

        let mut builder = ClubcardBuilder::new();
        let mut approx = builder.new_approx_builder(&issuer.0);
        for serial in revoked {
            approx.insert(CRLiteBuilderItem::revoked(issuer, serial.to_vec()));
        }
        approx.set_universe_size(universe_size);
        builder.collect_approx_ribbons(vec![ApproximateRibbon::from(approx)]);

        let mut exact = builder.new_exact_builder(&issuer.0);
        for serial in revoked {
            exact.insert(CRLiteBuilderItem::revoked(issuer, serial.to_vec()));
        }
        for serial in unrevoked {
            exact.insert(CRLiteBuilderItem::not_revoked(issuer, serial.to_vec()));
        }

        // The exact filter needs the full universe; fill it out with non-revoked
        // serials that cannot collide with the (short) revoked serials above.
        for j in 0usize..universe_size {
            exact.insert(CRLiteBuilderItem::not_revoked(
                issuer,
                j.to_le_bytes().to_vec(),
            ));
        }
        builder.collect_exact_ribbons(vec![ExactRibbon::from(exact)]);

        let entries = coverage
            .iter()
            .map(|(log_id, min_ts, max_ts)| {
                format!(
                    "{{\"LogID\":\"{}\",\"MaxTimestamp\":{max_ts},\"MinTimestamp\":{min_ts},\"MMD\":0,\"MinEntry\":0}}",
                    base64::prelude::BASE64_STANDARD.encode(log_id),
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let json = format!("[{entries}]");
        let coverage = CRLiteCoverage::from_mozilla_ct_logs_json(json.as_bytes());

        let clubcard = builder.build::<CRLiteQuery<'_>>(coverage, ());
        CRLiteClubcard::from(clubcard)
            .to_bytes(Encoding::V4)
            .unwrap()
    }

    fn multi_sct_input(scts: &[([u8; 32], u64)]) -> RevocationCheckInput {
        RevocationCheckInput::new(
            CertSerial(SERIAL.to_vec()),
            IssuerSpkiHash([0xaa; 32]),
            scts.iter()
                .map(|(log_id, timestamp)| CtTimestamp {
                    log_id: *log_id,
                    timestamp: *timestamp,
                })
                .collect(),
        )
    }

    fn test_config(dir: &Path) -> Config {
        Config {
            cache_dir: dir.to_owned(),
            revocation: RevocationConfig::default(),
            intermediates: IntermediatesConfig::default(),
        }
    }

    fn test_input() -> RevocationCheckInput {
        RevocationCheckInput::new(
            CertSerial(SERIAL.to_vec()),
            IssuerSpkiHash([0xaa; 32]),
            vec![CtTimestamp {
                log_id: [0xbb; 32],
                timestamp: 1000,
            }],
        )
    }

    fn write_file(dir: &Path, name: &str, data: &[u8]) {
        let revocation_dir = dir.join("revocation");
        fs::create_dir_all(&revocation_dir).unwrap();
        fs::write(revocation_dir.join(name), data).unwrap();
    }

    /// The serial number of the certificate checked by [`test_input`] and [`multi_sct_input`].
    const SERIAL: &[u8] = &[1, 2, 3];
}
