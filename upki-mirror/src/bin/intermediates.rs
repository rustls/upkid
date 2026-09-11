use core::time::Duration;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;

use aws_lc_rs::digest::{SHA256, digest};
use clap::Parser;
use eyre::{Context, Report, anyhow};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use serde::Deserialize;
use upki::data::{Manifest, ManifestFile};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Report> {
    let opts = Opts::try_parse()?;

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .timeout(Duration::from_secs(opts.http_timeout_secs))
        .user_agent(format!(
            "{}/{} ({})",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
            env!("CARGO_PKG_REPOSITORY")
        ))
        .build()
        .wrap_err("failed to create HTTP client")?;

    let response = client
        .get("https://ccadb.my.salesforce-sites.com/mozilla/MozillaIntermediateCertsCSVReport")
        .send()
        .await
        .wrap_err("records request failed")?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "HTTP error for records request: {}",
            response.status()
        ));
    }

    let csv_bytes = response
        .bytes()
        .await
        .wrap_err("failed to receive CSV body")?;

    let intermediates = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(&mut csv_bytes.as_ref())
        .into_deserialize::<IntermediateData>()
        .collect::<Result<Vec<_>, _>>()
        .wrap_err("failed to parse CSV")?;

    println!("we have {} intermediates", intermediates.len());

    // we bucket intermediates into up to 256 files, by the first byte of the
    // sha256-hash of their DER value.
    //
    // that means the manifest contains up to 256 items, and the filenames are small.
    let mut buckets: HashMap<u8, Vec<IntermediateData>> = HashMap::new();

    for i in intermediates {
        let der = CertificateDer::from_pem_slice(i.pem.as_bytes()).wrap_err("cannot parse PEM")?;

        // check hash matches
        let actual_hash = digest(&SHA256, &der);
        if i.sha256 != actual_hash.as_ref() {
            return Err(anyhow!("cert {i:?} does not have correct hash"));
        }

        let bucket = i.sha256[0];
        buckets
            .entry(bucket)
            .or_default()
            .push(i);
    }

    let mut files = Vec::new();
    for (bucket, certs) in buckets {
        let filename = format!("{bucket:02x?}.pem",);

        let mut contents = String::new();
        for inter in certs {
            contents.push_str(&inter.pem);
            contents.push('\n');
        }

        fs::write(opts.output_dir.join(&filename), &contents).wrap_err("cannot write PEM file")?;
        let hash = digest(&SHA256, contents.as_bytes());

        files.push(ManifestFile {
            filename,
            size: contents.len(),
            hash: hash.as_ref().to_vec(),
        });
    }

    let manifest = Manifest {
        generated_at: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        comment: opts.manifest_comment.clone(),
        files,
    };
    let output_filename = opts.output_dir.join("manifest.json");
    fs::write(
        output_filename,
        serde_json::to_string(&manifest)
            .wrap_err("cannot encode JSON manifest")?
            .as_bytes(),
    )
    .wrap_err_with(|| "cannot write manifest to {output_filename:?}")?;

    Ok(())
}

#[derive(Debug, Parser)]
struct Opts {
    /// Where to write output files.  This must exist.
    output_dir: PathBuf,

    /// Timeout in seconds for all HTTP requests.
    #[clap(long, default_value_t = 10)]
    http_timeout_secs: u64,

    /// Comment included in output manifest.
    #[clap(long, default_value = "")]
    manifest_comment: String,
}

#[non_exhaustive]
#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
struct IntermediateData {
    #[serde(rename = "Subject")]
    subject: String,

    #[serde(rename = "Issuer")]
    issuer: String,

    #[serde(rename = "SHA256", with = "hex::serde")]
    sha256: [u8; 32],

    #[serde(rename = "Full CRL Issued By This CA")]
    full_crl: String,

    #[serde(rename = "PEM")]
    pem: String,

    #[serde(rename = "JSON Array of Partitioned CRLs")]
    json_crls: String,
}
