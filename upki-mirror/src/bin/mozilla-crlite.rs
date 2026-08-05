use core::time::Duration;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;

use aws_lc_rs::digest::{SHA256, digest};
use clap::{Parser, ValueEnum};
use eyre::{Context, Report, anyhow};
use upki::data::{Manifest, ManifestFile};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Report> {
    let opts = Opts::try_parse()?;
    let source = Source::from(opts.mozilla_backend);

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
        .get(source.records_url)
        .send()
        .await
        .wrap_err("records request failed")?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "HTTP error for records request: {}",
            response.status()
        ));
    }

    let incoming_manifest = response
        .json::<mozilla::Manifest>()
        .await
        .wrap_err("failed to parse records JSON")?;

    let by_parent: HashMap<String, &mozilla::Item> = HashMap::from_iter(
        incoming_manifest
            .data
            .iter()
            .filter_map(|it| Some((it.parent.as_ref()?.clone(), it))),
    );

    // Walk the DAG of filters, starting from the root full filter.
    let mut next = incoming_manifest
        .data
        .iter()
        .find(|it| {
            !it.incremental && it.parent.is_none() && it.channel == mozilla::Channel::Default
        });

    let mut download_plan = Vec::new();

    while let Some(item) = next {
        next = by_parent.get(&item.id).copied();
        download_plan.push(item);
    }

    let mut files = Vec::new();

    for p in download_plan {
        let attachment_url = source.attachment_host.to_string() + &p.attachment.location;
        let response = client
            .get(&attachment_url)
            .send()
            .await
            .wrap_err_with(|| format!("download request failed for {attachment_url}"))?;
        let bytes = response.bytes().await?;

        // check hash matches
        let actual_hash = digest(&SHA256, &bytes);
        if p.attachment.hash != actual_hash.as_ref() {
            return Err(anyhow!(
                "item {p:?} downloaded from {attachment_url:?} does not have correct hash"
            ));
        }

        // and size (impossible if hash is correct, but should make us distrust the data)
        if p.attachment.size != bytes.len() {
            return Err(anyhow!(
                "item {p:?} downloaded from {attachment_url:?} does not have correct size"
            ));
        }

        let output_filename = opts
            .output_dir
            .join(&p.attachment.filename);
        fs::write(&output_filename, bytes)
            .wrap_err_with(|| format!("cannot write filter data to {output_filename:?}",))?;

        files.push(ManifestFile {
            filename: p.attachment.filename.clone(),
            size: p.attachment.size,
            hash: p.attachment.hash.clone(),
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

    /// Which Mozilla settings backend to fetch from.
    #[clap(default_value_t = MozillaBackend::Production)]
    #[arg(value_enum)]
    mozilla_backend: MozillaBackend,

    /// Timeout in seconds for all HTTP requests.
    #[clap(long, default_value_t = 10)]
    http_timeout_secs: u64,

    /// Comment included in output manifest.
    #[clap(long, default_value = "")]
    manifest_comment: String,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum MozillaBackend {
    Production,
}

struct Source {
    records_url: &'static str,
    attachment_host: &'static str,
}

impl From<MozillaBackend> for Source {
    fn from(value: MozillaBackend) -> Self {
        match value {
            MozillaBackend::Production => MOZILLA_PROD,
        }
    }
}

const MOZILLA_PROD: Source = Source {
    records_url: "https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/cert-revocations/records",
    attachment_host: "https://firefox-settings-attachments.cdn.mozilla.net/",
};

/// JSON structures used in the Mozilla preferences service.
mod mozilla {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    pub(crate) struct Manifest {
        pub(crate) data: Vec<Item>,
    }

    #[derive(Clone, Debug, Deserialize)]
    pub(crate) struct Item {
        pub(crate) attachment: Attachment,
        pub(crate) channel: Channel,
        pub(crate) id: String,
        pub(crate) incremental: bool,
        pub(crate) parent: Option<String>,
    }

    #[derive(Clone, Debug, Deserialize, PartialEq)]
    #[serde(rename_all = "snake_case")]
    pub(crate) enum Channel {
        Default,
        Compat,
    }

    #[derive(Clone, Debug, Deserialize)]
    pub(crate) struct Attachment {
        #[serde(with = "hex::serde")]
        pub hash: Vec<u8>,
        pub size: usize,
        pub filename: String,
        pub location: String,
    }
}
