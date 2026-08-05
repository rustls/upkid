//! upki command-line entrypoint.

use std::io::{BufReader, stdin};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use eyre::{Context, Report};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
#[cfg(feature = "__fetch")]
use upki::intermediates;
#[cfg(feature = "__fetch")]
use upki::revocation;
use upki::revocation::{Index, RevocationCheckInput};
use upki::{Config, ConfigPath};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<ExitCode, Report> {
    let args = Args::parse();
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().compact())
        .with(
            EnvFilter::builder()
                .with_default_directive(
                    match args.verbose {
                        true => LevelFilter::TRACE,
                        false => LevelFilter::ERROR,
                    }
                    .into(),
                )
                .from_env()?,
        )
        .init();

    let config_path =
        ConfigPath::new(args.config_file).wrap_err("cannot find configuration path")?;

    if let Command::ShowConfigPath = args.command {
        println!("{}", config_path.as_ref().display());
        return Ok(ExitCode::SUCCESS);
    }

    let config = Config::from_file_or_user_default(&config_path)?;

    Ok(match args.command {
        #[cfg(feature = "__fetch")]
        Command::Fetch { dry_run } => {
            revocation::fetch(dry_run, &config).await?;
            intermediates::fetch(dry_run, &config).await?;
            ExitCode::SUCCESS
        }
        #[cfg(feature = "__fetch")]
        Command::Verify => {
            revocation::Manifest::from_config(&config)?.verify(&config)?;
            if config.intermediates.enabled {
                intermediates::Manifest::from_config(&config)?.verify(&config)?;
            }
            ExitCode::SUCCESS
        }
        Command::ShowConfigPath => unreachable!(),
        Command::ShowConfig => {
            print!(
                "{}",
                toml::to_string_pretty(&config).wrap_err("cannot format configuration")?
            );
            ExitCode::SUCCESS
        }
        Command::Revocation(Revocation::Check) => {
            let mut certs = vec![];

            for cert in CertificateDer::pem_reader_iter(&mut BufReader::new(stdin())) {
                certs.push(cert.wrap_err("cannot read certificate from stdin")?);
            }

            let input = RevocationCheckInput::from_certificates(&certs)?;
            Index::from_cache(&config)?
                .check(&input)?
                .to_cli()
        }
    })
}

#[derive(Debug, Parser)]
#[command(name = "upki", author, version, about)]
struct Args {
    #[command(subcommand)]
    command: Command,

    /// Use this specific configuration file.  This must exist.
    ///
    /// If not specified, this tool looks for its configuration file in a platform-standard local directory.
    #[arg(long)]
    config_file: Option<PathBuf>,

    /// Emit logging output.
    #[arg(long)]
    verbose: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Update the local cache of crlite filters, downloading them as needed.
    ///
    /// If the `revocation.cache_dir` path does not exist, this tool creates it and parent directories.
    ///
    /// This also deletes filters that become unreferenced.
    #[cfg(feature = "__fetch")]
    Fetch {
        /// Download the new manifest, and then describe what actions are needed to
        /// synchronize with the remote server.
        #[arg(long)]
        dry_run: bool,
    },

    /// Verifies the local cache of crlite filters.
    ///
    /// Exits zero if the manifest and all referenced filters are present.
    ///
    /// Exits non-zero if the manifest if any filter file is missing or corrupt.
    ///
    /// This command does no network I/O.  It does not say anything whether the files are up-to-date or recent.
    #[cfg(feature = "__fetch")]
    Verify,

    /// Checks the revocation status of a certificate.
    #[clap(subcommand)]
    Revocation(Revocation),

    /// Print the location of the configuration file.
    ShowConfigPath,

    /// Print the configuration that will be used.
    ShowConfig,
}

#[derive(Debug, Subcommand)]
enum Revocation {
    /// Check the revocation status of an end-entity certificate.
    ///
    /// This interface reads a sequence of PEM-encoded certificates from standard input.
    /// The first **must** be the end-entity certificate.  The end-entity certificate's issuer
    /// **must** be present in the other certificates (but does not need to be in any specific
    /// position).
    ///
    /// Note this interface **only** checks the end-entity certificate for revocation.  It does
    /// **not** check any of the certificates for validity: it assumes the caller has done any
    /// required checks **before** calling this interface (path building, naming validation,
    /// expiry checking, etc.).
    ///
    /// # Exit status
    ///
    /// 0 means the certificate is not revoked or no revocation information is available,
    /// 1 means an error prevented the revocation check, and
    /// 2 means the revocation check completed and the certificate is revoked.
    Check,
}
