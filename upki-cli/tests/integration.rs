// these tests won't run on windows due to insurmountable disagreements over path formatting,
// but should work ok on macOS and WSL
#![cfg(not(target_os = "windows"))]

use core::error::Error;
use std::fs::create_dir;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::{fs, thread};

use insta::assert_snapshot;
use insta::internals::SettingsBindDropGuard;
use insta_cmd::assert_cmd_snapshot;
use rand::RngExt;
use tempfile::TempDir;

#[test]
fn version() {
    let _filters = apply_common_filters();
    assert_cmd_snapshot!(upki().arg("--version"), @"
    success: true
    exit_code: 0
    ----- stdout -----
    upki 1.0.0-beta.3

    ----- stderr -----
    ");
}

#[test]
fn config_unknown_fields() {
    let _filters = apply_common_filters();
    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg("tests/data/config_unknown_fields/config.toml")
            .arg("show-config"),
        @r#"
    success: false
    exit_code: 1
    ----- stdout -----

    ----- stderr -----
    Error: failed to parse config file at tests/data/config_unknown_fields/config.toml

    Caused by:
        TOML parse error at line 1, column 1
          |
        1 | cache_dir = "tests/data/config_unknown_fields/"
          | ^^^^^^^^^
        unknown field `cache_dir`, expected one of `cache-dir`, `revocation`, `intermediates`


    Location:
        upki-cli/src/bin/upki.rs:[LINE]:[COLUMN]
    "#);
}

#[test]
fn show_config_path_fixpoint() {
    let _filters = apply_common_filters();
    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg("/home/example/not-exist/yo.txt")
            .arg("show-config-path"),
        @r"
    success: true
    exit_code: 0
    ----- stdout -----
    /home/example/not-exist/yo.txt

    ----- stderr -----
    ");
}

#[test]
fn show_config_fixpoint() {
    let _filters = apply_common_filters();
    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg("tests/data/verify_non_existent_dir/config.toml")
            .arg("show-config"),
        @r#"
    success: true
    exit_code: 0
    ----- stdout -----
    cache-dir = "not-exist/"

    [revocation]
    fetch-url = ""

    [intermediates]
    enabled = false
    fetch-url = ""

    ----- stderr -----
    "#);
}

#[test]
fn verify_of_non_existent_dir() {
    let _filters = apply_common_filters();
    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg("tests/data/verify_non_existent_dir/config.toml")
            .arg("verify"),
        @r#"
    success: false
    exit_code: 1
    ----- stdout -----

    ----- stderr -----
    Error: cannot read file "not-exist/revocation/manifest.json"

    Caused by:
        No such file or directory (os error 2)

    Location:
        upki-cli/src/bin/upki.rs:[LINE]:[COLUMN]
    "#);
}

#[test]
fn verify_of_empty_manifest() {
    let _filters = apply_common_filters();
    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg("tests/data/verify_of_empty_manifest/config.toml")
            .arg("verify"),
        @r"
    success: true
    exit_code: 0
    ----- stdout -----

    ----- stderr -----
    ");
}

#[test]
fn verify_of_empty_intermediates_manifest() {
    let _filters = apply_common_filters();
    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg("tests/data/verify_of_empty_intermediates_manifest/config.toml")
            .arg("verify"),
        @r"
    success: true
    exit_code: 0
    ----- stdout -----

    ----- stderr -----
    ");
}

#[test]
fn fetch_of_empty_manifest() {
    let _filters = apply_common_filters();
    let (server, _filters) = http_server("tests/data/verify_of_empty_manifest/");
    let (temp, config_file, _filters) = temp_dir_and_config(server.url(), write_config);

    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg(config_file)
            .arg("fetch"),
        @r"
    success: true
    exit_code: 0
    ----- stdout -----

    ----- stderr -----
    ");
    assert_snapshot!(
        server.into_log(),
        @"GET /revocation/manifest.json  ->  200 OK (79 bytes)"
    );
    assert_eq!(
        list_dir(&temp.path().join("revocation")),
        vec!["index.bin", "manifest.json"],
    );
}

#[test]
fn full_fetch() {
    let _filters = apply_common_filters();
    let (server, _filters) = http_server("tests/data/typical/");
    let (temp, config_file, _filters) = temp_dir_and_config(server.url(), write_config);

    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg(config_file)
            .arg("fetch"),
        @r"
    success: true
    exit_code: 0
    ----- stdout -----

    ----- stderr -----
    ");
    assert_snapshot!(
        server.into_log(),
        @r"
    GET /revocation/manifest.json  ->  200 OK (530 bytes)
    GET /revocation/filter1.filter  ->  200 OK (11 bytes)
    GET /revocation/filter2.delta  ->  200 OK (14 bytes)
    GET /revocation/filter3.delta  ->  200 OK (10 bytes)
    ");
    assert_eq!(
        list_dir(&temp.path().join("revocation")),
        vec![
            "filter1.filter",
            "filter2.delta",
            "filter3.delta",
            "manifest.json"
        ]
    );
}

#[test]
fn full_fetch_of_intermediates() {
    let _filters = apply_common_filters();
    let (server, _filters) = http_server("tests/data/typical-intermediates/");
    let (temp, config_file, _filters) =
        temp_dir_and_config(server.url(), write_config_with_intermediates);

    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg(config_file)
            .arg("fetch"),
        @r"
    success: true
    exit_code: 0
    ----- stdout -----

    ----- stderr -----
    ");
    assert_snapshot!(
        server.into_log(),
        @r"
    GET /revocation/manifest.json  ->  200 OK (79 bytes)
    GET /intermediates/manifest.json  ->  200 OK (532 bytes)
    GET /intermediates/01.pem  ->  200 OK (1265 bytes)
    GET /intermediates/02.pem  ->  200 OK (1241 bytes)
    GET /intermediates/ff.pem  ->  200 OK (1103 bytes)
    ");
    assert_eq!(
        list_dir(&temp.path().join("intermediates")),
        vec!["01.pem", "02.pem", "ff.pem", "manifest.json"]
    );
}

#[test]
fn full_fetch_and_incremental_update() {
    let _filters = apply_common_filters();
    let (server, _filters) = http_server("tests/data/typical/");
    let (temp, config_file, _filters) = temp_dir_and_config(server.url(), write_config);

    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg(&config_file)
            .arg("fetch"),
        @r"
    success: true
    exit_code: 0
    ----- stdout -----

    ----- stderr -----
    ");
    assert_snapshot!(
        server.into_log(),
        @r"
    GET /revocation/manifest.json  ->  200 OK (530 bytes)
    GET /revocation/filter1.filter  ->  200 OK (11 bytes)
    GET /revocation/filter2.delta  ->  200 OK (14 bytes)
    GET /revocation/filter3.delta  ->  200 OK (10 bytes)
    ");
    assert_eq!(
        list_dir(&temp.path().join("revocation")),
        vec![
            "filter1.filter",
            "filter2.delta",
            "filter3.delta",
            "manifest.json"
        ],
    );

    // now server is updated to "evolution" which requires a partial update
    // compared to "typical"
    let (server, _filters) = http_server("tests/data/evolution/");
    write_config(&temp, server.url());
    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg(&config_file)
            .arg("fetch"),
        @r"
    success: true
    exit_code: 0
    ----- stdout -----

    ----- stderr -----
    ");
    assert_snapshot!(
        server.into_log(),
        @r"
    GET /revocation/manifest.json  ->  200 OK (545 bytes)
    GET /revocation/filter4.delta  ->  200 OK (3 bytes)
    ");
    // filter2 could be deleted, filter4 is new
    assert_eq!(
        list_dir(&temp.path().join("revocation")),
        vec![
            "filter1.filter",
            "filter2.delta",
            "filter3.delta",
            "filter4.delta",
            "manifest.json"
        ]
    );

    // a fetch of the same manifest clears away "filter2.delta" as it is now unused
    let (server, _filters) = http_server("tests/data/evolution/");
    write_config(&temp, server.url());
    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg(&config_file)
            .arg("fetch"),
        @r"
    success: true
    exit_code: 0
    ----- stdout -----

    ----- stderr -----
    ");
    assert_snapshot!(
        server.into_log(),
        @"GET /revocation/manifest.json  ->  200 OK (545 bytes)");

    // filter2 is now deleted
    assert_eq!(
        list_dir(&temp.path().join("revocation")),
        vec![
            "filter1.filter",
            "filter3.delta",
            "filter4.delta",
            "manifest.json"
        ]
    );
}

#[test]
fn typical_incremental_fetch() {
    let _filters = apply_common_filters();
    let (server, _filters) = http_server("tests/data/typical/");
    let (temp, config_file, _filters) = temp_dir_and_config(server.url(), write_config);

    fs::copy(
        "tests/data/typical/revocation/manifest.json",
        temp.path()
            .join("revocation/manifest.json"),
    )
    .unwrap();
    fs::copy(
        "tests/data/typical/revocation/filter1.filter",
        temp.path()
            .join("revocation/filter1.filter"),
    )
    .unwrap();
    fs::copy(
        "tests/data/typical/revocation/filter3.delta",
        temp.path()
            .join("revocation/filter3.delta"),
    )
    .unwrap();

    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg(config_file)
            .arg("fetch"),
        @r"
    success: true
    exit_code: 0
    ----- stdout -----

    ----- stderr -----
    ");

    // only fetched the neccessary files
    assert_snapshot!(
        server.into_log(),
        @r"
    GET /revocation/manifest.json  ->  200 OK (530 bytes)
    GET /revocation/filter2.delta  ->  200 OK (14 bytes)
    ");

    assert_eq!(list_dir(temp.path()), vec!["config.toml", "revocation",],);

    assert_eq!(
        list_dir(&temp.path().join("revocation")),
        vec![
            "filter1.filter",
            "filter2.delta",
            "filter3.delta",
            "manifest.json"
        ]
    );
}

#[test]
fn typical_incremental_fetch_dry_run() {
    let _filters = apply_common_filters();
    let (server, _filters) = http_server("tests/data/typical/");
    let (temp, config_file, _filters) = temp_dir_and_config(server.url(), write_config);
    fs::copy(
        "tests/data/typical/revocation/manifest.json",
        temp.path()
            .join("revocation/manifest.json"),
    )
    .unwrap();
    fs::copy(
        "tests/data/typical/revocation/filter1.filter",
        temp.path()
            .join("revocation/filter1.filter"),
    )
    .unwrap();
    fs::copy(
        "tests/data/typical/revocation/filter3.delta",
        temp.path()
            .join("revocation/filter3.delta"),
    )
    .unwrap();

    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg(config_file)
            .arg("fetch")
            .arg("--dry-run"),
        @r#"
    success: true
    exit_code: 0
    ----- stdout -----
    3 steps required (14 bytes to download)
    - download 14 bytes from http://127.0.0.1:[PORT]/revocation/filter2.delta to "[TEMPDIR]/revocation/filter2.delta"
    - build index from filters into "[TEMPDIR]/revocation"
    - save new manifest into "[TEMPDIR]/revocation"

    ----- stderr -----
    "#);

    // fetched just the manifest
    assert_eq!(list_dir(temp.path()), vec!["config.toml", "revocation",],);

    assert_eq!(
        list_dir(&temp.path().join("revocation")),
        vec!["filter1.filter", "filter3.delta", "manifest.json"]
    );
}

fn upki() -> Command {
    let mut cmd = Command::new("cargo");
    cmd.arg("run")
        .arg("--quiet")
        .arg("--package")
        .arg("upki-cli")
        .arg("--");
    cmd
}

fn http_server(root: &str) -> (TestHttpServer, SettingsBindDropGuard) {
    let port = rand::rng().random_range(4000..12000);

    // add a filter eliding the (random) port in logs
    let mut current_filters = insta::Settings::clone_current();
    current_filters.add_filter(&format!(":{port}/"), ":[PORT]/");

    (
        TestHttpServer::new(("127.0.0.1", port), Path::new(root)).unwrap(),
        current_filters.bind_to_scope(),
    )
}

fn list_dir(path: &Path) -> Vec<String> {
    let mut list = fs::read_dir(path)
        .unwrap()
        .map(|p| {
            p.unwrap()
                .file_name()
                .into_string()
                .unwrap()
        })
        .collect::<Vec<_>>();
    list.sort();
    list
}

fn temp_dir_and_config(
    fetch_url: &str,
    config_write: impl FnOnce(&TempDir, &str),
) -> (TempDir, PathBuf, SettingsBindDropGuard) {
    let temp = TempDir::new().unwrap();
    config_write(&temp, fetch_url);

    let mut settings = insta::Settings::clone_current();
    // remove tempdirs references
    settings.add_filter(
        &regex::escape(&temp.path().display().to_string()),
        "[TEMPDIR]",
    );

    let config_file = temp.path().join("config.toml");
    create_dir(temp.path().join("revocation")).unwrap();

    (temp, config_file, settings.bind_to_scope())
}

fn write_config(temp: &TempDir, fetch_url: &str) {
    fs::write(
        temp.path().join("config.toml"),
        format!(
            "cache-dir=\"{}\"\n\
            [revocation]\n\
            fetch-url=\"{fetch_url}revocation/\"\n",
            temp.path().display(),
        )
        .as_bytes(),
    )
    .unwrap();
}

fn write_config_with_intermediates(temp: &TempDir, fetch_url: &str) {
    fs::write(
        temp.path().join("config.toml"),
        format!(
            "cache-dir=\"{}\"\n\
                    [revocation]\n\
                    fetch-url=\"{fetch_url}revocation/\"\n\
                    [intermediates]\n\
                    enabled=true\n\
                    fetch-url=\"{fetch_url}intermediates/\"\n",
            temp.path().display(),
        )
        .as_bytes(),
    )
    .unwrap();
}

fn apply_common_filters() -> SettingsBindDropGuard {
    let mut settings = insta::Settings::clone_current();
    // remove source locations in errors
    settings.add_filter(r"\.rs:\d+:\d+", ".rs:[LINE]:[COLUMN]");
    // remove http.server timestamps
    settings.add_filter(
        r"\d{2}/[A-Z][a-z]{2}/\d{4} \d{2}:\d{2}:\d{2}",
        "[TIMESTAMP]",
    );

    settings.bind_to_scope()
}

pub struct TestHttpServer {
    server: Arc<tiny_http::Server>,
    url: String,
    handle: Option<thread::JoinHandle<String>>,
}

impl TestHttpServer {
    pub fn new(
        addr: (&str, u16),
        server_root: &Path,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let server = Arc::new(tiny_http::Server::http(addr)?);

        let thread_server = server.clone();
        let server_root = server_root.to_owned();

        let joiner = thread::spawn(move || {
            let mut log = String::new();

            for request in thread_server.incoming_requests() {
                let target = server_root.join(request.url().strip_prefix("/").unwrap());

                let response = match fs::read(&target) {
                    Ok(data) => tiny_http::Response::from_data(data),
                    Err(e) => tiny_http::Response::from_string(e.to_string()).with_status_code(404),
                };
                log.push_str(&format!(
                    "{} {}  ->  {} {} ({} bytes)\n",
                    request.method(),
                    request.url(),
                    response.status_code().0,
                    response
                        .status_code()
                        .default_reason_phrase(),
                    response
                        .data_length()
                        .unwrap_or_default(),
                ));

                let _ = request.respond(response);
            }

            log
        });

        Ok(Self {
            server,
            url: format!("http://{}:{}/", addr.0, addr.1),
            handle: Some(joiner),
        })
    }

    pub fn into_log(mut self) -> String {
        self.server.unblock();
        self.handle
            .take()
            .unwrap()
            .join()
            .unwrap()
    }

    pub fn url(&self) -> &str {
        &self.url
    }
}

impl Drop for TestHttpServer {
    fn drop(&mut self) {
        self.server.unblock();
    }
}
