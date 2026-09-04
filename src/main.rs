use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Parser, Subcommand};
use llmap::admin::{AdminSessionManager, SessionPolicy};
use llmap::auth::Authenticator;
use llmap::config::Config;
use llmap::data_plane::{DataPlane, ReqwestTransport};
use llmap::egress::DestinationPolicy;
use llmap::forward_proxy::{ForwardProxyHandler, generate_ca, serve_forward_proxy};
use llmap::http_app::{AdminRuntimeConfig, application_router};
use llmap::migration::{import_claudeproxy_env, parse_claudeproxy_env};
use llmap::routing::Router;
use llmap::secrets::{AdminPasswordHash, SecretBox, SecretInput, parse_master_key};
use llmap::storage::SqliteStore;
use sha2::{Digest, Sha256};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "llmap", version, about = "Provider-neutral LLM account proxy")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the reverse proxy and branded administrator control plane.
    Serve {
        #[arg(long, default_value = "llmap.toml")]
        config: PathBuf,
    },
    /// Validate configuration without opening listeners or secrets.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Create or inspect the local MITM certificate authority.
    Ca {
        #[command(subcommand)]
        command: CaCommand,
    },
    /// Import accounts from Claudeproxy's env file without printing secrets.
    Migrate {
        #[command(subcommand)]
        command: MigrateCommand,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    Check {
        #[arg(long, default_value = "llmap.toml")]
        config: PathBuf,
    },
}

#[derive(Subcommand)]
enum CaCommand {
    /// Generate a new CA without overwriting existing key material.
    Init {
        #[arg(long, default_value = "llmap.toml")]
        config: PathBuf,
    },
}

#[derive(Subcommand)]
enum MigrateCommand {
    ClaudeproxyEnv {
        #[arg(long, default_value = "llmap.toml")]
        config: PathBuf,
        #[arg(long)]
        input: PathBuf,
        /// Replace deterministic claudeproxy-N account IDs that already exist.
        #[arg(long)]
        replace: bool,
    },
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("llmap: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Config {
            command: ConfigCommand::Check { config },
        } => {
            load_config(&config)?;
            println!("configuration is valid: {}", config.display());
            Ok(())
        }
        Command::Serve { config } => serve(&config).await,
        Command::Ca {
            command: CaCommand::Init { config },
        } => {
            let config = load_config(&config)?;
            generate_ca(
                Path::new(&config.forward_proxy.ca_cert_path),
                Path::new(&config.forward_proxy.ca_key_path),
            )?;
            println!(
                "created local CA certificate: {}",
                config.forward_proxy.ca_cert_path
            );
            Ok(())
        }
        Command::Migrate {
            command:
                MigrateCommand::ClaudeproxyEnv {
                    config,
                    input,
                    replace,
                },
        } => migrate_claudeproxy_env(&config, &input, replace),
    }
}

fn migrate_claudeproxy_env(
    config_path: &Path,
    input: &Path,
    replace: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config(config_path)?;
    let encoded_master_key = Zeroizing::new(required_environment(&config.storage.master_key_env)?);
    let master_key = parse_master_key(&encoded_master_key)?;
    if let Some(parent) = Path::new(&config.storage.database_path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let source = zeroize::Zeroizing::new(std::fs::read_to_string(input)?);
    let accounts = parse_claudeproxy_env(&source)?;
    let store = SqliteStore::open(
        Path::new(&config.storage.database_path),
        SecretBox::new(master_key),
    )?;
    let summary = import_claudeproxy_env(&store, accounts, replace)?;
    println!(
        "imported {} account(s); skipped {} existing account(s)",
        summary.imported, summary.skipped_existing
    );
    Ok(())
}

async fn serve(config_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config(config_path)?;
    initialize_logging();

    let encoded_master_key = Zeroizing::new(required_environment(&config.storage.master_key_env)?);
    let master_key = parse_master_key(&encoded_master_key)?;
    let admin_password =
        SecretInput::new(required_environment(&config.admin.bootstrap_password_env)?);

    if let Some(parent) = Path::new(&config.storage.database_path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let store = Arc::new(SqliteStore::open(
        Path::new(&config.storage.database_path),
        SecretBox::new(master_key),
    )?);
    let expired_before = chrono::Utc::now()
        - chrono::Duration::days(i64::from(config.telemetry.audit_retention_days));
    let pruned = store.prune_audit_before(expired_before)?;
    if pruned > 0 {
        info!(
            pruned_events = pruned,
            "pruned expired metadata audit events"
        );
    }

    let auth_key = derive_key(&master_key, b"llmap-client-auth-v1");
    let session_key = derive_key(&master_key, b"llmap-admin-session-v1");
    let account_router = Router::new(store.route_accounts()?);
    let destination_policy =
        DestinationPolicy::new(config.server.allowed_upstream_hosts.clone(), false);
    let data_plane = Arc::new(DataPlane::new(
        config.auth.mode,
        Authenticator::new(auth_key),
        store.clone(),
        account_router,
        Arc::new(ReqwestTransport::new(destination_policy)),
        config.server.max_request_bytes,
    ));
    let sessions = Arc::new(AdminSessionManager::new(
        config.admin.username.clone(),
        AdminPasswordHash::create(&admin_password)?,
        session_key,
        SessionPolicy::default(),
    ));
    let refresh_store = store.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let summary = refresh_store.refresh_due_oauth(chrono::Utc::now()).await;
            if summary.refreshed > 0 {
                info!(
                    refreshed = summary.refreshed,
                    "refreshed OAuth account credentials"
                );
            }
            if summary.failed > 0 {
                tracing::warn!(
                    failed = summary.failed,
                    "one or more OAuth credential refreshes failed"
                );
            }
        }
    });
    let app = application_router(
        data_plane.clone(),
        store,
        sessions,
        AdminRuntimeConfig {
            auth_mode: config.auth.mode,
            auth_mode_locked: config.auth.mode_locked_by_environment,
            secure_cookies: config.admin.secure_cookies,
        },
    );

    let listener = tokio::net::TcpListener::bind(&config.server.bind).await?;
    info!(bind = %config.server.bind, auth_mode = ?config.auth.mode, "llmap is ready");
    let reverse = async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|error| -> Box<dyn std::error::Error> { Box::new(error) })
    };
    if config.forward_proxy.enabled {
        let handler = ForwardProxyHandler::new(
            data_plane,
            DestinationPolicy::new(config.forward_proxy.allowed_hosts.clone(), false),
            config.server.max_request_bytes,
        );
        let bind = config.forward_proxy.bind.clone();
        info!(bind = %bind, "HTTPS MITM forward proxy is ready");
        let forward = async move {
            serve_forward_proxy(
                &bind,
                PathBuf::from(config.forward_proxy.ca_cert_path),
                PathBuf::from(config.forward_proxy.ca_key_path),
                handler,
            )
            .await
            .map_err(|error| -> Box<dyn std::error::Error> { Box::new(error) })
        };
        tokio::select! {
            result = reverse => result?,
            result = forward => result?,
        }
    } else {
        reverse.await?;
    }
    Ok(())
}

fn load_config(path: &Path) -> Result<Config, Box<dyn std::error::Error>> {
    let source = std::fs::read_to_string(path)?;
    let environment = std::env::vars().collect::<BTreeMap<_, _>>();
    Ok(Config::from_toml_with_env(&source, &environment)?)
}

fn required_environment(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    std::env::var(name)
        .map_err(|_| format!("required environment variable {name} is not set").into())
}

fn derive_key(master_key: &[u8; 32], purpose: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(master_key);
    digest.update(purpose);
    digest.finalize().into()
}

fn initialize_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if std::env::var("LLMAP_LOG_FORMAT").as_deref() == Ok("json") {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .with_current_span(false)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        error!(%error, "failed to install shutdown handler");
    }
}
