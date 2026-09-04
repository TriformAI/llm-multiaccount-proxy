use llmap::migration::{import_claudeproxy_env, parse_claudeproxy_env};
use llmap::providers::ProviderKind;
use llmap::secrets::{SecretBox, parse_master_key};
use llmap::storage::SqliteStore;

const LEGACY: &str = r#"
CLAUDE_ACCOUNT_1_NAME="OAuth primary"
CLAUDE_ACCOUNT_1='{"claudeAiOauth":{"accessToken":"fake-oauth-access","refreshToken":"fake-oauth-refresh","expiresAt":1900000000000,"scopes":["user:profile","user:inference"]}}'
# CLAUDE_ACCOUNT_2_NAME="Paused compatible"
# CLAUDE_ACCOUNT_2='{"type":"minimax","apiKey":"fake-compatible-key","baseUrl":"https://api.minimax.invalid","model":"MiniMax-M3","proxyUrl":"socks5h://fake-user:fake-pass@residential.invalid:1080"}'
CLAUDE_ACCOUNT_3_NAME="Bedrock"
CLAUDE_ACCOUNT_3='{"type":"bedrock","region":"eu-north-1","accessKeyId":"AKIDEXAMPLE","secretAccessKey":"fake-aws-secret","modelMap":{"default":"eu.anthropic.claude-sonnet"}}'
"#;

#[test]
fn legacy_accounts_map_without_exposing_credentials() {
    let accounts = parse_claudeproxy_env(LEGACY).unwrap();
    assert_eq!(accounts.len(), 3);
    assert_eq!(accounts[0].account.kind, ProviderKind::ClaudeOauth);
    assert!(accounts[0].account.enabled);
    assert_eq!(
        accounts[1].account.base_url.as_str(),
        "https://api.minimax.invalid/anthropic/"
    );
    assert!(!accounts[1].account.enabled);
    assert_eq!(accounts[2].account.kind, ProviderKind::BedrockSigV4);
    assert_eq!(
        accounts[2].account.base_url.host_str(),
        Some("bedrock-runtime.eu-north-1.amazonaws.com")
    );
}

#[test]
fn import_is_encrypted_idempotent_and_replace_is_explicit() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("llmap.db");
    let key = parse_master_key("ERERERERERERERERERERERERERERERERERERERERERE=").unwrap();
    let store = SqliteStore::open(&database, SecretBox::new(key)).unwrap();

    let first =
        import_claudeproxy_env(&store, parse_claudeproxy_env(LEGACY).unwrap(), false).unwrap();
    assert_eq!(first.imported, 3);
    let second =
        import_claudeproxy_env(&store, parse_claudeproxy_env(LEGACY).unwrap(), false).unwrap();
    assert_eq!(second.skipped_existing, 3);
    assert_eq!(store.list_accounts().unwrap().len(), 3);
    let (_, oauth_secret) = store.load_account("claudeproxy-1").unwrap();
    assert!(oauth_secret.expose().contains("fake-oauth-access"));
    let (compatible, _) = store.load_account("claudeproxy-2").unwrap();
    assert_eq!(
        compatible.egress_proxies,
        vec!["socks5h://fake-user:fake-pass@residential.invalid:1080"]
    );

    let bytes = std::fs::read(database).unwrap();
    for secret in [
        "fake-oauth-access",
        "fake-oauth-refresh",
        "fake-compatible-key",
        "fake-pass",
        "fake-aws-secret",
    ] {
        assert!(
            !bytes
                .windows(secret.len())
                .any(|window| window == secret.as_bytes())
        );
    }
}
