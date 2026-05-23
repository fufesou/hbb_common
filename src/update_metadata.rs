use crate::{anyhow::{anyhow, Context}, ResultType};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_derive::{Deserialize, Serialize};
use sodiumoxide::crypto::sign::{verify_detached, PublicKey, Signature};
use std::sync::OnceLock;
use url::Url;

pub const UPDATE_METADATA_SIGNATURE_CONTEXT: &[u8] = b"RustDesk update metadata v1\n";
const METADATA_SCHEMA_VERSION: u32 = 1;
const SIGNATURE_SCHEMA_VERSION: u32 = 1;
const SIGNATURE_ALGORITHM: &str = "ed25519";

const TRUSTED_UPDATE_KEYS: &[TrustedUpdateKey] = &[TrustedUpdateKey {
    key_id: "2026-ed25519-main",
    algorithm: SIGNATURE_ALGORITHM,
    public_key: [118, 252, 116, 215, 49, 217, 220, 109, 145, 119, 210, 101, 225, 198, 63, 2, 41, 127, 197, 127, 52, 251, 6, 204, 125, 117, 96, 204, 187, 166, 85, 59],
}];

#[derive(Serialize, Deserialize)]
pub struct UpdateMetadata { pub schema_version: u32, pub app: String, pub package_id: String, pub version: String, pub release_id: String, pub published_at: String, pub signature_key_id: String, pub artifacts: Vec<UpdateArtifact> }
#[derive(Serialize, Deserialize)]
pub struct UpdateArtifact { pub platform: String, pub arch: String, pub format: String, pub url: String, pub file_name: String, pub size: u64, pub sha256: String }
#[derive(Serialize, Deserialize)]
pub struct UpdateSignature { pub schema_version: u32, pub algorithm: String, pub key_id: String, pub signature: String }
pub struct TrustedUpdateKey { pub key_id: &'static str, pub algorithm: &'static str, pub public_key: [u8; 32] }
pub struct UpdateMetadataPolicy<'a> { pub app: &'a str, pub allowed_package_ids: &'a [&'a str], pub expected_version: Option<&'a str>, pub expected_release_id: Option<&'a str>, pub expected_artifact_url_prefix: Option<&'a str> }
pub struct UpdateArtifactQuery<'a> { pub platform: &'a str, pub arch: &'a str, pub format: &'a str, pub file_name: Option<&'a str> }
pub struct VerifiedUpdateArtifact { pub version: String, pub release_id: String, pub package_id: String, pub url: String, pub file_name: String, pub size: u64, pub sha256: String }

pub fn verify_update_metadata_with_keys(metadata_bytes: &[u8], signature_bytes: &[u8], policy: &UpdateMetadataPolicy<'_>, query: &UpdateArtifactQuery<'_>, trusted_keys: &[TrustedUpdateKey]) -> ResultType<VerifiedUpdateArtifact> {
    let update_signature: UpdateSignature =
        serde_json::from_slice(signature_bytes).context("invalid update signature JSON")?;
    validate_signature_schema(&update_signature)?;
    let signature = decode_signature(&update_signature.signature)?;
    let trusted_key = trusted_keys
        .iter()
        .find(|key| key.key_id == update_signature.key_id && key.algorithm == update_signature.algorithm)
        .ok_or_else(|| anyhow!("unsupported update signature key"))?;
    verify_metadata_signature(metadata_bytes, &signature, trusted_key)?;
    let metadata: UpdateMetadata =
        serde_json::from_slice(metadata_bytes).context("invalid update metadata JSON")?;
    validate_metadata(&metadata, &update_signature, policy)?;
    let artifact = select_artifact(&metadata, query)?;
    validate_artifact(artifact, policy.expected_artifact_url_prefix)?;
    Ok(VerifiedUpdateArtifact {
        version: metadata.version.clone(),
        release_id: metadata.release_id.clone(),
        package_id: metadata.package_id.clone(),
        url: artifact.url.clone(),
        file_name: artifact.file_name.clone(),
        size: artifact.size,
        sha256: artifact.sha256.clone(),
    })
}

pub fn verify_update_metadata(
    metadata_bytes: &[u8],
    signature_bytes: &[u8],
    policy: &UpdateMetadataPolicy<'_>,
    query: &UpdateArtifactQuery<'_>,
) -> ResultType<VerifiedUpdateArtifact> {
    verify_update_metadata_with_keys(metadata_bytes, signature_bytes, policy, query, TRUSTED_UPDATE_KEYS)
}

fn validate_signature_schema(signature: &UpdateSignature) -> ResultType<()> {
    if signature.schema_version != SIGNATURE_SCHEMA_VERSION {
        return Err(anyhow!("unsupported update signature schema version"));
    }
    if signature.algorithm != SIGNATURE_ALGORITHM {
        return Err(anyhow!("unsupported update signature algorithm"));
    }
    Ok(())
}

fn decode_signature(encoded: &str) -> ResultType<Signature> {
    let decoded = STANDARD.decode(encoded).context("invalid update signature base64")?;
    if decoded.len() != 64 || STANDARD.encode(&decoded) != encoded {
        return Err(anyhow!("invalid update signature length or encoding"));
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&decoded);
    Signature::from_bytes(&signature).map_err(|_| anyhow!("invalid update signature bytes"))
}

fn verify_metadata_signature(metadata_bytes: &[u8], signature: &Signature, trusted_key: &TrustedUpdateKey) -> ResultType<()> {
    init_sodiumoxide()?;
    let mut signed_bytes = Vec::with_capacity(UPDATE_METADATA_SIGNATURE_CONTEXT.len() + metadata_bytes.len());
    signed_bytes.extend_from_slice(UPDATE_METADATA_SIGNATURE_CONTEXT);
    signed_bytes.extend_from_slice(metadata_bytes);
    if !verify_detached(signature, &signed_bytes, &PublicKey(trusted_key.public_key)) {
        return Err(anyhow!("invalid update metadata signature"));
    }
    Ok(())
}

fn init_sodiumoxide() -> ResultType<()> {
    static INIT: OnceLock<Result<(), String>> = OnceLock::new();
    let result = INIT.get_or_init(|| {
        #[cfg(test)]
        SODIUM_INIT_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        sodiumoxide::init().map_err(|_| "failed to initialize sodiumoxide".to_string())
    });
    match result {
        Ok(()) => Ok(()),
        Err(err) => Err(anyhow!(err.clone())),
    }
}

fn validate_metadata(metadata: &UpdateMetadata, signature: &UpdateSignature, policy: &UpdateMetadataPolicy<'_>) -> ResultType<()> {
    if metadata.schema_version != METADATA_SCHEMA_VERSION {
        return Err(anyhow!("unsupported update metadata schema version"));
    }
    if metadata.signature_key_id != signature.key_id {
        return Err(anyhow!("update metadata signature key id mismatch"));
    }
    if metadata.app != policy.app {
        return Err(anyhow!("update metadata app mismatch"));
    }
    if !policy.allowed_package_ids.contains(&metadata.package_id.as_str()) {
        return Err(anyhow!("update metadata package id is not allowed"));
    }
    if let Some(version) = policy.expected_version {
        if version != metadata.version {
            return Err(anyhow!("update metadata version mismatch"));
        }
    }
    if let Some(release_id) = policy.expected_release_id {
        if release_id != metadata.release_id {
            return Err(anyhow!("update metadata release id mismatch"));
        }
    }
    Ok(())
}

fn select_artifact<'a>(metadata: &'a UpdateMetadata, query: &UpdateArtifactQuery<'_>) -> ResultType<&'a UpdateArtifact> {
    let mut matches = metadata.artifacts.iter().filter(|artifact| {
        artifact.platform == query.platform
            && artifact.arch == query.arch
            && artifact.format == query.format
            && query.file_name.map_or(true, |file_name| artifact.file_name == file_name)
    });
    let artifact = matches.next().ok_or_else(|| anyhow!("matching update artifact not found"))?;
    if matches.next().is_some() {
        return Err(anyhow!("multiple matching update artifacts found"));
    }
    Ok(artifact)
}

fn validate_artifact(artifact: &UpdateArtifact, expected_url_prefix: Option<&str>) -> ResultType<()> {
    if !is_sha256_hex(&artifact.sha256) {
        return Err(anyhow!("invalid update artifact sha256"));
    }
    let parsed_url = Url::parse(&artifact.url).context("invalid update artifact URL")?;
    if parsed_url.query().is_some() || parsed_url.fragment().is_some() {
        return Err(anyhow!("update artifact URL must not contain query or fragment"));
    }
    if let Some(prefix) = expected_url_prefix {
        let expected_url = format!("{}{}", prefix, artifact.file_name);
        if artifact.url != expected_url {
            return Err(anyhow!("update artifact URL is outside expected release prefix"));
        }
    }
    let basename = parsed_url
        .path_segments()
        .and_then(|segments| segments.last())
        .ok_or_else(|| anyhow!("update artifact URL has no basename"))?;
    if basename != artifact.file_name {
        return Err(anyhow!("update artifact URL basename mismatch"));
    }
    Ok(())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

#[cfg(test)]
static SODIUM_INIT_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
fn sodiumoxide_init_call_count() -> usize {
    SODIUM_INIT_CALLS.load(std::sync::atomic::Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base64::engine::general_purpose::STANDARD;
    use crate::sodiumoxide::crypto::sign;
    use serde_json::{json, Value};

    const KEY_ID: &str = "test-ed25519-main";
    const SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    struct Fixture { metadata: Vec<u8>, signature: Vec<u8>, public_key: [u8; 32] }

    fn artifact() -> Value {
        json!({"platform":"windows","arch":"x86_64","format":"exe","url":"https://github.com/rustdesk/rustdesk/releases/download/v1.4.6/rustdesk-1.4.6-x86_64.exe","file_name":"rustdesk-1.4.6-x86_64.exe","size":123456,"sha256":SHA256})
    }

    fn metadata() -> Value {
        json!({"schema_version":1,"app":"rustdesk","package_id":"rustdesk","version":"1.4.6","release_id":"v1.4.6","published_at":"2026-05-14T00:00:00Z","signature_key_id":KEY_ID,"artifacts":[artifact()]})
    }

    fn set_value(metadata: &mut Value, key: &str, value: Value, artifact_field: bool) {
        let target = if artifact_field { &mut metadata["artifacts"][0] } else { metadata };
        target.as_object_mut().expect("JSON object").insert(key.to_string(), value);
    }

    fn sign_fixture(metadata: Value, signature_key_id: &str) -> Fixture {
        sodiumoxide::init().expect("test sodiumoxide init");
        let metadata = serde_json::to_vec(&metadata).expect("metadata JSON");
        let (public_key, secret_key) = sign::gen_keypair();
        let mut signed = UPDATE_METADATA_SIGNATURE_CONTEXT.to_vec();
        signed.extend_from_slice(&metadata);
        let sig = sign::sign_detached(&signed, &secret_key);
        let sig_json = json!({"schema_version":1,"algorithm":"ed25519","key_id":signature_key_id,"signature":STANDARD.encode(sig.to_bytes())});
        Fixture { metadata, signature: serde_json::to_vec(&sig_json).expect("signature JSON"), public_key: public_key.0 }
    }

    fn valid_fixture() -> Fixture { sign_fixture(metadata(), KEY_ID) }
    fn key(public_key: [u8; 32]) -> TrustedUpdateKey { TrustedUpdateKey { key_id: KEY_ID, algorithm: "ed25519", public_key } }
    fn policy<'a>() -> UpdateMetadataPolicy<'a> {
        UpdateMetadataPolicy { app: "rustdesk", allowed_package_ids: &["rustdesk"], expected_version: Some("1.4.6"), expected_release_id: Some("v1.4.6"), expected_artifact_url_prefix: Some("https://github.com/rustdesk/rustdesk/releases/download/v1.4.6/") }
    }
    fn query<'a>() -> UpdateArtifactQuery<'a> {
        UpdateArtifactQuery { platform: "windows", arch: "x86_64", format: "exe", file_name: Some("rustdesk-1.4.6-x86_64.exe") }
    }
    fn verify(fixture: &Fixture) -> ResultType<VerifiedUpdateArtifact> {
        verify_update_metadata_with_keys(&fixture.metadata, &fixture.signature, &policy(), &query(), &[key(fixture.public_key)])
    }

    #[test]
    fn accepts_valid_metadata_and_signature() {
        let artifact = verify(&valid_fixture()).expect("verified artifact");
        assert_eq!("rustdesk-1.4.6-x86_64.exe", artifact.file_name);
        assert_eq!(123456, artifact.size);
        assert_eq!(SHA256, artifact.sha256);
        assert_eq!(("1.4.6", "v1.4.6", "rustdesk"), (artifact.version.as_str(), artifact.release_id.as_str(), artifact.package_id.as_str()));
    }

    #[test]
    fn rejects_bad_signature_or_tampered_metadata() {
        let mut fixture = valid_fixture();
        fixture.metadata.push(b' ');
        assert!(verify(&fixture).is_err());
        for (key, value) in [("schema_version", json!(2)), ("algorithm", json!("rsa")), ("signature", json!("not base64")), ("signature", json!(STANDARD.encode([1u8; 63])))] {
            let mut fixture = valid_fixture();
            let mut sig: Value = serde_json::from_slice(&fixture.signature).expect("signature");
            sig.as_object_mut().expect("signature object").insert(key.to_string(), value);
            fixture.signature = serde_json::to_vec(&sig).expect("signature bytes");
            assert!(verify(&fixture).is_err(), "{}", key);
        }
    }

    #[test]
    fn rejects_schema_policy_artifact_and_url_mismatches() {
        let cases = [
            ("schema_version", json!(2), false), ("app", json!("other"), false),
            ("version", json!("1.4.7"), false), ("release_id", json!("v1.4.7"), false),
            ("package_id", json!("custom"), false), ("arch", json!("x86"), true),
            ("sha256", json!("not-a-sha256"), true),
            ("url", json!("https://github.com/rustdesk/rustdesk/releases/download/v1.4.7/rustdesk-1.4.6-x86_64.exe"), true),
            ("url", json!("https://github.com/rustdesk/rustdesk/releases/download/v1.4.6/other.exe"), true),
            ("url", json!("https://github.com/rustdesk/rustdesk/releases/download/v1.4.6/rustdesk-1.4.6_x86_64.exe?download=1"), true),
            ("url", json!("https://github.com/rustdesk/rustdesk/releases/download/v1.4.6/rustdesk-1.4.6_x86_64.exe#hash"), true),
        ];
        for (key, value, artifact_field) in cases {
            let mut metadata = metadata();
            set_value(&mut metadata, key, value, artifact_field);
            assert!(verify(&sign_fixture(metadata, KEY_ID)).is_err(), "{}", key);
        }
    }

    #[test]
    fn rejects_key_id_mismatch_ambiguous_matches_and_prefix_without_release_id() {
        let mut key_metadata = metadata();
        set_value(&mut key_metadata, "signature_key_id", json!("different-key"), false);
        assert!(verify(&sign_fixture(key_metadata, KEY_ID)).is_err());
        let mut duplicate_metadata = metadata();
        duplicate_metadata["artifacts"].as_array_mut().expect("artifacts").push(artifact());
        assert!(verify(&sign_fixture(duplicate_metadata, KEY_ID)).is_err());
        let mut prefix_metadata = metadata();
        set_value(&mut prefix_metadata, "url", json!("https://github.com/rustdesk/rustdesk/releases/download/v1.4.7/rustdesk-1.4.6-x86_64.exe"), true);
        let fixture = sign_fixture(prefix_metadata, KEY_ID);
        let mut policy = policy();
        policy.expected_release_id = None;
        assert!(verify_update_metadata_with_keys(&fixture.metadata, &fixture.signature, &policy, &query(), &[key(fixture.public_key)]).is_err());
    }

    #[test]
    fn rejects_non_canonical_artifact_url_inside_expected_prefix() {
        let mut metadata = metadata();
        set_value(
            &mut metadata,
            "url",
            json!("https://github.com/rustdesk/rustdesk/releases/download/v1.4.6/%2e%2e/v1.4.7/rustdesk-1.4.6-x86_64.exe"),
            true,
        );

        assert!(verify(&sign_fixture(metadata, KEY_ID)).is_err());
    }

    #[test]
    fn sodiumoxide_is_initialized_once_and_default_keys_are_separate() {
        let before = sodiumoxide_init_call_count();
        verify(&valid_fixture()).expect("first verification");
        let fixture = valid_fixture();
        verify(&fixture).expect("explicit test key verifies");
        assert!(sodiumoxide_init_call_count() <= before + 1);
        assert!(verify_update_metadata(&fixture.metadata, &fixture.signature, &policy(), &query()).is_err());
    }

    #[test]
    fn verifies_metadata_generated_by_python_release_script_fixture() {
        const PYTHON_KEY_ID: &str = "python-test-ed25519-main";
        let metadata = br#"{"schema_version":1,"app":"rustdesk","package_id":"rustdesk","version":"1.4.6","release_id":"v1.4.6","published_at":"2026-05-14T00:00:00Z","signature_key_id":"python-test-ed25519-main","artifacts":[{"platform":"windows","arch":"x86_64","format":"exe","url":"https://github.com/rustdesk/rustdesk/releases/download/v1.4.6/rustdesk-1.4.6-x86_64.exe","file_name":"rustdesk-1.4.6-x86_64.exe","size":8,"sha256":"304ca1638c5effa6832e0e15b958a8f74847efe4df9c3f3187216e921c168fed"}]}"#;
        let signature = br#"{"schema_version":1,"algorithm":"ed25519","key_id":"python-test-ed25519-main","signature":"ZMcod9VNaEGTYK0gIfGmMQ44HAvrYAkYDyIL9JTKjzUH+hVFYs8KpvnGSlteAHwqiJuJDdiKBVCPEdtcRRAJCA=="}"#;
        let trusted_key = TrustedUpdateKey {
            key_id: PYTHON_KEY_ID,
            algorithm: "ed25519",
            public_key: [
                3, 161, 7, 191, 243, 206, 16, 190, 29, 112, 221, 24, 231, 75, 192, 153,
                103, 228, 214, 48, 155, 165, 13, 95, 29, 220, 134, 100, 18, 85, 49, 184,
            ],
        };

        let artifact = verify_update_metadata_with_keys(
            metadata,
            signature,
            &policy(),
            &query(),
            &[trusted_key],
        )
        .expect("Python-generated update metadata verifies");

        assert_eq!("rustdesk-1.4.6-x86_64.exe", artifact.file_name);
        assert_eq!(8, artifact.size);
        assert_eq!(
            "304ca1638c5effa6832e0e15b958a8f74847efe4df9c3f3187216e921c168fed",
            artifact.sha256
        );
    }
}
