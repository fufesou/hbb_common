use crate::{
    anyhow::{anyhow, Context},
    ResultType,
};
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
    public_key: [
        118, 252, 116, 215, 49, 217, 220, 109, 145, 119, 210, 101, 225, 198, 63, 2, 41, 127, 197,
        127, 52, 251, 6, 204, 125, 117, 96, 204, 187, 166, 85, 59,
    ],
}];

#[derive(Serialize, Deserialize)]
pub struct UpdateMetadata {
    pub schema_version: u32,
    pub app: String,
    pub package_id: String,
    pub version: String,
    pub release_id: String,
    pub published_at: String,
    pub signature_key_id: String,
    pub artifacts: Vec<UpdateArtifact>,
}
#[derive(Serialize, Deserialize)]
pub struct UpdateArtifact {
    pub platform: String,
    pub arch: String,
    pub format: String,
    pub url: String,
    pub file_name: String,
    pub size: u64,
    pub sha256: String,
}
#[derive(Serialize, Deserialize)]
pub struct UpdateSignature {
    pub schema_version: u32,
    pub algorithm: String,
    pub key_id: String,
    pub signature: String,
}
pub struct TrustedUpdateKey {
    pub key_id: &'static str,
    pub algorithm: &'static str,
    pub public_key: [u8; 32],
}
pub struct UpdateMetadataPolicy<'a> {
    pub app: &'a str,
    pub allowed_package_ids: &'a [&'a str],
    pub expected_version: Option<&'a str>,
    pub expected_release_id: Option<&'a str>,
    pub expected_artifact_url_prefix: Option<&'a str>,
}
pub struct UpdateArtifactQuery<'a> {
    pub platform: &'a str,
    pub arch: &'a str,
    pub format: &'a str,
    pub file_name: Option<&'a str>,
}
#[derive(Clone)]
pub struct VerifiedUpdateArtifact {
    pub version: String,
    pub release_id: String,
    pub package_id: String,
    pub url: String,
    pub file_name: String,
    pub size: u64,
    pub sha256: String,
}

pub fn verify_update_metadata_with_keys(
    metadata_bytes: &[u8],
    signature_bytes: &[u8],
    policy: &UpdateMetadataPolicy<'_>,
    query: &UpdateArtifactQuery<'_>,
    trusted_keys: &[TrustedUpdateKey],
) -> ResultType<VerifiedUpdateArtifact> {
    let update_signature: UpdateSignature =
        serde_json::from_slice(signature_bytes).context("invalid update signature JSON")?;
    validate_signature_schema(&update_signature)?;
    let signature = decode_signature(&update_signature.signature)?;
    let trusted_key = trusted_keys
        .iter()
        .find(|key| {
            key.key_id == update_signature.key_id && key.algorithm == update_signature.algorithm
        })
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
    verify_update_metadata_with_keys(
        metadata_bytes,
        signature_bytes,
        policy,
        query,
        TRUSTED_UPDATE_KEYS,
    )
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
    let decoded = STANDARD
        .decode(encoded)
        .context("invalid update signature base64")?;
    if decoded.len() != 64 || STANDARD.encode(&decoded) != encoded {
        return Err(anyhow!("invalid update signature length or encoding"));
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&decoded);
    Signature::from_bytes(&signature).map_err(|_| anyhow!("invalid update signature bytes"))
}

fn verify_metadata_signature(
    metadata_bytes: &[u8],
    signature: &Signature,
    trusted_key: &TrustedUpdateKey,
) -> ResultType<()> {
    init_sodiumoxide()?;
    let mut signed_bytes =
        Vec::with_capacity(UPDATE_METADATA_SIGNATURE_CONTEXT.len() + metadata_bytes.len());
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
        sodiumoxide::init().map_err(|_| "failed to initialize sodiumoxide".to_string())
    });
    match result {
        Ok(()) => Ok(()),
        Err(err) => Err(anyhow!(err.clone())),
    }
}

fn validate_metadata(
    metadata: &UpdateMetadata,
    signature: &UpdateSignature,
    policy: &UpdateMetadataPolicy<'_>,
) -> ResultType<()> {
    if metadata.schema_version != METADATA_SCHEMA_VERSION {
        return Err(anyhow!("unsupported update metadata schema version"));
    }
    if metadata.signature_key_id != signature.key_id {
        return Err(anyhow!("update metadata signature key id mismatch"));
    }
    if metadata.app != policy.app {
        return Err(anyhow!("update metadata app mismatch"));
    }
    if !policy
        .allowed_package_ids
        .contains(&metadata.package_id.as_str())
    {
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
    for artifact in &metadata.artifacts {
        validate_artifact_file_name(&artifact.file_name)?;
    }
    Ok(())
}

fn select_artifact<'a>(
    metadata: &'a UpdateMetadata,
    query: &UpdateArtifactQuery<'_>,
) -> ResultType<&'a UpdateArtifact> {
    let mut matches = metadata.artifacts.iter().filter(|artifact| {
        artifact.platform == query.platform
            && artifact.arch == query.arch
            && artifact.format == query.format
            && query
                .file_name
                .map_or(true, |file_name| artifact.file_name == file_name)
    });
    let artifact = matches
        .next()
        .ok_or_else(|| anyhow!("matching update artifact not found"))?;
    if matches.next().is_some() {
        return Err(anyhow!("multiple matching update artifacts found"));
    }
    Ok(artifact)
}

fn validate_artifact(
    artifact: &UpdateArtifact,
    expected_url_prefix: Option<&str>,
) -> ResultType<()> {
    validate_artifact_file_name(&artifact.file_name)?;
    if !is_sha256_hex(&artifact.sha256) {
        return Err(anyhow!("invalid update artifact sha256"));
    }
    let parsed_url = Url::parse(&artifact.url).context("invalid update artifact URL")?;
    if parsed_url.query().is_some() || parsed_url.fragment().is_some() {
        return Err(anyhow!(
            "update artifact URL must not contain query or fragment"
        ));
    }
    if let Some(prefix) = expected_url_prefix {
        let expected_url = format!("{}{}", prefix, artifact.file_name);
        if artifact.url != expected_url {
            return Err(anyhow!(
                "update artifact URL is outside expected release prefix"
            ));
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

fn validate_artifact_file_name(file_name: &str) -> ResultType<()> {
    if file_name == ".." || file_name.contains('/') || file_name.contains('\\') {
        return Err(anyhow!("invalid update artifact file name"));
    }
    Ok(())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

#[cfg(test)]
#[path = "update_metadata_tests.rs"]
mod tests;
