use crate::config::Config;
use sodiumoxide::base64;
use std::sync::{Arc, RwLock};

lazy_static::lazy_static! {
    pub static ref TEMPORARY_PASSWORD:Arc<RwLock<String>> = Arc::new(RwLock::new(get_auto_password()));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerificationMethod {
    OnlyUseTemporaryPassword,
    OnlyUsePermanentPassword,
    UseBothPasswords,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApproveMode {
    Both,
    Password,
    Click,
}

fn get_auto_password() -> String {
    let len = temporary_password_length();
    if Config::get_bool_option(crate::config::keys::OPTION_ALLOW_NUMERNIC_ONE_TIME_PASSWORD) {
        Config::get_auto_numeric_password(len)
    } else {
        Config::get_auto_password(len)
    }
}

// Should only be called in server
pub fn update_temporary_password() {
    *TEMPORARY_PASSWORD.write().unwrap() = get_auto_password();
}

// Should only be called in server
pub fn temporary_password() -> String {
    TEMPORARY_PASSWORD.read().unwrap().clone()
}

fn verification_method() -> VerificationMethod {
    let method = Config::get_option("verification-method");
    if method == "use-temporary-password" {
        VerificationMethod::OnlyUseTemporaryPassword
    } else if method == "use-permanent-password" {
        VerificationMethod::OnlyUsePermanentPassword
    } else {
        VerificationMethod::UseBothPasswords // default
    }
}

pub fn temporary_password_length() -> usize {
    let length = Config::get_option("temporary-password-length");
    if length == "8" {
        8
    } else if length == "10" {
        10
    } else {
        6 // default
    }
}

pub fn temporary_enabled() -> bool {
    verification_method() != VerificationMethod::OnlyUsePermanentPassword
}

pub fn permanent_enabled() -> bool {
    verification_method() != VerificationMethod::OnlyUseTemporaryPassword
}

pub fn has_valid_password() -> bool {
    temporary_enabled() && !temporary_password().is_empty()
        || permanent_enabled() && Config::has_permanent_password()
}

pub fn approve_mode() -> ApproveMode {
    let mode = Config::get_option("approve-mode");
    if mode == "password" {
        ApproveMode::Password
    } else if mode == "click" {
        ApproveMode::Click
    } else {
        ApproveMode::Both
    }
}

pub fn hide_cm() -> bool {
    approve_mode() == ApproveMode::Password
        && verification_method() == VerificationMethod::OnlyUsePermanentPassword
        && crate::config::option2bool("allow-hide-cm", &Config::get_option("allow-hide-cm"))
}

const VERSION_LEN: usize = 2;
const FORMAT_V1: u8 = 1;
pub const CRYPTO_LOG_PREFIX: &str = "=========================";

// Check if data is already encrypted by verifying:
// 1) version prefix "00"
// 2) valid base64 payload
// 3) decoded payload length >= secretbox::MACBYTES
//
// We intentionally avoid trying to decrypt here because key mismatch would cause
// false negatives.
// The decoded payload may be either legacy ciphertext or FORMAT_V1 || nonce || ciphertext.
// Reference: secretbox::seal returns ciphertext length = plaintext length + MACBYTES
// https://github.com/sodiumoxide/sodiumoxide/blob/3057acb1a030ad86ed8892a223d64036ab5e8523/src/crypto/secretbox/xsalsa20poly1305.rs#L67
fn is_encrypted(v: &[u8]) -> bool {
    if v.len() <= VERSION_LEN || !v.starts_with(b"00") {
        return false;
    }
    match base64::decode(&v[VERSION_LEN..], base64::Variant::Original) {
        Ok(decoded) => decoded.len() >= sodiumoxide::crypto::secretbox::MACBYTES,
        Err(_) => false,
    }
}

pub fn encrypt_str_or_original(s: &str, version: &str, max_len: usize) -> String {
    log::info!(
        "{CRYPTO_LOG_PREFIX} encrypt_str_or_original called, version={version}, char_len={}, max_len={max_len}",
        s.chars().count()
    );
    if is_encrypted(s.as_bytes()) {
        log::info!("{CRYPTO_LOG_PREFIX} encrypt_str_or_original skipped, input already encrypted");
        log::error!("Duplicate encryption!");
        return s.to_owned();
    }
    if s.chars().count() > max_len {
        log::info!("{CRYPTO_LOG_PREFIX} encrypt_str_or_original skipped, input exceeds max_len");
        return String::default();
    }
    if version == "00" {
        log::info!("{CRYPTO_LOG_PREFIX} encrypt_str_or_original -> encrypt");
        if let Ok(s) = encrypt(s.as_bytes()) {
            log::info!("{CRYPTO_LOG_PREFIX} encrypt_str_or_original succeeded with version 00");
            return version.to_owned() + &s;
        }
        log::info!("{CRYPTO_LOG_PREFIX} encrypt_str_or_original failed inside encrypt, returning original");
    } else {
        log::info!(
            "{CRYPTO_LOG_PREFIX} encrypt_str_or_original skipped, unsupported version={version}"
        );
    }
    s.to_owned()
}

// String: password
// bool: whether decryption is successful
// bool: whether should store to re-encrypt when load
// note: s.len() return length in bytes, s.chars().count() return char count
//       &[..2] return the left 2 bytes, s.chars().take(2) return the left 2 chars
pub fn decrypt_str_or_original(s: &str, current_version: &str) -> (String, bool, bool) {
    log::info!(
        "{CRYPTO_LOG_PREFIX} decrypt_str_or_original called, current_version={current_version}, byte_len={}",
        s.len()
    );
    if s.len() > VERSION_LEN {
        if s.starts_with("00") {
            log::info!("{CRYPTO_LOG_PREFIX} decrypt_str_or_original -> decrypt for version 00");
            if let Ok(v) = decrypt(s[VERSION_LEN..].as_bytes()) {
                log::info!(
                    "{CRYPTO_LOG_PREFIX} decrypt_str_or_original succeeded with version 00"
                );
                return (
                    String::from_utf8_lossy(&v).to_string(),
                    true,
                    "00" != current_version,
                );
            }
        }
    }

    // For values that already look encrypted (version prefix + base64), avoid
    // repeated store on each load when decryption fails.
    (
        s.to_owned(),
        false,
        !s.is_empty() && !is_encrypted(s.as_bytes()),
    )
}

pub fn encrypt_vec_or_original(v: &[u8], version: &str, max_len: usize) -> Vec<u8> {
    log::info!(
        "{CRYPTO_LOG_PREFIX} encrypt_vec_or_original called, version={version}, byte_len={}, max_len={max_len}",
        v.len()
    );
    if is_encrypted(v) {
        log::info!("{CRYPTO_LOG_PREFIX} encrypt_vec_or_original skipped, input already encrypted");
        log::error!("Duplicate encryption!");
        return v.to_owned();
    }
    if v.len() > max_len {
        log::info!("{CRYPTO_LOG_PREFIX} encrypt_vec_or_original skipped, input exceeds max_len");
        return vec![];
    }
    if version == "00" {
        log::info!("{CRYPTO_LOG_PREFIX} encrypt_vec_or_original -> encrypt");
        if let Ok(s) = encrypt(v) {
            log::info!("{CRYPTO_LOG_PREFIX} encrypt_vec_or_original succeeded with version 00");
            let mut version = version.to_owned().into_bytes();
            version.append(&mut s.into_bytes());
            return version;
        }
        log::info!("{CRYPTO_LOG_PREFIX} encrypt_vec_or_original failed inside encrypt, returning original");
    } else {
        log::info!(
            "{CRYPTO_LOG_PREFIX} encrypt_vec_or_original skipped, unsupported version={version}"
        );
    }
    v.to_owned()
}

// Vec<u8>: password
// bool: whether decryption is successful
// bool: whether should store to re-encrypt when load
pub fn decrypt_vec_or_original(v: &[u8], current_version: &str) -> (Vec<u8>, bool, bool) {
    log::info!(
        "{CRYPTO_LOG_PREFIX} decrypt_vec_or_original called, current_version={current_version}, byte_len={}",
        v.len()
    );
    if v.len() > VERSION_LEN {
        let version = String::from_utf8_lossy(&v[..VERSION_LEN]);
        if version == "00" {
            log::info!("{CRYPTO_LOG_PREFIX} decrypt_vec_or_original -> decrypt for version 00");
            if let Ok(v) = decrypt(&v[VERSION_LEN..]) {
                log::info!("{CRYPTO_LOG_PREFIX} decrypt_vec_or_original succeeded with version 00");
                return (v, true, version != current_version);
            }
        }
    }

    // For values that already look encrypted (version prefix + base64), avoid
    // repeated store on each load when decryption fails.
    (v.to_owned(), false, !v.is_empty() && !is_encrypted(v))
}

fn encrypt(v: &[u8]) -> Result<String, ()> {
    if !v.is_empty() {
        log::info!("{CRYPTO_LOG_PREFIX} encrypt called, byte_len={}, entering symmetric_crypt", v.len());
        symmetric_crypt(v, true).map(|v| {
            log::info!(
                "{CRYPTO_LOG_PREFIX} encrypt symmetric_crypt succeeded, encoding base64 byte_len={}",
                v.len()
            );
            base64::encode(v, base64::Variant::Original)
        })
    } else {
        log::info!("{CRYPTO_LOG_PREFIX} encrypt skipped, empty input");
        Err(())
    }
}

fn decrypt(v: &[u8]) -> Result<Vec<u8>, ()> {
    if !v.is_empty() {
        log::info!("{CRYPTO_LOG_PREFIX} decrypt called, byte_len={}, decoding base64", v.len());
        base64::decode(v, base64::Variant::Original).and_then(|v| {
            log::info!(
                "{CRYPTO_LOG_PREFIX} decrypt base64 decode succeeded, entering symmetric_crypt with byte_len={}",
                v.len()
            );
            symmetric_crypt(&v, false)
        })
    } else {
        log::info!("{CRYPTO_LOG_PREFIX} decrypt skipped, empty input");
        Err(())
    }
}

fn decrypt_symmetric_payload(data: &[u8]) -> Result<Vec<u8>, ()> {
    let uuid = crate::get_uuid();
    let key = secretbox_key(uuid.clone())?;
    log::info!(
        "{CRYPTO_LOG_PREFIX} decrypt_symmetric_payload trying machine uuid key, payload_len={}",
        data.len()
    );
    let res = open_secretbox_payload(data, &key, "machine uuid");
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    if res.is_err() {
        if let Some(key_pair) = Config::get_existing_key_pair() {
            let pk = key_pair.1;
            if pk != uuid {
                log::info!(
                    "{CRYPTO_LOG_PREFIX} decrypt_symmetric_payload retrying with existing key pair material"
                );
                let pk_key = secretbox_key(pk)?;
                return open_secretbox_payload(data, &pk_key, "existing key pair material");
            }
        }
    }
    res
}

pub fn symmetric_crypt(data: &[u8], encrypt: bool) -> Result<Vec<u8>, ()> {
    use sodiumoxide::crypto::secretbox;

    if encrypt {
        log::info!(
            "{CRYPTO_LOG_PREFIX} symmetric_crypt encrypt called, byte_len={}, using FORMAT_V1 random nonce",
            data.len()
        );
        let uuid = crate::get_uuid();
        let key = secretbox_key(uuid)?;
        let nonce = secretbox::gen_nonce();
        let encrypted = secretbox::seal(data, &nonce, &key);
        let mut output = Vec::with_capacity(1 + nonce.0.len() + encrypted.len());
        output.push(FORMAT_V1);
        output.extend(nonce.0);
        output.extend(encrypted);
        log::info!(
            "{CRYPTO_LOG_PREFIX} symmetric_crypt encrypt succeeded with FORMAT_V1 payload_len={}",
            output.len()
        );
        Ok(output)
    } else {
        log::info!(
            "{CRYPTO_LOG_PREFIX} symmetric_crypt decrypt called, payload_len={}",
            data.len()
        );
        decrypt_symmetric_payload(data)
    }
}

fn secretbox_key(key_material: Vec<u8>) -> Result<sodiumoxide::crypto::secretbox::Key, ()> {
    use sodiumoxide::crypto::secretbox;
    use std::convert::TryInto;

    let mut keybuf = key_material;
    keybuf.resize(secretbox::KEYBYTES, 0);
    Ok(secretbox::Key(keybuf.try_into().map_err(|_| ())?))
}

fn open_secretbox_payload(
    data: &[u8],
    key: &sodiumoxide::crypto::secretbox::Key,
    key_source: &str,
) -> Result<Vec<u8>, ()> {
    use sodiumoxide::crypto::secretbox;

    if data.first() == Some(&FORMAT_V1)
        && data.len() >= 1 + secretbox::NONCEBYTES + secretbox::MACBYTES
    {
        let mut nonce = [0u8; secretbox::NONCEBYTES];
        nonce.copy_from_slice(&data[1..1 + secretbox::NONCEBYTES]);
        let nonce = secretbox::Nonce(nonce);
        if let Ok(decrypted) = secretbox::open(&data[1 + secretbox::NONCEBYTES..], &nonce, key) {
            log::info!(
                "{CRYPTO_LOG_PREFIX} Successfully decrypted with FORMAT_V1 payload via {key_source}"
            );
            return Ok(decrypted);
        }
    }

    let legacy_nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);
    log::info!(
        "{CRYPTO_LOG_PREFIX} Attempting to decrypt with legacy zero nonce via {key_source}"
    );
    let result = secretbox::open(data, &legacy_nonce, key);
    if result.is_ok() {
        log::info!(
            "{CRYPTO_LOG_PREFIX} Successfully decrypted with legacy zero nonce via {key_source}"
        );
    }
    result
}

mod test {

    #[test]
    fn test() {
        use super::*;
        use rand::{thread_rng, Rng};
        use std::time::Instant;

        let version = "00";
        let max_len = 128;

        println!("test str");
        let data = "1ü1111";
        let encrypted = encrypt_str_or_original(data, version, max_len);
        let (decrypted, succ, store) = decrypt_str_or_original(&encrypted, version);
        println!("data: {data}");
        println!("encrypted: {encrypted}");
        println!("decrypted: {decrypted}");
        assert_eq!(data, decrypted);
        assert_eq!(version, &encrypted[..2]);
        assert!(succ);
        assert!(!store);
        let (_, _, store) = decrypt_str_or_original(&encrypted, "99");
        assert!(store);
        assert!(!decrypt_str_or_original(&decrypted, version).1);
        assert_eq!(
            encrypt_str_or_original(&encrypted, version, max_len),
            encrypted
        );

        println!("test vec");
        let data: Vec<u8> = "1ü1111".as_bytes().to_vec();
        let encrypted = encrypt_vec_or_original(&data, version, max_len);
        let (decrypted, succ, store) = decrypt_vec_or_original(&encrypted, version);
        println!("data: {data:?}");
        println!("encrypted: {encrypted:?}");
        println!("decrypted: {decrypted:?}");
        assert_eq!(data, decrypted);
        assert_eq!(version.as_bytes(), &encrypted[..2]);
        assert!(!store);
        assert!(succ);
        let (_, _, store) = decrypt_vec_or_original(&encrypted, "99");
        assert!(store);
        assert!(!decrypt_vec_or_original(&decrypted, version).1);
        assert_eq!(
            encrypt_vec_or_original(&encrypted, version, max_len),
            encrypted
        );

        println!("test original");
        let data = version.to_string() + "Hello World";
        let (decrypted, succ, store) = decrypt_str_or_original(&data, version);
        assert_eq!(data, decrypted);
        assert!(store);
        assert!(!succ);
        let verbytes = version.as_bytes();
        let data: Vec<u8> = vec![verbytes[0], verbytes[1], 1, 2, 3, 4, 5, 6];
        let (decrypted, succ, store) = decrypt_vec_or_original(&data, version);
        assert_eq!(data, decrypted);
        assert!(store);
        assert!(!succ);
        let (_, succ, store) = decrypt_str_or_original("", version);
        assert!(!store);
        assert!(!succ);
        let (_, succ, store) = decrypt_vec_or_original(&[], version);
        assert!(!store);
        assert!(!succ);
        let data = "1ü1111";
        assert_eq!(decrypt_str_or_original(data, version).0, data);
        let data: Vec<u8> = "1ü1111".as_bytes().to_vec();
        assert_eq!(decrypt_vec_or_original(&data, version).0, data);

        // Base64-shaped "00" prefixed values shorter than MACBYTES are treated
        // as original/plain values and should be stored.
        let data = "00YWJjZA==";
        let (decrypted, succ, store) = decrypt_str_or_original(data, version);
        assert_eq!(decrypted, data);
        assert!(!succ);
        assert!(store);
        let data = b"00YWJjZA==".to_vec();
        let (decrypted, succ, store) = decrypt_vec_or_original(&data, version);
        assert_eq!(decrypted, data);
        assert!(!succ);
        assert!(store);

        // When decoded length reaches MACBYTES, it is treated as encrypted-like
        // and should not trigger repeated store.
        let exact_mac = vec![0u8; sodiumoxide::crypto::secretbox::MACBYTES];
        let exact_mac_b64 =
            sodiumoxide::base64::encode(&exact_mac, sodiumoxide::base64::Variant::Original);
        let data = format!("00{exact_mac_b64}");
        let (_, succ, store) = decrypt_str_or_original(&data, version);
        assert!(!succ);
        assert!(!store);
        let data = data.into_bytes();
        let (_, succ, store) = decrypt_vec_or_original(&data, version);
        assert!(!succ);
        assert!(!store);

        println!("test speed");
        let test_speed = |len: usize, name: &str| {
            let mut data: Vec<u8> = vec![];
            let mut rng = thread_rng();
            for _ in 0..len {
                data.push(rng.gen_range(0..255));
            }
            let start: Instant = Instant::now();
            let encrypted = encrypt_vec_or_original(&data, version, len);
            assert_ne!(data, decrypted);
            let t1 = start.elapsed();
            let start = Instant::now();
            let (decrypted, _, _) = decrypt_vec_or_original(&encrypted, version);
            let t2 = start.elapsed();
            assert_eq!(data, decrypted);
            println!("{name}");
            println!("encrypt:{:?}, decrypt:{:?}", t1, t2);

            let start: Instant = Instant::now();
            let encrypted = base64::encode(&data, base64::Variant::Original);
            let t1 = start.elapsed();
            let start = Instant::now();
            let decrypted = base64::decode(&encrypted, base64::Variant::Original).unwrap();
            let t2 = start.elapsed();
            assert_eq!(data, decrypted);
            println!("base64, encrypt:{:?}, decrypt:{:?}", t1, t2,);
        };
        test_speed(128, "128");
        test_speed(1024, "1k");
        test_speed(1024 * 1024, "1M");
        test_speed(10 * 1024 * 1024, "10M");
        test_speed(100 * 1024 * 1024, "100M");
    }

    #[test]
    fn test_is_encrypted() {
        use super::*;
        use sodiumoxide::base64::{encode, Variant};
        use sodiumoxide::crypto::secretbox;

        // Empty data should not be considered encrypted
        assert!(!is_encrypted(b""));
        assert!(!is_encrypted(b"0"));
        assert!(!is_encrypted(b"00"));

        // Data without "00" prefix should not be considered encrypted
        assert!(!is_encrypted(b"01abcd"));
        assert!(!is_encrypted(b"99abcd"));
        assert!(!is_encrypted(b"hello world"));

        // Data with "00" prefix but invalid base64 should not be considered encrypted
        assert!(!is_encrypted(b"00!!!invalid base64!!!"));
        assert!(!is_encrypted(b"00@#$%"));

        // Data with "00" prefix and valid base64 but shorter than MACBYTES is not encrypted
        assert!(!is_encrypted(b"00YWJjZA==")); // "abcd" in base64
        assert!(!is_encrypted(b"00SGVsbG8gV29ybGQ=")); // "Hello World" in base64

        // Data with "00" prefix and valid base64 with decoded len == MACBYTES is considered encrypted
        let exact_mac = vec![0u8; secretbox::MACBYTES];
        let exact_mac_b64 = encode(&exact_mac, Variant::Original);
        let exact_mac_candidate = format!("00{exact_mac_b64}");
        assert!(is_encrypted(exact_mac_candidate.as_bytes()));

        // Real encrypted data should be detected
        let version = "00";
        let max_len = 128;
        let encrypted_str = encrypt_str_or_original("1", version, max_len);
        assert!(is_encrypted(encrypted_str.as_bytes()));
        let encrypted_vec = encrypt_vec_or_original(b"1", version, max_len);
        assert!(is_encrypted(&encrypted_vec));

        // Original unencrypted data should not be detected as encrypted
        assert!(!is_encrypted(b"1"));
        assert!(!is_encrypted("1".as_bytes()));
    }

    #[test]
    fn test_encrypted_payload_min_len_macbytes() {
        use super::*;
        use sodiumoxide::base64::{decode, Variant};
        use sodiumoxide::crypto::secretbox;

        let version = "00";
        let max_len = 128;

        let encrypted_str = encrypt_str_or_original("1", version, max_len);
        let decoded = decode(&encrypted_str.as_bytes()[VERSION_LEN..], Variant::Original).unwrap();
        assert!(
            decoded.len() >= secretbox::MACBYTES,
            "decoded encrypted payload must be at least MACBYTES"
        );

        let encrypted_vec = encrypt_vec_or_original(b"1", version, max_len);
        let decoded = decode(&encrypted_vec[VERSION_LEN..], Variant::Original).unwrap();
        assert!(
            decoded.len() >= secretbox::MACBYTES,
            "decoded encrypted payload must be at least MACBYTES"
        );
    }

    #[test]
    fn test_encryption_uses_random_nonce() {
        use super::*;
        use sodiumoxide::crypto::secretbox;

        let data = b"test password 123";
        let encrypted1 = symmetric_crypt(data, true).unwrap();
        let encrypted2 = symmetric_crypt(data, true).unwrap();

        assert_eq!(encrypted1.first(), Some(&FORMAT_V1));
        assert_eq!(encrypted2.first(), Some(&FORMAT_V1));
        assert_eq!(
            encrypted1.len(),
            1 + secretbox::NONCEBYTES + data.len() + secretbox::MACBYTES
        );
        assert_ne!(encrypted1, encrypted2);
        assert_eq!(symmetric_crypt(&encrypted1, false).unwrap(), data);
        assert_eq!(symmetric_crypt(&encrypted2, false).unwrap(), data);
    }

    #[test]
    fn test_decrypt_legacy_zero_nonce_payload() {
        use super::*;
        use sodiumoxide::crypto::secretbox;
        use std::convert::TryInto;

        let data = b"test password 123";
        let uuid = crate::get_uuid();
        let mut keybuf = uuid.clone();
        keybuf.resize(secretbox::KEYBYTES, 0);
        let key = secretbox::Key(keybuf.try_into().unwrap());
        let nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);
        let encrypted = secretbox::seal(data, &nonce, &key);

        assert_eq!(symmetric_crypt(&encrypted, false).unwrap(), data);
    }

    #[test]
    fn test_decrypt_legacy_payload_starting_with_v1_marker() {
        use super::*;
        use sodiumoxide::crypto::secretbox;
        use std::convert::TryInto;

        let mut keybuf = crate::get_uuid();
        keybuf.resize(secretbox::KEYBYTES, 0);
        let key = secretbox::Key(keybuf.try_into().unwrap());
        let nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);

        for i in 0..=u16::MAX {
            let data = format!("legacy collision payload {i:05}");
            let encrypted = secretbox::seal(data.as_bytes(), &nonce, &key);
            if encrypted.first() == Some(&FORMAT_V1) {
                assert_eq!(symmetric_crypt(&encrypted, false).unwrap(), data.as_bytes());
                return;
            }
        }

        panic!("failed to find legacy payload starting with FORMAT_V1");
    }

    #[test]
    fn test_invalid_short_v1_payload_returns_error() {
        use super::*;

        let encrypted = vec![FORMAT_V1];

        assert!(symmetric_crypt(&encrypted, false).is_err());
    }

    #[test]
    fn test_decrypt_legacy_string_does_not_request_store() {
        use super::*;
        use sodiumoxide::base64::{encode, Variant};
        use sodiumoxide::crypto::secretbox;
        use std::convert::TryInto;

        let data = "test password 123";
        let uuid = crate::get_uuid();
        let mut keybuf = uuid.clone();
        keybuf.resize(secretbox::KEYBYTES, 0);
        let key = secretbox::Key(keybuf.try_into().unwrap());
        let nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);
        let encrypted = secretbox::seal(data.as_bytes(), &nonce, &key);
        let encrypted = "00".to_owned() + &encode(encrypted, Variant::Original);

        let (decrypted, success, store) = decrypt_str_or_original(&encrypted, "00");

        assert_eq!(decrypted, data);
        assert!(success);
        assert!(!store);
    }

    #[test]
    fn test_decrypt_legacy_vec_does_not_request_store() {
        use super::*;
        use sodiumoxide::base64::{encode, Variant};
        use sodiumoxide::crypto::secretbox;
        use std::convert::TryInto;

        let data = b"test password 123";
        let uuid = crate::get_uuid();
        let mut keybuf = uuid.clone();
        keybuf.resize(secretbox::KEYBYTES, 0);
        let key = secretbox::Key(keybuf.try_into().unwrap());
        let nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);
        let encrypted = secretbox::seal(data, &nonce, &key);
        let encrypted = ("00".to_owned() + &encode(encrypted, Variant::Original)).into_bytes();

        let (decrypted, success, store) = decrypt_vec_or_original(&encrypted, "00");

        assert_eq!(decrypted, data);
        assert!(success);
        assert!(!store);
    }

    // Test decryption fallback when data was encrypted with key_pair but decryption tries machine_uid first
    #[test]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn test_decrypt_with_pk_fallback() {
        use sodiumoxide::crypto::secretbox;
        use std::convert::TryInto;

        let uuid = crate::get_uuid();
        let pk = crate::config::Config::get_key_pair().1;

        // Ensure uuid != pk, otherwise fallback branch won't be tested
        if uuid == pk {
            eprintln!("skip: uuid == pk, fallback branch won't be tested");
            return;
        }

        let data = b"test password 123";
        let nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);

        // Encrypt with pk (simulating machine_uid failure during encryption)
        let mut pk_keybuf = pk;
        pk_keybuf.resize(secretbox::KEYBYTES, 0);
        let pk_key = secretbox::Key(pk_keybuf.try_into().unwrap());
        let encrypted = secretbox::seal(data, &nonce, &pk_key);

        // Decrypt using symmetric_crypt (should fallback to pk since uuid differs)
        let decrypted = super::symmetric_crypt(&encrypted, false);
        assert!(
            decrypted.is_ok(),
            "Decryption with pk fallback should succeed"
        );
        assert_eq!(decrypted.unwrap(), data);
    }
}
