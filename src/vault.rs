use aes_gcm::{Aes256Gcm, Key, Nonce};         // AES-GCM with 256-bit key
use aes_gcm::aead::{Aead, KeyInit};
use argon2::Argon2;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Serialize, Deserialize};
use std::fs;
use std::io;
use base64::{engine::general_purpose, Engine as _};

#[derive(Serialize, Deserialize, Debug)]
pub struct Vault {
    pub entries: Vec<Entry>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Entry {
    pub title: String,
    pub entry_type: EntryType,
    pub content: String,
}

#[derive(Debug, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum EntryType {
    Note,
    Password,
}

impl Default for EntryType {
    fn default() -> Self {
        EntryType::Note // or EntryType::Password, whichever you want as default
    }
}

#[allow(dead_code)]
impl Vault {
    /// Create a new empty vault
    pub fn new() -> Self {
        Vault {
            entries: Vec::new(),
        }
    }

    /// Add an entry to the vault
    pub fn add_entry(&mut self, entry: Entry) {
        self.entries.push(entry);
    }

    /// Remove an entry by index, returning true if successful
    pub fn remove_entry(&mut self, index: usize) -> bool {
        if index < self.entries.len() {
            self.entries.remove(index);
            true
        } else {
            false
        }
    }

    /// List all entries to stdout
    pub fn list_entries(&self) {
        for (i, entry) in self.entries.iter().enumerate() {
            println!(
                "[{}] {} ({:?})\n{}\n",
                i + 1,
                entry.title,
                entry.entry_type,
                entry.content
            );
        }
    }

    /// Derive a 32-byte key from password and salt using Argon2id
    fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
        let argon2 = Argon2::default();
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .expect("Key derivation failed");
        key
    }

    /// Encrypt and save vault to file at `path`
    pub fn save_encrypted(&self, path: &str, password: &str) -> io::Result<()> {
        let json = serde_json::to_string(&self).unwrap();

        // generate salt & nonce
        let mut rng = OsRng;
        let mut salt = [0u8; 16];
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce_bytes);

        // derive key
        let key_bytes = Self::derive_key(password, &salt);
        // from_slice returns &GenericArray<u8, _> which is the Key
        let key_slice: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(&key_bytes);
        // new takes that reference
        let cipher = Aes256Gcm::new(key_slice);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, json.as_bytes())
            .expect("Encryption failure!");

        // Combine salt + nonce + ciphertext, then base64
        let mut blob = Vec::new();
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);

        fs::write(path, general_purpose::STANDARD.encode(blob))?;
        Ok(())
    }

    /// Load and decrypt vault from file at `path`
    pub fn load_encrypted(path: &str, password: &str) -> io::Result<Self> {
        let encoded = fs::read_to_string(path)?;
        let raw = general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Base64 decode failed: {}", e)))?;

        if raw.len() < 28 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Corrupted vault file: too short",
            ));
        }

        let salt = &raw[0..16];
        let nonce_bytes = &raw[16..28];
        let ciphertext = &raw[28..];

        // derive key again
        let key_bytes = Self::derive_key(password, salt);
        let key_slice: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key_slice);
        let nonce = Nonce::from_slice(nonce_bytes);

        let decrypted = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, format!("Decryption failed: {}", e)))?;

        let vault: Vault = serde_json::from_slice(&decrypted)?;
        Ok(vault)
    }
}
