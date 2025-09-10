use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES-GCM with 256-bit key
use aes_gcm::aead::{Aead, KeyInit};
use argon2::Argon2;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Serialize, Deserialize};
use std::fs;
use std::io;
use base64::{Engine as _};




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

#[derive(Debug, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub enum EntryType {
    Note,
    Password,
}

impl Default for EntryType {
    fn default() -> Self {
        EntryType::Note
    }
}

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

    /// Remove an entry by index
    pub fn remove_entry(&mut self, index: usize) -> bool {
        if index < self.entries.len() {
            self.entries.remove(index);
            true
        } else {
            false
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

    /// Encrypt and save vault to file at a numbered path
    pub fn save_with_number(&self, password: &str, vault_number: Option<u32>) -> io::Result<String> {
        // Determine vault number
        let number = match vault_number {
            Some(n) => n,
            None => Self::next_vault_number()?,
        };

        let filename = format!("vault_{:02}.dat", number);
        self.save_encrypted(&filename, password)?;
        Ok(filename)
    }

    /// Get next available vault number based on existing vault files
    fn next_vault_number() -> io::Result<u32> {
        let mut max_number = 0;
        for entry in fs::read_dir(".")? {
            let entry = entry?;
            if let Some(number) = Self::parse_vault_number(entry.file_name().to_string_lossy().as_ref()) {
                if number >= max_number {
                    max_number = number + 1;
                }
            }
        }
        Ok(max_number)
    }

    /// Parse vault number from filename
    pub fn parse_vault_number(filename: &str) -> Option<u32> {
        if filename.starts_with("vault_") && filename.ends_with(".dat") {
            let number_str = &filename[6..8];
            number_str.parse().ok()
        } else {
            None
        }
    }

    /// Scan all vault files to find the one matching the given password
    pub fn find_vault_by_passcode(password: &str) -> Option<String> {
        let paths = fs::read_dir(".").ok()?;
        for path in paths {
            if let Ok(entry) = path {
                let filename = entry.file_name().to_string_lossy().into_owned();
                if filename.starts_with("vault_") && filename.ends_with(".dat") {
                    if Vault::load_encrypted(&filename, password).is_ok() {
                        return Some(filename);
                    }
                }
            }
        }
        None
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
        let key_slice: &Key<Aes256Gcm> = Key::<Aes256Gcm>::from_slice(&key_bytes);
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

        fs::write(path, base64::engine::general_purpose::STANDARD.encode(blob))?;
        Ok(())
    }

    /// Load and decrypt vault from file at `path`
    pub fn load_encrypted(path: &str, password: &str) -> io::Result<Self> {
        let encoded = fs::read_to_string(path)?;
        let raw = base64::engine::general_purpose::STANDARD
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
