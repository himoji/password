use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::Rng;

pub fn generate_password(password: &str, salt: &str) -> String {
    let argon2 = Argon2::default();
    let salt = SaltString::from_b64(salt).expect("Invalid salt");
    argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string()
}

pub fn verify_password(password: &str, master: &str) -> bool {
    let parsed_hash = PasswordHash::new(master).expect("Invalid master hash");
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

pub fn encrypt_password(password: &str, master_key: &[u8; 32]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(master_key.into());
    let rand: [u8; 12] = rand::thread_rng().gen();
    let nonce = Nonce::from_slice(&rand);
    let ciphertext = cipher
        .encrypt(nonce, password.as_bytes())
        .expect("encryption failure!");
    [nonce.to_vec(), ciphertext].concat()
}

pub fn decrypt_password(encrypted: &[u8], master_key: &[u8; 32]) -> Option<String> {
    if encrypted.len() < 12 {
        return None;
    }
    let (nonce, ciphertext) = encrypted.split_at(12);
    let cipher = Aes256Gcm::new(master_key.into());
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .ok()
        .and_then(|decrypted| String::from_utf8(decrypted).ok())
}
