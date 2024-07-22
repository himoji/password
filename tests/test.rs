use password::{decrypt_password, encrypt_password, generate_password, verify_password};

#[test]
fn test_password_correct() {
    let master_pass = "pass";
    let salt = "saltsaltsalt";
    let master_hash = generate_password(master_pass, salt);
    // Test correct password
    let correct_pass = "pass";
    assert!(verify_password(correct_pass, &master_hash));
}

#[test]
fn test_password_incorrect() {
    let master_pass = "pass";
    let salt = "saltsaltsalt";
    let master_hash = generate_password(master_pass, salt);
    // Test incorrect password
    let incorrect_pass = "wrong";
    assert!(!verify_password(incorrect_pass, &master_hash));
}

#[test]
fn test_encrypt_decrypt() {
    let master_key = [0u8; 32]; // In real usage, this should be a secure and random key
    let password = "mysecretpassword";
    let encrypted = encrypt_password(password, &master_key);
    let decrypted = decrypt_password(&encrypted, &master_key).unwrap();
    assert_eq!(password, decrypted);
}
