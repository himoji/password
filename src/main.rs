use password::{decrypt_password, encrypt_password, generate_password, verify_password};
use std::io;

fn main() {
    let master_pass = "masterpassword";
    let salt = "saltsaltsalt";
    let master_hash = generate_password(master_pass, salt);

    // In a real application, you'd get this from user input
    let input_pass = &get_input("input your password: ");

    if verify_password(input_pass, &master_hash) {
        println!("Master password correct. Encrypting passwords...");

        // Use the master password to derive an encryption key
        // In a real application, you'd use a proper key derivation function
        let mut master_key = [0u8; 32];
        master_pass.bytes().enumerate().for_each(|(i, b)| {
            if i < 32 {
                master_key[i] = b;
            }
        });

        let password_to_encrypt = "secret password 228";
        let encrypted = encrypt_password(password_to_encrypt, &master_key);
        println!("Encrypted password: {:?}", encrypted);

        let decrypted = decrypt_password(&encrypted, &master_key).unwrap();
        println!("Decrypted password: {}", decrypted);
    } else {
        println!("Incorrect master password");
    }
}

fn get_input(prompt: &str) -> String {
    println!("{}", prompt);
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");
    input.trim().to_string()
}
