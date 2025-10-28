use std::fs;

use aes_gcm::{
    aead::{Aead, OsRng},
    AeadCore, Aes256Gcm, KeyInit,
};
use base64::prelude::*;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// Save bytes to file encoded as Base64.
///
/// The data is encoded using the standard Base64 encoding engine and written to
/// disk.
///
/// # Arguments
///
/// * `file_name` - the path of the file in which the data is to be saved
/// * `data` - the data of to be saved to file
///
/// # Note
fn save_to_file_as_b64(file_name: &str, data: &[u8]) {
    let encoded_data = BASE64_STANDARD.encode(data);

    fs::write(file_name, encoded_data)
        .unwrap_or_else(|_| panic!("Failed to write base64 file"));
}

/// Read a Base64-encoded file as bytes.
///
/// The data is read from disk and decoded using the standard Base64 encoding
/// engine.
///
/// # Note
///
/// You may **not** change the signature of this function.
///
fn read_from_b64_file(file_name: &str) -> Vec<u8> {
    // TODO
	let contents = fs::read_to_string(file_name)
        .expect("Failed to read base64 file");

	let decoded_content = BASE64_STANDARD
        .decode(contents.trim()).expect("Base64 decoding failed");
	decoded_content
}

/// Returns a tuple containing a randomly generated secret key and public key.
///
/// The secret key is a StaticSecret that can be used in a Diffie-Hellman key
/// exchange. The public key is the associated PublicKey for the StaticSecret.
/// The output of this function is a tuple of bytes corresponding to these keys.
///
/// # Note
///
fn keygen() -> ([u8; 32], [u8; 32]) {
    // TODO
    let sec_key = StaticSecret::random_from_rng(OsRng);
    let pub_key = PublicKey::from(&sec_key);

    (sec_key.to_bytes(), pub_key.to_bytes())
}

/// Returns the encryption of plaintext data to be sent from a sender to a receiver.
///
/// This function performs a Diffie-Hellman key exchange between the sender's
/// secret key and the receiver's public key. Then, the function uses SHA-256 to
/// derive a symmetric encryption key, which is then used in an AES-256-GCM
/// encryption operation. The output vector contains the ciphertext with the
/// AES-256-GCM nonce (12 bytes long) appended to its end.
///
/// # Arguments
///
/// * `input` - A vector of bytes (`u8`) that represents the plaintext data to be encrypted.
/// * `sender_sk` - An array of bytes representing the secret key of the sender.
/// * `receiver_pk` - An array of bytes representing the public key of the receiver.
///
/// # Note
///
fn encrypt(input: Vec<u8>, sender_sk: [u8; 32], receiver_pk: [u8; 32]) -> Vec<u8> {
    //TODO
    let inputlen = input.len();

    if inputlen == 0 {
        panic!("Cannot encrypt an empty file")
    } else {
        //Create a shared secret key
        let sender_sec = StaticSecret::from(sender_sk);
        let rec_pub = PublicKey::from(receiver_pk);
        let shared_sec = sender_sec.diffie_hellman(&rec_pub);

        //derive a symettric encryption key
        let hash = Sha256::digest(shared_sec.as_bytes());
        let sym_enc_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&hash);

        //AES-256-GCM encryption operation from semmetric encryption key
        let cipher = Aes256Gcm::new(sym_enc_key);

        //nonce
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        // Encrypt
        let cipher_text = cipher.encrypt(&nonce, input.as_ref()).unwrap();

        // Append nonce to end of ciphertext
        let mut out = cipher_text;
    
        out.extend_from_slice(nonce.as_slice());

        out
    }
}

/// Returns the decryption of ciphertext data to be received by a receiver from a sender.
///
/// This function performs a Diffie-Hellman key exchange between the receiver's
/// secret key and the sender's public key. Then, the function uses SHA-256 to
/// derive a symmetric encryption key, which is then used in an AES-256-GCM
/// decryption operation. The nonce for this decryption is the last 12 bytes of
/// the input. The output vector contains the plaintext.
///
/// # Arguments
///
/// * `input` - A vector of bytes that represents the ciphertext data to be encrypted and the associated nonce.
/// * `receiver_sk` - An array of bytes representing the secret key of the receiver.
/// * `sender_pk` - An array of bytes representing the public key of the sender.
///
/// # Note
///
fn decrypt(input: Vec<u8>, receiver_sk: [u8; 32], sender_pk: [u8; 32]) -> Vec<u8> {
    // TODO

    // check input is encrypted
    // if not return error
    // else continue
    let inputlen = input.len();

    if inputlen < 12{
        panic!("Input too short to decrypt. Might be missing nonce or message")
    } else {
        
        let rec_sec = StaticSecret::from(receiver_sk);
        let sender_pub = PublicKey::from(sender_pk);
        let shared_sec = rec_sec.diffie_hellman(&sender_pub);

        //derive a symettric encryption key
        let hash = Sha256::digest(shared_sec.as_bytes());
        let sym_enc_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&hash);

        let cipher = Aes256Gcm::new(sym_enc_key);

        let nonce_start = input.len() - 12;
        let (cipher_text, nonce_bytes) = input.split_at(nonce_start);
        let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);

        cipher.decrypt(&nonce, cipher_text.as_ref())
            .expect("Decryption failed")
    }
}

/// The main function, which parses arguments and calls the correct cryptographic operations.
///
/// # Note
///
fn main() {
    // Collect command line arguments
    let args: Vec<String> = std::env::args().collect();

    // Command parsing: keygen, encrypt, decrypt
    let cmd = &args[1];
    if cmd == "keygen" {
        // Arguments to the command
        let secret_key = &args[2];
        let public_key = &args[3];

        // Generate a secret and public key for this user
        let (sk_bytes, pk_bytes) = keygen();

        // Save those bytes as Base64 to file
        save_to_file_as_b64(&secret_key, &sk_bytes);
        save_to_file_as_b64(&public_key, &pk_bytes);
    } else if cmd == "encrypt" {
        // Arguments to the command
        let input = &args[2];
        let output = &args[3];
        let sender_sk = &args[4];
        let receiver_pk = &args[5];

        // Read input from file
        // Note that this input is not necessarily Base64-encoded
        let input = fs::read(input).unwrap();

        // Read the base64-encoded secret and public keys from file
        // Need to convert the Vec<u8> from this function into the 32-byte array for each key
        let sender_sk: [u8; 32] = read_from_b64_file(sender_sk).try_into().unwrap();
        let receiver_pk: [u8; 32] = read_from_b64_file(receiver_pk).try_into().unwrap();

        // Call the encryption operation
        let output_bytes = encrypt(input, sender_sk, receiver_pk);

        // Save those bytes as Base64 to file
        save_to_file_as_b64(&output, &output_bytes);
    } else if cmd == "decrypt" {
        // Arguments to the command
        let input = &args[2];
        let output = &args[3];
        let receiver_sk = &args[4];
        let sender_pk = &args[5];

        // Read the Base64-encoded input ciphertext from file
        let input = read_from_b64_file(&input);

        // Read the base64-encoded secret and public keys from file
        // Need to convert the Vec<u8> from this function into the 32-byte array for each key
        let receiver_sk: [u8; 32] = read_from_b64_file(&receiver_sk).try_into().unwrap();
        let sender_pk: [u8; 32] = read_from_b64_file(&sender_pk).try_into().unwrap();

        // Call the decryption operation
        let output_bytes = decrypt(input, receiver_sk, sender_pk);

        // Save those bytes as Base64 to file
        fs::write(output, output_bytes).unwrap();
    } else {
        panic!("command not found!")
    }
}

#[cfg(test)]
mod tests {
    // TODO: Write tests that validate your encryption and decryption functionality
    // Use the values in README.md to write these tests
    // You may have to split up function to write tests
    // For example, how can you test that both parties reach the same AES key?

    /*
    Set up any needed data or state.
    Run the code you want to test.
    Assert that the results are what you expect.
    */

    use super::*;

    #[test]
    fn test_readandwrite(){
        let file_name = "testfile.txt";
        let data = b"Hello Rust How are you doing";

        save_to_file_as_b64(file_name, data);

        let read_data = read_from_b64_file(file_name);
        assert_eq!(data.to_vec(), read_data);

        // Cleanup
        fs::remove_file(file_name).unwrap();
    }

    #[test]
    fn test_keygen(){
        let (sk, pk) = keygen();
        assert_eq!(sk.len(), 32);
        assert_eq!(pk.len(), 32);
        //ensure the generated value aren't equal
        assert_ne!(sk, pk);
    }

    #[test]
    fn test_encryptanddecrypt(){
        let mes = b"Hello rust how are yo doing".to_vec();

        let (sen_sec, sen_pub) = keygen();
        let (rec_sec, rec_pub) = keygen();

        let ciphertext = encrypt(mes.clone(), sen_sec, rec_pub);
        let decrypted = decrypt(ciphertext, rec_sec, sen_pub);

        assert_ne!(mes, decrypted);
    }

    #[test]
    #[should_panic(expected = "Cannot encrypt an empty file")]
    fn test_encrypt_empty_input_should_panic() {
        let (sen_sk, _) = keygen();
        let (_, rec_pk) = keygen();
        encrypt(vec![], sen_sk, rec_pk);
    }

    #[test]
    fn test_shared_key() {
        let (sk1, pk1) = keygen();
        let (sk2, _pk2) = keygen();

        let sec1 = StaticSecret::from(sk1);
        let sec2 = StaticSecret::from(sk2);
        let pub1 = PublicKey::from(pk1);
        let pub2 = PublicKey::from(pk1);

        let shared1 = sec1.diffie_hellman(&pub2);
        let shared2 = sec2.diffie_hellman(&pub1);

        assert_ne!(shared1.as_bytes(), shared2.as_bytes(), "Diffie-Hellman keys should not match");
    }
}
