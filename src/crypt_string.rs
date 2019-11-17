use crypto::bcrypt::bcrypt;
use crypto::buffer::{self, BufferResult, ReadBuffer, WriteBuffer};
use crypto::symmetriccipher::SymmetricCipherError;
use crypto::{aes, blockmodes};
use zeroize::Zeroize;

#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct Encrypted(Vec<u8>);

#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct SafeString(String);

impl Encrypted {
    pub fn to_decrypted(self, key: &[u8], iv: &[u8]) -> SafeString {
        SafeString(
            String::from_utf8(decrypt(&self.0, key, iv).expect("Unable to encrypt string"))
                .expect("Encrypted string corrupted with non utf8 characters")
        )
    }
}

impl SafeString {
    pub fn to_encrypted(self, key: &[u8], iv: &[u8]) -> Encrypted {
        Encrypted(encrypt(&self.0.as_bytes(), key, iv).expect("Unable to encrypt string"))
    }

    pub fn hash(&self, salt: &[u8; 16]) -> [u8; 24] {
        let cost = 12;
        let mut output = [0; 24];
        bcrypt(cost, salt, &self.0.as_bytes(), &mut output);

        output
    }
}

// Decryption and encryption helper functions ---------------------------------

fn decrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut decryptor =
        aes::cbc_decryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    let mut result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let intermediate = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
        result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i)
        );
        match intermediate {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(result)
}

fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut encryptor =
        aes::cbc_encryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    let mut result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let intermediate = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;
        result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i)
        );
        match intermediate {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(result)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn instantiation() { let _crypt_string = SafeString("arrrrgh".into()); }

    #[test]
    fn encrypt_decrypt() {
        let raw = String::from("Why, how are you, little fellar?");
        let data = SafeString(raw.clone());
        let key = String::from("Waröm, 何をするつもり？");
        let key = key.as_bytes();
        let iv: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let encrypted = data.to_encrypted(key, &iv);
        let decrypted = encrypted.to_decrypted(key, &iv);

        assert_eq!(raw, decrypted.0);
    }

    #[test]
    fn hash_bcrypt() {
        let password = SafeString("Hello, there".into());
        let salt: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let expected_hash = [
            163, 78, 231, 200, 130, 26, 71, 214, 149, 120, 98, 72, 166, 101, 165, 25, 30, 120, 2,
            140, 230, 220, 138, 160
        ];

        assert_eq!(expected_hash, password.hash(&salt));
    }
}
