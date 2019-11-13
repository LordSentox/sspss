use crypto::bcrypt::bcrypt;
use crypto::buffer::{self, BufferResult, ReadBuffer, WriteBuffer};
use crypto::symmetriccipher::SymmetricCipherError;
use crypto::{aes, blockmodes};
use zeroize::Zeroize;

#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub enum CryptString {
    Encrypted(Vec<u8>),
    Decrypted(String)
}

impl CryptString {
    pub fn to_decrypted(self, key: &[u8], iv: &[u8]) -> Self {
        match self {
            Self::Encrypted(data) => Self::Decrypted(
                String::from_utf8(decrypt(&data, key, iv).expect("Unable to encrypt string"))
                    .expect("Encrypted string corrupted with non utf8 characters")
            ),
            decrypted => decrypted
        }
    }

    pub fn to_encrypted(self, key: &[u8], iv: &[u8]) -> Self {
        match self {
            Self::Decrypted(string) => Self::Encrypted(
                encrypt(&string.as_bytes(), key, iv).expect("Unable to encrypt string")
            ),
            encrypted => encrypted
        }
    }

    pub fn hash(&self, salt: &[u8; 16]) -> [u8; 24] {
        let string = match self {
            Self::Decrypted(string) => string,
            Self::Encrypted(_) => {
                panic!("Tried to hash encrypted password, but it must be decrypted before")
            }
        };

        let cost = 12;
        let mut output = [0; 24];
        bcrypt(cost, salt, &string.as_bytes(), &mut output);

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
    fn instantiation() { let _crypt_string = CryptString::Decrypted("arrrrgh".into()); }

    #[test]
    fn encrypt_decrypt() {
        let raw = String::from("Why, how are you, little fellar?");
        let data = CryptString::Decrypted(raw.clone());
        let key = String::from("Waröm, 何をするつもり？");
        let key = key.as_bytes();
        let iv: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let encrypted = data.to_encrypted(key, &iv);
        let decrypted = encrypted.to_decrypted(key, &iv);

        match decrypted {
            CryptString::Decrypted(dec) => assert_eq!(raw, dec),
            enc => panic!("Unable to decrypt string {:?}", enc)
        }
    }

    #[test]
    fn hash_bcrypt() {
        let password = CryptString::Decrypted("Hello, there".into());
        let salt: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let expected_hash = [
            163, 78, 231, 200, 130, 26, 71, 214, 149, 120, 98, 72, 166, 101, 165, 25, 30, 120, 2,
            140, 230, 220, 138, 160
        ];

        assert_eq!(expected_hash, password.hash(&salt));
    }
}
