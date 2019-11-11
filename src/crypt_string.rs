use crypto::bcrypt::bcrypt;
use zeroize::Zeroize;

#[derive(Zeroize)]
#[zeroize(drop)]
pub enum CryptString {
    Encrypted(Vec<u8>),
    Decrypted(String),
}

impl CryptString {
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn instantiation() {
        let _crypt_string = CryptString::Decrypted("arrrrgh".into());
    }

    #[test]
    fn encrypt_decrypt() {
        unimplemented!()
    }

    #[test]
    fn hash_bcrypt() {
        let password = CryptString::Decrypted("Hello, there".into());
        let salt: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let expected_hash = [
            163, 78, 231, 200, 130, 26, 71, 214, 149, 120, 98, 72, 166, 101, 165, 25, 30, 120, 2,
            140, 230, 220, 138, 160,
        ];

        assert_eq!(expected_hash, password.hash(&salt));
    }
}
