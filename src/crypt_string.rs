use zeroize::Zeroize;

#[derive(Zeroize)]
#[zeroize(drop)]
pub enum CryptString {
    Encrypted(Vec<u8>),
    Decrypted(String),
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn rarr() {
        let crypt_string = CryptString::Decrypted("arrrrgh".into());
    }
}
