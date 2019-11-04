#[derive(Zeroize)]
#[drop(zeroize)]
pub enum CryptString {
    Encrypted(Vec<u8>),
    Decrypted(String),
}

#[cfg(test)]
mod test {
    #[test]
    fn rarr() {
        let crypt_string = CryptString::Decrypted("arrrrgh");
    }
}
