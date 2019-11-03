#[derive(Zeroize)]
#[drop(zeroize)]
pub enum CryptString {
    Encrypted(Vec<u8>),
    Decrypted(String),
}
