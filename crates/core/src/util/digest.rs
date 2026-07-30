use sha2::{Digest, Sha256};
use std::fmt::Write as _;

/// Return the lowercase hexadecimal SHA-256 digest of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
  let digest = Sha256::digest(bytes);
  let mut encoded = String::with_capacity(digest.len() * 2);
  for byte in digest {
    write!(encoded, "{byte:02x}").expect("writing a SHA-256 digest to a String cannot fail");
  }
  encoded
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn encodes_a_known_sha256_vector() {
    assert_eq!(
      sha256_hex(b"abc"),
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
  }
}
