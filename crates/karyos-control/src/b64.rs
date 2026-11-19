// SPDX-License-Identifier: Apache-2.0

//! Base64url without padding (RFC 4648 §5; RFC 7515 §2), the encoding of
//! every JWS segment and JWK member.

/// The alphabet's value of `byte`, if it is in it.
const fn value(byte: u8) -> Option<u32> {
    Some(match byte {
        b'A'..=b'Z' => (byte - b'A') as u32,
        b'a'..=b'z' => (byte - b'a') as u32 + 26,
        b'0'..=b'9' => (byte - b'0') as u32 + 52,
        b'-' => 62,
        b'_' => 63,
        _ => return None,
    })
}

/// The bytes `text` encodes; `None` for a character outside the alphabet,
/// padding, a length no encoding has, or nonzero trailing bits (a
/// non-canonical encoding).
#[must_use]
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 2);
    for chunk in bytes.chunks(4) {
        let mut word = 0u32;
        for byte in chunk {
            word = (word << 6) | value(*byte)?;
        }
        match chunk.len() {
            4 => out.extend_from_slice(&[(word >> 16) as u8, (word >> 8) as u8, word as u8]),
            3 => {
                if word & 0b11 != 0 {
                    return None;
                }
                let word = word >> 2;
                out.extend_from_slice(&[(word >> 8) as u8, word as u8]);
            }
            2 => {
                if word & 0b1111 != 0 {
                    return None;
                }
                out.push((word >> 4) as u8);
            }
            _ => return None,
        }
    }
    Some(out)
}

/// `bytes`, encoded.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let symbol =
        |index: u32| char::from(ALPHABET.get(index as usize & 63).copied().unwrap_or(b'A'));
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let (a, b, c) = match *chunk {
            [a, b, c] => (a, b, c),
            [a, b] => (a, b, 0),
            [a] => (a, 0, 0),
            _ => break,
        };
        let word = (u32::from(a) << 16) | (u32::from(b) << 8) | u32::from(c);
        let symbols = chunk.len() + 1;
        for index in 0..symbols {
            out.push(symbol(word >> (18 - 6 * index as u32)));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 §10's vectors, in the URL alphabet without padding; a
    /// non-canonical or padded encoding is refused.
    #[test]
    fn round_trips_and_refuses_the_non_canonical() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes()), encoded);
            assert_eq!(decode(encoded).as_deref(), Some(plain.as_bytes()));
        }
        assert_eq!(encode(&[0xfb, 0xff]), "-_8");
        for bad in ["Zg==", "Z", "Zh", "Zm9", "Zm+v", "Zm/v", "Zm9v Yg"] {
            assert_eq!(decode(bad), None, "{bad}");
        }
    }
}
