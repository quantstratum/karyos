// SPDX-License-Identifier: Apache-2.0

//! Self-validating message payloads: a header of publisher, sequence,
//! length and checksum, then bytes derived from them, so a reader can
//! validate any message alone.

/// Bytes of the header.
pub const HEADER: usize = 16;

/// What a valid payload names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Stamp {
    /// The publishing actor.
    pub publisher: u32,
    /// Its sequence number.
    pub sequence: u32,
}

fn checksum(publisher: u32, sequence: u32, length: u32) -> u32 {
    // FNV-1a over the three fields.
    let mut hash: u32 = 0x811C_9DC5;
    for byte in publisher
        .to_le_bytes()
        .into_iter()
        .chain(sequence.to_le_bytes())
        .chain(length.to_le_bytes())
    {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

fn body_byte(stamp: Stamp, index: usize) -> u8 {
    (stamp.publisher as usize * 31 + stamp.sequence as usize * 17 + index) as u8
}

/// The payload of `stamp`, `length` bytes long (at least [`HEADER`]).
#[must_use]
pub fn encode(stamp: Stamp, length: usize) -> Vec<u8> {
    let length = length.max(HEADER);
    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(&stamp.publisher.to_le_bytes());
    bytes.extend_from_slice(&stamp.sequence.to_le_bytes());
    bytes.extend_from_slice(&(length as u32).to_le_bytes());
    bytes
        .extend_from_slice(&checksum(stamp.publisher, stamp.sequence, length as u32).to_le_bytes());
    bytes.extend((HEADER..length).map(|index| body_byte(stamp, index)));
    bytes
}

fn word(bytes: &[u8], at: usize) -> Option<u32> {
    let field: [u8; 4] = bytes.get(at..at + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(field))
}

/// The stamp of a valid payload, or why it is not valid.
///
/// # Errors
///
/// Returns a description of the first defect found.
pub fn decode(bytes: &[u8]) -> Result<Stamp, String> {
    let (Some(publisher), Some(sequence), Some(length), Some(sum)) = (
        word(bytes, 0),
        word(bytes, 4),
        word(bytes, 8),
        word(bytes, 12),
    ) else {
        return Err(format!("payload of {} bytes has no header", bytes.len()));
    };
    if length as usize != bytes.len() {
        return Err(format!("length field {length} but {} bytes", bytes.len()));
    }
    if sum != checksum(publisher, sequence, length) {
        return Err("header checksum mismatch".into());
    }
    let stamp = Stamp {
        publisher,
        sequence,
    };
    for (index, &byte) in bytes.iter().enumerate().skip(HEADER) {
        if byte != body_byte(stamp, index) {
            return Err(format!("body byte {index} corrupt"));
        }
    }
    Ok(stamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_round_trip_and_corruption_is_found() {
        let stamp = Stamp {
            publisher: 3,
            sequence: 9,
        };
        let mut bytes = encode(stamp, 64);
        assert_eq!(bytes.len(), 64);
        assert_eq!(decode(&bytes), Ok(stamp));
        assert_eq!(encode(stamp, 4).len(), HEADER);
        bytes[40] ^= 1;
        assert!(decode(&bytes).is_err());
        assert!(decode(&bytes[..10]).is_err());
        let mut short = encode(stamp, 32);
        short.pop();
        assert!(decode(&short).is_err());
    }
}
