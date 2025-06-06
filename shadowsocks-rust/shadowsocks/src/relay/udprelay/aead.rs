//! Shadowsocks UDP AEAD protocol
//!
//! Payload with AEAD cipher
//!
//! ```plain
//! UDP (after encryption, *ciphertext*)
//! +--------+-----------+-----------+
//! | NONCE  |  *Data*   |  Data_TAG |
//! +--------+-----------+-----------+
//! | Fixed  | Variable  |   Fixed   |
//! +--------+-----------+-----------+
//! ```

use std::io::Cursor;

use byte_string::ByteStr;
use bytes::{BufMut, BytesMut};
use log::trace;
use rand::seq::SliceRandom;
use rand::Rng;
use rand_pcg::Pcg64;
use rand_seeder::Seeder;

use crate::{
    context::Context,
    crypto::{v1::Cipher, CipherKind},
    relay::socks5::{Address, Error as Socks5Error},
};

/// AEAD packet payload must be smaller than 0x3FFF
pub const MAX_PACKET_SIZE: usize = 0x3FFF;

/// Since we append extra 1s or 0s to the payload, the actual payload size should be smaller
pub const MAX_PAYLOAD_SIZE: usize = 0x2F00;

/// AEAD protocol error
#[derive(thiserror::Error, Debug)]
pub enum ProtocolError {
    #[error("packet too short for salt, at least {0} bytes, but only {1} bytes")]
    PacketTooShortForSalt(usize, usize),
    #[error("packet too short for tag, at least {0} bytes, but only {1} bytes")]
    PacketTooShortForTag(usize, usize),
    #[error("invalid address in packet, {0}")]
    InvalidAddress(Socks5Error),
    #[error("decrypt payload failed")]
    DecryptPayloadError,
    #[error("packet too large ({0:#x}), AEAD encryption protocol requires packet to be smaller than 0x3FFF")]
    PacketTooLong(usize),
}

/// AEAD protocol result
pub type ProtocolResult<T> = Result<T, ProtocolError>;

/// Encrypt UDP AEAD protocol packet
pub fn encrypt_payload_aead(
    context: &Context,
    method: CipherKind,
    key: &[u8],
    addr: &Address,
    payload: &[u8],
    dst: &mut BytesMut,
) {
    if payload.len() > MAX_PAYLOAD_SIZE {
        // Truncate payload if it's too large
        let payload = &payload[..MAX_PAYLOAD_SIZE];
    }

    let salt_len = method.salt_len();
    let addr_len = addr.serialized_len();

    // Generate IV
    dst.resize(salt_len, 0);
    let salt = &mut dst[..salt_len];

    if salt_len > 0 {
        context.generate_nonce(method, salt, false);
        trace!("UDP packet generated aead salt {:?}", ByteStr::new(salt));
    }

    let mut cipher_for_data = Cipher::new(method, key, salt);

    // Prepare data
    addr.write_to_buf(dst);
    dst.put_slice(payload);

    let data_len = dst.len() - salt_len;
    trace!("before encoding size: {}", data_len);

    // Count number of 1s and 0s in the packet
    let mut number_of_ones: u32 = 0;
    let mut number_of_zeros: u32 = 0;
    for i in salt_len..dst.len() {
        for j in 0..8 {
            let bit = (dst[i] >> j) & 1;
            if bit == 1 {
                number_of_ones += 1;
            } else {
                number_of_zeros += 1;
            }
        }
    }
    trace!("number_of_ones = {}, number_of_zeros = {}", number_of_ones, number_of_zeros);

    let mut rng = rand::thread_rng();
    let current_ratio = number_of_ones as f32 / number_of_zeros as f32;
    trace!("1/0 ratio = {}", current_ratio);
    println!("udp加密: 1/0 ratio = {}", current_ratio);

    // Add padding if needed
    let mut extra_bytes_len = 0u32;
    if current_ratio > 0.7 && current_ratio < 1.4 {
        if number_of_ones <= number_of_zeros {
            // Append more 0s
            let target_ratio = rng.gen_range(0.6..0.7);
            trace!("target 1/0 ratio = {}", target_ratio);
            print!("udp加密: target 1/0 ratio = {}", target_ratio);
            extra_bytes_len = ((number_of_ones as f32 / target_ratio) as u32 - number_of_zeros) / 8 + 1;
            dst.reserve(extra_bytes_len as usize + 4);
            for _ in 0..extra_bytes_len {
                dst.put_u8(0);
            }
        } else {
            // Append more 1s
            let target_ratio = rng.gen_range(1.4..1.5);
            trace!("target 1/0 ratio = {}", target_ratio);
            print!("udp加密: target 1/0 ratio = {}", target_ratio);
            extra_bytes_len = ((number_of_zeros as f32 * target_ratio) as u32 - number_of_ones) / 8 + 1;
            dst.reserve(extra_bytes_len as usize + 4);
            for _ in 0..extra_bytes_len {
                dst.put_u8(0xff);
            }
        }
    }

    // Append extra bytes length
    dst.put_u32(extra_bytes_len);

    // Bit-level shuffle
    let data_size = dst.len() - salt_len;
    let bit_vector_len = data_size * 8;

    // Initialize random number generator from seed
    let mut rng: Pcg64 = Seeder::from(key).make_rng();
    let mut shuffled_idx: Vec<usize> = (0..bit_vector_len).collect();
    shuffled_idx.shuffle(&mut rng);

    // Convert byte vector to bit vector
    let mut bit_vector: Vec<u8> = Vec::new();
    for i in salt_len..dst.len() {
        for j in 0..8 {
            let bit = (dst[i] >> j) & 1;
            bit_vector.push(bit);
        }
    }

    // Shuffle bit vector
    let mut bit_vector_shuffled = vec![0u8; bit_vector_len];
    for i in 0..bit_vector_len {
        bit_vector_shuffled[shuffled_idx[i]] = bit_vector[i];
    }

    // Convert back to bytes
    let mut data_shuffled = Vec::new();
    for chunk in bit_vector_shuffled.chunks(8) {
        let mut byte = 0u8;
        for (j, &bit) in chunk.iter().enumerate() {
            byte |= bit << j;
        }
        data_shuffled.push(byte);
    }

    // Replace data in dst
    dst.truncate(salt_len);
    dst.put_slice(&data_shuffled);

    trace!("after encoding size: {}", dst.len() - salt_len);

    // Add tag space
    unsafe {
        dst.advance_mut(method.tag_len());
    }

    // Encrypt
    let m = &mut dst[salt_len..];
    cipher_for_data.encrypt_packet(m);
}

/// Decrypt UDP AEAD protocol packet
pub fn decrypt_payload_aead(
    _context: &Context,
    method: CipherKind,
    key: &[u8],
    payload: &mut [u8],
) -> ProtocolResult<(usize, Address)> {
    let plen = payload.len();
    let salt_len = method.salt_len();

    if plen < salt_len {
        return Err(ProtocolError::PacketTooShortForSalt(salt_len, plen));
    }

    let (salt, data) = payload.split_at_mut(salt_len);

    trace!("UDP packet got AEAD salt {:?}", ByteStr::new(salt));

    let mut cipher = Cipher::new(method, key, salt);
    let tag_len = cipher.tag_len();

    if data.len() < tag_len {
        return Err(ProtocolError::PacketTooShortForTag(tag_len, data.len()));
    }

    if !cipher.decrypt_packet(data) {
        return Err(ProtocolError::DecryptPayloadError);
    }

    // Truncate TAG
    let data_len = data.len() - tag_len;
    let data = &mut data[..data_len];

    // Reverse bit-level shuffle
    let bit_vector_len = data_len * 8;

    // Initialize random number generator from seed
    let mut rng: Pcg64 = Seeder::from(key).make_rng();
    let mut shuffled_idx: Vec<usize> = (0..bit_vector_len).collect();
    shuffled_idx.shuffle(&mut rng);

    // Convert to bit vector
    let mut bit_vector = Vec::new();
    for i in 0..data_len {
        for j in 0..8 {
            let bit = (data[i] >> j) & 1;
            bit_vector.push(bit);
        }
    }

    // Unshuffle bit vector
    let mut bit_vector_unshuffled = vec![0u8; bit_vector_len];
    for i in 0..bit_vector_len {
        bit_vector_unshuffled[shuffled_idx[i]] = bit_vector[i];
    }

    // Convert back to bytes
    let mut decoded_data = Vec::new();
    for chunk in bit_vector_unshuffled.chunks(8) {
        let mut byte = 0u8;
        for (j, &bit) in chunk.iter().enumerate() {
            byte |= bit << j;
        }
        decoded_data.push(byte);
    }

    // Get and remove padding length
    let padding_bytes = 4;
    let mut extra_bytes_len: u32 = 0;
    for i in 0..4 {
        extra_bytes_len |= (decoded_data[decoded_data.len() - i - 1] as u32) << (i * 8);
    }
    println!("udp: extra_bytes_len = {}", extra_bytes_len);
    // Remove padding and padding length
    decoded_data.truncate(decoded_data.len() - extra_bytes_len as usize - padding_bytes);

    // Copy back decoded data
    data[..decoded_data.len()].copy_from_slice(&decoded_data);

    let (dn, addr) = parse_packet(&data[..decoded_data.len()])?;
    let data_length = decoded_data.len() - dn;

    // Move actual data to beginning of payload
    let data_start_idx = salt_len + dn;
    let data_end_idx = data_start_idx + data_length;
    payload.copy_within(data_start_idx..data_end_idx, 0);

    Ok((data_length, addr))
}

#[inline]
fn parse_packet(buf: &[u8]) -> ProtocolResult<(usize, Address)> {
    let mut cur = Cursor::new(buf);
    match Address::read_cursor(&mut cur) {
        Ok(address) => {
            let pos = cur.position() as usize;
            Ok((pos, address))
        }
        Err(err) => Err(ProtocolError::InvalidAddress(err)),
    }
}