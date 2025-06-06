use rand::seq::SliceRandom;
use rand_pcg::Pcg64;
use rand_seeder::Seeder;
use std::slice;

#[no_mangle]
pub extern "C" fn pcg64_shuffle_bits(data_ptr: *mut u8, len: usize, key_ptr: *const u8, key_len: usize, seed_ptr: *const u8, seed_len: usize) {
    if data_ptr.is_null() { return; }
    let data = unsafe { slice::from_raw_parts_mut(data_ptr, len) };
    let _key = unsafe { slice::from_raw_parts(key_ptr, key_len) };
    let seed = unsafe { slice::from_raw_parts(seed_ptr, seed_len) };
    let mut rng: Pcg64 = Seeder::from(seed).make_rng();
    let bit_len = data.len() * 8;
    let mut idx: Vec<usize> = (0..bit_len).collect();
    idx.shuffle(&mut rng);
    let mut bits: Vec<u8> = Vec::with_capacity(bit_len);
    for &b in data.iter() { for j in 0..8 { bits.push((b>>j)&1); } }
    let mut shuffled = vec![0u8; bit_len];
    for i in 0..bit_len { shuffled[idx[i]] = bits[i]; }
    for (i, byte) in data.iter_mut().enumerate() {
        let mut v = 0u8;
        for j in 0..8 { v |= shuffled[i*8+j]<<j; }
        *byte = v;
    }
}

#[no_mangle]
pub extern "C" fn pcg64_unshuffle_bits(data_ptr: *mut u8, len: usize, key_ptr: *const u8, key_len: usize, seed_ptr: *const u8, seed_len: usize) {
    if data_ptr.is_null() { return; }
    let data = unsafe { slice::from_raw_parts_mut(data_ptr, len) };
    let _key = unsafe { slice::from_raw_parts(key_ptr, key_len) };
    let seed = unsafe { slice::from_raw_parts(seed_ptr, seed_len) };
    let mut rng: Pcg64 = Seeder::from(seed).make_rng();
    let bit_len = data.len() * 8;
    let mut idx: Vec<usize> = (0..bit_len).collect();
    idx.shuffle(&mut rng);
    let mut bits: Vec<u8> = Vec::with_capacity(bit_len);
    for &b in data.iter() { for j in 0..8 { bits.push((b>>j)&1); } }
    let mut unshuffled = vec![0u8; bit_len];
    for i in 0..bit_len { unshuffled[i] = bits[idx[i]]; }
    for (i, byte) in data.iter_mut().enumerate() {
        let mut v = 0u8;
        for j in 0..8 { v |= unshuffled[i*8+j]<<j; }
        *byte = v;
    }
}
