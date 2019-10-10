use std::convert::TryInto;

pub fn chacha20_xor(plaintext: &Vec<u8>, key: &[u8; 32], nonce: &[u8; 12], count: &u32) -> Vec<u8> {
    let plain_len = plaintext.len();
    let plain_blocks = plaintext.as_slice().chunks_exact(64);
    let mut j: usize = 0;

    let mut enc_message: Vec<u8> = vec![];

    for block in plain_blocks {
        let key_stream = chacha20_block(&key, &nonce, &(count + j as u32));
        enc_message.append(
            &mut key_stream
                .iter()
                .zip(block)
                .map(|(k, b)| k ^ b)
                .collect::<Vec<u8>>(),
        );
        j += 1
    }

    if plain_len % 64 != 0 {
        j = plain_len / 64usize;
        let key_stream = chacha20_block(&key, &nonce, &(count + j as u32));
        enc_message.append(
            &mut key_stream
                .iter()
                .zip(plaintext.split_at(j as usize * 64usize).1)
                .map(|(k, b)| k ^ b)
                .collect::<Vec<u8>>(),
        )
    }

    enc_message
}

fn quarter_round(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
    *a = a.wrapping_add(*b);
    *d ^= *a;
    *d = d.rotate_left(16);

    *c = c.wrapping_add(*d);
    *b ^= *c;
    *b = b.rotate_left(12);

    *a = a.wrapping_add(*b);
    *d ^= *a;
    *d = d.rotate_left(8);

    *c = c.wrapping_add(*d);
    *b ^= *c;
    *b = b.rotate_left(7);
}

fn chacha20_block(key: &[u8; 32], nonce: &[u8; 12], count: &u32) -> Vec<u8> {
    let mut state = block_init_state(key, nonce, count);
    let init_state = state.clone();

    let mut ret: Vec<u8> = vec![];

    block_rounds(&mut state);

    for (s, i) in state.iter_mut().zip(init_state) {
        *s = s.wrapping_add(i);
        ret.extend_from_slice(&s.to_le_bytes());
    }

    ret
}

fn block_init_state(key: &[u8; 32], nonce: &[u8; 12], count: &u32) -> Vec<u32> {
    let u32_size = std::mem::size_of::<u32>();
    let mut state: Vec<u32> = vec![0x61707865u32, 0x3320646eu32, 0x79622d32u32, 0x6b206574];

    state.append(
        &mut key
            .chunks_exact(u32_size)
            .map(|i| u32::from_le_bytes(i.try_into().unwrap_or([0, 0, 0, 0])))
            .collect::<Vec<u32>>(),
    );

    state.push(*count);

    state.append(
        &mut nonce
            .chunks_exact(u32_size)
            .map(|i| u32::from_le_bytes(i.try_into().unwrap_or([0, 0, 0, 0])))
            .collect::<Vec<u32>>(),
    );

    state
}

fn block_rounds(state: &mut Vec<u32>) {
    let mut err0: &mut u32 = &mut 0u32;
    let mut err1: &mut u32 = &mut 0u32;
    let mut err2: &mut u32 = &mut 0u32;
    let mut err3: &mut u32 = &mut 0u32;

    for _ in 0..10 {
        // quarter_round(0, 4, 8, 12)
        // quarter_round(1, 5, 9, 13)
        // quarter_round(2, 6, 10, 14)
        // quarter_round(3, 7, 11, 15)
        for i in 0..=3 {
            let mut it = state.iter_mut();
            quarter_round(
                it.nth(i).unwrap_or(&mut err0),
                it.nth(3).unwrap_or(&mut err1),
                it.nth(3).unwrap_or(&mut err2),
                it.nth(3).unwrap_or(&mut err3),
            );
        }

        // quarter_round(0, 5, 10, 15)
        // quarter_round(1, 6, 11, 12)
        // quarter_round(2, 7, 8, 13)
        // quarter_round(3, 4, 9, 14)
        for i in 0..=3 {
            let mut it = state.iter_mut();
            quarter_round(
                it.nth(i).unwrap_or(&mut err0),
                it.nth(if i + 1 == 4 { 0 } else { 4 }).unwrap_or(&mut err1),
                it.nth(if i + 2 == 4 { 0 } else { 4 }).unwrap_or(&mut err2),
                it.nth(if i + 3 == 4 { 0 } else { 4 }).unwrap_or(&mut err3),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarter_round_test() {
        let mut a: u32 = 0x11111111;
        let mut b: u32 = 0x01020304;
        let mut c: u32 = 0x9b8d6f43;
        let mut d: u32 = 0x01234567;

        let exp_a: u32 = 0xea2a92f4;
        let exp_b: u32 = 0xcb1cf8ce;
        let exp_c: u32 = 0x4581472e;
        let exp_d: u32 = 0x5881c4bb;

        quarter_round(&mut a, &mut b, &mut c, &mut d);

        assert_eq!(a, exp_a);
        assert_eq!(b, exp_b);
        assert_eq!(c, exp_c);
        assert_eq!(d, exp_d);
    }

    #[test]
    fn quarter_round_vector_test() {
        let mut abcd: Vec<u32> = vec![0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567];

        let exp_a: u32 = 0xea2a92f4;
        let exp_b: u32 = 0xcb1cf8ce;
        let exp_c: u32 = 0x4581472e;
        let exp_d: u32 = 0x5881c4bb;

        let mut it = abcd.iter_mut();
        let mut err0: &mut u32 = &mut 0;
        let mut err1: &mut u32 = &mut 0;
        let mut err2: &mut u32 = &mut 0;
        let mut err3: &mut u32 = &mut 0;
        quarter_round(
            it.next().unwrap_or(&mut err0),
            it.next().unwrap_or(&mut err1),
            it.next().unwrap_or(&mut err2),
            it.next().unwrap_or(&mut err3),
        );

        assert_eq!(*abcd.get(0).unwrap_or(err0), exp_a);
        assert_eq!(*abcd.get(1).unwrap_or(err1), exp_b);
        assert_eq!(*abcd.get(2).unwrap_or(err2), exp_c);
        assert_eq!(*abcd.get(3).unwrap_or(err3), exp_d);
    }

    #[test]
    fn diagonal_round() {
        let mut a: u32 = 0x516461b1;
        let mut b: u32 = 0x2a5f714c;
        let mut c: u32 = 0x53372767;
        let mut d: u32 = 0x3d631689;

        let exp_a: u32 = 0xbdb886dc;
        let exp_b: u32 = 0xcfacafd2;
        let exp_c: u32 = 0xe46bea80;
        let exp_d: u32 = 0xccc07c79;

        quarter_round(&mut a, &mut b, &mut c, &mut d);

        assert_eq!(a, exp_a);
        assert_eq!(b, exp_b);
        assert_eq!(c, exp_c);
        assert_eq!(d, exp_d);
    }

    #[test]
    fn block_init_test() {
        let key: Vec<u8> = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];

        let nonce: Vec<u8> = vec![
            0x00, 0x00, 0x0, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];

        let count: u32 = 0x01;

        let exp_state: Vec<u32> = vec![
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504, 0x0b0a0908,
            0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x00000001, 0x09000000,
            0x4a000000, 0x00000000,
        ];

        let state = block_init_state(
            key.as_slice().try_into().unwrap(),
            nonce.as_slice().try_into().unwrap(),
            &count,
        );

        assert_eq!(state, exp_state);
    }

    #[test]
    fn block_rounds_test() {
        let key: Vec<u8> = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];

        let nonce: Vec<u8> = vec![
            0x00, 0x00, 0x0, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];

        let count: u32 = 0x01;

        let mut state = block_init_state(
            key.as_slice().try_into().unwrap(),
            nonce.as_slice().try_into().unwrap(),
            &count,
        );

        let exp_init_state: Vec<u32> = vec![
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504, 0x0b0a0908,
            0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x00000001, 0x09000000,
            0x4a000000, 0x00000000,
        ];

        assert_eq!(state, exp_init_state);

        block_rounds(&mut state);

        let exp_block_state: Vec<u32> = vec![
            0x837778ab, 0xe238d763, 0xa67ae21e, 0x5950bb2f, 0xc4f2d0c7, 0xfc62bb2f, 0x8fa018fc,
            0x3f5ec7b7, 0x335271c2, 0xf29489f3, 0xeabda8fc, 0x82e46ebd, 0xd19c12b4, 0xb04e16de,
            0x9e83d0cb, 0x4e3c50a2,
        ];

        assert_eq!(state, exp_block_state);
    }

    #[test]
    fn chacha20_block_test() {
        let key: Vec<u8> = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];

        let nonce: Vec<u8> = vec![
            0x00, 0x00, 0x0, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];

        let count: u32 = 0x01;

        let exp_res: Vec<u8> = vec![
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
            0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
            0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
            0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
            0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];

        let res = chacha20_block(
            key.as_slice().try_into().unwrap(),
            nonce.as_slice().try_into().unwrap(),
            &count,
        );

        assert_eq!(res, exp_res);
    }

    #[test]
    fn chacha20_xor_test() {
        let key: Vec<u8> = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];

        let nonce: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];

        let count: u32 = 0x01;

        let plaintext: Vec<u8> = vec![
            0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e,
            0x74, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20,
            0x63, 0x6c, 0x61, 0x73, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20,
            0x49, 0x66, 0x20, 0x49, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
            0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e,
            0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20,
            0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, 0x63, 0x72,
            0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
            0x74, 0x2e,
        ];

        let exp_ciphertext: Vec<u8> = vec![
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d,
            0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc,
            0xfd, 0x9f, 0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59,
            0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
            0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d,
            0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d,
            0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9,
            0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
            0x87, 0x4d,
        ];

        let ciphertext = chacha20_xor(
            &plaintext,
            key.as_slice().try_into().unwrap(),
            nonce.as_slice().try_into().unwrap(),
            &count,
        );

        assert_eq!(ciphertext, exp_ciphertext);
    }
}
