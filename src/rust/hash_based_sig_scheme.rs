use ring::{
    digest::{
        digest,
        SHA256 as HASH_FN,
        SHA256_OUTPUT_LEN as HASH_LEN
    },
    rand::{SystemRandom, SecureRandom}
};


const KEY_LEN: usize = 256;

type Key     = [[u8; HASH_LEN]; KEY_LEN];
type KeyPair = [Key; 2];


fn get_hash(data: &[u8]) -> [u8; HASH_LEN] {
    let mut h = [0u8; HASH_LEN];

    for (i, b) in digest(&HASH_FN, data).as_ref().iter().enumerate() {
        h[i] = *b;
    }

    h
}


pub fn generate_keys() -> (KeyPair, KeyPair) {
    let mut pub_key_pair: KeyPair = [[[0; HASH_LEN]; KEY_LEN]; 2];
    let mut sec_key_pair: KeyPair = [[[0; HASH_LEN]; KEY_LEN]; 2];

    let mut rand_bytes: [u8; 4] = [0; 4];
    let rng = SystemRandom::new();

    for i in 0..2 {
        for j in 0..KEY_LEN {
            match rng.fill(&mut rand_bytes) {
                Ok(_)  => {
                    sec_key_pair[i][j] = get_hash(&rand_bytes);
                    pub_key_pair[i][j] = get_hash(&sec_key_pair[i][j]);
                },
                Err(e) => println!("{}", e),
            };
        }
    }

    (pub_key_pair, sec_key_pair)
}


pub fn get_signature(sec_key_pair: &KeyPair, data: &[u8]) -> Key {
    let mut s: Key = [[0; HASH_LEN]; KEY_LEN];

    for (i, b) in get_hash(data).iter().enumerate() {
        for (j, bit) in format!("{:08b}", b).chars().enumerate() {
            s[8*i+j] = sec_key_pair[bit.to_digit(10).unwrap() as usize][8*i+j];
        }
    }

    s
}


pub fn verify(pub_key_pair: &KeyPair, sig: &Key) -> bool {
    for i in 0..KEY_LEN {
        let sig_h = get_hash(&sig[i]);
        if sig_h != pub_key_pair[0][i] && sig_h != pub_key_pair[1][i] {
            return false;
        }
    }

    true
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_a() {
        let key_pair = generate_keys();
        let sig = get_signature(&key_pair.1, b"hello world");
        let is_valid = verify(&key_pair.0, &sig);
        assert_eq!(is_valid, true);
    }
}
