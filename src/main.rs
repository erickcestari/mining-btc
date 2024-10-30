use std::time::Instant;

use num_bigint::BigUint;
use num_traits::Num;
use sha2::{Digest, Sha256};

fn main() {
    let difficulty_hex = "0x1";
    let difficulty = BigUint::from_str_radix(&difficulty_hex[2..], 16).expect("Invalid hex string");

    println!("Mining with difficulty: {}", difficulty);

    let genesis_block_hex = "0x00000000ffff0000000000000000000000000000000000000000000000000000";
    let genesis_block =
        BigUint::from_str_radix(&genesis_block_hex[2..], 16).expect("Invalid hex string");

    let target = &genesis_block / &difficulty;
    let target_full_hash = format!("{:064x}", target);
    println!("Target full hash: {}", target_full_hash);

    let now = Instant::now();
    let mut nonce = 0;

    loop {
        let msg = format!("Hello World! {}", nonce);

        let mut hasher = Sha256::new();
        hasher.update(msg.as_bytes());
        let result = hasher.finalize();
        let hex = format!("{:x}", result);

        let hex_num = BigUint::from_str_radix(&hex, 16).expect("Invalid hex string");

        print!(
            "msg: {}, nonce: {}, hash: {}, hex_num: {}\r",
            msg, nonce, hex, hex_num
        );

        if hex_num < target {
            let duration = now.elapsed();
            println!("msg: {}", msg);
            println!("nonce: {}", nonce);
            println!("hash: {}", hex);
            println!("time: {:.2?}", duration);
            break;
        }
        nonce += 1;
    }
}
