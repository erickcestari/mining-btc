use num_bigint::BigUint;
use num_traits::Num;
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Instant;
use tokio::task;

#[tokio::main]
async fn main() {
    let difficulty_hex = "0x000000001";
    let difficulty = BigUint::from_str_radix(&difficulty_hex[2..], 16).expect("Invalid hex string");

    println!("Mining with difficulty: {}", difficulty);

    let genesis_block_hex = "0x00000000ffff0000000000000000000000000000000000000000000000000000";
    let genesis_block =
        BigUint::from_str_radix(&genesis_block_hex[2..], 16).expect("Invalid hex string");

    let target = genesis_block / &difficulty;
    let mut target_bytes = target.to_bytes_be();

    while target_bytes.len() < 32 {
        target_bytes.insert(0, 0);
    }

    println!("Target full hash: {:064x}", target);

    let now = Instant::now();
    let prefix = b"Hello World! ".to_vec();
    let found = Arc::new(AtomicBool::new(false));
    let target_bytes = Arc::new(target_bytes);

    let mut handles = vec![];

    let num_threads = 16;
    let nonces_per_thread = u64::MAX / num_threads;

    for i in 0..num_threads {
        let start_nonce = i * nonces_per_thread;
        let end_nonce = start_nonce + nonces_per_thread;
        let target_bytes = Arc::clone(&target_bytes);
        let prefix = prefix.clone();
        let found = Arc::clone(&found);

        let handle = task::spawn(async move {
            let mut hasher = Sha256::new();
            hasher.update(&prefix);

            let mut current_nonce = start_nonce;
            while current_nonce < end_nonce {
                if found.load(Ordering::Acquire) {
                    break;
                }

                hasher.update(&current_nonce.to_be_bytes());
                let result = hasher.finalize_reset();

                if result.as_slice() < target_bytes.as_slice() {
                    found.store(true, Ordering::Release);
                    let duration = now.elapsed();
                    println!("\nFound valid hash!");
                    println!("msg: Hello World! {}", current_nonce);
                    println!("nonce: {}", current_nonce);
                    println!("hash: {:x}", result);
                    println!("time: {:.2?}", duration);
                    break;
                }

                if current_nonce % 100_000_000 == 0 {
                    println!("Trying nonce: {}, hash: {:x}", current_nonce, result);
                }

                current_nonce += 1;
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.await.expect("Task failed");
    }
}
