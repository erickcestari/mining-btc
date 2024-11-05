use num_bigint::BigUint;
use num_traits::Num;
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Instant;
use tokio::task;

extern crate num_cpus;

#[tokio::main]
async fn main() {
    // Setup difficulty in hexadecimal format
    let difficulty_hex = "0x000000001";
    let difficulty = BigUint::from_str_radix(&difficulty_hex[2..], 16).expect("Invalid hex string");

    println!("Mining with difficulty: {}", difficulty);

    // Genesis block target for Bitcoin
    let genesis_block_hex = "00000000ffff0000000000000000000000000000000000000000000000000000";
    let genesis_block =
        BigUint::from_str_radix(&genesis_block_hex, 16).expect("Invalid hex string");

    // Calculate target
    let target = genesis_block / &difficulty;
    let mut target_bytes = target.to_bytes_be();
    while target_bytes.len() < 32 {
        target_bytes.insert(0, 0);
    }

    println!("Target full hash: {:064x}", target);

    // Define Genesis block fields
    let version = Arc::new(hex::decode("01000000").expect("Invalid hex for version"));
    let hash_prev_block = Arc::new(
        hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
            .expect("Invalid hex for hashPrevBlock"),
    );
    let hash_merkle_root = Arc::new(
        hex::decode("3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a")
            .expect("Invalid hex for hashMerkleRoot"),
    );
    let timestamp = Arc::new(hex::decode("29ab5f49").expect("Invalid hex for timestamp"));
    let bits = Arc::new(hex::decode("ffff001d").expect("Invalid hex for bits"));

    // Setup for mining
    let now = Instant::now();
    let found = Arc::new(AtomicBool::new(false));
    let target_bytes = Arc::new(target_bytes);

    // Get the number of available threads
    let num_threads = num_cpus::get() as u32;
    println!("Num threads: {}", num_threads);

    let nonces_per_thread = u32::MAX / num_threads;

    let mut handles = vec![];

    for i in 0..num_threads {
        let start_nonce = i * nonces_per_thread;
        let end_nonce = start_nonce + nonces_per_thread;
        let target_bytes = Arc::clone(&target_bytes);
        let found = Arc::clone(&found);

        let version = Arc::clone(&version);
        let hash_prev_block = Arc::clone(&hash_prev_block);
        let hash_merkle_root = Arc::clone(&hash_merkle_root);
        let timestamp = Arc::clone(&timestamp);
        let bits = Arc::clone(&bits);

        let handle = task::spawn(async move {
            let mut hasher = Sha256::new();
            let mut current_nonce = start_nonce;

            // Pre-allocate and reuse block header buffer
            let mut block_header = vec![];
            block_header.extend(version.as_ref());
            block_header.extend(hash_prev_block.as_ref());
            block_header.extend(hash_merkle_root.as_ref());
            block_header.extend(timestamp.as_ref());
            block_header.extend(bits.as_ref());
            block_header.extend(&[0; 4]);

            while current_nonce < end_nonce {
                if found.load(Ordering::Relaxed) {
                    break;
                }

                // Update only the nonce part of the block header
                block_header[76..80].copy_from_slice(&current_nonce.to_le_bytes());

                // Double SHA-256 hashing
                hasher.update(&block_header);
                let first_hash = hasher.finalize_reset();
                hasher.update(&first_hash);
                let second_hash = hasher.finalize_reset();

                // Convert to little-endian format by reversing the byte order
                let result = second_hash.iter().rev().cloned().collect::<Vec<u8>>();

                // Early exit if target found
                if result.as_slice() < target_bytes.as_slice() {
                    found.store(true, Ordering::Release);
                    let duration = now.elapsed();
                    println!("\nFound valid hash!");
                    println!("nonce: {}", current_nonce);
                    println!("hash: {}", hex::encode(&result));
                    println!("time: {:.2?}", duration);
                    break;
                }

                if current_nonce % 100_000_000 == 0 {
                    println!(
                        "Trying nonce: {}, hash: {}",
                        current_nonce,
                        hex::encode(&result)
                    );
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
