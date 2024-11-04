use libc::{cpu_set_t, sched_setaffinity, CPU_SET, CPU_ZERO};
use num_bigint::BigUint;
use num_traits::Num;
use sha2::{Digest, Sha256};
use std::time::Instant;

fn set_thread_affinity(core_id: usize) -> Result<(), String> {
    unsafe {
        // Create a CPU set and zero it
        let mut cpu_set: cpu_set_t = std::mem::zeroed();
        CPU_ZERO(&mut cpu_set);

        // Add the specified core to the CPU set
        CPU_SET(core_id, &mut cpu_set);

        // Set the affinity of the current thread
        let result = sched_setaffinity(0, std::mem::size_of::<cpu_set_t>(), &cpu_set);
        if result != 0 {
            return Err(format!("Failed to set CPU affinity for core {}", core_id));
        }
    }
    Ok(())
}

fn main() {
    let difficulty_hex = "0x000000001";
    let difficulty = BigUint::from_str_radix(&difficulty_hex[2..], 16).expect("Invalid hex string");

    println!("Mining with difficulty: {}", difficulty);

    const GENESIS_BLOCK_HEX: &str =
        "0x00000000ffff0000000000000000000000000000000000000000000000000000";
    let genesis_block =
        BigUint::from_str_radix(&GENESIS_BLOCK_HEX[2..], 16).expect("Invalid hex string");

    let target = genesis_block / &difficulty;
    let mut target_bytes = target.to_bytes_be();

    while target_bytes.len() < 32 {
        target_bytes.insert(0, 0);
    }

    println!("Target full hash: {:064x}", target);

    let now = Instant::now();
    let prefix = b"Hello World! ".to_vec();

    let mut handles = vec![];

    let num_threads = num_cpus::get();
    let nonces_per_thread = usize::MAX / num_threads;

    for i in 0..num_threads {
        let start_nonce = i * nonces_per_thread;
        let end_nonce = start_nonce + nonces_per_thread;
        let prefix = prefix.clone();
        let temp_target_bytes = target_bytes.clone();

        let handle = std::thread::spawn(move || {
            // Set thread affinity to the specific core
            set_thread_affinity(i as usize).expect("Failed to set thread affinity");

            let mut hasher = Sha256::new();
            hasher.update(&prefix);

            let target_bytes = temp_target_bytes.as_slice();
            for current_nonce in start_nonce..end_nonce {
                hasher.update(&current_nonce.to_be_bytes());
                let result = hasher.finalize_reset();

                if result.as_slice() < target_bytes {
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
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Task failed");
    }
}
