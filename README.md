# mining-btc

This script is for educational-only purposes and is not intended for production.

It performs a proof-of-work's simulation of genesis block given:

- `dificulty_hex`: `0x000000001`;
- `target`: `0x00000000ffff0000000000000000000000000000000000000000000000000000`
- `prefix`: `Hello Wolrd!`
- `nonce`: it receive an increment until find a value less than `target`;

## Install

```bash
git clone https://github.com/erickcestari/mining-btc
```

## Build

```bash
cargo build --release
```

## Run

```bash
./target/release/mining-btc
```

## WARNING

This script will increase **a lot** your CPU usage (depending on system).

For best performance, close all unused programs.


## Benchmark

| OS         | Processor   | Number of threads | CPU usage | found hash in (s) | nonce                | hash                     | 
| ---------- | ----------- | ----------------- | --------- | ----------------- | -------------------- | ------------------------ |
| Arch Linux | 12th gen i5 | 16                | `80-90%`  | `2.80s`           | 3458764513870408011  | `000000009257b...7dcdb6` |
| MacOS      | M2 (arm64)  | 8                 | `90-95%`  | `3186.61s`        | 4611686018698950180  | `00000000862e5...80821c` |
