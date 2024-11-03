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

## Change variable `num_threads`

At line 38, change the variable `num_threads`.

To know how many threads your machine support, do

- Linux: `awk '/^processor/ {++n} END {print n+1}' /proc/cpuinfo`
- MacOS: `sysctl -n hw.ncp`

## Build

```bash
cargo build
```

## Run

```bash
./target/debug/grind-rust-simulator
```

## WARNING

This script will increase **a lot** your CPU usage (depending on system).

For best performance, close all unused programs.

