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

### Contributor's machines

| OS         | Processor   | Number of threads | CPU usage | found hash in (s) | nonce                | hash                     | 
| ---------- | ----------- | ----------------- | --------- | ----------------- | -------------------- | ------------------------ |
| Arch Linux | 12th gen i5 | 16                | `95-99%`  | `2.80s`           | 3458764513870408011  | `000000009257b...7dcdb6` |
| MacOS      | M2 (arm64)  | 8                 | `90-95%`  | `384.80s`         | 2083236893           | `000000000019d...8ce26f` |
| Arch Linux | i7-2600     | 8                 | `95-99%`  | `255.76s`         | 4611686018698950180  | `00000000862e5...80821c` |
| Windows 10 | 10th gen i5 | 12                | `95-99%`  | `149.77s`         | 4611686018698950180  | `00000000862e5...80821c` |

### Github VM machines

| OS              | Processor   | Number of threads | CPU usage | found hash in (s) | nonce                | hash                       | 
| --------------- | ----------- | ----------------- | --------- | ----------------- | -------------------- | -------------------------- |
| `ubuntu-latest` | x64         | 4                 | `?`       | `198.44s`         | 2083236893           | `000000000019d66...8ce26f` |
| `windows-latest`| x64         | 4                 | `?`       | `259.92s`         | 2083236893           | `000000000019d66...8ce26f` |
| `macos-13`      | x64         | 4                 | `?`       | `1879.70s`        | 2083236893           | `000000000019d66...8ce26f` |
| `macos-14`      | arm64       | 3                 | `?`       | `236.40s`         | 3197545707           | `00000000ea53292...a44719` |
