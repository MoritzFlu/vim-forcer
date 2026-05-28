# Building vim-forcer

Built with [aya-template](https://github.com/aya-rs/aya-template).

## Prerequisites

1. stable rust toolchain: `rustup toolchain install stable`
1. nightly rust toolchain: `rustup toolchain install nightly --component rust-src`
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)
1. (cross-compiling only) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (cross-compiling only) LLVM: e.g. `brew install llvm`
1. (cross-compiling only) musl C toolchain: e.g. [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross)

## Build & Run

```shell
cargo build --release
cargo run --release
```

Cargo build scripts compile the eBPF program and embed it automatically.

## Cross-compiling on macOS

Works on both Intel and Apple Silicon.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package vim-forcer --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```

Copy `target/${ARCH}-unknown-linux-musl/release/vim-forcer` to a Linux machine and run it there.

## License

vim-forcer is distributed under the terms of the [MIT license](LICENSE).

The eBPF object declares `Dual MIT/GPL` to the kernel for compatibility with Linux eBPF helper licensing rules; the project source is MIT licensed.
