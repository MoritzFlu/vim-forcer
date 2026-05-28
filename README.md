# vim-forcer

vim-forcer watches for attempts to open nano and replaces them with vim, transparently, before the user ever sees the wrong editor.

## Disclaimer

This tool kills processes and hijacks terminals system-wide. Do not run it on any critical system. It is intended for educational purposes only. The developer takes no responsibility for any damage or misuse.

## How it works

**Detection**: vim-forcer loads an eBPF program that attaches to the `execve` syscall tracepoint. Every time a process is exec'd, the kernel-side program checks whether the executable basename is `nano`. If there is a match, it sends an event to userspace via a ring buffer, carrying the PID and the file argument.

For renamed binaries, eBPF emits candidate events for processes whose first
argument looks like a file rather than a flag. Userspace then resolves the
executable path and counts how often the ELF binary contains the string
`nano`, case-insensitively. If the count is at least 15, vim-forcer treats it as
nano and swaps it. Results are cached by device/inode, so repeated launches of
the same executable do not reread the file.

Candidate events are also rate-filtered in eBPF. For each non-`nano` basename,
the first two launches in a one-minute window are allowed through for userspace
inspection. The third launch marks that basename as noisy and suppresses it for
five minutes. Direct `nano` launches are never rate-filtered.

**Takeover**: once userspace receives an event, it:

1. Resolves the terminal from `/proc/[pid]/fd/0` and the file path from `/proc/[pid]/cwd`.
2. Sends `SIGSTOP` to the parent shell so it does not reclaim the terminal.
3. Sends `SIGKILL` to the intercepted editor process.
4. Spawns a new shell on the same terminal running `exec vim '[file]'`.
5. Waits for vim to exit, then sends `SIGCONT` to the parent shell.

The result is a seamless swap with no visible gap (I am still trying to get rid of the `killed nano` message... ).
It also tracks and stores the number of swaps peformed per uid, if you want to put a wall of shame in your motd or somewhere else.

## Demo

![demo](demo.gif)

For a recordable walkthrough of name-based bypasses and string-count catches,
run vim-forcer in one terminal and the demo script in another:

```shell
sudo env PATH="/tmp/vim-forcer-demo/vim-wrapper:$PATH" target/release/vim-forcer
./scripts/circumvention-demo.sh
```

The script tries a direct `nano` launch, a renamed symlink, a renamed copy, a
hard link, PATH shadowing, and a shell wrapper. A downloaded executable case is
included by default: it detects Arch or Ubuntu from `/etc/os-release`,
downloads the distro nano package into the script's temporary directory,
extracts `usr/bin/nano` there, renames it, and runs it. Nothing is extracted
into the repository.

## AI Assistance Disclosure

This project has been developed with assistance from AI-powered coding tools for code generation and documentation. All code has been reviewed, tested, and verified by me before inclusion.

---



# Built with aya-template (https://github.com/aya-rs/aya-template)

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package vim-forcer --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/vim-forcer` can be
copied to a Linux server or VM and run there.

## License

vim-forcer is distributed under the terms of the [MIT license].

The eBPF object declares `Dual MIT/GPL` to the kernel for compatibility with
Linux eBPF helper licensing rules; the project source is MIT licensed.

[MIT license]: LICENSE
