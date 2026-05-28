# vim-forcer

A daemon that intercepts nano and silently replaces it with vim.

> **Warning:** kills processes and hijacks terminals system-wide. Don't run this anywhere that matters. The developer accepts zero responsibility, moral or legal.

## How it works

An eBPF program hooks the `execve` syscall. The moment nano dares to launch, it gets `SIGKILL`'d and vim opens in its place. On the same terminal, with the same file, before the user knows what hit them. Renamed nano binaries are caught by scanning the ELF for the string `"nano"`. Swap counts are tracked per-uid, in case you want a wall of shame in your motd.

## Demo

![demo](demo.gif)

## Building

See [BUILDING.md](BUILDING.md).

## AI Assistance Disclosure

Written with AI assistance. All code reviewed and tested by me before inclusion. Unlike certain editors, I take some responsibility for my choices.
