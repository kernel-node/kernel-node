# Kernel-Node

An experimental bitcoin node written in Rust using the libbitcoinkernel
library. The node just validates blocks, and does not serve blocks to the
network. It is meant to showcase the limited initial API of the kernel library.
It is not meant to be particularly performant, or robust against misbehaving
peers.

## Quick Start

If you have the dependencies to build Bitcoin Core with IPC and a usual Rust program, you can build `kernel-node`. For build instructions, see the [build documentation](./doc/build.md).

To run on e.g. signet:

```
cargo run --bin node --release -- --network signet
```

By default it will put data in the `$HOME/.kernel-node` directory.

Options: 

```
Arguments:
        --network        Which Bitcoin network to use.
        --datadir        Data directory for blockchain and configuration.
        --connect        Connect only to this node (format: ip:port or hostname:port)
        --daemon         Run the server as a daemon
        --sp-keys-file   Path to a binary silent payments keys file to import at startup.
        --proxy          Socks5 proxy for outbound peer connections (format: ip:port).
```

Or use the interactive wizard to walk through the options and start the node:

```
cargo run --bin wizard
```

## Bitcoin Core Compatibility

`kernel-node` uses the same database implementation and consensus rules as Bitcoin Core. If you have an existing data directory, you may skip IBD and pass it as the `--datadir` argument on startup. Any updates to the chainstate will be compatible with Bitcoin Core.

## MSRV

The crate binaries will compile with a compiler version of **1.84.0** or greater.

## Platform Support

The developers of `kernel-node` and CI jobs are on Unix-like systems.
