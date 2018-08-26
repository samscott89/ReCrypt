## THIS IS PROTOTYPE CODE FOR RESEARCH - DO NOT USE

# ReCrypt
### Key Rotation for Authenticated Encryption

This repo contains a prototype implementation of ReCrypt.

For the accompanying research paper, see: http://eprint.iacr.org/2017/527.

We are currently pegged to an older version of [`curve25519-dalek`](https://dalek.rs)
for which we implemented the Elligator map and inverse for use with the Edwards
curve. Ideally, we would switch to using [Ristretto](https://ristretto.group/),
when there is an available implementation for the inverse Elligator map, to
map byte strings to the curve.

## Installation & Usage

Requires Rust - https://rustup.rs/

Once installed, you can download with:

```bash
git clone https://github.com/samscott89/recrypt/
cd recrypt
cargo build
# Optional: builds and opens documentation
cargo doc --no-deps --open
```

By default, running with `cargo run` gives the benchmarks. Ensure to run with
`cargo run --release` to get profiles for optimised code.
