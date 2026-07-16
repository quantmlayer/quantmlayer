# Third-party dependency licenses

Generated from `Cargo.lock` (workspace) and `crates/ql-lsm/Cargo.lock` via the crates.io API.
First-party `ql-*` crates are Apache-2.0 and excluded.

**104 unique external crate versions audited. All are under permissive licenses (MIT, Apache-2.0, BSD, ISC, Zlib, Unicode-3.0, or dual/multi-licensed with a permissive option). No copyleft-only dependency exists in the tree.**

Notes from review:

- `unicode-ident` is `(MIT OR Apache-2.0) AND Unicode-3.0`; Unicode-3.0 is a permissive license and this combination is standard across the Rust ecosystem (it is a dependency of `syn`/`proc-macro2`).
- `libbpf-rs` / `libbpf-cargo` are `LGPL-2.1-only OR BSD-2-Clause`; the BSD-2-Clause option applies. `libbpf-sys` is BSD-2-Clause and vendors libbpf, itself dual `LGPL-2.1 OR BSD-2-Clause` — again the BSD option applies. BSD-2-Clause requires retaining the copyright notice in binary distributions; releases should ship this file (or a NOTICE) alongside the binary.
- The static musl release binary links the **system** libelf (elfutils, LGPL-3.0-or-later/GPL-2.0-or-later) and zlib (Zlib license) statically. Because QuantmLayer's complete corresponding source is published under Apache-2.0, LGPL relinking obligations are satisfiable; this only becomes a diligence item if the binary is ever distributed without source availability.
- `scripts/lsm-enforce/enforce.bpf.c` (first-party) is GPL-2.0-only — see the License section of the README.

## Full inventory

| Crate | Version | License | Used by |
|---|---|---|---|
| aho-corasick | 1.1.4 | Unlicense OR MIT | ql-lsm+workspace |
| anstream | 1.0.0 | MIT OR Apache-2.0 | ql-lsm+workspace |
| anstyle | 1.0.14 | MIT OR Apache-2.0 | ql-lsm+workspace |
| anstyle-parse | 1.0.0 | MIT OR Apache-2.0 | ql-lsm+workspace |
| anstyle-query | 1.1.5 | MIT OR Apache-2.0 | ql-lsm+workspace |
| anstyle-wincon | 3.0.11 | MIT OR Apache-2.0 | ql-lsm+workspace |
| anyhow | 1.0.102 | MIT OR Apache-2.0 | ql-lsm |
| anyhow | 1.0.103 | MIT OR Apache-2.0 | workspace |
| bitflags | 2.13.0 | MIT OR Apache-2.0 | ql-lsm+workspace |
| block-buffer | 0.10.4 | MIT OR Apache-2.0 | ql-lsm+workspace |
| camino | 1.2.2 | MIT OR Apache-2.0 | ql-lsm |
| camino | 1.2.4 | MIT OR Apache-2.0 | workspace |
| cargo-platform | 0.1.9 | MIT OR Apache-2.0 | ql-lsm+workspace |
| cargo_metadata | 0.15.4 | MIT | ql-lsm+workspace |
| cc | 1.2.64 | MIT OR Apache-2.0 | ql-lsm |
| cc | 1.2.65 | MIT OR Apache-2.0 | workspace |
| cfg-if | 1.0.4 | MIT OR Apache-2.0 | ql-lsm+workspace |
| cfg_aliases | 0.2.1 | MIT | ql-lsm+workspace |
| clap | 4.6.1 | MIT OR Apache-2.0 | ql-lsm+workspace |
| clap_builder | 4.6.0 | MIT OR Apache-2.0 | ql-lsm+workspace |
| clap_derive | 4.6.1 | MIT OR Apache-2.0 | ql-lsm+workspace |
| clap_lex | 1.1.0 | MIT OR Apache-2.0 | ql-lsm+workspace |
| colorchoice | 1.0.5 | MIT OR Apache-2.0 | ql-lsm+workspace |
| cpufeatures | 0.2.17 | MIT OR Apache-2.0 | ql-lsm+workspace |
| crypto-common | 0.1.7 | MIT OR Apache-2.0 | ql-lsm+workspace |
| digest | 0.10.7 | MIT OR Apache-2.0 | ql-lsm+workspace |
| ed25519-compact | 2.3.0 | MIT | workspace |
| equivalent | 1.0.2 | Apache-2.0 OR MIT | ql-lsm+workspace |
| errno | 0.3.14 | MIT OR Apache-2.0 | ql-lsm+workspace |
| fastrand | 2.4.1 | Apache-2.0 OR MIT | ql-lsm+workspace |
| find-msvc-tools | 0.1.9 | MIT OR Apache-2.0 | ql-lsm+workspace |
| foldhash | 0.1.5 | Zlib | ql-lsm |
| generic-array | 0.14.7 | MIT | ql-lsm+workspace |
| getrandom | 0.2.17 | MIT OR Apache-2.0 | workspace |
| getrandom | 0.4.2 | MIT OR Apache-2.0 | ql-lsm |
| getrandom | 0.4.3 | MIT OR Apache-2.0 | workspace |
| hashbrown | 0.15.5 | MIT OR Apache-2.0 | ql-lsm+workspace |
| hashbrown | 0.17.1 | MIT OR Apache-2.0 | ql-lsm |
| heck | 0.5.0 | MIT OR Apache-2.0 | ql-lsm+workspace |
| id-arena | 2.3.0 | MIT/Apache-2.0 | ql-lsm |
| indexmap | 2.14.0 | Apache-2.0 OR MIT | ql-lsm |
| indexmap | 2.9.0 | Apache-2.0 OR MIT | workspace |
| is_terminal_polyfill | 1.70.2 | MIT OR Apache-2.0 | ql-lsm+workspace |
| itoa | 1.0.18 | MIT OR Apache-2.0 | ql-lsm+workspace |
| leb128fmt | 0.1.0 | MIT OR Apache-2.0 | ql-lsm |
| libbpf-cargo | 0.24.8 | LGPL-2.1-only OR BSD-2-Clause | ql-lsm+workspace |
| libbpf-rs | 0.24.8 | LGPL-2.1-only OR BSD-2-Clause | ql-lsm+workspace |
| libbpf-sys | 1.7.0+v1.7.0 | BSD-2-Clause | ql-lsm+workspace |
| libc | 0.2.186 | MIT OR Apache-2.0 | ql-lsm+workspace |
| linux-raw-sys | 0.12.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | ql-lsm+workspace |
| log | 0.4.32 | MIT OR Apache-2.0 | ql-lsm |
| memchr | 2.8.2 | Unlicense OR MIT | ql-lsm+workspace |
| memmap2 | 0.5.10 | MIT OR Apache-2.0 | ql-lsm+workspace |
| nix | 0.27.1 | MIT | workspace |
| nix | 0.31.3 | MIT | ql-lsm+workspace |
| once_cell | 1.21.4 | MIT OR Apache-2.0 | ql-lsm+workspace |
| once_cell_polyfill | 1.70.2 | MIT OR Apache-2.0 | ql-lsm+workspace |
| pkg-config | 0.3.33 | MIT OR Apache-2.0 | ql-lsm+workspace |
| prettyplease | 0.2.37 | MIT OR Apache-2.0 | ql-lsm |
| proc-macro2 | 1.0.106 | MIT OR Apache-2.0 | ql-lsm+workspace |
| quote | 1.0.45 | MIT OR Apache-2.0 | ql-lsm+workspace |
| r-efi | 6.0.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later | ql-lsm+workspace |
| regex | 1.12.4 | MIT OR Apache-2.0 | ql-lsm+workspace |
| regex-automata | 0.4.14 | MIT OR Apache-2.0 | ql-lsm+workspace |
| regex-syntax | 0.8.11 | MIT OR Apache-2.0 | ql-lsm+workspace |
| rustix | 1.1.4 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | ql-lsm+workspace |
| ryu | 1.0.23 | Apache-2.0 OR BSL-1.0 | ql-lsm+workspace |
| seccompiler | 0.4.0 | Apache-2.0 OR BSD-3-Clause | workspace |
| semver | 1.0.28 | MIT OR Apache-2.0 | ql-lsm+workspace |
| serde | 1.0.228 | MIT OR Apache-2.0 | ql-lsm+workspace |
| serde_core | 1.0.228 | MIT OR Apache-2.0 | ql-lsm+workspace |
| serde_derive | 1.0.228 | MIT OR Apache-2.0 | ql-lsm+workspace |
| serde_json | 1.0.150 | MIT OR Apache-2.0 | ql-lsm+workspace |
| serde_yaml | 0.9.34+deprecated | MIT OR Apache-2.0 | ql-lsm+workspace |
| sha2 | 0.10.9 | MIT OR Apache-2.0 | ql-lsm+workspace |
| shlex | 2.0.1 | MIT OR Apache-2.0 | ql-lsm+workspace |
| strsim | 0.11.1 | MIT | ql-lsm+workspace |
| syn | 2.0.117 | MIT OR Apache-2.0 | ql-lsm+workspace |
| tempfile | 3.27.0 | MIT OR Apache-2.0 | ql-lsm+workspace |
| thiserror | 1.0.69 | MIT OR Apache-2.0 | ql-lsm+workspace |
| thiserror-impl | 1.0.69 | MIT OR Apache-2.0 | ql-lsm+workspace |
| typenum | 1.20.1 | MIT OR Apache-2.0 | ql-lsm+workspace |
| unicode-ident | 1.0.24 | (MIT OR Apache-2.0) AND Unicode-3.0 | ql-lsm+workspace |
| unicode-xid | 0.2.6 | MIT OR Apache-2.0 | ql-lsm |
| unsafe-libyaml | 0.2.11 | MIT | ql-lsm+workspace |
| utf8parse | 0.2.2 | Apache-2.0 OR MIT | ql-lsm+workspace |
| version_check | 0.9.5 | MIT/Apache-2.0 | ql-lsm+workspace |
| vsprintf | 2.0.0 | MIT | ql-lsm+workspace |
| wasi | 0.11.1+wasi-snapshot-preview1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | workspace |
| wasip2 | 1.0.4+wasi-0.2.12 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | ql-lsm |
| wasip3 | 0.4.0+wasi-0.3.0-rc-2026-01-06 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | ql-lsm |
| wasm-encoder | 0.244.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | ql-lsm |
| wasm-metadata | 0.244.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | ql-lsm |
| wasmparser | 0.244.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | ql-lsm |
| windows-link | 0.2.1 | MIT OR Apache-2.0 | ql-lsm+workspace |
| windows-sys | 0.61.2 | MIT OR Apache-2.0 | ql-lsm+workspace |
| wit-bindgen | 0.51.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | ql-lsm |
| wit-bindgen | 0.57.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | ql-lsm |
| wit-bindgen-core | 0.51.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | ql-lsm |
| wit-bindgen-rust | 0.51.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | ql-lsm |
| wit-bindgen-rust-macro | 0.51.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | ql-lsm |
| wit-component | 0.244.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | ql-lsm |
| wit-parser | 0.244.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | ql-lsm |
| zmij | 1.0.21 | MIT | ql-lsm+workspace |
