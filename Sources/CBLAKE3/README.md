# Vendored BLAKE3 C implementation

This target contains the portable C implementation from [BLAKE3 1.8.7](https://github.com/BLAKE3-team/BLAKE3/releases/tag/1.8.7).
The [official source archive](https://github.com/BLAKE3-team/BLAKE3/archive/refs/tags/1.8.7.tar.gz)
SHA-256 is `c6782a28842b1c0478524ac06a4f2ede784038ee298d6e2162c0b089c4306a3c`.

The selected upstream files are `c/blake3.c`, `c/blake3_dispatch.c`,
`c/blake3_portable.c`, `c/blake3.h`, `c/blake3_impl.h`, and the three license
files. The headers are placed in `include/`. Compared with the previous 1.8.5
selection, only `BLAKE3_VERSION_STRING` changes; the implementation is identical.
SIMD remains disabled. Enable it only after the cross-language vector suite
proves the optimized build.
