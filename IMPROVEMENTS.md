# Current Improvements

This project now keeps one active BCJ implementation: the internal reversible x86/x86-64 transform in `tos_codec_enhanced.py`.

## What Changed From The Older PoC

- Removed unused external BCJ C engines and Makefiles.
- Removed CLI/web wiring for the unused `--engine` option.
- Kept the reversible Python x86 BCJ path as the source of truth.
- Kept measured adaptive routing, so transforms are only accepted when a sample LZMA2 trial improves size.
- Kept the final plain solid LZMA2 fallback, so adaptive preprocessing cannot make the final archive larger.

## Active Compression Features

- File classification by magic bytes, extension, entropy, text/UTF-8 status, and structured-data shape.
- Internal x86 BCJ for executable CALL/JMP operands.
- Stride-4 delta preprocessing for numeric/time-series text.
- JSON key-order normalization for exact minified JSON object lines.
- CSV column componentization for regular CSV rows.
- Solid LZMA2 payload with a 256 MB dictionary.
- Compact binary archive metadata.
- CRC32 and SHA-256 verification during extraction.

## Removed Or Not Active

- External `engine/bcj_filter.c`.
- External `engine/bcj_filter_enhanced.c`.
- ARM, ARM64, and MIPS BCJ filters.
- Engine compilation steps.
- `--engine` CLI option.

## Why This Is Cleaner

The codebase no longer implies that a C engine or multi-architecture BCJ path is active. The implementation, docs, validation, and CLI now line up around the actual pipeline: measured preprocessing plus internal reversible x86 BCJ plus LZMA2.
