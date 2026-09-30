# TOS Enhanced

TOS3 is an adaptive compression wrapper around LZMA2. It analyzes files, applies only reversible preprocessing that proves useful in an LZMA2 sample trial, then writes a compact binary manifest plus a solid LZMA2 payload.

## Active Pipeline

```text
Input files
-> file analysis
-> conservative transform selection
-> early entropy gate for dense inputs
-> measured reversible preprocessing
   -> internal x86 BCJ for CALL/JMP targets
   -> stride-4 delta for numeric/time-series text
   -> JSON key-order normalization
   -> JSONL binary packing for repeated object records
   -> CSV column componentization
   -> tokenization filter for repeated structured-text keys and long integers
-> solid stream
-> Best-of Zstandard/LZMA2 for small solid streams when zstd is available
-> TOS3 archive
```

The external C BCJ engines from the old proof of concept were removed. The active BCJ path is `transform_bcj_x86()` in `tos_codec_enhanced.py`.

## Why It Helps

- x86 BCJ rewrites relative branch/call offsets into address patterns that LZMA2 can match more easily.
- Delta encoding turns slowly changing numeric bytes into smaller residuals.
- JSON key ordering lines up repeated object schemas.
- JSONL binary packing stores object keys once in metadata and writes compact typed values in the payload.
- CSV componentization stores columns together so similar values become adjacent.
- Solid packing exposes redundancy across files.
- A final fallback compares the adaptive archive against plain solid LZMA2 and keeps the smaller result.

For structured text such as JSONL logs, CSV exports, and telemetry records, the target archive ratio can approach or beat 35-40% when repeated schema/key data dominates. Already-compressed or high-entropy files are routed through the entropy gate because no lossless codec can reliably force dense data to that ratio without an external trained dictionary or changing the data.

## Setup

```bash
pip install Flask Werkzeug
# Optional: enables the small-file zstd backend
pip install zstandard
python validate.py
```

Run the web UI:

```bash
python app_enhanced.py
```

Then open `http://localhost:5000`.

## CLI

Compress:

```bash
python tos_codec_enhanced.py compress "path/to/input" "path/to/archive.tos"
```

Extract:

```bash
python tos_codec_enhanced.py extract "path/to/archive.tos" "path/to/output_dir"
```

Use plain solid LZMA2 mode:

```bash
python tos_codec_enhanced.py compress "path/to/input" "path/to/archive.tos" --mode general
```

## Important Limits

- Only x86/x86-64 BCJ is active.
- ARM, ARM64, and MIPS BCJ filters are not implemented in the current pipeline.
- Compression is ratio-focused and can be slow at LZMA2 preset 9.
- During compression, temporary files and the plain fallback can increase working disk I/O. The bandwidth savings apply mainly to the final archive and later reads/writes/copies.

## Key Files

| File | Purpose |
|------|---------|
| `tos_codec_enhanced.py` | Core TOS3 codec and internal reversible x86 BCJ |
| `app_enhanced.py` | Flask web UI |
| `benchmark_tos.py` | Benchmark helper |
| `validate.py` | Validation and round-trip tests |
| `TOS_PIPELINE_REDESIGN.md` | Current pipeline design notes |
