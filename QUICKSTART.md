# TOS Enhanced Quick Start

## Install

```bash
pip install Flask Werkzeug
python validate.py
```

No BCJ engine compilation is needed. The active BCJ implementation is the internal reversible x86 filter in `tos_codec_enhanced.py`.

## Web UI

```bash
python app_enhanced.py
```

Open `http://localhost:5000`, upload files, and download the `.tos` archive.

## CLI

Compress a file or folder:

```bash
python tos_codec_enhanced.py compress "C:\path\to\input" "C:\path\to\archive.tos"
```

Extract:

```bash
python tos_codec_enhanced.py extract "C:\path\to\archive.tos" "C:\path\to\output_dir"
```

Use general-purpose plain solid LZMA2:

```bash
python tos_codec_enhanced.py compress "C:\path\to\input" "C:\path\to\archive.tos" --mode general
```

## What Is Active

- Internal reversible x86/x86-64 BCJ
- Delta preprocessing for numeric/time-series text
- JSON key-order normalization
- CSV column componentization
- Solid LZMA2 compression with final plain-LZMA2 fallback

## What Was Removed

- `engine/bcj_filter.c`
- `engine/bcj_filter_enhanced.c`
- Engine Makefiles
- CLI/web references to `--engine`

## Notes

- Already-compressed/high-entropy files are skipped by the adaptive routing.
- ARM, ARM64, and MIPS BCJ are not active.
- The pipeline reduces final archive size and later storage bandwidth, but compression itself may use temporary disk I/O.
