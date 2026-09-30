# TOS Pipeline Redesign

This design rejects preprocessing unless it improves the final LZMA2 archive in a measured trial.

## Stage 1: Intelligent File Classification

- Why different from LZMA2: classification does not compress; it prevents transforms on data where LZMA2 or the source codec is already the right model.
- Redundancy removed: none directly.
- Benefiting datasets: mixed archives, source trees with media/assets, executable bundles, logs, CSV exports.
- CPU overhead: one bounded sample scan plus entropy counting.
- RAM overhead: bounded by the classification sample.
- Risks: false positives can route to a transform candidate, but Stage 4 rejects it by LZMA2 trial.

## Stage 2: Adaptive Routing

- Why different from LZMA2: it chooses representation-changing filters by file semantics instead of applying byte-substitution universally.
- Redundancy removed: avoids archive growth from irrelevant transforms.
- Benefiting datasets: heterogeneous directories where only a subset is executable, numeric, JSONL, or CSV.
- CPU overhead: negligible rule checks.
- RAM overhead: none beyond the profile.
- Risks: conservative routing may miss a profitable transform; this is preferred over duplicating LZMA2 work.

## Stage 3: Semantic Preprocessing

- BCJ for x86 executables: normalizes relative branch/call targets. LZMA2 sees bytes, not instruction pointer-relative address semantics. Benefits compiled x86/x64 code. CPU is linear; RAM is one buffer. Risk: false executable detection, guarded by magic/type checks and sample verification.
- Delta for numeric/time-series text: converts slowly changing byte positions to residuals. LZMA2 can match repeated substrings but cannot infer arithmetic progression across records as compactly. Benefits sensor exports and regular numeric logs. CPU is linear; RAM is one buffer. Risk: noisy data can get worse, guarded by sample verification.
- JSON key-order normalization: only applies to exact minified JSON object lines. It sorts keys so records with the same schema align even when input key order varies, and stores compact schema IDs to restore original key order. LZMA2 cannot reorder object members across lines. Benefits JSONL telemetry/API dumps. CPU includes JSON parsing; RAM holds parsed sample/file and schema metadata. Risk: whitespace or duplicate-key JSON is skipped to preserve exact reversibility.
- CSV column componentization: stores raw cells column-major while preserving raw quoting and line endings. LZMA2 cannot transpose row-major CSV into column streams by itself. Benefits wide CSV/time-series tables where columns have independent distributions. CPU is linear CSV-aware scanning; RAM holds the transformed file. Risk: malformed or irregular CSV is skipped.
- XML normalization: routed but currently conservative; no active transform is applied until a reversible compact XML representation is implemented. This avoids whitespace/attribute-order changes that would need large metadata.

Removed active stages:

- Structural tokenizer, template detector, math detector, and cross-file token dictionary were removed from the active pipeline because they primarily replace repeated byte strings or line templates, which overlaps LZMA2 dictionary matching and range coding.

## Stage 4: Feedback Verification

- Why different from LZMA2: it uses LZMA2 itself as the acceptance oracle.
- Redundancy removed: rejects transforms whose metadata plus transformed sample compresses no smaller than the original sample.
- Benefiting datasets: all datasets, because bad transforms are automatically skipped.
- CPU overhead: two sample LZMA2 compressions per attempted transform.
- RAM overhead: bounded by the trial sample and transformed sample.
- Risks: a sample can mispredict the whole file; the final archive is also compared against plain solid LZMA2 as a fallback.

## Stage 5: Solid Archive

- Why different from LZMA2: solid packing exposes cross-file redundancy to one LZMA2 stream.
- Redundancy removed: shared headers, repeated schemas, repeated code/text fragments across files.
- Benefiting datasets: many small related files and source/data bundles.
- CPU overhead: one final LZMA2 pass.
- RAM overhead: LZMA2 dictionary plus stream buffers.
- Risks: extraction requires processing the solid stream; acceptable for ratio-focused archives.

## Metadata

TOS3 stores binary metadata only: member names, offsets, sizes, checksums, filter flags, and transform reversal state. Analysis data is returned to callers for benchmarks/UI but is not written into the archive.
