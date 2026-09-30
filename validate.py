#!/usr/bin/env python3
"""Validation suite for the enhanced TOS codec."""

import sys
import tempfile
from pathlib import Path


def check_python_version():
    if sys.version_info < (3, 7):
        print("FAIL Python 3.7+ required")
        return False
    print(f"OK Python {sys.version.split()[0]} OK")
    return True


def check_dependencies():
    required = ["flask", "werkzeug"]
    missing = []

    for package in required:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)

    if missing:
        print(f"WARN Optional web UI packages missing: {', '.join(missing)}")
        print(f"     Install with: pip install {' '.join(missing)}")
        return True

    print("OK Dependencies (Flask, Werkzeug) OK")
    return True


def check_tos_codec():
    codec_path = Path(__file__).parent / "tos_codec_enhanced.py"

    if not codec_path.exists():
        print(f"FAIL tos_codec_enhanced.py not found at {codec_path}")
        return False

    try:
        import tos_codec_enhanced

        print("OK tos_codec_enhanced.py imports OK")
        functions = [
            "detect_file_type",
            "apply_delta_filter",
            "remove_delta_filter",
            "apply_byte_shuffle",
            "apply_float_xor",
            "transform_bcj_x86",
            "stream_compress_lzma",
            "write_tos_archive_streaming",
            "extract_tos_archive_reversible",
        ]
        for function in functions:
            if not hasattr(tos_codec_enhanced, function):
                print(f"FAIL Missing function: {function}")
                return False
        print("OK All key functions present")
        return True
    except Exception as exc:
        print(f"FAIL Error importing tos_codec_enhanced: {exc}")
        return False


def check_bcj_filter():
    import tos_codec_enhanced

    if not hasattr(tos_codec_enhanced, "transform_bcj_x86"):
        print("FAIL Internal x86 BCJ filter is missing")
        return False
    print("OK Internal reversible x86 BCJ filter is available")
    return True


def test_delta_filter():
    import zlib

    from tos_codec_enhanced import apply_delta_filter, remove_delta_filter

    test_data = (b"ABCD" * 1000) + bytes(range(64))
    encoded, stride = apply_delta_filter(test_data, stride=4)
    decoded = remove_delta_filter(encoded, stride=stride)

    if decoded != test_data:
        print(f"FAIL Delta filter failed: {len(decoded)} != {len(test_data)}")
        return False

    original_compressed = len(zlib.compress(test_data))
    delta_compressed = len(zlib.compress(encoded))
    if delta_compressed >= original_compressed:
        print("WARN Delta filter did not improve this sample")

    print(f"OK Delta filter round trip OK ({len(test_data)} bytes)")
    return True


def test_content_detection():
    from tos_codec_enhanced import FILTER_BCJ_X86, analyze_file, detect_file_type

    pe_data = b"MZ\x90\x00" + b"\x00" * 100
    filter_type = detect_file_type(pe_data)
    if filter_type != FILTER_BCJ_X86:
        print(f"FAIL PE detection returned {filter_type}, expected {FILTER_BCJ_X86}")
        return False

    zip_data = b"PK\x03\x04" + b"\x00" * 100
    filter_type = detect_file_type(zip_data)
    if filter_type != 0:
        print(f"FAIL ZIP detection returned {filter_type}, expected 0")
        return False

    raw_code = bytearray()
    for _ in range(32):
        raw_code.extend(b"\x55\x48\x89\xE5")
        raw_code.extend(b"\xE8\x08\x00\x00\x00")
        raw_code.extend(b"\x90\x90\x90\x90\xC3")
    if detect_file_type(bytes(raw_code)) != FILTER_BCJ_X86:
        print("FAIL Headerless x86 code did not trigger BCJ filter")
        return False
    if not analyze_file("dump.text", bytes(raw_code)).is_executable:
        print("FAIL Headerless x86 code did not analyze as executable")
        return False

    print("OK Content detection OK")
    return True


def test_entropy_calculation():
    from tos_codec_enhanced import conditional_entropy, shannon_entropy

    high_entropy_data = bytes(range(256)) * 10
    low_entropy_data = b"A" * 1000
    patterned_data = b"AB" * 1000
    high_entropy = shannon_entropy(high_entropy_data)
    low_entropy = shannon_entropy(low_entropy_data)
    patterned_h0 = shannon_entropy(patterned_data)
    patterned_h1 = conditional_entropy(patterned_data, 1)

    if high_entropy <= low_entropy:
        print(
            f"FAIL Entropy calculation failed: "
            f"random={high_entropy}, repetitive={low_entropy}"
        )
        return False
    if patterned_h1 >= patterned_h0:
        print(f"FAIL Conditional entropy did not detect pattern: H0={patterned_h0}, H1={patterned_h1}")
        return False

    print(
        f"OK Entropy calculation OK "
        f"(random={high_entropy:.2f}, repetitive={low_entropy:.2f}, H1-pattern={patterned_h1:.2f})"
    )
    return True


def test_mdl_trial_and_reordering():
    from tos_codec_enhanced import (
        benchmark_transform_trial,
        reorder_file_records,
        RuleEngine,
        analyze_file,
    )

    original = bytes(range(64)) * 1024
    transformed = b"\x00" * len(original)
    report = benchmark_transform_trial(
        "synthetic_zero_residual",
        original,
        transformed,
        metadata_bytes=b"meta",
        config={"trial_sample_size": 12 * 1024, "trial_sample_count": 3, "entropy_trial_min_reduction": 0.0},
    )
    if not report["accepted"] or report["sample_count"] != 3 or report["metadata_size"] != 4:
        print(f"FAIL MDL trial did not accept expected synthetic residual: {report}")
        return False

    rule_engine = RuleEngine()
    records = []
    for name, payload in [
        ("b.txt", b"alpha beta gamma\n" * 200),
        ("c.txt", b"alpha beta gamma\n" * 201),
        ("a.bin", bytes(range(128)) * 20),
    ]:
        analysis = analyze_file(name, payload, rule_engine)
        records.append({"member_name": name, "data": payload, "analysis": analysis})
    ordered = reorder_file_records(records, {"enable_file_reordering": True})
    if sorted(record["solid_order"] for record in ordered) != list(range(3)):
        print("FAIL Solid-stream reordering did not assign a stable permutation")
        return False

    print("OK MDL trial and solid-stream reordering OK")
    return True


def test_transform_library_and_lzma_params():
    import struct

    from tos_codec_enhanced import (
        RuleEngine,
        analyze_file,
        apply_byte_shuffle,
        apply_float_xor,
        compress_file_lzma,
        looks_like_binary_float_series,
        remove_byte_shuffle,
        remove_float_xor,
    )

    binary_records = b"".join(struct.pack("<I", value) for value in range(512))
    shuffled, shuffle_meta = apply_byte_shuffle(binary_records, width=4)
    if not shuffle_meta.get("applied") or remove_byte_shuffle(shuffled, shuffle_meta) != binary_records:
        print("FAIL Byte-plane shuffle round trip failed")
        return False

    floats = b"".join(struct.pack("<d", index * 0.5) for index in range(512))
    encoded, float_meta = apply_float_xor(floats, width=8)
    if not float_meta.get("applied") or remove_float_xor(encoded, float_meta) != floats:
        print("FAIL Float-XOR round trip failed")
        return False
    if not looks_like_binary_float_series(floats):
        print("FAIL Structured float series was not detected")
        return False

    fake_pyc = b"\x2b\x0e\r\n" + b"\x00\x00\x00\x00" + b"\x00" * 8 + floats
    if looks_like_binary_float_series(fake_pyc):
        print("FAIL CPython bytecode header was misdetected as a float series")
        return False

    dense_binary = bytes(((index * 131 + 17) ^ (index >> 3)) & 0xFF for index in range(8192))
    if looks_like_binary_float_series(dense_binary):
        print("FAIL Dense binary data was misdetected as a float series")
        return False

    analysis = analyze_file("series.bin", floats, RuleEngine())
    selected = analysis.suggested_transforms
    if "float_xor" not in selected or "byte_shuffle" not in selected or "lzma_param_search" not in selected:
        print(f"FAIL Composed transform selection missing expected transforms: {selected}")
        return False

    with tempfile.TemporaryDirectory(prefix="tos_lzma_params_") as temp_dir:
        temp_dir = Path(temp_dir)
        source = temp_dir / "solid.bin"
        out = temp_dir / "solid.lzma"
        source.write_bytes(binary_records * 4)
        _raw, compressed, filters, report = compress_file_lzma(
            source,
            out,
            config={"enable_lzma_param_search": True, "trial_sample_size": 8192},
        )
        params = filters[-1]
        if compressed != out.stat().st_size or not {"lc", "lp", "pb"}.issubset(params):
            print(f"FAIL LZMA parameter search did not return custom params: {report}")
            return False

    print("OK Transform library and LZMA parameter search OK")
    return True


def test_archive_roundtrip():
    from tos_codec_enhanced import (
        extract_tos_archive_reversible,
        transform_bcj_x86,
        write_tos_archive_streaming,
    )

    with tempfile.TemporaryDirectory(prefix="tos_validate_") as temp_dir:
        temp_dir = Path(temp_dir)
        plain = temp_dir / "plain.txt"
        code = temp_dir / "program.exe"
        archive = temp_dir / "bundle.tos"
        general_archive = temp_dir / "bundle_general.tos"
        output = temp_dir / "out"
        general_output = temp_dir / "out_general"

        plain_data = (b"hello world\n" * 2000) + bytes(range(256))
        code_data = bytearray(b"MZ" + b"\x00" * 256)
        code_data[32] = 0xE8
        code_data[33:37] = (0x40).to_bytes(4, "little")
        code_data[96] = 0xE9
        code_data[97:101] = (0xFFFFFF80).to_bytes(4, "little")
        code_data.extend(b"CODE" * 1000)

        plain.write_bytes(plain_data)
        code.write_bytes(code_data)

        transformed, patched = transform_bcj_x86(bytes(code_data), inverse=False)
        restored, _ = transform_bcj_x86(transformed, inverse=True)
        if patched != 2 or restored != bytes(code_data):
            print("FAIL x86 BCJ transform is not reversible")
            return False

        write_tos_archive_streaming([plain, code], archive)
        extracted = extract_tos_archive_reversible(archive, output)
        restored_files = {Path(path).name: Path(path).read_bytes() for path in extracted}

        if restored_files.get("plain.txt") != plain_data:
            print("FAIL Plain file round trip mismatch")
            return False
        if restored_files.get("program.exe") != bytes(code_data):
            print("FAIL BCJ file round trip mismatch")
            return False
        manifest_file = write_tos_archive_streaming([plain, code], archive)["manifest"]["files"][0]
        if "crc32" in manifest_file:
            print("FAIL Public archive manifest still includes redundant CRC32")
            return False

        write_tos_archive_streaming([plain, code], general_archive, general_mode=True)
        extracted = extract_tos_archive_reversible(general_archive, general_output)
        restored_files = {Path(path).name: Path(path).read_bytes() for path in extracted}

        if restored_files.get("plain.txt") != plain_data:
            print("FAIL General mode plain file round trip mismatch")
            return False
        if restored_files.get("program.exe") != bytes(code_data):
            print("FAIL General mode binary file round trip mismatch")
            return False

    print("OK Archive round trip restores exact bytes in both modes")
    return True


def test_adaptive_transforms():
    from tos_codec_enhanced import (
        apply_csv_componentization,
        apply_jsonl_binary_pack,
        apply_json_key_order_normalization,
        remove_csv_componentization,
        remove_jsonl_binary_pack,
        remove_json_key_order_normalization,
    )

    jsonl = (
        b'{"z":1,"a":2}\n'
        b'{"a":3,"z":4}\n'
        b'{"z":5,"a":6}\n'
    )
    encoded, metadata = apply_json_key_order_normalization(jsonl)
    if not metadata.get("applied") or remove_json_key_order_normalization(encoded, metadata) != jsonl:
        print("FAIL JSON key-order normalization round trip failed")
        return False

    jsonl_records = (
        b'{"timestamp":1700000000000,"user_id":12345678,"event":"click"}\n'
        b'{"timestamp":1700000000001,"user_id":12345679,"event":"click"}\n'
        b'{"timestamp":1700000000002,"user_id":12345680,"event":"view"}\n'
    )
    encoded, metadata = apply_jsonl_binary_pack(jsonl_records)
    if not metadata.get("applied") or remove_jsonl_binary_pack(encoded, metadata) != jsonl_records:
        print("FAIL JSONL binary packing round trip failed")
        return False

    csv_data = (
        b"ts,sensor,value\n"
        b"2026-01-01T00:00:00Z,A,10\n"
        b"2026-01-01T00:01:00Z,A,11\n"
        b"2026-01-01T00:02:00Z,A,12\n"
    )
    encoded, metadata = apply_csv_componentization(csv_data)
    if not metadata.get("applied") or remove_csv_componentization(encoded, metadata) != csv_data:
        print("FAIL CSV componentization round trip failed")
        return False

    print("OK Semantic transforms round trip OK")
    return True


def test_flask_app():
    app_path = Path(__file__).parent / "app_enhanced.py"

    if not app_path.exists():
        print("WARN app_enhanced.py not found")
        return False

    print("OK app_enhanced.py exists")
    return True


def main():
    print("=" * 60)
    print("TOS Enhanced: Validation Suite")
    print("=" * 60)
    print()

    checks = [
        ("Python version", check_python_version),
        ("Dependencies", check_dependencies),
        ("TOS codec module", check_tos_codec),
        ("BCJ filter", check_bcj_filter),
        ("Delta filter", test_delta_filter),
        ("Content detection", test_content_detection),
        ("Entropy calculation", test_entropy_calculation),
        ("MDL trial/reordering", test_mdl_trial_and_reordering),
        ("Transform library/LZMA params", test_transform_library_and_lzma_params),
        ("Adaptive transforms", test_adaptive_transforms),
        ("Archive round trip", test_archive_roundtrip),
        ("Flask app", test_flask_app),
    ]

    results = []
    for name, check_fn in checks:
        try:
            result = check_fn()
            results.append((name, result))
        except Exception as exc:
            print(f"FAIL {name}: {exc}")
            results.append((name, False))
        print()

    print("=" * 60)
    print("Summary:")
    print("=" * 60)
    passed = sum(1 for _, result in results if result)
    total = len(results)

    for name, result in results:
        status = "OK" if result else "FAIL"
        print(f"{status} {name}")

    print()
    print(f"Passed: {passed}/{total}")

    if passed == total:
        print()
        print("All checks passed. Ready to use TOS Enhanced.")
        print()
        print("Next steps:")
        print("  1. Run web UI: python app_enhanced.py")
        print("  2. Upload a file to compress")
        print()
        return 0

    print()
    print("Some checks failed. Please fix the issues above.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
