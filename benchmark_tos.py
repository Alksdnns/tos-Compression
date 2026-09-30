#!/usr/bin/env python3
"""Benchmark TOS against optional 7-Zip and report adaptive transform gains."""

import argparse
import json
import shutil
import subprocess
import tempfile
import time
import tracemalloc
from pathlib import Path

from tos_codec_enhanced import (
    extract_tos_archive_reversible,
    format_bytes,
    write_tos_archive_streaming,
)


def collect_inputs(input_path):
    """Return all files that should be included in a benchmark archive."""
    input_path = Path(input_path)
    if input_path.is_file():
        return [input_path]
    return sorted(path for path in input_path.rglob("*") if path.is_file())


def folder_size(path):
    """Return total bytes in a file or directory tree."""
    path = Path(path)
    if path.is_file():
        return path.stat().st_size
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def run_timed(label, function):
    """Run one benchmark action and return elapsed seconds plus result."""
    tracemalloc.start()
    start = time.perf_counter()
    cpu_start = time.process_time()
    result = function()
    elapsed = time.perf_counter() - start
    cpu_elapsed = time.process_time() - cpu_start
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {
        "label": label,
        "seconds": elapsed,
        "cpu_seconds": cpu_elapsed,
        "memory_usage": peak,
        "result": result,
    }


def run_7z(input_path, output_path):
    """Run 7-Zip if a compatible executable is available."""
    seven_zip = shutil.which("7z") or shutil.which("7za") or shutil.which("7zz")
    if not seven_zip:
        return None
    command = [seven_zip, "a", "-t7z", "-mx=9", str(output_path), str(input_path)]
    subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return output_path.stat().st_size


def transform_contributions(manifest):
    """Aggregate per-transform byte gains from TOS metadata."""
    files = manifest.get("files")
    if files is None and "t" in manifest:
        files = [{"transform_report": manifest.get("t", [])}]
    totals = {}
    for entry in files or []:
        for item in entry.get("transform_report", []):
            totals[item["name"]] = totals.get(item["name"], 0) + item.get("gain", 0)
    return totals


def report_contributions(transform_reports):
    """Aggregate per-transform LZMA net gains returned by the compressor."""
    totals = {}
    for file_reports in transform_reports or []:
        for item in file_reports:
            totals[item["name"]] = totals.get(item["name"], 0) + item.get("net_gain", 0)
    return totals


def benchmark(input_path, output_dir, config_path=None):
    """Compress, extract, and compare ratios/speed for one input."""
    input_path = Path(input_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    original_size = folder_size(input_path)
    tos_path = output_dir / f"{input_path.stem or 'archive'}.tos"
    seven_path = output_dir / f"{input_path.stem or 'archive'}.7z"

    with tempfile.TemporaryDirectory(prefix="tos_bench_") as temp_dir:
        extract_dir = Path(temp_dir) / "extract"

        tos_compress = run_timed(
            "tos_compress",
            lambda: write_tos_archive_streaming(
                collect_inputs(input_path) if input_path.is_dir() else [input_path],
                tos_path,
                config_path=config_path,
            ),
        )
        tos_extract = run_timed("tos_extract", lambda: extract_tos_archive_reversible(tos_path, extract_dir))

    seven_result = None
    try:
        seven_timed = run_timed("7z_compress", lambda: run_7z(input_path, seven_path))
        if seven_timed["result"] is not None:
            seven_result = {
                "size": seven_timed["result"],
                "seconds": round(seven_timed["seconds"], 4),
                "ratio": round(seven_timed["result"] / original_size, 4) if original_size else 0,
            }
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        seven_result = {"error": str(exc)}

    tos_size = tos_path.stat().st_size
    transform_reports = tos_compress["result"].get("transform_reports", [])
    report = {
        "input": str(input_path),
        "original_size": original_size,
        "original_size_human": format_bytes(original_size),
        "tos": {
            "size": tos_size,
            "size_human": format_bytes(tos_size),
            "transformed_size": tos_compress["result"].get("transformed_size", 0),
            "transformed_size_human": format_bytes(tos_compress["result"].get("transformed_size", 0)),
            "final_lzma_size": tos_compress["result"].get("final_lzma_size", 0),
            "final_lzma_size_human": format_bytes(tos_compress["result"].get("final_lzma_size", 0)),
            "ratio": round(tos_size / original_size, 4) if original_size else 0,
            "compression_seconds": round(tos_compress["seconds"], 4),
            "decompression_seconds": round(tos_extract["seconds"], 4),
            "compression_cpu_seconds": round(tos_compress["cpu_seconds"], 4),
            "decompression_cpu_seconds": round(tos_extract["cpu_seconds"], 4),
            "compression_cpu_usage_percent": round((tos_compress["cpu_seconds"] / tos_compress["seconds"]) * 100, 2)
            if tos_compress["seconds"] else 0,
            "decompression_cpu_usage_percent": round((tos_extract["cpu_seconds"] / tos_extract["seconds"]) * 100, 2)
            if tos_extract["seconds"] else 0,
            "compression_memory_usage": max(
                tos_compress["memory_usage"],
                tos_compress["result"].get("memory_usage", 0),
            ),
            "decompression_memory_usage": tos_extract["memory_usage"],
            "compression_speed_mb_s": round((original_size / 1024 / 1024) / tos_compress["seconds"], 3)
            if tos_compress["seconds"] else 0,
            "decompression_speed_mb_s": round((original_size / 1024 / 1024) / tos_extract["seconds"], 3)
            if tos_extract["seconds"] else 0,
            "dictionary_size": tos_compress["result"].get("global_dictionary_size", 0),
            "per_transform_contribution": report_contributions(transform_reports),
            "transform_reports": transform_reports,
        },
        "seven_zip": seven_result or "7z executable not found",
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="Benchmark TOS adaptive compression.")
    parser.add_argument("input", help="File or directory to benchmark")
    parser.add_argument("--output-dir", default="benchmarks", help="Directory for benchmark archives")
    parser.add_argument("--config", default=None, help="Optional TOS JSON config")
    args = parser.parse_args()

    report = benchmark(args.input, args.output_dir, config_path=args.config)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
