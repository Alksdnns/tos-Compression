"""
TOS adaptive compression pipeline.

The active path is deliberately small: each preprocessing transform must expose
redundancy that LZMA2 cannot easily derive from the original byte order, and it
must win an LZMA2 sample trial before it is kept.
"""

import argparse
import ctypes
import hashlib
import json
import lzma
import mimetypes
import os
import re
import shutil
import struct
import sys
import tempfile
import time
import tracemalloc
import zlib
from collections import Counter
from dataclasses import dataclass, field
from math import isfinite, log2
from pathlib import Path

VENDOR_SITE = os.path.join(os.path.dirname(__file__), "vendor")
if os.path.isdir(VENDOR_SITE) and VENDOR_SITE not in sys.path:
    sys.path.insert(0, VENDOR_SITE)

try:
    import zstandard as zstd
except ImportError:
    zstd = None

try:
    from werkzeug.utils import secure_filename
except ImportError:
    def secure_filename(filename):
        """Fallback secure filename if werkzeug not available."""
        import re
        filename = re.sub(r'[^\w\s.-]', '', filename)
        return filename[:255] or "file"


MAGIC = b"TOS3"
MAGIC_SLIM = b"TS3S"
ARCHIVE_VERSION = 5
HEADER_STRUCT = struct.Struct("<4sIQQI")  # Added filter_mask
HEADER_SLIM = struct.Struct("<4sIQQI")  # Same size but different magic for single-file
TOKEN_MARKER = b"\x00TOS\xFF"
TOKEN_REPLACEMENT_SIZE = len(TOKEN_MARKER) + 3
TRIAL_SAMPLE_SIZE = 1024 * 1024
ENTROPY_GATE_SAMPLE_SIZE = 4 * 1024
BACKEND_LZMA2 = 0
BACKEND_ZSTD = 1
MANIFEST_COMPRESSION_ZLIB = 1

# Max ratio: 1 GB dictionary, preset 9 - larger dict improves compression for big inputs
# Note: increasing dict_size increases memory usage during compression/decompression.
LZMA_FILTERS = [
    {
        "id": lzma.FILTER_LZMA2,
        "dict_size": 256 * 1024 * 1024,  # 256 MB (sweep: reduce memory further)
        "preset": 9,
    }
]

# Stream chunk size. Keep this below the LZMA dictionary so large archives do
# not require holding the whole payload in memory.
CHUNK_SIZE = 4 * 1024 * 1024

# Filter type flags. TOS3 currently writes only internal reversible x86 BCJ
# and delta markers; external C BCJ engines are not part of the active path.
FILTER_BCJ_X86 = 1
FILTER_DELTA = 8
VIRTUAL_BASE = 0x00400000
ENTROPY_SAMPLE_LIMIT = 4 * 1024 * 1024
TEXT_SAMPLE_LIMIT = 256 * 1024


DEFAULT_CONFIG = {
    "enable_json_key_order": True,
    "enable_jsonl_binary_pack": True,
    "enable_xml_normalization": True,
    "enable_csv_componentization": True,
    "enable_tokenization_filter": True,
    "enable_bcj": True,
    "enable_delta": True,
    "enable_file_reordering": True,
    "enable_duplicate_diff": True,
    "enable_byte_shuffle": True,
    "enable_float_xor": True,
    "enable_lzma_param_search": True,
    "skip_already_compressed": True,
    "min_lzma_gain": 1,
    "trial_sample_size": 64 * 1024,
    "trial_sample_count": 1,
    "entropy_order": 2,
    "entropy_trial_min_reduction": 0.02,
    "duplicate_similarity_threshold": 0.97,
    "lzma_param_min_reduction": 0.01,
    "entropy_gate_enabled": True,
    "entropy_gate_threshold": 7.5,
    "entropy_gate_sample_size": ENTROPY_GATE_SAMPLE_SIZE,
    "small_file_zstd_threshold": 1024 * 1024,
    "small_file_backend_mode": "best",
    "zstd_compare_lzma_search": False,
    "zstd_level": 22,
    "zstd_static_dictionary": None,
    "lzma_preset": 9,
    "lzma_dict_size": 256 * 1024 * 1024,
    "lzma_param_search_small_threshold": 10 * 1024,
    "lzma_param_search_medium_threshold": 100 * 1024,
    "lzma_param_search_large_threshold": 1024 * 1024,
    "lzma_param_search_very_large_threshold": 8 * 1024 * 1024,
    "lzma_param_search_medium_candidates": 4,
    "lzma_param_search_large_candidates": 8,
    "lzma_param_search_very_large_candidates": 12,
    "lzma_param_search_max_candidates": 24,
    "lzma_param_search_time_budget_ms": 0,
    "streaming_solid_mode": False,
}


ALREADY_COMPRESSED_TYPES = {
    "jpeg",
    "png",
    "zip",
    "gzip",
    "mp3",
    "mp4",
    "pdf",
    "7z",
    "xz",
    "zstd",
    "rar",
    "bz2",
}

MAGIC_SIGNATURES = {
    "zip": b"PK\x03\x04",
    "gzip": b"\x1f\x8b",
    "jpeg": b"\xFF\xD8\xFF",
    "png": b"\x89PNG\r\n\x1a\n",
    "pdf": b"%PDF",
    "7z": b"7z\xBC\xAF\x27\x1C",
    "xz": b"\xFD7zXZ\x00",
    "zstd": b"\x28\xB5\x2F\xFD",
    "rar": b"Rar!\x1A\x07",
    "bz2": b"BZh",
}

TRANSFORM_JSON_KEY_ORDER = 1
TRANSFORM_CSV_COMPONENTS = 2
TRANSFORM_BYTE_SHUFFLE = 3
TRANSFORM_FLOAT_XOR = 4
TRANSFORM_TOKENIZATION_FILTER = 5
TRANSFORM_JSONL_BINARY_PACK = 6


TEXT_EXTENSIONS = {
    ".py": "python",
    ".java": "java",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".json": "json",
    ".xml": "xml",
    ".csv": "csv",
    ".txt": "text",
    ".md": "text",
    ".html": "html",
    ".css": "css",
    ".js": "javascript",
    ".ts": "typescript",
    ".yaml": "yaml",
    ".yml": "yaml",
}


class TosFormatError(Exception):
    pass


@dataclass
class FileAnalysis:
    """File profile used by the adaptive preprocessing rule engine."""

    name: str
    extension: str
    file_type: str
    mime_type: str
    size: int
    magic_number: bytes
    entropy: float
    utf8_valid: bool
    is_binary: bool
    is_text: bool
    is_executable: bool
    is_json: bool
    is_xml: bool
    is_csv: bool
    is_numeric_series: bool
    is_float_series: bool
    is_already_compressed: bool
    entropy_gate_dense: bool
    entropy_gate_sample: float
    line_count: int
    average_line_length: float
    suggested_transforms: list = field(default_factory=list)


class RuleEngine:
    """Rule-based transform selector with an ML-compatible feature boundary."""

    def __init__(self, config=None):
        self.config = {**DEFAULT_CONFIG, **(config or {})}

    def select(self, analysis):
        """Return an ordered transform pipeline to try for one file."""
        if analysis.is_already_compressed and self.config["skip_already_compressed"]:
            return ["skip"]

        transforms = []
        if self.config["enable_bcj"] and analysis.is_executable:
            transforms.append("bcj_x86")
        if self.config["enable_delta"] and analysis.is_numeric_series:
            transforms.append("delta")
        if self.config["enable_float_xor"] and analysis.is_float_series:
            transforms.append("float_xor")
        if self.config["enable_byte_shuffle"] and (analysis.is_numeric_series or analysis.is_float_series):
            transforms.append("byte_shuffle")
        if self.config["enable_jsonl_binary_pack"] and analysis.is_json:
            transforms.append("jsonl_binary_pack")
        if self.config["enable_json_key_order"] and analysis.is_json:
            transforms.append("json_key_order")
        if self.config["enable_xml_normalization"] and analysis.is_xml:
            transforms.append("xml_normalization")
        if self.config["enable_csv_componentization"] and analysis.is_csv:
            transforms.append("csv_componentization")
        if self.config["enable_tokenization_filter"] and (
            analysis.is_json or analysis.is_xml or analysis.is_csv
        ):
            transforms.append("tokenization_filter")
        if self.config["enable_lzma_param_search"]:
            transforms.append("lzma_param_search")
        return transforms or ["direct_lzma2"]

    def feature_vector(self, analysis):
        """Stable hook for a future ML model to consume instead of rules."""
        return {
            "file_type": analysis.file_type,
            "magic_number": analysis.magic_number.hex(),
            "entropy": analysis.entropy,
            "utf8_valid": analysis.utf8_valid,
            "executable": analysis.is_executable,
            "json": analysis.is_json,
            "xml": analysis.is_xml,
            "csv": analysis.is_csv,
            "numeric_series": analysis.is_numeric_series,
            "float_series": analysis.is_float_series,
            "entropy_gate_dense": analysis.entropy_gate_dense,
            "entropy_gate_sample": round(analysis.entropy_gate_sample, 4),
            "average_line_length": analysis.average_line_length,
            "binary": analysis.is_binary,
            "size": analysis.size,
        }


def format_bytes(value):
    units = ["B", "KB", "MB", "GB", "TB"]
    number = float(value)
    for unit in units:
        if number < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(number)} B"
            return f"{number:.2f} {unit}"
        number /= 1024.0


def shannon_entropy(data):
    if not data:
        return 0.0
    size = len(data)
    counts = Counter(data)
    return -sum((count / size) * log2(count / size) for count in counts.values())


def load_c_core():
    """Load the optional C engine for hot-path entropy/signature routines."""
    module_dir = Path(__file__).resolve().parent
    candidates = [
        module_dir / "tos_core.dll",
        module_dir / "libtos_core.so",
        module_dir / "libtos_core.dylib",
    ]
    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            library = ctypes.CDLL(str(candidate))
            library.tos_conditional_entropy.argtypes = [
                ctypes.POINTER(ctypes.c_ubyte),
                ctypes.c_size_t,
                ctypes.c_int,
            ]
            library.tos_conditional_entropy.restype = ctypes.c_double
            library.tos_simhash64.argtypes = [
                ctypes.POINTER(ctypes.c_ubyte),
                ctypes.c_size_t,
                ctypes.c_int,
            ]
            library.tos_simhash64.restype = ctypes.c_uint64
            return library
        except OSError:
            continue
    return None


C_CORE = load_c_core()


def conditional_entropy(data, order=1):
    """Return H_k in bits/byte using the previous 1 or 2 bytes as context."""
    if not data:
        return 0.0
    order = max(0, min(2, int(order)))
    if order == 0 or len(data) <= order:
        return shannon_entropy(data)
    if C_CORE is not None:
        buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        return float(C_CORE.tos_conditional_entropy(buffer, len(data), order))

    contexts = {}
    for index in range(order, len(data)):
        context = data[index - order:index]
        bucket = contexts.setdefault(context, [0, Counter()])
        bucket[0] += 1
        bucket[1][data[index]] += 1

    total = len(data) - order
    entropy = 0.0
    for context_total, counts in contexts.values():
        context_entropy = -sum(
            (count / context_total) * log2(count / context_total)
            for count in counts.values()
        )
        entropy += (context_total / total) * context_entropy
    return entropy


def compression_entropy(data, config=None):
    config = {**DEFAULT_CONFIG, **(config or {})}
    return conditional_entropy(data, config.get("entropy_order", 2))


def entropy_gate_is_dense(data, config=None):
    """Fast first-page Shannon gate for files that are already near-random."""
    config = {**DEFAULT_CONFIG, **(config or {})}
    if not config.get("entropy_gate_enabled", True):
        return False, 0.0
    limit = max(1, int(config.get("entropy_gate_sample_size", ENTROPY_GATE_SAMPLE_SIZE)))
    entropy = shannon_entropy(data[:limit])
    return entropy > float(config.get("entropy_gate_threshold", 7.5)), entropy


def read_le32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def write_le32(buffer, offset, value):
    struct.pack_into("<I", buffer, offset, value & 0xFFFFFFFF)


def encode_varint(value):
    """Encode a non-negative integer as unsigned LEB128."""
    if value < 0:
        raise ValueError("varint cannot encode negative values")
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def decode_varint(data, offset=0):
    """Decode unsigned LEB128 and return (value, new_offset)."""
    shift = 0
    value = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7
        if shift > 63:
            raise TosFormatError("varint is too large")
    raise TosFormatError("truncated varint")


def varint_size(value):
    """Return the number of bytes needed for unsigned LEB128."""
    return len(encode_varint(value))


def zigzag_encode(value):
    if value >= 0:
        return value << 1
    return ((-value) << 1) - 1


def zigzag_decode(value):
    return (value >> 1) ^ -(value & 1)


def pack_binary_dictionary(dictionary):
    """Pack dictionary entries as count + raw length/value pairs."""
    blob = bytearray(encode_varint(len(dictionary)))
    for token in dictionary:
        blob.extend(encode_varint(len(token)))
        blob.extend(token)
    return bytes(blob)


def unpack_binary_dictionary(blob):
    """Decode a compact raw-byte dictionary blob."""
    count, offset = decode_varint(blob, 0)
    dictionary = []
    for _ in range(count):
        size, offset = decode_varint(blob, offset)
        end = offset + size
        if end > len(blob):
            raise TosFormatError("truncated binary dictionary")
        dictionary.append(blob[offset:end])
        offset = end
    if offset != len(blob):
        raise TosFormatError("extra bytes after binary dictionary")
    return dictionary


def lzma_compressed_size(data, filters=None):
    """Return raw LZMA2 compressed size for decision trials."""
    if filters is None:
        filters = LZMA_FILTERS
    compressor = lzma.LZMACompressor(format=lzma.FORMAT_RAW, filters=filters)
    return len(compressor.compress(data) + compressor.flush())


def lzma_params_from_filters(filters):
    item = (filters or LZMA_FILTERS)[-1]
    return {
        "dict_size": item.get("dict_size", 256 * 1024 * 1024),
        "lc": item.get("lc", 3),
        "lp": item.get("lp", 0),
        "pb": item.get("pb", 2),
    }


def lzma_filters_from_params(params=None):
    params = {
        **lzma_params_from_filters(LZMA_FILTERS),
        "preset": LZMA_FILTERS[-1].get("preset", 9),
        **(params or {}),
    }
    return [{
        "id": lzma.FILTER_LZMA2,
        "dict_size": params["dict_size"],
        "preset": params.get("preset", 9),
        "lc": params["lc"],
        "lp": params["lp"],
        "pb": params["pb"],
    }]


def lzma_param_candidates(config=None):
    config = {**DEFAULT_CONFIG, **(config or {})}
    dict_size = int(config.get("lzma_dict_size", lzma_params_from_filters(LZMA_FILTERS)["dict_size"]))
    preset = int(config.get("lzma_preset", LZMA_FILTERS[-1].get("preset", 9)))
    for lc in range(0, 5):
        for lp in range(0, 3):
            if lc + lp > 4:
                continue
            for pb in range(0, 3):
                yield {"dict_size": dict_size, "preset": preset, "lc": lc, "lp": lp, "pb": pb}


def lzma_param_search_budget(data_size, config=None):
    """Return the deterministic lc/lp/pb candidate budget for an input size."""
    config = {**DEFAULT_CONFIG, **(config or {})}
    small = int(config.get("lzma_param_search_small_threshold", 10 * 1024))
    medium = int(config.get("lzma_param_search_medium_threshold", 100 * 1024))
    large = int(config.get("lzma_param_search_large_threshold", 1024 * 1024))
    very_large = int(config.get("lzma_param_search_very_large_threshold", 8 * 1024 * 1024))
    max_candidates = int(config.get("lzma_param_search_max_candidates", 24))

    if data_size < small:
        return 0, "small_input_default_params"
    if data_size < medium:
        return min(max_candidates, int(config.get("lzma_param_search_medium_candidates", 4))), "medium_input_limited_search"
    if data_size < large:
        return min(max_candidates, int(config.get("lzma_param_search_large_candidates", 8))), "large_input_limited_search"
    if data_size < very_large:
        return min(max_candidates, int(config.get("lzma_param_search_very_large_candidates", 12))), "very_large_input_limited_search"
    return max_candidates, "max_search_budget"


def lzma_filter_candidates(config=None, limit=None, skip_params=None):
    """Yield prebuilt LZMA filter configs for candidate params."""
    count = 0
    skip_params = skip_params or set()
    for params in lzma_param_candidates(config):
        key = (params["dict_size"], params["lc"], params["lp"], params["pb"])
        if key in skip_params:
            continue
        if limit is not None and count >= limit:
            break
        yield params, lzma_filters_from_params(params)
        count += 1


def search_lzma_filters_for_data(data, config=None):
    """Return best raw-LZMA2 filters within an adaptive lc/lp/pb budget."""
    config = {**DEFAULT_CONFIG, **(config or {})}
    default_filters = lzma_filters_from_params({
        "dict_size": int(config.get("lzma_dict_size", lzma_params_from_filters(LZMA_FILTERS)["dict_size"])),
        "preset": int(config.get("lzma_preset", LZMA_FILTERS[-1].get("preset", 9))),
    })
    default_size = lzma_compressed_size(data, default_filters)
    default_params = lzma_params_from_filters(default_filters)
    if not config.get("enable_lzma_param_search", True) or not data:
        return default_filters, {
            "enabled": False,
            "default_size": default_size,
            "best_size": default_size,
            "size": default_size,
            "params": default_params,
            "candidates_tested": 0,
            "total_trials": 1 if data else 0,
            "reason": "disabled" if data else "empty_input",
        }

    best_size = default_size
    best_filters = default_filters
    best_params = default_params
    budget_size = int(config.get("lzma_param_search_input_size", len(data)))
    candidate_budget, budget_reason = lzma_param_search_budget(budget_size, config)
    if candidate_budget <= 0:
        return default_filters, {
            "enabled": True,
            "default_size": default_size,
            "best_size": default_size,
            "size": default_size,
            "params": default_params,
            "candidates_tested": 0,
            "total_trials": 1,
            "candidate_budget": 0,
            "budget_size": budget_size,
            "reason": budget_reason,
        }

    candidates_tested = 0
    skipped_errors = 0
    stopped_by_time = False
    time_budget_ms = float(config.get("lzma_param_search_time_budget_ms", 0) or 0)
    search_start = time.perf_counter()
    default_key = (default_params["dict_size"], default_params["lc"], default_params["lp"], default_params["pb"])
    for params, filters in lzma_filter_candidates(config, limit=candidate_budget, skip_params={default_key}):
        try:
            size = lzma_compressed_size(data, filters)
        except lzma.LZMAError:
            skipped_errors += 1
            continue
        candidates_tested += 1
        if size < best_size:
            best_size = size
            best_filters = filters
            best_params = params
        if time_budget_ms > 0 and (time.perf_counter() - search_start) * 1000 >= time_budget_ms:
            stopped_by_time = True
            break

    min_reduction = config.get("lzma_param_min_reduction", 0.01)
    if default_size and (default_size - best_size) / default_size <= min_reduction:
        best_size = default_size
        best_filters = default_filters
        best_params = default_params

    return best_filters, {
        "enabled": True,
        "default_size": default_size,
        "best_size": best_size,
        "size": best_size,
        "params": best_params,
        "candidates_tested": candidates_tested,
        "total_trials": 1 + candidates_tested,
        "candidate_budget": candidate_budget,
        "budget_size": budget_size,
        "reason": "time_budget_exhausted" if stopped_by_time else budget_reason,
        "skipped_errors": skipped_errors,
    }


def ans_fractional_bit_estimate(data):
    """ANS entropy model for compression ratio prediction."""
    entropy = shannon_entropy(data)
    ideal_bits = entropy * len(data)
    huffman_floor_bits = int(ideal_bits + len(data) * 0.04)
    return {
        "entropy_bits_per_byte": round(entropy, 4),
        "ideal_ans_bytes": int((ideal_bits + 7) // 8),
        "estimated_huffman_bytes": int((huffman_floor_bits + 7) // 8),
    }


def load_config(config_path=None):
    """Load optional JSON configuration for enabling/disabling modules."""
    if not config_path:
        return dict(DEFAULT_CONFIG)
    with open(config_path, "r", encoding="utf-8") as handle:
        user_config = json.load(handle)
    return {**DEFAULT_CONFIG, **user_config}


def is_probably_text(data):
    """Classify bytes as text when nulls are absent and UTF-8 mostly decodes."""
    if not data:
        return True
    sample = data[:TEXT_SAMPLE_LIMIT]
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        printable = sum(1 for byte in sample if byte in b"\r\n\t" or 32 <= byte <= 126)
        return printable / max(1, len(sample)) > 0.90


def utf8_valid(data):
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def detect_file_kind(path, data):
    """Detect common source/data/media formats from magic bytes and extension."""
    sample = data[:8192]
    suffix = Path(path).suffix.lower()
    if sample.startswith(b"MZ") or sample.startswith(b"\x7fELF") or sample.startswith(b"\xCA\xFE\xBA\xBE"):
        return "executable"
    for kind, magic in MAGIC_SIGNATURES.items():
        if sample.startswith(magic):
            return kind
    if sample.startswith(b"ID3") or sample[:2] == b"\xFF\xFB":
        return "mp3"
    if b"ftyp" in sample[:16]:
        return "mp4"
    if suffix in {".bin", ".text", ".code", ".raw", ""} and looks_like_raw_x86_code(data):
        return "executable"
    return TEXT_EXTENSIONS.get(suffix, "binary" if not is_probably_text(sample) else "text")


def decoded_text(data):
    try:
        return data[:TEXT_SAMPLE_LIMIT].decode("utf-8")
    except UnicodeDecodeError:
        return ""


def looks_like_json(text):
    stripped = text.lstrip()
    return stripped.startswith("{") or stripped.startswith("[")


def looks_like_xml(text):
    stripped = text.lstrip()
    return stripped.startswith("<") and ">" in stripped[:512]


def looks_like_csv(text):
    lines = [line for line in text.splitlines()[:32] if line]
    if len(lines) < 2:
        return False
    comma_counts = [line.count(",") for line in lines]
    return max(comma_counts) >= 1 and len(set(comma_counts[: min(8, len(comma_counts))])) <= 2


def looks_like_numeric_series(text):
    lines = [line.strip() for line in text.splitlines()[:128] if line.strip()]
    if len(lines) < 8:
        return False
    numeric = 0
    for line in lines:
        fields = re.split(r"[\s,;]+", line)
        if fields and all(re.fullmatch(r"-?\d+(?:\.\d+)?|(?:\d{4}-\d{2}-\d{2})(?:[T ][0-9:.+-]+)?", field) for field in fields):
            numeric += 1
    return numeric / len(lines) >= 0.85


def looks_like_raw_x86_code(data):
    """Heuristic for headerless x86/x64 .text dumps without PE/ELF/Mach-O magic."""
    sample = data[:4096]
    if len(sample) < 64:
        return False
    if conditional_entropy(sample, 2) > 7.7:
        return False

    control_sites = 0
    plausible_rel32 = 0
    common_opcodes = {
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x68, 0x6A, 0x74, 0x75, 0x83, 0x85, 0x89, 0x8B,
        0x8D, 0x90, 0xC3, 0xC7, 0xE8, 0xE9, 0xEB, 0xF3,
    }
    common_count = sum(1 for byte in sample if byte in common_opcodes)
    for index in range(0, len(sample) - 5):
        opcode = sample[index]
        if opcode not in (0xE8, 0xE9):
            continue
        control_sites += 1
        rel = struct.unpack_from("<i", sample, index + 1)[0]
        target = index + 5 + rel
        if -len(sample) <= target <= len(sample) * 2:
            plausible_rel32 += 1

    density_per_kb = control_sites / max(1.0, len(sample) / 1024.0)
    plausible_ratio = plausible_rel32 / max(1, control_sites)
    common_density = common_count / len(sample)
    return (
        control_sites >= 4
        and density_per_kb >= 1.0
        and plausible_ratio >= 0.35
        and common_density >= 0.08
    )


def has_known_non_float_binary_header(data):
    """Reject common binary container/code formats before float-array probing."""
    if len(data) < 4:
        return False
    fixed_headers = (
        b"MZ",
        b"\x7fELF",
        b"\xCA\xFE\xBA\xBE",
        b"\xFE\xED\xFA\xCE",
        b"\xFE\xED\xFA\xCF",
        b"\xCE\xFA\xED\xFE",
        b"\xCF\xFA\xED\xFE",
        b"PK\x03\x04",
        b"\x1f\x8b",
        b"\xFF\xD8\xFF",
        b"\x89PNG\r\n\x1a\n",
        b"%PDF",
        b"7z\xBC\xAF\x27\x1C",
        b"\xFD7zXZ\x00",
        b"\x28\xB5\x2F\xFD",
        b"Rar!\x1A\x07",
        b"BZh",
        b"SQLite format 3\x00",
        b"\xCA\xFE\xBA\xBE",
        b"\x00asm",
        b"!<arch>\n",
    )
    if any(data.startswith(header) for header in fixed_headers):
        return True

    # CPython bytecode starts with a two-byte version-specific magic followed
    # by CR LF. Python 3.7+ then stores a small flags field at bytes 4..8.
    if len(data) >= 16 and data[2:4] == b"\r\n":
        flags = struct.unpack_from("<I", data, 4)[0]
        if flags & ~0x03 == 0:
            return True
    return False


def percentile(values, ratio):
    if not values:
        return 0.0
    index = min(len(values) - 1, max(0, int((len(values) - 1) * ratio)))
    return sorted(values)[index]


def looks_like_binary_float_series(data):
    """Detect raw little-endian float/double streams without accepting bytecode."""
    if len(data) < 64:
        return False
    if has_known_non_float_binary_header(data):
        return False

    entropy_sample = data[: min(len(data), 8192)]
    if shannon_entropy(entropy_sample) > 7.65 and conditional_entropy(entropy_sample, 2) > 7.25:
        return False

    for width, fmt in ((8, "<d"), (4, "<f")):
        usable = min(len(data) - (len(data) % width), 8192)
        if usable < width * 16:
            continue
        values = [
            struct.unpack_from(fmt, data, offset)[0]
            for offset in range(0, usable, width)
        ]
        plausible = [
            value
            for value in values
            if isfinite(value) and (value == 0.0 or 1e-12 <= abs(value) <= 1e12)
        ]
        if len(plausible) / len(values) < 0.98:
            continue

        changes = sum(1 for index in range(1, len(values)) if values[index] != values[index - 1])
        if changes < len(values) * 0.25:
            continue

        diffs = [abs(values[index] - values[index - 1]) for index in range(1, len(values))]
        sorted_values = sorted(values)
        robust_range = percentile(sorted_values, 0.95) - percentile(sorted_values, 0.05)
        if robust_range <= 0:
            continue
        median_step = percentile(diffs, 0.50)
        if median_step > max(1e-9, robust_range * 0.20):
            continue

        smooth_steps = 0
        for index in range(2, len(values)):
            prev = values[index - 1] - values[index - 2]
            step = values[index] - values[index - 1]
            scale = max(1.0, abs(prev), abs(step))
            if abs(step - prev) / scale < 0.25:
                smooth_steps += 1
        if smooth_steps < max(8, len(values) * 0.35):
            continue

        plane_entropies = [
            shannon_entropy(bytes(data[plane:usable:width]))
            for plane in range(width)
        ]
        scale_entropy = (
            sum(plane_entropies[width - 2:width]) / 2.0
            if width == 8
            else plane_entropies[width - 1]
        )
        if scale_entropy <= 3.5:
            return True
    return False


def analyze_file(path, data, rule_engine=None):
    """Analyze one file and produce transform-selection features."""
    name = str(path)
    sample = data[:TEXT_SAMPLE_LIMIT]
    file_type = detect_file_kind(path, data)
    entropy_sample = data[:ENTROPY_SAMPLE_LIMIT]
    entropy = shannon_entropy(entropy_sample)
    entropy_gate_dense, entropy_gate_sample = entropy_gate_is_dense(data, rule_engine.config if rule_engine else None)
    conditional = compression_entropy(entropy_sample, rule_engine.config if rule_engine else None)
    text = is_probably_text(sample)
    valid_utf8 = utf8_valid(sample)
    text_sample = decoded_text(data) if valid_utf8 else ""
    lines = sample.splitlines()
    suffix = Path(path).suffix.lower()
    analysis = FileAnalysis(
        name=name,
        extension=Path(path).suffix.lower(),
        file_type=file_type,
        mime_type=mimetypes.guess_type(name)[0] or "",
        size=len(data),
        magic_number=data[:16],
        entropy=entropy,
        utf8_valid=valid_utf8,
        is_binary=not text,
        is_text=text,
        is_executable=file_type == "executable",
        is_json=file_type == "json" or (valid_utf8 and looks_like_json(text_sample)),
        is_xml=file_type == "xml" or (valid_utf8 and looks_like_xml(text_sample)),
        is_csv=file_type == "csv" or (valid_utf8 and looks_like_csv(text_sample)),
        is_numeric_series=valid_utf8 and looks_like_numeric_series(text_sample) and suffix not in {".json", ".xml"},
        is_float_series=looks_like_binary_float_series(data),
        is_already_compressed=file_type in ALREADY_COMPRESSED_TYPES or entropy_gate_dense or conditional > 7.75,
        entropy_gate_dense=entropy_gate_dense,
        entropy_gate_sample=entropy_gate_sample,
        line_count=len(lines),
        average_line_length=(sum(len(line) for line in lines) / len(lines)) if lines else 0.0,
    )
    if rule_engine:
        analysis.suggested_transforms = rule_engine.select(analysis)
    return analysis


def detect_file_type(data, size=8192):
    """Detect file type from magic bytes and return safe reversible filters."""
    sample = data[:min(len(data), size)]
    
    # Check common formats
    if sample.startswith(b'MZ'):  # PE executable
        return FILTER_BCJ_X86
    elif sample.startswith(b'\x7fELF'):  # ELF executable
        # Only x86/x86-64 is supported by the active reversible BCJ path.
        if len(sample) >= 20:
            machine = struct.unpack('<H', sample[18:20])[0]
            if machine == 0x03 or machine == 0x3E:  # x86, x86-64
                return FILTER_BCJ_X86
        return 0
    elif sample.startswith(b'\xCA\xFE\xBA\xBE'):  # Mach-O (macOS)
        return FILTER_BCJ_X86
    elif sample.startswith(b'PK\x03\x04'):  # ZIP/JAR
        return 0  # Already compressed
    elif sample.startswith(b'\x1f\x8b'):  # GZIP
        return 0
    elif sample.startswith(b'\xFF\xD8\xFF'):  # JPEG
        return 0
    elif sample.startswith(b'\x89PNG'):  # PNG
        return 0
    elif sample.startswith(b'\x00\x00\x00\x18ftypmp42'):  # MP4
        return 0
    
    # Check entropy to detect compression
    entropy_val = conditional_entropy(sample, 2)
    if entropy_val > 7.75:  # High conditional entropy = likely compressed
        return 0
    if looks_like_raw_x86_code(data):
        return FILTER_BCJ_X86
    
    return 0


def apply_delta_filter(data, stride=4):
    """
    Delta preprocessing: encode differences instead of absolute values.
    Improves compression for structured data (tables, arrays, etc.).
    """
    if len(data) < 2 or stride < 1:
        return data, stride
    
    result = bytearray(len(data))
    result[0:stride] = data[0:stride]
    
    for i in range(stride, len(data)):
        result[i] = (data[i] - data[i - stride]) & 0xFF
    
    return bytes(result), stride


def remove_delta_filter(data, stride=4):
    """Reverse delta encoding."""
    if len(data) < 2:
        return data
    
    result = bytearray(len(data))
    result[0:stride] = data[0:stride]
    
    for i in range(stride, len(data)):
        result[i] = (result[i - stride] + data[i]) & 0xFF
    
    return bytes(result)


def byte_plane_shuffle(data, width):
    if width < 2 or len(data) < width * 2:
        return data
    record_count = len(data) // width
    body_size = record_count * width
    output = bytearray(body_size + (len(data) - body_size))
    write_offset = 0
    for plane in range(width):
        for record in range(record_count):
            output[write_offset] = data[(record * width) + plane]
            write_offset += 1
    output[body_size:] = data[body_size:]
    return bytes(output)


def byte_plane_unshuffle(data, width, tail_size=0):
    if width < 2 or len(data) < width * 2:
        return data
    body_size = len(data) - tail_size
    if body_size < 0 or body_size % width:
        raise TosFormatError("invalid byte-shuffle metadata")
    record_count = body_size // width
    output = bytearray(len(data))
    read_offset = 0
    for plane in range(width):
        for record in range(record_count):
            output[(record * width) + plane] = data[read_offset]
            read_offset += 1
    output[body_size:] = data[body_size:]
    return bytes(output)


def apply_byte_shuffle(data, width=None):
    widths = [width] if width else [2, 4, 8, 16]
    best = None
    for candidate_width in widths:
        if candidate_width is None or len(data) < candidate_width * 4:
            continue
        transformed = byte_plane_shuffle(data, candidate_width)
        if transformed == data:
            continue
        entropy = conditional_entropy(transformed[:ENTROPY_SAMPLE_LIMIT], 1)
        item = (entropy, candidate_width, transformed)
        if best is None or item[:2] < best[:2]:
            best = item
    if best is None:
        return data, {"name": "byte_shuffle", "applied": False}
    _entropy, selected_width, transformed = best
    return transformed, {
        "name": "byte_shuffle",
        "applied": True,
        "width": selected_width,
        "tail_size": len(data) % selected_width,
    }


def remove_byte_shuffle(data, metadata):
    return byte_plane_unshuffle(data, metadata["width"], metadata.get("tail_size", 0))


def apply_float_xor(data, width=None):
    widths = [width] if width else [8, 4]
    for candidate_width in widths:
        if candidate_width not in (4, 8) or len(data) < candidate_width * 4:
            continue
        body_size = len(data) - (len(data) % candidate_width)
        if body_size < candidate_width * 4:
            continue
        output = bytearray()
        previous = data[:candidate_width]
        output.extend(previous)
        for offset in range(candidate_width, body_size, candidate_width):
            current = data[offset:offset + candidate_width]
            xor_bytes = bytes(left ^ right for left, right in zip(current, previous))
            prefix = 0
            while prefix < candidate_width and xor_bytes[prefix] == 0:
                prefix += 1
            suffix = 0
            while suffix < candidate_width - prefix and xor_bytes[candidate_width - 1 - suffix] == 0:
                suffix += 1
            middle = xor_bytes[prefix:candidate_width - suffix]
            output.append(prefix)
            output.append(len(middle))
            output.extend(middle)
            previous = current
        output.extend(data[body_size:])
        if len(output) < len(data):
            return bytes(output), {
                "name": "float_xor",
                "applied": True,
                "width": candidate_width,
                "record_count": body_size // candidate_width,
                "tail_size": len(data) - body_size,
            }
    return data, {"name": "float_xor", "applied": False}


def remove_float_xor(data, metadata):
    width = metadata["width"]
    record_count = metadata["record_count"]
    tail_size = metadata.get("tail_size", 0)
    if width not in (4, 8) or record_count < 1 or len(data) < width + tail_size:
        raise TosFormatError("invalid float-xor metadata")
    body_end = len(data) - tail_size
    offset = 0
    previous = data[offset:offset + width]
    offset += width
    output = bytearray(previous)
    for _ in range(1, record_count):
        if offset + 2 > body_end:
            raise TosFormatError("truncated float-xor stream")
        prefix = data[offset]
        middle_size = data[offset + 1]
        offset += 2
        if prefix > width or middle_size > width or prefix + middle_size > width or offset + middle_size > body_end:
            raise TosFormatError("invalid float-xor run")
        xor_bytes = bytearray(width)
        xor_bytes[prefix:prefix + middle_size] = data[offset:offset + middle_size]
        offset += middle_size
        current = bytes(left ^ right for left, right in zip(previous, xor_bytes))
        output.extend(current)
        previous = current
    if offset != body_end:
        raise TosFormatError("extra bytes after float-xor stream")
    output.extend(data[body_end:])
    return bytes(output)


def hex_preview(data, limit=384):
    return " ".join(f"{byte:02X}" for byte in data[:limit])


def transform_bcj_x86(data, inverse=False, virtual_base=VIRTUAL_BASE):
    """
    Reversible x86 BCJ transform for CALL/JMP rel32 operands.

    Forward mode stores absolute virtual targets. Inverse mode restores rel32.
    The scanner skips rewritten operands in both directions, making the exact
    byte stream round-trip without external side data.
    """
    if len(data) < 5:
        return data, 0

    buffer = bytearray(data)
    patched = 0
    i = 0
    end = len(buffer) - 5

    while i <= end:
        opcode = buffer[i]
        if opcode in (0xE8, 0xE9):
            value = read_le32(buffer, i + 1)
            next_ip = (virtual_base + i + 5) & 0xFFFFFFFF
            if inverse:
                transformed = (value - next_ip) & 0xFFFFFFFF
            else:
                transformed = (next_ip + value) & 0xFFFFFFFF
            write_le32(buffer, i + 1, transformed)
            patched += 1
            i += 5
        else:
            i += 1

    return bytes(buffer), patched


def marker_escape(data):
    """Escape the transform marker so generated records are unambiguous."""
    return data.replace(TOKEN_MARKER, TOKEN_MARKER + b"\x00")


def marker_unescape(data):
    """Remove marker escaping when no token records are present."""
    return data.replace(TOKEN_MARKER + b"\x00", TOKEN_MARKER)


def apply_structural_tokenizer(data, dictionary):
    """Replace selected structural patterns with marker + varint IDs."""
    if not dictionary:
        return data, {"name": "structural_tokenizer", "applied": False, "gain": 0}

    encoded = marker_escape(data)
    hits = 0
    for token_id, token in enumerate(dictionary):
        replacement = TOKEN_MARKER + b"\x01" + encode_varint(token_id)
        count = encoded.count(token)
        if count:
            encoded = encoded.replace(token, replacement)
            hits += count

    gain = len(data) - len(encoded)
    if gain <= 0 or hits == 0:
        return data, {"name": "structural_tokenizer", "applied": False, "gain": 0}
    return encoded, {"name": "structural_tokenizer", "applied": True, "gain": gain, "hits": hits}


def remove_structural_tokenizer(data, dictionary):
    """Reverse structural token marker IDs back to original bytes."""
    output = bytearray()
    index = 0
    while index < len(data):
        marker_index = data.find(TOKEN_MARKER, index)
        if marker_index < 0:
            output.extend(data[index:])
            break
        output.extend(data[index:marker_index])
        kind_index = marker_index + len(TOKEN_MARKER)
        if kind_index >= len(data):
            raise TosFormatError("truncated structural token marker")
        kind = data[kind_index]
        if kind == 0:
            output.extend(TOKEN_MARKER)
            index = kind_index + 1
        elif kind == 1:
            token_id, token_end = decode_varint(data, kind_index + 1)
            if token_id >= len(dictionary):
                raise TosFormatError(f"unknown structural token id: {token_id}")
            output.extend(dictionary[token_id])
            index = token_end
        else:
            raise TosFormatError(f"unknown structural marker kind: {kind}")
    return bytes(output)


def score_structural_candidate(token, count, token_id):
    """Score one candidate using costs that affect the final stream."""
    replacement_size = len(TOKEN_MARKER) + 1 + varint_size(token_id)
    dictionary_cost = varint_size(len(token)) + len(token)
    replacement_cost = replacement_size * count
    raw_saved = len(token) * count
    estimated_gain = raw_saved - replacement_cost - dictionary_cost
    return {
        "occurrences": count,
        "pattern_length": len(token),
        "dictionary_cost": dictionary_cost,
        "replacement_cost": replacement_cost,
        "estimated_lzma_benefit": estimated_gain,
        "estimated_gain": estimated_gain,
    }


TOKEN_KEY_RE = re.compile(
    rb'"(?:\\.|[^"\\]){3,64}"\s*:|[A-Za-z_][A-Za-z0-9_.:-]{2,63}\s*='
)
TOKEN_NUMBER_RE = re.compile(rb'-?\d{8,19}')
TOKEN_SCAN_RE = re.compile(
    rb'"(?:\\.|[^"\\]){3,64}"\s*:|[A-Za-z_][A-Za-z0-9_.:-]{2,63}\s*=|-?\d{8,19}'
)


def select_tokenization_tokens(data, max_tokens=240):
    counts = Counter(match.group(0) for match in TOKEN_KEY_RE.finditer(data))
    candidates = []
    for token, count in counts.items():
        if count < 2:
            continue
        replacement_size = len(TOKEN_MARKER) + 2
        dictionary_cost = varint_size(len(token)) + len(token)
        gain = len(token) * count - replacement_size * count - dictionary_cost
        if gain > 0:
            candidates.append((gain, count, token))
    candidates.sort(reverse=True)
    return [token for _gain, _count, token in candidates[:max_tokens]]


def pack_tokenized_integer(raw):
    try:
        value = int(raw)
    except ValueError:
        return None
    if str(value).encode("ascii") != raw and not (
        value >= 0 and raw.isdigit() and raw == str(value).encode("ascii").rjust(len(raw), b"0")
    ):
        return None
    if -(1 << 31) <= value < (1 << 31):
        width = 4
    elif -(1 << 63) <= value < (1 << 63):
        width = 8
    else:
        return None
    return width, value.to_bytes(width, "little", signed=True), len(raw)


def apply_tokenization_filter(data):
    """Pack repeated structured-text keys and long integers into binary records."""
    if not is_probably_text(data[:TEXT_SAMPLE_LIMIT]):
        return data, {"name": "tokenization_filter", "applied": False}
    tokens = select_tokenization_tokens(data)
    if not tokens and not TOKEN_NUMBER_RE.search(data):
        return data, {"name": "tokenization_filter", "applied": False}

    token_ids = {token: index for index, token in enumerate(tokens)}
    output = bytearray()
    index = 0
    key_hits = 0
    number_hits = 0
    for match in TOKEN_SCAN_RE.finditer(data):
        start, end = match.span()
        if start < index:
            continue
        literal = data[index:start]
        output.extend(marker_escape(literal) if TOKEN_MARKER in literal else literal)

        raw = match.group(0)
        token_id = token_ids.get(raw)
        if token_id is not None:
            output.extend(TOKEN_MARKER)
            output.append(4)
            output.append(token_id)
            key_hits += 1
        else:
            packed = pack_tokenized_integer(raw)
            if packed is None:
                output.extend(marker_escape(raw) if TOKEN_MARKER in raw else raw)
            else:
                width, payload, original_length = packed
                output.extend(TOKEN_MARKER)
                output.append(5)
                output.append(width)
                output.extend(encode_varint(original_length))
                output.extend(payload)
                number_hits += 1
        index = end

    tail = data[index:]
    output.extend(marker_escape(tail) if TOKEN_MARKER in tail else tail)
    if output == data or (key_hits + number_hits) == 0:
        return data, {"name": "tokenization_filter", "applied": False}
    return bytes(output), {
        "name": "tokenization_filter",
        "applied": True,
        "tokens": tokens,
        "key_hits": key_hits,
        "number_hits": number_hits,
    }


def remove_tokenization_filter(data, metadata):
    tokens = metadata.get("tokens", [])
    output = bytearray()
    index = 0
    while index < len(data):
        marker_index = data.find(TOKEN_MARKER, index)
        if marker_index < 0:
            output.extend(data[index:])
            break
        output.extend(data[index:marker_index])
        kind_index = marker_index + len(TOKEN_MARKER)
        if kind_index >= len(data):
            raise TosFormatError("truncated tokenization marker")
        kind = data[kind_index]
        if kind == 0:
            output.extend(TOKEN_MARKER)
            index = kind_index + 1
        elif kind == 4:
            token_index = kind_index + 1
            if token_index >= len(data):
                raise TosFormatError("truncated key token")
            token_id = data[token_index]
            if token_id >= len(tokens):
                raise TosFormatError(f"unknown key token id: {token_id}")
            output.extend(tokens[token_id])
            index = token_index + 1
        elif kind == 5:
            width_index = kind_index + 1
            if width_index >= len(data):
                raise TosFormatError("truncated integer token")
            width = data[width_index]
            original_length, payload_offset = decode_varint(data, width_index + 1)
            payload_end = payload_offset + width
            if width not in (4, 8) or payload_end > len(data):
                raise TosFormatError("invalid integer token")
            value = int.from_bytes(data[payload_offset:payload_end], "little", signed=True)
            raw = str(value).encode("ascii")
            if value >= 0 and len(raw) < original_length:
                raw = raw.rjust(original_length, b"0")
            output.extend(raw)
            index = payload_end
        else:
            raise TosFormatError(f"unknown tokenization marker kind: {kind}")
    return bytes(output)


def sample_for_trial(data, limit):
    """Use deterministic prefix/middle/suffix bytes for LZMA trials."""
    if len(data) <= limit:
        return data
    part = limit // 3
    middle_start = max(0, (len(data) - part) // 2)
    return data[:part] + data[middle_start:middle_start + part] + data[-part:]


def sample_ranges_for_trial(size, limit, count=1):
    """Return deterministic stratified byte ranges for MDL transform trials."""
    if size <= 0:
        return [(0, 0)]
    count = max(1, min(3, int(count or 1)))
    if size <= limit or count == 1:
        return [(0, min(size, limit))]

    per_sample = max(1, limit // count)
    anchors = [0, max(0, (size - per_sample) // 2), max(0, size - per_sample)]
    ranges = []
    seen = set()
    for start in anchors[:count]:
        end = min(size, start + per_sample)
        key = (start, end)
        if key not in seen:
            ranges.append(key)
            seen.add(key)
    return ranges


def sample_segments_for_trial(data, limit, count=1):
    return [data[start:end] for start, end in sample_ranges_for_trial(len(data), limit, count)]


def entropy_prefilter_allows(original_samples, transformed_samples, config):
    order = config.get("entropy_order", 2)
    threshold = config.get("entropy_trial_min_reduction", 0.02)
    original_entropy = sum(conditional_entropy(sample, order) * len(sample) for sample in original_samples)
    transformed_entropy = sum(conditional_entropy(sample, order) * len(sample) for sample in transformed_samples)
    total = sum(len(sample) for sample in original_samples)
    if total <= 0:
        return True, 0.0, 0.0, 0.0
    original_h = original_entropy / total
    transformed_h = transformed_entropy / total
    if original_h <= 0:
        return True, original_h, transformed_h, 0.0
    reduction = (original_h - transformed_h) / original_h
    return reduction >= threshold, original_h, transformed_h, reduction


def trial_accepts(original, transformed, metadata_bytes=b"", config=None):
    """Accept only when transformed samples win an MDL LZMA comparison."""
    config = {**DEFAULT_CONFIG, **(config or {})}
    limit = config.get("trial_sample_size", TRIAL_SAMPLE_SIZE)
    count = config.get("trial_sample_count", 1)
    original_samples = sample_segments_for_trial(original, limit, count)
    transformed_samples = sample_segments_for_trial(transformed, limit, count)
    allowed, original_h, transformed_h, entropy_reduction = entropy_prefilter_allows(
        original_samples,
        transformed_samples,
        config,
    )
    if not allowed:
        return False, {
            "sample_original_lzma": 0,
            "sample_transformed_lzma": len(metadata_bytes),
            "sample_lzma_gain": -len(metadata_bytes),
            "metadata_size": len(metadata_bytes),
            "sample_count": len(original_samples),
            "entropy_original": round(original_h, 4),
            "entropy_transformed": round(transformed_h, 4),
            "entropy_reduction": round(entropy_reduction, 6),
            "entropy_prefilter": "skipped",
        }

    original_blob = b"".join(original_samples)
    transformed_blob = metadata_bytes + b"".join(transformed_samples)
    original_filters, original_search = search_lzma_filters_for_data(original_blob, config)
    transformed_filters, transformed_search = search_lzma_filters_for_data(transformed_blob, config)
    original_lzma = original_search["size"]
    transformed_lzma = transformed_search["size"]
    gain = original_lzma - transformed_lzma
    return gain >= config["min_lzma_gain"], {
        "sample_original_lzma": original_lzma,
        "sample_transformed_lzma": transformed_lzma,
        "sample_lzma_gain": gain,
        "metadata_size": len(metadata_bytes),
        "sample_count": len(original_samples),
        "entropy_original": round(original_h, 4),
        "entropy_transformed": round(transformed_h, 4),
        "entropy_reduction": round(entropy_reduction, 6),
        "entropy_prefilter": "passed",
        "original_lzma_params": original_search["params"],
        "transformed_lzma_params": transformed_search["params"],
    }


def benchmark_transform_trial(name, original, transformed, metadata_bytes=b"", dictionary_size=0, config=None):
    """Measure sample-level compression effect for one transform."""
    config = {**DEFAULT_CONFIG, **(config or {})}
    tracemalloc.start()
    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    accepted, trial = trial_accepts(original, transformed, metadata_bytes, config)
    original_lzma = trial["sample_original_lzma"]
    transformed_lzma = trial["sample_transformed_lzma"]
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    wall_time = time.perf_counter() - wall_start
    cpu_time = time.process_time() - cpu_start
    return {
        "name": name,
        "original_size": len(original),
        "after_transform": len(transformed),
        "after_lzma": transformed_lzma,
        "baseline_lzma": original_lzma,
        "compression_ratio": round(transformed_lzma / len(original), 6) if original else 0,
        "compression_time": round(wall_time, 6),
        "memory_usage": peak,
        "cpu_time": round(cpu_time, 6),
        "dictionary_size": dictionary_size,
        "net_gain": original_lzma - transformed_lzma,
        "accepted": accepted,
        "metadata_size": trial.get("metadata_size", len(metadata_bytes)),
        "sample_count": trial.get("sample_count", 1),
        "entropy_original": trial.get("entropy_original", 0.0),
        "entropy_transformed": trial.get("entropy_transformed", 0.0),
        "entropy_reduction": trial.get("entropy_reduction", 0.0),
        "entropy_prefilter": trial.get("entropy_prefilter", "passed"),
    }


def build_global_structural_dictionary(file_records, config):
    """Build a raw-byte dictionary selected by LZMA trial compression."""
    if not config["enable_cross_file_dictionary"]:
        return []

    counts = Counter()
    eligible = []
    for record in file_records:
        if record["analysis"].is_text and "structural_tokenizer" in record["analysis"].suggested_transforms:
            counts.update(extract_text_tokens(record["data"]))
            eligible.append(record)

    candidates = []
    for token, count in counts.items():
        if len(token) <= TOKEN_REPLACEMENT_SIZE or count < 2:
            continue
        score = score_structural_candidate(token, count, len(candidates))
        if score["estimated_gain"] > 0:
            candidates.append((score["estimated_gain"], token, score))

    candidates.sort(reverse=True)
    trial_limit = config.get("trial_sample_size", TRIAL_SAMPLE_SIZE)
    original_sample = b"".join(sample_for_trial(record["data"], trial_limit // max(1, len(eligible))) for record in eligible)
    dictionary = []
    for _, token, _score in candidates[: config["max_global_tokens"]]:
        trial_dictionary = dictionary + [token]
        dict_blob = pack_binary_dictionary(trial_dictionary)
        transformed_sample, metadata = apply_structural_tokenizer(original_sample, trial_dictionary)
        if not metadata.get("applied"):
            continue
        accepted, _trial = trial_accepts(original_sample, transformed_sample, dict_blob, config)
        if accepted:
            dictionary = trial_dictionary
    return dictionary


def stable_hash64(data):
    return int.from_bytes(hashlib.blake2b(data, digest_size=8).digest(), "little")


def simhash64(data, shingle_size=6):
    """Return a deterministic 64-bit SimHash signature over byte shingles."""
    if not data:
        return 0
    shingle_size = max(1, int(shingle_size))
    if C_CORE is not None:
        buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        return int(C_CORE.tos_simhash64(buffer, len(data), shingle_size))

    weights = [0] * 64
    if len(data) < shingle_size:
        shingles = [data]
    else:
        shingles = (data[index:index + shingle_size] for index in range(0, len(data) - shingle_size + 1))
    for shingle in shingles:
        value = stable_hash64(shingle)
        for bit in range(64):
            weights[bit] += 1 if value & (1 << bit) else -1
    signature = 0
    for bit, weight in enumerate(weights):
        if weight >= 0:
            signature |= 1 << bit
    return signature


def hamming64(left, right):
    return (left ^ right).bit_count()


def reorder_file_records(file_records, config):
    """Greedily chain files by SimHash distance to improve solid-stream locality."""
    if not config.get("enable_file_reordering", True) or len(file_records) < 3:
        for index, record in enumerate(file_records):
            record["solid_order"] = index
            record["simhash64"] = simhash64(record["data"][:ENTROPY_SAMPLE_LIMIT])
        return file_records

    records = list(file_records)
    for index, record in enumerate(records):
        record["input_order"] = index
        record["simhash64"] = simhash64(record["data"][:ENTROPY_SAMPLE_LIMIT])

    remaining = set(range(len(records)))
    current = min(remaining, key=lambda item: (records[item]["analysis"].file_type, records[item]["member_name"]))
    ordered = []
    while remaining:
        remaining.remove(current)
        ordered.append(records[current])
        if not remaining:
            break
        current_sig = records[current]["simhash64"]
        current = min(
            remaining,
            key=lambda item: (
                hamming64(current_sig, records[item]["simhash64"]),
                records[item]["analysis"].file_type,
                records[item]["member_name"],
            ),
        )

    for index, record in enumerate(ordered):
        record["solid_order"] = index
    return ordered


def normalize_template_line(line):
    """Return a template shape and captured fields for one structured line."""
    fields = []

    def capture(match):
        fields.append(match.group(0))
        return f"%{len(fields)}%"

    shaped = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|-?\d+(?:\.\d+)?', capture, line)
    if len(fields) < 2 or shaped == line:
        return None, []
    return shaped, fields


def apply_template_detector(data):
    """Compress repeated JSON/XML/CSV-like line templates with field records."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data, {"name": "template", "applied": False, "gain": 0}

    lines = text.splitlines(keepends=True)
    groups = Counter()
    parsed = []
    for line in lines:
        body = line.rstrip("\r\n")
        newline = line[len(body):]
        shape, fields = normalize_template_line(body)
        parsed.append((shape, fields, newline, line))
        if shape:
            groups[(shape, newline)] += 1

    templates = {}
    for (shape, newline), count in groups.items():
        if count > 1 and len(shape) > 8:
            templates[(shape, newline)] = len(templates)

    if not templates:
        return data, {"name": "template", "applied": False, "gain": 0}

    output = bytearray(marker_escape(b""))
    output.clear()
    hits = 0
    for shape, fields, newline, original in parsed:
        key = (shape, newline)
        if key not in templates:
            output.extend(marker_escape(original.encode("utf-8")))
            continue
        record = {
            "t": templates[key],
            "f": fields,
        }
        payload = json.dumps(record, separators=(",", ":")).encode("utf-8")
        output.extend(TOKEN_MARKER + b"\x02" + struct.pack("<I", len(payload)) + payload)
        hits += 1

    template_list = [
        {"shape": shape, "newline": newline}
        for (shape, newline), _ in sorted(templates.items(), key=lambda item: item[1])
    ]
    metadata = {"name": "template", "applied": True, "templates": template_list, "hits": hits}
    gain = len(data) - (len(output) + len(json.dumps(template_list, separators=(",", ":"))))
    if gain <= 0:
        return data, {"name": "template", "applied": False, "gain": 0}
    metadata["gain"] = gain
    return bytes(output), metadata


def remove_template_detector(data, metadata):
    """Reverse template records to exact original UTF-8 text lines."""
    templates = metadata.get("templates", [])
    output = bytearray()
    index = 0
    while index < len(data):
        marker_index = data.find(TOKEN_MARKER, index)
        if marker_index < 0:
            output.extend(data[index:])
            break
        output.extend(data[index:marker_index])
        kind_index = marker_index + len(TOKEN_MARKER)
        if kind_index >= len(data):
            raise TosFormatError("truncated template marker")
        kind = data[kind_index]
        if kind == 0:
            output.extend(TOKEN_MARKER)
            index = kind_index + 1
        elif kind == 2:
            size_start = kind_index + 1
            size_end = size_start + 4
            size = struct.unpack("<I", data[size_start:size_end])[0]
            payload = data[size_end:size_end + size]
            record = json.loads(payload.decode("utf-8"))
            template = templates[record["t"]]
            line = template["shape"]
            for field_index, value in enumerate(record["f"], start=1):
                line = line.replace(f"%{field_index}%", value, 1)
            output.extend((line + template["newline"]).encode("utf-8"))
            index = size_end + size
        else:
            raise TosFormatError(f"unknown template marker kind: {kind}")
    return bytes(output)


def detect_numeric_sequence(values):
    """Detect arithmetic or geometric sequences in a list of integers."""
    if len(values) < 5:
        return None
    step = values[1] - values[0]
    if all(values[index] - values[index - 1] == step for index in range(2, len(values))):
        return {"kind": "arithmetic", "start": values[0], "step": step, "length": len(values)}
    if values[0] != 0 and values[1] % values[0] == 0:
        ratio = values[1] // values[0]
        if ratio not in (0, 1) and all(values[index - 1] * ratio == values[index] for index in range(2, len(values))):
            return {"kind": "geometric", "start": values[0], "ratio": ratio, "length": len(values)}
    return None


def apply_math_detector(data):
    """Encode whole-file newline-separated arithmetic/geometric integer series."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data, {"name": "math", "applied": False, "gain": 0}

    lines = text.splitlines(keepends=True)
    if not lines:
        return data, {"name": "math", "applied": False, "gain": 0}

    values = []
    newline = None
    for line in lines:
        body = line.rstrip("\r\n")
        ending = line[len(body):]
        if not re.fullmatch(r"-?\d+", body):
            return data, {"name": "math", "applied": False, "gain": 0}
        if newline is None:
            newline = ending
        elif newline != ending:
            return data, {"name": "math", "applied": False, "gain": 0}
        values.append(int(body))

    sequence = detect_numeric_sequence(values)
    if not sequence:
        return data, {"name": "math", "applied": False, "gain": 0}

    sequence["newline"] = newline or ""
    payload = json.dumps(sequence, separators=(",", ":")).encode("utf-8")
    encoded = TOKEN_MARKER + b"\x03" + struct.pack("<I", len(payload)) + payload
    gain = len(data) - len(encoded)
    if gain <= 0:
        return data, {"name": "math", "applied": False, "gain": 0}
    return encoded, {"name": "math", "applied": True, "gain": gain, "sequence": sequence}


def remove_math_detector(data, metadata):
    """Rebuild an integer sequence encoded by apply_math_detector."""
    sequence = metadata["sequence"]
    values = []
    current = sequence["start"]
    for _ in range(sequence["length"]):
        values.append(str(current))
        if sequence["kind"] == "arithmetic":
            current += sequence["step"]
        else:
            current *= sequence["ratio"]
    return (sequence["newline"].join(values) + sequence["newline"]).encode("utf-8")


def newline_code(value):
    return {"": 0, "\n": 1, "\r\n": 2, "\r": 3}.get(value, 0)


def newline_from_code(code):
    return {0: "", 1: "\n", 2: "\r\n", 3: "\r"}[code]


def pack_rle_codes(codes):
    out = bytearray()
    if not codes:
        return bytes(out)
    current = codes[0]
    count = 1
    for code in codes[1:]:
        if code == current:
            count += 1
        else:
            out.append(current)
            out.extend(encode_varint(count))
            current = code
            count = 1
    out.append(current)
    out.extend(encode_varint(count))
    return bytes(out)


def unpack_rle_codes(data, expected_count):
    codes = []
    offset = 0
    while offset < len(data):
        code = data[offset]
        offset += 1
        count, offset = decode_varint(data, offset)
        codes.extend([code] * count)
    if len(codes) != expected_count:
        raise TosFormatError("newline RLE count mismatch")
    return codes


def split_csv_raw_line(line, delimiter=b","):
    fields = []
    start = 0
    index = 0
    in_quotes = False
    while index < len(line):
        byte = line[index:index + 1]
        if byte == b'"':
            if in_quotes and index + 1 < len(line) and line[index + 1:index + 2] == b'"':
                index += 2
                continue
            in_quotes = not in_quotes
        elif byte == delimiter and not in_quotes:
            fields.append(line[start:index])
            start = index + 1
        index += 1
    if in_quotes:
        return None
    fields.append(line[start:])
    return fields


def split_line_ending(line):
    if line.endswith(b"\r\n"):
        return line[:-2], "\r\n"
    if line.endswith(b"\n"):
        return line[:-1], "\n"
    if line.endswith(b"\r"):
        return line[:-1], "\r"
    return line, ""


def apply_csv_componentization(data):
    """Store raw CSV cells column-major so LZMA2 sees same-column locality."""
    lines = data.splitlines(keepends=True)
    if len(lines) < 2:
        return data, {"name": "csv_componentization", "applied": False}

    rows = []
    newline_codes = []
    field_count = None
    for line in lines:
        body, ending = split_line_ending(line)
        fields = split_csv_raw_line(body)
        if fields is None or len(fields) < 2:
            return data, {"name": "csv_componentization", "applied": False}
        if field_count is None:
            field_count = len(fields)
        elif len(fields) != field_count:
            return data, {"name": "csv_componentization", "applied": False}
        rows.append(fields)
        newline_codes.append(newline_code(ending))

    output = bytearray()
    output.extend(encode_varint(field_count))
    output.extend(encode_varint(len(rows)))
    for column in range(field_count):
        for row in rows:
            cell = row[column]
            output.extend(encode_varint(len(cell)))
            output.extend(cell)

    metadata = {
        "name": "csv_componentization",
        "applied": True,
        "field_count": field_count,
        "row_count": len(rows),
        "delimiter": ord(","),
        "newlines": newline_codes,
    }
    return bytes(output), metadata


def remove_csv_componentization(data, metadata):
    offset = 0
    field_count, offset = decode_varint(data, offset)
    row_count, offset = decode_varint(data, offset)
    if field_count != metadata["field_count"] or row_count != metadata["row_count"]:
        raise TosFormatError("CSV component metadata mismatch")
    rows = [[b""] * field_count for _ in range(row_count)]
    for column in range(field_count):
        for row_index in range(row_count):
            size, offset = decode_varint(data, offset)
            end = offset + size
            if end > len(data):
                raise TosFormatError("truncated CSV component stream")
            rows[row_index][column] = data[offset:end]
            offset = end
    if offset != len(data):
        raise TosFormatError("extra bytes after CSV component stream")
    delimiter = bytes([metadata.get("delimiter", ord(","))])
    output = bytearray()
    for row, code in zip(rows, metadata["newlines"]):
        output.extend(delimiter.join(row))
        output.extend(newline_from_code(code).encode("ascii"))
    return bytes(output)


def encode_jsonl_binary_value(value):
    if value is None:
        return b"\x00"
    if value is False:
        return b"\x01"
    if value is True:
        return b"\x02"
    if isinstance(value, int) and not isinstance(value, bool):
        return b"\x03" + encode_varint(zigzag_encode(value))
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return b"\x04" + encode_varint(len(raw)) + raw
    raw_json = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return b"\x05" + encode_varint(len(raw_json)) + raw_json


def decode_jsonl_binary_value(data, offset):
    if offset >= len(data):
        raise TosFormatError("truncated JSONL binary value")
    kind = data[offset]
    offset += 1
    if kind == 0:
        return None, offset
    if kind == 1:
        return False, offset
    if kind == 2:
        return True, offset
    if kind == 3:
        encoded, offset = decode_varint(data, offset)
        return zigzag_decode(encoded), offset
    if kind == 4:
        size, offset = decode_varint(data, offset)
        end = offset + size
        if end > len(data):
            raise TosFormatError("truncated JSONL string value")
        return data[offset:end].decode("utf-8"), end
    if kind == 5:
        size, offset = decode_varint(data, offset)
        end = offset + size
        if end > len(data):
            raise TosFormatError("truncated JSONL raw value")
        return json.loads(data[offset:end].decode("utf-8")), end
    raise TosFormatError(f"unknown JSONL binary value type: {kind}")


def json_separator_profile(obj, body):
    for separators, code in (((",", ":"), 0), ((", ", ": "), 1)):
        if json.dumps(obj, separators=separators, ensure_ascii=False) == body:
            return separators, code
    return None, None


def json_separators_from_code(code):
    if code == 0:
        return (",", ":")
    if code == 1:
        return (", ", ": ")
    raise TosFormatError(f"unknown JSONL separator profile: {code}")


def apply_jsonl_binary_pack(data):
    """Store canonical JSON object lines as schema IDs plus typed value streams."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data, {"name": "jsonl_binary_pack", "applied": False}

    lines = text.splitlines(keepends=True)
    if len(lines) < 2:
        return data, {"name": "jsonl_binary_pack", "applied": False}

    schema_map = {}
    schema_orders = []
    row_schema_ids = []
    newline_codes = []
    output = bytearray()
    value_count = 0
    separator_code = None
    for line in lines:
        body = line.rstrip("\r\n")
        ending = line[len(body):]
        if not body:
            return data, {"name": "jsonl_binary_pack", "applied": False}
        try:
            obj = json.loads(body)
        except json.JSONDecodeError:
            return data, {"name": "jsonl_binary_pack", "applied": False}
        if not isinstance(obj, dict) or not obj:
            return data, {"name": "jsonl_binary_pack", "applied": False}
        separators, line_separator_code = json_separator_profile(obj, body)
        if separators is None:
            return data, {"name": "jsonl_binary_pack", "applied": False}
        if separator_code is None:
            separator_code = line_separator_code
        elif separator_code != line_separator_code:
            return data, {"name": "jsonl_binary_pack", "applied": False}
        schema = tuple(obj.keys())
        if schema not in schema_map:
            schema_map[schema] = len(schema_orders)
            schema_orders.append(list(schema))
        row_schema_ids.append(schema_map[schema])
        newline_codes.append(newline_code(ending))
        for key in schema:
            output.extend(encode_jsonl_binary_value(obj[key]))
            value_count += 1

    if not output:
        return data, {"name": "jsonl_binary_pack", "applied": False}
    metadata = {
        "name": "jsonl_binary_pack",
        "applied": True,
        "schema_orders": schema_orders,
        "row_schema_ids": row_schema_ids,
        "newlines": newline_codes,
        "separator_code": separator_code or 0,
        "value_count": value_count,
    }
    metadata_cost = len(pack_jsonl_binary_metadata(metadata))
    if len(output) + metadata_cost >= len(data):
        return data, {"name": "jsonl_binary_pack", "applied": False}
    return bytes(output), metadata


def remove_jsonl_binary_pack(data, metadata):
    offset = 0
    lines = []
    for row_index, schema_id in enumerate(metadata["row_schema_ids"]):
        schema = metadata["schema_orders"][schema_id]
        obj = {}
        for key in schema:
            value, offset = decode_jsonl_binary_value(data, offset)
            obj[key] = value
        separators = json_separators_from_code(metadata.get("separator_code", 0))
        lines.append(json.dumps(obj, separators=separators, ensure_ascii=False))
        lines.append(newline_from_code(metadata["newlines"][row_index]))
    if offset != len(data):
        raise TosFormatError("extra bytes after JSONL binary stream")
    return "".join(lines).encode("utf-8")


def pack_jsonl_binary_metadata(metadata):
    out = bytearray()
    out.extend(encode_varint(len(metadata["schema_orders"])))
    for schema in metadata["schema_orders"]:
        out.extend(encode_varint(len(schema)))
        for key in schema:
            out.extend(pack_string(key))
    out.extend(encode_varint(len(metadata["row_schema_ids"])))
    for schema_id in metadata["row_schema_ids"]:
        out.extend(encode_varint(schema_id))
    rle = pack_rle_codes(metadata["newlines"])
    out.extend(encode_varint(len(rle)))
    out.extend(rle)
    out.append(metadata.get("separator_code", 0))
    return bytes(out)


def unpack_jsonl_binary_metadata(blob, offset):
    schema_count, offset = decode_varint(blob, offset)
    schemas = []
    for _ in range(schema_count):
        key_count, offset = decode_varint(blob, offset)
        schema = []
        for _ in range(key_count):
            key, offset = unpack_string(blob, offset)
            schema.append(key)
        schemas.append(schema)
    row_count, offset = decode_varint(blob, offset)
    row_schema_ids = []
    for _ in range(row_count):
        schema_id, offset = decode_varint(blob, offset)
        row_schema_ids.append(schema_id)
    rle_size, offset = decode_varint(blob, offset)
    rle_end = offset + rle_size
    if rle_end > len(blob):
        raise TosFormatError("truncated JSONL newline metadata")
    newlines = unpack_rle_codes(blob[offset:rle_end], row_count)
    offset = rle_end
    separator_code = 0
    if offset < len(blob):
        separator_code = blob[offset]
        offset += 1
    return {
        "name": "jsonl_binary_pack",
        "schema_orders": schemas,
        "row_schema_ids": row_schema_ids,
        "newlines": newlines,
        "separator_code": separator_code,
    }, offset


def apply_json_key_order_normalization(data):
    """Canonicalize JSON-object key order and store compact original schemas."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data, {"name": "json_key_order", "applied": False}

    lines = text.splitlines(keepends=True)
    if len(lines) < 2:
        return data, {"name": "json_key_order", "applied": False}

    output_lines = []
    schema_map = {}
    schema_orders = []
    row_schema_ids = []
    newline_codes = []
    for line in lines:
        body = line.rstrip("\r\n")
        ending = line[len(body):]
        try:
            obj = json.loads(body)
        except json.JSONDecodeError:
            return data, {"name": "json_key_order", "applied": False}
        if not isinstance(obj, dict) or not obj:
            return data, {"name": "json_key_order", "applied": False}
        original_order = tuple(obj.keys())
        exact = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
        if exact != body:
            return data, {"name": "json_key_order", "applied": False}
        if original_order not in schema_map:
            schema_map[original_order] = len(schema_orders)
            schema_orders.append(list(original_order))
        row_schema_ids.append(schema_map[original_order])
        newline_codes.append(newline_code(ending))
        ordered = {key: obj[key] for key in sorted(obj)}
        output_lines.append(json.dumps(ordered, separators=(",", ":"), ensure_ascii=False) + ending)

    transformed = "".join(output_lines).encode("utf-8")
    if transformed == data:
        return data, {"name": "json_key_order", "applied": False}
    return transformed, {
        "name": "json_key_order",
        "applied": True,
        "schema_orders": schema_orders,
        "row_schema_ids": row_schema_ids,
        "newlines": newline_codes,
    }


def remove_json_key_order_normalization(data, metadata):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TosFormatError("invalid UTF-8 in JSON transform") from exc
    lines = text.splitlines(keepends=True)
    if len(lines) != len(metadata["row_schema_ids"]):
        raise TosFormatError("JSON row count mismatch")
    output = []
    for index, line in enumerate(lines):
        body = line.rstrip("\r\n")
        obj = json.loads(body)
        schema = metadata["schema_orders"][metadata["row_schema_ids"][index]]
        restored = {key: obj[key] for key in schema}
        output.append(json.dumps(restored, separators=(",", ":"), ensure_ascii=False))
        output.append(newline_from_code(metadata["newlines"][index]))
    return "".join(output).encode("utf-8")


def pack_string(value):
    raw = value.encode("utf-8")
    return encode_varint(len(raw)) + raw


def unpack_string(data, offset):
    size, offset = decode_varint(data, offset)
    end = offset + size
    if end > len(data):
        raise TosFormatError("truncated string")
    return data[offset:end].decode("utf-8"), end


def pack_transform_metadata(metadata):
    name = metadata.get("name")
    out = bytearray()
    if name == "json_key_order":
        out.append(TRANSFORM_JSON_KEY_ORDER)
        out.extend(encode_varint(len(metadata["schema_orders"])))
        for schema in metadata["schema_orders"]:
            out.extend(encode_varint(len(schema)))
            for key in schema:
                out.extend(pack_string(key))
        out.extend(encode_varint(len(metadata["row_schema_ids"])))
        for schema_id in metadata["row_schema_ids"]:
            out.extend(encode_varint(schema_id))
        rle = pack_rle_codes(metadata["newlines"])
        out.extend(encode_varint(len(rle)))
        out.extend(rle)
    elif name == "csv_componentization":
        out.append(TRANSFORM_CSV_COMPONENTS)
        out.extend(encode_varint(metadata["field_count"]))
        out.extend(encode_varint(metadata["row_count"]))
        out.append(metadata.get("delimiter", ord(",")))
        rle = pack_rle_codes(metadata["newlines"])
        out.extend(encode_varint(len(rle)))
        out.extend(rle)
    elif name == "byte_shuffle":
        out.append(TRANSFORM_BYTE_SHUFFLE)
        out.extend(encode_varint(metadata["width"]))
        out.extend(encode_varint(metadata.get("tail_size", 0)))
    elif name == "float_xor":
        out.append(TRANSFORM_FLOAT_XOR)
        out.extend(encode_varint(metadata["width"]))
        out.extend(encode_varint(metadata["record_count"]))
        out.extend(encode_varint(metadata.get("tail_size", 0)))
    elif name == "tokenization_filter":
        out.append(TRANSFORM_TOKENIZATION_FILTER)
        out.extend(encode_varint(len(metadata["tokens"])))
        for token in metadata["tokens"]:
            out.extend(encode_varint(len(token)))
            out.extend(token)
    elif name == "jsonl_binary_pack":
        out.append(TRANSFORM_JSONL_BINARY_PACK)
        out.extend(pack_jsonl_binary_metadata(metadata))
    else:
        raise TosFormatError(f"cannot pack transform metadata: {name}")
    return bytes(out)


def unpack_transform_metadata(blob, offset):
    kind = blob[offset]
    offset += 1
    if kind == TRANSFORM_JSON_KEY_ORDER:
        schema_count, offset = decode_varint(blob, offset)
        schemas = []
        for _ in range(schema_count):
            key_count, offset = decode_varint(blob, offset)
            schema = []
            for _ in range(key_count):
                key, offset = unpack_string(blob, offset)
                schema.append(key)
            schemas.append(schema)
        row_count, offset = decode_varint(blob, offset)
        row_schema_ids = []
        for _ in range(row_count):
            schema_id, offset = decode_varint(blob, offset)
            row_schema_ids.append(schema_id)
        rle_size, offset = decode_varint(blob, offset)
        rle_end = offset + rle_size
        newlines = unpack_rle_codes(blob[offset:rle_end], row_count)
        return {
            "name": "json_key_order",
            "schema_orders": schemas,
            "row_schema_ids": row_schema_ids,
            "newlines": newlines,
        }, rle_end
    if kind == TRANSFORM_CSV_COMPONENTS:
        field_count, offset = decode_varint(blob, offset)
        row_count, offset = decode_varint(blob, offset)
        delimiter = blob[offset]
        offset += 1
        rle_size, offset = decode_varint(blob, offset)
        rle_end = offset + rle_size
        newlines = unpack_rle_codes(blob[offset:rle_end], row_count)
        return {
            "name": "csv_componentization",
            "field_count": field_count,
            "row_count": row_count,
            "delimiter": delimiter,
            "newlines": newlines,
        }, rle_end
    if kind == TRANSFORM_BYTE_SHUFFLE:
        width, offset = decode_varint(blob, offset)
        tail_size, offset = decode_varint(blob, offset)
        return {
            "name": "byte_shuffle",
            "width": width,
            "tail_size": tail_size,
        }, offset
    if kind == TRANSFORM_FLOAT_XOR:
        width, offset = decode_varint(blob, offset)
        record_count, offset = decode_varint(blob, offset)
        tail_size, offset = decode_varint(blob, offset)
        return {
            "name": "float_xor",
            "width": width,
            "record_count": record_count,
            "tail_size": tail_size,
        }, offset
    if kind == TRANSFORM_TOKENIZATION_FILTER:
        token_count, offset = decode_varint(blob, offset)
        tokens = []
        for _ in range(token_count):
            token_size, offset = decode_varint(blob, offset)
            token_end = offset + token_size
            if token_end > len(blob):
                raise TosFormatError("truncated tokenization dictionary")
            tokens.append(blob[offset:token_end])
            offset = token_end
        return {
            "name": "tokenization_filter",
            "tokens": tokens,
        }, offset
    if kind == TRANSFORM_JSONL_BINARY_PACK:
        return unpack_jsonl_binary_metadata(blob, offset)
    raise TosFormatError(f"unknown transform metadata type: {kind}")


def transform_metadata_bytes(transforms):
    out = bytearray()
    out.extend(encode_varint(len(transforms)))
    for transform in transforms:
        blob = pack_transform_metadata(transform)
        out.extend(encode_varint(len(blob)))
        out.extend(blob)
    return bytes(out)


def reverse_preprocessing_transforms(data, transforms, global_dictionary=None):
    """Reverse adaptive preprocessing transforms in last-applied-first order."""
    for transform in reversed(transforms or []):
        name = transform.get("name")
        if name == "json_key_order":
            data = remove_json_key_order_normalization(data, transform)
        elif name == "csv_componentization":
            data = remove_csv_componentization(data, transform)
        elif name == "byte_shuffle":
            data = remove_byte_shuffle(data, transform)
        elif name == "float_xor":
            data = remove_float_xor(data, transform)
        elif name == "tokenization_filter":
            data = remove_tokenization_filter(data, transform)
        elif name == "jsonl_binary_pack":
            data = remove_jsonl_binary_pack(data, transform)
        else:
            raise TosFormatError(f"unknown preprocessing transform: {name}")
    return data


def stream_compress_lzma(input_stream, output_stream, chunk_size=CHUNK_SIZE, filters=None):
    """
    Stream-based LZMA compression: compress in chunks, track total size.
    Avoids loading entire file into memory.
    """
    if filters is None:
        filters = LZMA_FILTERS
    
    compressor = lzma.LZMACompressor(format=lzma.FORMAT_RAW, filters=filters)
    total_compressed = 0
    total_uncompressed = 0
    
    while True:
        chunk = input_stream.read(chunk_size)
        if not chunk:
            break
        
        total_uncompressed += len(chunk)
        compressed_chunk = compressor.compress(chunk)
        if compressed_chunk:
            output_stream.write(compressed_chunk)
            total_compressed += len(compressed_chunk)
    
    # Flush remaining data
    final_chunk = compressor.flush()
    if final_chunk:
        output_stream.write(final_chunk)
        total_compressed += len(final_chunk)
    
    return total_uncompressed, total_compressed


def stream_decompress_lzma(input_stream, output_stream, chunk_size=CHUNK_SIZE, filters=None):
    """Stream-based LZMA decompression."""
    if filters is None:
        filters = LZMA_FILTERS
    
    decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
    
    while True:
        chunk = input_stream.read(chunk_size)
        if not chunk:
            break
        decompressed = decompressor.decompress(chunk)
        if decompressed:
            output_stream.write(decompressed)


def load_zstd_dictionary(config=None):
    """Future hook for static zstd dictionaries once archive IDs are persisted."""
    config = {**DEFAULT_CONFIG, **(config or {})}
    _dictionary_path = config.get("zstd_static_dictionary")
    return None


def compress_file_zstd(input_path, output_path, config=None):
    if zstd is None:
        raise RuntimeError("zstandard package is not installed")
    config = {**DEFAULT_CONFIG, **(config or {})}
    zdict = load_zstd_dictionary(config)
    compressor = zstd.ZstdCompressor(
        level=int(config.get("zstd_level", 22)),
        dict_data=zdict,
    )
    uncompressed = 0
    with open(input_path, "rb") as input_stream, open(output_path, "wb") as output_stream:
        with compressor.stream_writer(output_stream, closefd=False) as writer:
            while True:
                chunk = input_stream.read(CHUNK_SIZE)
                if not chunk:
                    break
                uncompressed += len(chunk)
                writer.write(chunk)
    return uncompressed, Path(output_path).stat().st_size, {
        "enabled": True,
        "level": int(config.get("zstd_level", 22)),
        "dictionary": bool(zdict),
        "static_dictionary_configured": bool(config.get("zstd_static_dictionary")),
    }


def stream_decompress_zstd(input_stream, output_stream, chunk_size=CHUNK_SIZE, config=None):
    if zstd is None:
        raise TosFormatError("zstandard package is required to extract zstd payloads")
    zdict = load_zstd_dictionary(config)
    decompressor = zstd.ZstdDecompressor(dict_data=zdict)
    with decompressor.stream_reader(input_stream) as reader:
        while True:
            chunk = reader.read(chunk_size)
            if not chunk:
                break
            output_stream.write(chunk)


def safe_member_name(path):
    parts = []
    for part in Path(path).parts:
        if part in ("", ".", ".."):
            continue
        cleaned = part.replace("\\", "_").replace("/", "_")
        if cleaned:
            parts.append(cleaned)
    return "/".join(parts) or "payload.bin"


def normalize_input_item(item):
    if isinstance(item, (tuple, list)) and len(item) == 2:
        return Path(item[0]), safe_member_name(item[1])
    path = Path(item)
    return path, safe_member_name(path.name)


def safe_output_path(output_dir, member_name):
    target = (output_dir / Path(member_name)).resolve()
    root = output_dir.resolve()
    if target != root and root not in target.parents:
        raise TosFormatError(f"unsafe archive member path: {member_name}")
    return target


def build_transform_candidate(name, data):
    """Apply one preprocessing candidate and return candidate bytes plus metadata."""
    if name == "bcj_x86":
        candidate, patched = transform_bcj_x86(data, inverse=False)
        return candidate, {"name": "bcj_x86", "applied": patched > 0, "patched": patched}
    if name == "delta":
        candidate, stride = apply_delta_filter(data, stride=4)
        return candidate, {"name": "delta", "applied": candidate != data, "stride": stride}
    if name == "byte_shuffle":
        return apply_byte_shuffle(data)
    if name == "float_xor":
        return apply_float_xor(data)
    if name == "jsonl_binary_pack":
        return apply_jsonl_binary_pack(data)
    if name == "json_key_order":
        return apply_json_key_order_normalization(data)
    if name == "csv_componentization":
        return apply_csv_componentization(data)
    if name == "tokenization_filter":
        return apply_tokenization_filter(data)
    return data, {"name": name, "applied": False}


def candidate_metadata_bytes(metadata):
    if metadata.get("name") in {"bcj_x86", "delta"}:
        return b""
    return pack_transform_metadata(metadata)


def build_solid_stream_adaptive(
    files,
    work_dir=None,
    solid_path=None,
    general_mode=False,
    config=None,
):
    """Build the measured solid stream for the TOS3 pipeline."""
    manifest = []
    visual = {"before_hex": "", "after_hex": "", "patched": 0}
    offset = 0
    solid_hash = hashlib.sha256()
    entropy_sample = bytearray()
    config = {**DEFAULT_CONFIG, **(config or {})}
    rule_engine = RuleEngine(config)
    file_records = []

    for item in files:
        source, member_name = normalize_input_item(item)
        original = source.read_bytes()
        analysis = analyze_file(member_name, original, rule_engine)
        file_records.append({"source": source, "member_name": member_name, "data": original, "analysis": analysis})

    file_records = reorder_file_records(file_records, config)

    if solid_path is None:
        solid_file = tempfile.NamedTemporaryFile(prefix="tos_solid_", delete=False)
        solid_path = Path(solid_file.name)
        close_solid = True
    else:
        solid_file = open(solid_path, "wb")
        close_solid = True

    try:
        for record in file_records:
            member_name = record["member_name"]
            original = record["data"]
            analysis = record["analysis"]
            processed = original
            bcj_applied = False
            delta_applied = False
            delta_stride = 0
            patched = 0
            filter_type = 0
            transforms = []
            transform_report = []

            if not general_mode:
                selected = analysis.suggested_transforms

                filter_type = detect_file_type(original)

                for transform_name in selected:
                    if transform_name in {"skip", "direct_lzma2", "lzma_param_search", "xml_normalization"}:
                        continue
                    if transform_name == "bcj_x86" and filter_type != FILTER_BCJ_X86:
                        continue
                    before = processed
                    candidate, metadata = build_transform_candidate(transform_name, processed)
                    if not metadata.get("applied") or candidate == processed:
                        continue
                    report = benchmark_transform_trial(
                        transform_name,
                        processed,
                        candidate,
                        candidate_metadata_bytes(metadata),
                        config=config,
                    )
                    if not report["accepted"]:
                        continue

                    processed = candidate
                    transform_report.append(report)
                    if transform_name == "bcj_x86":
                        patched = metadata["patched"]
                        bcj_applied = True
                        report["patched"] = patched
                        if not visual["before_hex"]:
                            visual = {
                                "before_hex": hex_preview(before),
                                "after_hex": hex_preview(processed),
                                "patched": patched,
                            }
                    elif transform_name == "delta":
                        delta_stride = metadata["stride"]
                        delta_applied = True
                    else:
                        transforms.append(metadata)

            solid_file.write(processed)
            solid_hash.update(processed)
            remaining_sample = ENTROPY_SAMPLE_LIMIT - len(entropy_sample)
            if remaining_sample > 0:
                entropy_sample.extend(processed[:remaining_sample])

            entry = {
                "name": member_name,
                "offset": offset,
                "original_size": len(original),
                "stored_size": len(processed),
                "sha256": hashlib.sha256(original).hexdigest(),
                "bcj": bcj_applied,
                "bcj_patched": patched,
                "filter_type": filter_type if bcj_applied else 0,
                "delta": delta_applied,
                "delta_stride": delta_stride,
                "analysis": {
                    "file_type": analysis.file_type,
                    "entropy": round(analysis.entropy, 4),
                    "conditional_entropy": round(compression_entropy(original[:ENTROPY_SAMPLE_LIMIT], config), 4),
                    "entropy_gate_dense": analysis.entropy_gate_dense,
                    "entropy_gate_sample": round(analysis.entropy_gate_sample, 4),
                    "is_text": analysis.is_text,
                    "utf8_valid": analysis.utf8_valid,
                    "magic_number": analysis.magic_number.hex(),
                    "is_already_compressed": analysis.is_already_compressed,
                    "suggested_transforms": analysis.suggested_transforms,
                    "features": rule_engine.feature_vector(analysis),
                },
                "input_order": record.get("input_order", len(manifest)),
                "solid_order": record.get("solid_order", len(manifest)),
                "simhash64": f"{record.get('simhash64', 0):016x}",
                "transforms": transforms,
                "transform_report": transform_report,
            }
            manifest.append(entry)
            offset += len(processed)
    finally:
        if close_solid:
            solid_file.close()

    return {
        "solid_path": solid_path,
        "solid_size": offset,
        "sha256_solid": solid_hash.hexdigest(),
        "entropy_sample": bytes(entropy_sample),
        "manifest": manifest,
        "global_dictionary": [],
        "dictionary_blob_size": 0,
        "entropy_gate_triggered": all(record["analysis"].entropy_gate_dense for record in file_records) if file_records else False,
        "visual": visual,
        "lzma_filters": LZMA_FILTERS,
        "lzma_param_search": {},
    }


def build_solid_stream_streaming(files, solid_path=None, config=None):
    """Build a plain solid stream without loading the whole dataset in memory."""
    manifest = []
    visual = {"before_hex": "", "after_hex": "", "patched": 0}
    offset = 0
    solid_hash = hashlib.sha256()
    entropy_sample = bytearray()
    config = {**DEFAULT_CONFIG, **(config or {})}

    if solid_path is None:
        solid_file = tempfile.NamedTemporaryFile(prefix="tos_solid_", delete=False)
        solid_path = Path(solid_file.name)
        close_solid = True
    else:
        solid_file = open(solid_path, "wb")
        close_solid = True

    try:
        for index, item in enumerate(files):
            source, member_name = normalize_input_item(item)
            source_hash = hashlib.sha256()
            stored_size = 0
            sample = bytearray()

            with open(source, "rb") as input_stream:
                while True:
                    chunk = input_stream.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    solid_file.write(chunk)
                    solid_hash.update(chunk)
                    source_hash.update(chunk)
                    stored_size += len(chunk)
                    if len(sample) < ENTROPY_SAMPLE_LIMIT:
                        sample.extend(chunk[: ENTROPY_SAMPLE_LIMIT - len(sample)])
                    remaining_entropy = ENTROPY_SAMPLE_LIMIT - len(entropy_sample)
                    if remaining_entropy > 0:
                        entropy_sample.extend(chunk[:remaining_entropy])

            entropy_value = shannon_entropy(sample) if sample else 0.0
            entry = {
                "name": member_name,
                "offset": offset,
                "original_size": stored_size,
                "stored_size": stored_size,
                "sha256": source_hash.hexdigest(),
                "bcj": False,
                "bcj_patched": 0,
                "filter_type": 0,
                "delta": False,
                "delta_stride": 0,
                "analysis": {
                    "file_type": "streaming",
                    "entropy": round(entropy_value, 4),
                    "conditional_entropy": round(compression_entropy(bytes(sample), config), 4) if sample else 0.0,
                    "entropy_gate_dense": False,
                    "entropy_gate_sample": round(entropy_value, 4),
                    "is_text": False,
                    "utf8_valid": False,
                    "magic_number": "",
                    "is_already_compressed": False,
                    "suggested_transforms": ["streaming_solid"],
                    "features": {},
                },
                "input_order": index,
                "solid_order": index,
                "simhash64": "0" * 16,
                "transforms": [],
                "transform_report": [],
            }
            manifest.append(entry)
            offset += stored_size
    finally:
        if close_solid:
            solid_file.close()

    return {
        "solid_path": solid_path,
        "solid_size": offset,
        "sha256_solid": solid_hash.hexdigest(),
        "entropy_sample": bytes(entropy_sample),
        "manifest": manifest,
        "global_dictionary": [],
        "dictionary_blob_size": 0,
        "entropy_gate_triggered": False,
        "visual": visual,
        "lzma_filters": LZMA_FILTERS,
        "lzma_param_search": {},
    }


def copy_stream(input_path, output_stream, chunk_size=CHUNK_SIZE):
    total = 0
    with open(input_path, "rb") as input_stream:
        while True:
            chunk = input_stream.read(chunk_size)
            if not chunk:
                break
            output_stream.write(chunk)
            total += len(chunk)
    return total


class LimitedReader:
    def __init__(self, stream, limit):
        self.stream = stream
        self.remaining = limit

    def read(self, size=-1):
        if self.remaining <= 0:
            return b""
        if size is None or size < 0 or size > self.remaining:
            size = self.remaining
        data = self.stream.read(size)
        self.remaining -= len(data)
        return data


def read_trial_sample_from_path(input_path, limit, count=1):
    input_path = Path(input_path)
    size = input_path.stat().st_size
    pieces = []
    with open(input_path, "rb") as handle:
        for start, end in sample_ranges_for_trial(size, limit, count):
            handle.seek(start)
            pieces.append(handle.read(end - start))
    return b"".join(pieces)


def compress_file_lzma(input_path, output_path, filters=None, config=None):
    config = {**DEFAULT_CONFIG, **(config or {})}
    search_report = None
    if filters is None:
        sample = read_trial_sample_from_path(
            input_path,
            config.get("trial_sample_size", TRIAL_SAMPLE_SIZE),
            config.get("trial_sample_count", 1),
        )
        search_config = dict(config)
        search_config["lzma_param_search_input_size"] = Path(input_path).stat().st_size
        filters, search_report = search_lzma_filters_for_data(sample, search_config)
    else:
        search_report = {
            "enabled": False,
            "params": lzma_params_from_filters(filters),
        }

    with open(input_path, "rb") as input_stream, open(output_path, "wb") as output_stream:
        uncompressed, compressed = stream_compress_lzma(input_stream, output_stream, filters=filters)
    return uncompressed, compressed, filters, search_report


def should_use_zstd(input_path, config=None):
    config = {**DEFAULT_CONFIG, **(config or {})}
    if zstd is None:
        return False
    return Path(input_path).stat().st_size < int(config.get("small_file_zstd_threshold", 1024 * 1024))


def compress_file_backend(input_path, output_path, config=None, force_plain=False):
    config = {**DEFAULT_CONFIG, **(config or {})}
    if should_use_zstd(input_path, config):
        try:
            if config.get("small_file_backend_mode", "best") != "best":
                uncompressed, compressed, zstd_report = compress_file_zstd(input_path, output_path, config)
                return uncompressed, compressed, {
                    "backend": BACKEND_ZSTD,
                    "backend_name": "zstd",
                    "lzma_filters": LZMA_FILTERS,
                    "lzma_search": {"enabled": False, "reason": "zstd_small_file_backend"},
                    "zstd": zstd_report,
                }

            output_path = Path(output_path)
            zstd_path = output_path.with_suffix(output_path.suffix + ".zst.tmp")
            lzma_path = output_path.with_suffix(output_path.suffix + ".lzma.tmp")
            uncompressed, zstd_size, zstd_report = compress_file_zstd(input_path, zstd_path, config)
            lzma_config = dict(config)
            if force_plain or not config.get("zstd_compare_lzma_search", False):
                lzma_config["enable_lzma_param_search"] = False
            _raw, lzma_size, lzma_filters, lzma_search = compress_file_lzma(
                input_path,
                lzma_path,
                config=lzma_config,
            )
            if zstd_size < lzma_size:
                shutil.move(str(zstd_path), output_path)
                if lzma_path.exists():
                    lzma_path.unlink()
                zstd_report["compared_lzma_size"] = lzma_size
                return uncompressed, zstd_size, {
                    "backend": BACKEND_ZSTD,
                    "backend_name": "zstd",
                    "lzma_filters": LZMA_FILTERS,
                    "lzma_search": {"enabled": False, "reason": "zstd_won_small_file_compare"},
                    "zstd": zstd_report,
                }
            shutil.move(str(lzma_path), output_path)
            if zstd_path.exists():
                zstd_path.unlink()
            zstd_report["compared_lzma_size"] = lzma_size
            zstd_report["selected"] = False
            return uncompressed, lzma_size, {
                "backend": BACKEND_LZMA2,
                "backend_name": "lzma2",
                "lzma_filters": lzma_filters,
                "lzma_search": lzma_search,
                "zstd": zstd_report,
            }
        except RuntimeError:
            pass

    lzma_config = dict(config)
    if force_plain:
        lzma_config["enable_lzma_param_search"] = False
    uncompressed, compressed, filters, search_report = compress_file_lzma(
        input_path,
        output_path,
        config=lzma_config,
    )
    return uncompressed, compressed, {
        "backend": BACKEND_LZMA2,
        "backend_name": "lzma2",
        "lzma_filters": filters,
        "lzma_search": search_report,
        "zstd": {"enabled": False, "reason": "zstandard_unavailable" if zstd is None else "not_small_file"},
    }


def pack_archive_metadata(solid_info, payload_size, fallback_used=False, archive_version=ARCHIVE_VERSION):
    """Pack only extraction-critical metadata in a compact binary manifest."""
    out = bytearray()
    out.extend(encode_varint(len(solid_info["manifest"])))
    out.extend(encode_varint(solid_info["solid_size"]))
    out.extend(bytes.fromhex(solid_info["sha256_solid"]))
    out.extend(encode_varint(payload_size))
    out.append(1 if fallback_used else 0)
    if archive_version >= 5:
        out.append(solid_info.get("payload_backend", BACKEND_LZMA2))
    if archive_version >= 4:
        lzma_params = lzma_params_from_filters(solid_info.get("lzma_filters", LZMA_FILTERS))
        out.extend(encode_varint(lzma_params["dict_size"]))
        out.append(lzma_params["lc"])
        out.append(lzma_params["lp"])
        out.append(lzma_params["pb"])
    for entry in solid_info["manifest"]:
        out.extend(pack_string(entry["name"]))
        out.extend(encode_varint(entry["offset"]))
        out.extend(encode_varint(entry["original_size"]))
        out.extend(encode_varint(entry["stored_size"]))
        if archive_version < 4:
            out.extend(struct.pack("<I", entry.get("crc32", 0)))
        out.extend(bytes.fromhex(entry["sha256"]))
        flags = 0
        if entry["bcj"]:
            flags |= 1
        if entry["delta"]:
            flags |= 2
        if entry["transforms"]:
            flags |= 4
        out.append(flags)
        out.extend(encode_varint(entry["filter_type"]))
        out.extend(encode_varint(entry["delta_stride"]))
        transform_blob = transform_metadata_bytes(entry["transforms"])
        out.extend(encode_varint(len(transform_blob)))
        out.extend(transform_blob)
        out.extend(encode_varint(entry.get("input_order", 0)))
        out.extend(encode_varint(entry.get("solid_order", 0)))
    raw = bytes(out)
    if archive_version >= 5:
        compressed = zlib.compress(raw, level=9)
        packed = bytearray([MANIFEST_COMPRESSION_ZLIB])
        packed.extend(encode_varint(len(raw)))
        packed.extend(compressed)
        return bytes(packed)
    return raw


def unpack_archive_metadata(blob, version=ARCHIVE_VERSION):
    if version >= 5:
        if not blob:
            raise TosFormatError("truncated compressed metadata")
        method = blob[0]
        raw_size, offset = decode_varint(blob, 1)
        if method != MANIFEST_COMPRESSION_ZLIB:
            raise TosFormatError(f"unsupported metadata compression: {method}")
        try:
            blob = zlib.decompress(blob[offset:])
        except zlib.error as exc:
            raise TosFormatError("invalid compressed metadata") from exc
        if len(blob) != raw_size:
            raise TosFormatError("metadata size mismatch")
    offset = 0
    file_count, offset = decode_varint(blob, offset)
    solid_size, offset = decode_varint(blob, offset)
    solid_hash = blob[offset:offset + 32].hex()
    if len(solid_hash) != 64:
        raise TosFormatError("truncated solid checksum")
    offset += 32
    payload_size, offset = decode_varint(blob, offset)
    fallback_used = bool(blob[offset])
    offset += 1
    payload_backend = BACKEND_LZMA2
    if version >= 5:
        if offset >= len(blob):
            raise TosFormatError("truncated payload backend metadata")
        payload_backend = blob[offset]
        offset += 1
    lzma_filters = LZMA_FILTERS
    if version >= 4:
        dict_size, offset = decode_varint(blob, offset)
        if offset + 3 > len(blob):
            raise TosFormatError("truncated LZMA metadata")
        lc = blob[offset]
        lp = blob[offset + 1]
        pb = blob[offset + 2]
        offset += 3
        lzma_filters = lzma_filters_from_params({
            "dict_size": dict_size,
            "lc": lc,
            "lp": lp,
            "pb": pb,
        })
    files = []
    for _ in range(file_count):
        name, offset = unpack_string(blob, offset)
        member_offset, offset = decode_varint(blob, offset)
        original_size, offset = decode_varint(blob, offset)
        stored_size, offset = decode_varint(blob, offset)
        crc32 = None
        if version < 4:
            if offset + 4 > len(blob):
                raise TosFormatError("truncated file CRC metadata")
            crc32 = struct.unpack("<I", blob[offset:offset + 4])[0]
            offset += 4
        if offset + 32 > len(blob):
            raise TosFormatError("truncated file checksum metadata")
        sha256 = blob[offset:offset + 32].hex()
        offset += 32
        flags = blob[offset]
        offset += 1
        filter_type, offset = decode_varint(blob, offset)
        delta_stride, offset = decode_varint(blob, offset)
        transform_size, offset = decode_varint(blob, offset)
        transform_end = offset + transform_size
        if transform_end > len(blob):
            raise TosFormatError("truncated transform metadata")
        transform_blob = blob[offset:transform_end]
        offset = transform_end
        transform_offset = 0
        transform_count, transform_offset = decode_varint(transform_blob, transform_offset)
        transforms = []
        for _ in range(transform_count):
            item_size, transform_offset = decode_varint(transform_blob, transform_offset)
            item_end = transform_offset + item_size
            transform, parsed = unpack_transform_metadata(transform_blob[transform_offset:item_end], 0)
            if parsed != item_size:
                raise TosFormatError("transform metadata size mismatch")
            transforms.append(transform)
            transform_offset = item_end
        input_order, offset = decode_varint(blob, offset)
        solid_order, offset = decode_varint(blob, offset)
        files.append({
            "name": name,
            "offset": member_offset,
            "original_size": original_size,
            "stored_size": stored_size,
            "crc32": crc32,
            "sha256": sha256,
            "bcj": bool(flags & 1),
            "delta": bool(flags & 2),
            "filter_type": filter_type,
            "delta_stride": delta_stride,
            "transforms": transforms,
            "input_order": input_order,
            "solid_order": solid_order,
        })
    if offset != len(blob):
        raise TosFormatError("extra bytes after archive metadata")
    return {
        "version": version,
        "files": files,
        "solid_size": solid_size,
        "compressed_payload_size": payload_size,
        "sha256_solid": solid_hash,
        "plain_fallback": fallback_used,
        "payload_backend": payload_backend,
        "payload_backend_name": "zstd" if payload_backend == BACKEND_ZSTD else "lzma2",
        "lzma_filters": lzma_filters,
        "lzma_params": lzma_params_from_filters(lzma_filters),
    }


def public_manifest(solid_info, payload_size, fallback_used=False):
    """Return a UI/benchmark-friendly manifest without using it as archive metadata."""
    return {
        "version": ARCHIVE_VERSION,
        "algorithm": (
            "TOS3: plain solid LZMA2 fallback"
            if fallback_used
            else "TOS3: measured adaptive routing + binary metadata + solid LZMA2"
        ),
        "files": [
            {
                "name": entry["name"],
                "offset": entry["offset"],
                "original_size": entry["original_size"],
                "stored_size": entry["stored_size"],
                "sha256": entry["sha256"],
                "bcj": entry["bcj"],
                "bcj_patched": entry["bcj_patched"],
                "filter_type": entry["filter_type"],
                "delta": entry["delta"],
                "delta_stride": entry["delta_stride"],
                "input_order": entry.get("input_order", 0),
                "solid_order": entry.get("solid_order", 0),
                "simhash64": entry.get("simhash64", "0" * 16),
                "transforms": [transform["name"] for transform in entry["transforms"]],
                "analysis": entry.get("analysis", {}),
                "transform_report": entry.get("transform_report", []),
            }
            for entry in solid_info["manifest"]
        ],
        "solid_size": solid_info["solid_size"],
        "compressed_payload_size": payload_size,
        "sha256_solid": solid_info["sha256_solid"],
        "plain_fallback": fallback_used,
        "metadata_format": "zlib-compressed binary" if ARCHIVE_VERSION >= 5 else "binary",
        "entropy_coding": solid_info.get("payload_backend_name", "LZMA2 range coder"),
        "payload_backend": solid_info.get("payload_backend_name", "lzma2"),
        "lzma_params": lzma_params_from_filters(solid_info.get("lzma_filters", LZMA_FILTERS)),
        "lzma_param_search": solid_info.get("lzma_param_search", {}),
        "zstd": solid_info.get("zstd", {"enabled": False}),
    }


def write_tos_archive_streaming(input_paths, output_path, general_mode=False, config_path=None, config=None):
    """
    Write TOS archive with streaming compression.
    - Detects file types
    - Builds solid stream
    - Streams compression to avoid high memory usage
    - Supports general-purpose mode for broader compatibility
    - Single-file optimized format to reduce overhead on small archives
    """
    start = time.perf_counter()
    cpu_start = time.process_time()
    tracemalloc.start()
    output_path = Path(output_path)
    input_items = [normalize_input_item(path) for path in input_paths]
    is_single_file = len(input_items) == 1
    active_config = load_config(config_path) if config_path else {**DEFAULT_CONFIG, **(config or {})}
    dense_fast_path = False
    streaming_solid_mode = bool(active_config.get("streaming_solid_mode", False))
    if active_config.get("entropy_gate_enabled", True) and not streaming_solid_mode:
        gate_results = []
        for path, _member_name in input_items:
            with open(path, "rb") as handle:
                gate_results.append(entropy_gate_is_dense(handle.read(ENTROPY_GATE_SAMPLE_SIZE), active_config)[0])
        dense_fast_path = bool(gate_results) and all(gate_results)

    with tempfile.TemporaryDirectory(prefix="tos_work_") as temp_dir:
        temp_dir = Path(temp_dir)
        solid_path = temp_dir / "solid.bin"
        compressed_path = temp_dir / "payload.bin"

        if streaming_solid_mode:
            solid = build_solid_stream_streaming(
                input_items,
                solid_path=solid_path,
                config=active_config,
            )
        else:
            solid = build_solid_stream_adaptive(
                input_items,
                work_dir=temp_dir,
                solid_path=solid_path,
                general_mode=general_mode or dense_fast_path,
                config=active_config,
            )
        _, compressed_size, backend_report = compress_file_backend(
            solid_path,
            compressed_path,
            config=active_config,
            force_plain=dense_fast_path,
        )
        solid["payload_backend"] = backend_report["backend"]
        solid["payload_backend_name"] = backend_report["backend_name"]
        solid["lzma_filters"] = backend_report["lzma_filters"]
        solid["lzma_param_search"] = backend_report["lzma_search"]
        solid["zstd"] = backend_report["zstd"]
        metadata_bytes = pack_archive_metadata(solid, compressed_size, fallback_used=False)
        metadata = public_manifest(solid, compressed_size, fallback_used=False)

        if not general_mode and not dense_fast_path and not streaming_solid_mode:
            plain_solid_path = temp_dir / "plain_solid.bin"
            plain_compressed_path = temp_dir / "plain_payload.bin"
            plain_solid = build_solid_stream_adaptive(
                input_items,
                work_dir=temp_dir,
                solid_path=plain_solid_path,
                general_mode=True,
                config=active_config,
            )
            _, plain_compressed_size, plain_backend_report = compress_file_backend(
                plain_solid_path,
                plain_compressed_path,
                config=active_config,
            )
            plain_solid["payload_backend"] = plain_backend_report["backend"]
            plain_solid["payload_backend_name"] = plain_backend_report["backend_name"]
            plain_solid["lzma_filters"] = plain_backend_report["lzma_filters"]
            plain_solid["lzma_param_search"] = plain_backend_report["lzma_search"]
            plain_solid["zstd"] = plain_backend_report["zstd"]
            plain_metadata_bytes = pack_archive_metadata(plain_solid, plain_compressed_size, fallback_used=True)
            plain_metadata = public_manifest(plain_solid, plain_compressed_size, fallback_used=True)
            adaptive_total = HEADER_STRUCT.size + len(metadata_bytes) + compressed_size
            plain_total = HEADER_STRUCT.size + len(plain_metadata_bytes) + plain_compressed_size
            if plain_total <= adaptive_total:
                solid = plain_solid
                compressed_path = plain_compressed_path
                compressed_size = plain_compressed_size
                metadata = plain_metadata
                metadata_bytes = plain_metadata_bytes

        filter_mask = 0
        for entry in solid["manifest"]:
            filter_mask |= entry["filter_type"]
            if entry["delta"]:
                filter_mask |= FILTER_DELTA
        
        magic = MAGIC_SLIM if is_single_file else MAGIC
        header = HEADER_STRUCT.pack(magic, ARCHIVE_VERSION, len(metadata_bytes), compressed_size, filter_mask)

        with open(output_path, "wb") as archive:
            archive.write(header)
            archive.write(metadata_bytes)
            copy_stream(compressed_path, archive)

    current_memory, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    cpu_ms = round((time.process_time() - cpu_start) * 1000, 2)

    original_size = sum(path.stat().st_size for path, _ in input_items)
    archive_size = output_path.stat().st_size
    reduction = 0.0 if original_size == 0 else (1.0 - archive_size / original_size) * 100.0

    return {
        "output_path": str(output_path),
        "original_size": original_size,
        "transformed_size": solid["solid_size"],
        "final_lzma_size": compressed_size,
        "payload_backend": solid.get("payload_backend_name", "lzma2"),
        "metadata_size": len(metadata_bytes),
        "archive_size": archive_size,
        "compression_ratio": round(archive_size / original_size, 6) if original_size else 0,
        "reduction_percent": round(reduction, 2),
        "time_ms": elapsed_ms,
        "cpu_time_ms": cpu_ms,
        "memory_usage": peak_memory,
        "manifest": metadata,
        "transform_reports": [entry.get("transform_report", []) for entry in solid["manifest"]],
        "global_dictionary_size": solid["dictionary_blob_size"],
        "visual": solid["visual"],
    }


def extract_tos_archive_reversible(archive_path, output_dir):
    """
    Extract TOS archive with full reversibility:
    - Removes delta preprocessing
    - Applies internal inverse x86 BCJ when used
    - Handles both full and single-file optimized formats
    """
    archive_path = Path(archive_path)
    output_dir = Path(output_dir)
    with open(archive_path, "rb") as archive:
        header_bytes = archive.read(HEADER_STRUCT.size)

    if len(header_bytes) < HEADER_STRUCT.size:
        raise TosFormatError("archive too small")

    magic, version, metadata_size, payload_size, filter_mask = HEADER_STRUCT.unpack(
        header_bytes
    )
    is_slim = magic == MAGIC_SLIM
    if magic not in (MAGIC, MAGIC_SLIM) or version not in (3, 4, ARCHIVE_VERSION):
        raise TosFormatError("unsupported TOS archive")

    with tempfile.TemporaryDirectory(prefix="tos_extract_") as temp_dir:
        temp_dir = Path(temp_dir)
        solid_path = temp_dir / "solid.bin"
        metadata = None

        with open(archive_path, "rb") as archive, open(solid_path, "wb") as solid_output:
            archive.seek(HEADER_STRUCT.size)
            metadata_bytes = archive.read(metadata_size)
            if len(metadata_bytes) != metadata_size:
                raise TosFormatError("truncated metadata")
            metadata = unpack_archive_metadata(metadata_bytes, version)
            payload_reader = LimitedReader(archive, payload_size)
            if metadata.get("payload_backend", BACKEND_LZMA2) == BACKEND_ZSTD:
                stream_decompress_zstd(payload_reader, solid_output)
            else:
                stream_decompress_lzma(
                    payload_reader,
                    solid_output,
                    filters=metadata.get("lzma_filters", LZMA_FILTERS),
                )

        output_dir.mkdir(parents=True, exist_ok=True)
        extracted = []

        solid_hash = hashlib.sha256()
        with open(solid_path, "rb") as solid_input:
            while True:
                chunk = solid_input.read(CHUNK_SIZE)
                if not chunk:
                    break
                solid_hash.update(chunk)

        if solid_hash.hexdigest() != metadata["sha256_solid"]:
            raise TosFormatError("solid stream checksum mismatch")

        with open(solid_path, "rb") as solid_input:
            for entry in metadata["files"]:
                solid_input.seek(entry["offset"])
                data = solid_input.read(entry["stored_size"])
                if len(data) != entry["stored_size"]:
                    raise TosFormatError(f"truncated member: {entry['name']}")

                data = reverse_preprocessing_transforms(data, entry.get("transforms", []))

                if entry.get("delta", False):
                    data = remove_delta_filter(data, stride=entry.get("delta_stride", 4))

                if entry.get("bcj", False):
                    if entry.get("filter_type") != FILTER_BCJ_X86:
                        raise TosFormatError(f"unsupported BCJ filter: {entry['filter_type']}")
                    data, _ = transform_bcj_x86(data, inverse=True)

                if entry.get("crc32") is not None and zlib.crc32(data) & 0xFFFFFFFF != entry["crc32"]:
                    raise TosFormatError(f"CRC mismatch: {entry['name']}")
                if hashlib.sha256(data).hexdigest() != entry["sha256"]:
                    raise TosFormatError(f"SHA-256 mismatch: {entry['name']}")

                target = safe_output_path(output_dir, entry["name"])
                if is_slim:
                    target = output_dir / secure_filename(Path(entry["name"]).name)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                extracted.append(str(target))

        return extracted


def copy_or_collect_inputs(input_path, temp_dir):
    input_path = Path(input_path)
    if input_path.is_file():
        return [(input_path, input_path.name)]

    copied = []
    seen = set()
    for path in sorted(input_path.rglob("*")):
        if path.is_file():
            relative = path.relative_to(input_path)
            target = Path(temp_dir) / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            archive_name = safe_member_name(relative)
            if archive_name in seen:
                raise TosFormatError(f"duplicate archive member: {archive_name}")
            seen.add(archive_name)
            shutil.copy2(path, target)
            copied.append((target, archive_name))
    return copied


def main():
    parser = argparse.ArgumentParser(description="TOS Enhanced compression (top-level)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    compress = subparsers.add_parser("compress")
    compress.add_argument("input")
    compress.add_argument("output")
    compress.add_argument(
        "--mode",
        choices=["best", "general"],
        default="best",
        help="Compression mode: best uses reversible x86 BCJ/delta; general uses plain LZMA2",
    )
    compress.add_argument(
        "--config",
        default=None,
        help="Optional JSON file that enables/disables adaptive preprocessing modules",
    )

    extract = subparsers.add_parser("extract")
    extract.add_argument("archive")
    extract.add_argument("output_dir")

    args = parser.parse_args()

    if args.command == "compress":
        with tempfile.TemporaryDirectory(prefix="tos_input_") as temp_dir:
            files = copy_or_collect_inputs(args.input, temp_dir)
            result = write_tos_archive_streaming(
                files,
                args.output,
                general_mode=args.mode == "general",
                config_path=args.config,
            )
        print(json.dumps(result, indent=2))
    elif args.command == "extract":
        files = extract_tos_archive_reversible(args.archive, args.output_dir)
        print(json.dumps({"extracted": files}, indent=2))


if __name__ == "__main__":
    main()
