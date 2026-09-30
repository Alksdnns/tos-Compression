"""
Enhanced TOS Flask App (Top-Level Production Grade)
- Uses streaming LZMA compression
- Adaptive preprocessing with internal reversible x86 BCJ
- Delta preprocessing for structured data
- Reversible extraction with internal x86 BCJ
"""

import shutil
import tempfile
import zipfile
from pathlib import Path

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    send_file,
)
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge

from tos_codec_enhanced import (
    format_bytes,
    write_tos_archive_streaming,
    extract_tos_archive_reversible,
)


BASE_DIR = Path(__file__).resolve().parent

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024 * 1024  # 16 GB upload limit for folders and large files
app.config["MAX_FORM_MEMORY_SIZE"] = 64 * 1024 * 1024
app.config["MAX_FORM_PARTS"] = 200000


BIG_DATASET_CONFIG = {
    "streaming_solid_mode": True,
    "small_file_zstd_threshold": 16 * 1024 * 1024 * 1024,
    "small_file_backend_mode": "zstd",
    "zstd_level": 12,
    "lzma_preset": 3,
    "lzma_dict_size": 16 * 1024 * 1024,
    "enable_lzma_param_search": False,
    "enable_file_reordering": False,
    "entropy_gate_enabled": False,
}


@app.errorhandler(RequestEntityTooLarge)
def handle_request_too_large(exc):
    limit_gb = app.config["MAX_CONTENT_LENGTH"] / (1024 ** 3)
    return jsonify({
        "error": (
            f"Upload rejected by Flask multipart limits. "
            f"Keep total upload below {limit_gb:.0f} GB and below "
            f"{app.config['MAX_FORM_PARTS']} files/form parts."
        )
    }), 413


@app.route("/")
def index():
    return render_template("index_enhanced.html")


def save_uploaded_files(files, temp_dir):
    saved_items = []
    for uploaded in files:
        if uploaded.filename == "":
            continue

        path = Path(uploaded.filename)
        safe_parts = [secure_filename(part) for part in path.parts if part not in ("", ".", "..")]
        if not safe_parts:
            safe_parts = ["payload.bin"]

        member_name = "/".join(safe_parts)
        target_path = Path(temp_dir).joinpath(*safe_parts)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        uploaded.save(target_path)
        saved_items.append((target_path, member_name))

    return saved_items


def cleanup_after_send(response, temp_dir):
    response.call_on_close(lambda: shutil.rmtree(temp_dir, ignore_errors=True))
    return response


@app.route("/process", methods=["POST"])
def process_file():
    action = request.form.get("action", "compress")
    uploaded_files = request.files.getlist("file")
    if not uploaded_files:
        return jsonify({"error": "No files were uploaded"}), 400

    print(f"[DEBUG] Action: {action}, Files uploaded: {len(uploaded_files)}")
    for f in uploaded_files:
        print(f"[DEBUG]   - {f.filename}")

    temp_dir = Path(tempfile.mkdtemp(prefix="tos_upload_"))

    try:
        if action == "extract":
            if len(uploaded_files) != 1:
                shutil.rmtree(temp_dir, ignore_errors=True)
                return jsonify({"error": "Please upload exactly one .tos archive to extract."}), 400

            uploaded = uploaded_files[0]
            if uploaded.filename == "":
                shutil.rmtree(temp_dir, ignore_errors=True)
                return jsonify({"error": "No archive file was uploaded"}), 400

            archive_path = temp_dir / secure_filename(uploaded.filename)
            uploaded.save(archive_path)
            print(f"[DEBUG] Extracting archive: {archive_path}")

            extract_dir = temp_dir / "extracted"
            extracted_files = extract_tos_archive_reversible(archive_path, extract_dir)
            print(f"[DEBUG] Extracted {len(extracted_files)} files")

            zip_path = temp_dir / f"{archive_path.stem}_extracted.zip"
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zipf:
                for extracted in extracted_files:
                    extracted_path = Path(extracted)
                    zipf.write(extracted_path, arcname=extracted_path.relative_to(extract_dir))

            response = send_file(
                zip_path,
                as_attachment=True,
                download_name=zip_path.name,
                mimetype="application/zip",
            )
            return cleanup_after_send(response, temp_dir)

        file_paths = save_uploaded_files(uploaded_files, temp_dir)
        if not file_paths:
            shutil.rmtree(temp_dir, ignore_errors=True)
            return jsonify({"error": "No valid files were uploaded"}), 400

        mode = request.form.get("mode", "best")
        print(f"[DEBUG] Compressing {len(file_paths)} file(s) in {mode} mode")
        output_path = temp_dir / "archive.tos"
        codec_config = BIG_DATASET_CONFIG if mode == "big" else None
        result = write_tos_archive_streaming(
            file_paths,
            output_path,
            general_mode=(mode in {"general", "big"}),
            config=codec_config,
        )

        manifest = result["manifest"]
        # Handle both full and single-file optimized formats
        ans_model = manifest.get("ans_model", {
            "entropy_bits_per_byte": 0.0,
            "ideal_ans_bytes": 0,
            "estimated_huffman_bytes": 0
        })

        response = send_file(
            output_path,
            as_attachment=True,
            download_name=output_path.name,
            mimetype="application/octet-stream",
        )
        response.headers["X-TOS-Original-Size"] = format_bytes(result["original_size"])
        response.headers["X-TOS-Compressed-Size"] = format_bytes(result["archive_size"])
        response.headers["X-TOS-Ratio"] = f"{result['reduction_percent']:.2f}%"
        response.headers["X-TOS-Time-Ms"] = str(result["time_ms"])
        response.headers["X-TOS-BCJ-Patched"] = str(result["visual"].get("patched", 0))
        response.headers["X-TOS-Entropy"] = str(ans_model.get("entropy_bits_per_byte", 0.0))
        response.headers["X-TOS-Algorithm"] = (
            "TOS3: big-dataset streaming solid + zstd"
            if mode == "big"
            else (
                "TOS3: general-purpose streamed LZMA2"
                if mode == "general"
                else "TOS3: measured adaptive routing + streamed LZMA2"
            )
        )
        response.headers["X-TOS-Before-Hex"] = result["visual"].get("before_hex", "")
        response.headers["X-TOS-After-Hex"] = result["visual"].get("after_hex", "")
        return cleanup_after_send(response, temp_dir)

    except TimeoutError:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return jsonify({"error": "Processing timed out. Pipeline aborted."}), 504
    except Exception as exc:
        shutil.rmtree(temp_dir, ignore_errors=True)
        print(f"[ERROR] {str(exc)}", flush=True)
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    app.run(debug=True, port=5000)
