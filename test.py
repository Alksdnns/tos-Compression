"""
Run from inside your bcj_project/ folder:
    python3 tos3_diagnose.py path/to/your_44kb_file
"""
import sys
sys.path.insert(0, '.')
import tos_codec_enhanced as tos
path = r"C:\Users\toshi\Desktop\bcj_project\sample.bin"  # <-- put your actual 44 KB file path here
data = open(path, "rb").read()
rule = tos.RuleEngine(tos.DEFAULT_CONFIG)
analysis = tos.analyze_file(path, data, rule)

print("size:", len(data))
print("file_type:", analysis.file_type)
print("is_executable:", analysis.is_executable)
print("is_already_compressed:", analysis.is_already_compressed)
print("shannon entropy (order-0):", round(analysis.entropy, 3), "bits/byte")
print("conditional entropy (order-2):", round(tos.compression_entropy(data), 3), "bits/byte")
print("selected transform:", analysis.suggested_transforms)

plain = tos.lzma_compressed_size(data, tos.LZMA_FILTERS)
print("plain LZMA2 (no transform):", plain, f"({plain/len(data)*100:.1f}% of original)")

if analysis.is_executable:
    cand, patched = tos.transform_bcj_x86(data, inverse=False)
    bcj = tos.lzma_compressed_size(cand, tos.LZMA_FILTERS)
    print("BCJ+LZMA2:", bcj, f"({bcj/len(data)*100:.1f}% of original), patched={patched} calls/jumps")
else:
    print("NOTE: file was not classified as executable, so BCJ was never attempted.")
    print("If this IS x86 code without an MZ/ELF/Mach-O header, that's your ceiling right there.")


