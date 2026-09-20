"""Write phase10_manifest.sha256 for the built bridge artifacts."""
import hashlib
import os

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

FILES = [
    (os.path.join("phase10_hip_bridge", "prod_build", "amdhip64_7.dll"),
     "production bridge (embedded absolute HIP6.4 path)"),
    (os.path.join("phase10_hip_bridge", "test_build", "amdhip64_7.dll"),
     "test bridge (embedded absolute mock path)"),
    (os.path.join("phase10_hip_bridge", "mock_hip6.dll"), "mock backend"),
    (os.path.join("phase10_hip_bridge", "hip_bridge_smoke.exe"),
     "host smoke test executable (no GPU)"),
]

HEADER = [
    "# Phase 10 manifest - built 2026-09-06",
    "# toolchain: MSVC 2022 BuildTools cl.exe (x64); /MT static CRT;",
    "# bridge links NO HIP headers and imports only KERNEL32.dll.",
    "",
]

with open(os.path.join(ROOT, "phase10_manifest.sha256"), "w", encoding="utf-8") as f:
    f.write("\n".join(HEADER))
    for rel, desc in FILES:
        path = os.path.join(ROOT, rel)
        h = hashlib.sha256(open(path, "rb").read()).hexdigest()
        f.write("%s  %s  # %s\n" % (h, rel.replace("/", "\\"), desc))
print("wrote phase10_manifest.sha256")
