"""Phase 10B: ABI matrix for the 29 imported HIP symbols.

Extracts the canonical declaration of each symbol from the HIP 6.4 and
HIP 7.1 header trees, normalizes (comments stripped, whitespace collapsed,
parameter names removed), and compares. Non-identical rows are reported
for manual review; the CSV status is DIRECT_ABI_MATCH only when the
normalized declarations are equal.

Host-only. Does not call or load any HIP DLL.
"""
from __future__ import annotations

import csv
import os
import re

H64 = r"C:\Program Files\AMD\ROCm\6.4\include"
H71 = r"C:\Program Files\AMD\ROCm\7.1\include"
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "phase10_abi_matrix.csv")

SYMBOLS = [
    "__hipPopCallConfiguration", "__hipPushCallConfiguration",
    "__hipRegisterFatBinary", "__hipRegisterFunction", "__hipRegisterVar",
    "__hipUnregisterFatBinary", "hipDestroyExternalMemory",
    "hipDeviceSynchronize", "hipDriverGetVersion", "hipEventCreate",
    "hipEventElapsedTime", "hipEventRecord", "hipEventSynchronize",
    "hipExternalMemoryGetMappedBuffer", "hipFree", "hipGetDeviceCount",
    "hipGetDevicePropertiesR0600", "hipGetErrorString", "hipGetLastError",
    "hipImportExternalMemory", "hipLaunchKernel", "hipMalloc", "hipMemcpy",
    "hipMemcpyAsync", "hipMemcpyToSymbol", "hipMemset", "hipMemsetAsync",
    "hipRuntimeGetVersion", "hipSetDevice",
]

CATEGORY = {
    "__hipPopCallConfiguration": "LAUNCH", "__hipPushCallConfiguration": "LAUNCH",
    "hipLaunchKernel": "LAUNCH",
    "__hipRegisterFatBinary": "REGISTRATION", "__hipUnregisterFatBinary": "REGISTRATION",
    "__hipRegisterFunction": "REGISTRATION", "__hipRegisterVar": "REGISTRATION",
    "hipGetDeviceCount": "DEVICE", "hipGetDevicePropertiesR0600": "DEVICE",
    "hipSetDevice": "DEVICE", "hipDeviceSynchronize": "DEVICE",
    "hipDriverGetVersion": "DEVICE", "hipRuntimeGetVersion": "DEVICE",
    "hipMalloc": "MEMORY", "hipFree": "MEMORY", "hipMemcpy": "MEMORY",
    "hipMemcpyAsync": "MEMORY", "hipMemcpyToSymbol": "MEMORY",
    "hipMemset": "MEMORY", "hipMemsetAsync": "MEMORY",
    "hipEventCreate": "STREAM_EVENT", "hipEventRecord": "STREAM_EVENT",
    "hipEventSynchronize": "STREAM_EVENT", "hipEventElapsedTime": "STREAM_EVENT",
    "hipImportExternalMemory": "EXTERNAL_MEMORY",
    "hipDestroyExternalMemory": "EXTERNAL_MEMORY",
    "hipExternalMemoryGetMappedBuffer": "EXTERNAL_MEMORY",
    "hipGetErrorString": "OTHER", "hipGetLastError": "OTHER",
}


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    return text


def decl_of(root, symbol):
    """Return (normalized_decl, file, line_no) of the first complete
    declaration found for symbol, or (None, None, None)."""
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if not (fn.endswith(".h") or fn.endswith(".hpp") or fn.endswith(".inl")):
                continue
            path = os.path.join(dirpath, fn)
            try:
                txt = open(path, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            lines = txt.splitlines()
            clean = [strip_comments(l) for l in lines]
            for i, line in enumerate(clean):
                if re.search(r"\b" + re.escape(symbol) + r"\s*\(", line):
                    # skip trace/macro/typedef noise: declaration must
                    # contain the symbol followed by '(' as a parameter list
                    # of a function declaration, i.e. the line contains a
                    # return type word before the symbol.
                    joined = clean[i]
                    j = i + 1
                    # collect until balanced parens and a terminating ';'
                    while (joined.count("(") > joined.count(")") or not joined.rstrip().endswith(";")) and j < len(clean):
                        joined += " " + clean[j]
                        j += 1
                    if not joined.rstrip().endswith(";"):
                        continue
                    # crude validity: symbol inside parens as fn name not
                    # followed by ')' immediately after params -> we already
                    # require '(' right after symbol; also skip if preceded
                    # by '->' or '.' or '#' or 'typedef' fn-pointer patterns
                    if re.search(r"[\w.]" + re.escape(symbol) + r"\s*\(", joined):
                        continue
                    norm = re.sub(r"\s+", " ", joined).strip()
                    norm = re.sub(r"\b[A-Za-z_]\w*\s*(?=[,()])", " ", norm)  # param names
                    norm = re.sub(r"\s+", " ", norm)
                    return norm, os.path.relpath(path, root), i + 1
    return None, None, None


INTERNAL_REGISTER = {"__hipRegisterFatBinary", "__hipRegisterFunction",
                     "__hipRegisterVar", "__hipUnregisterFatBinary"}


def register_typedef(root, symbol):
    """The __hip* register functions are compiler-internal; their canonical
    signatures live as fn-pointer typedefs in
    hip/amd_detail/hip_api_trace.hpp (both versions). Return the normalized
    typedef text."""
    path = os.path.join(root, "hip", "amd_detail", "hip_api_trace.hpp")
    txt = open(path, encoding="utf-8", errors="replace").read()
    txt = strip_comments(txt)
    txt = re.sub(r"\s+", " ", txt)
    tname = "t___hip" + symbol[len("__hip"):]
    m = re.search(r"typedef\s+([^;]*?)\s*\(\*\s*" + re.escape(tname) + r"\s*\)\s*\(([^;]*?)\)\s*;",
                  txt, flags=re.S)
    if not m:
        return None
    return "typedef %s (*%s)(%s);" % (m.group(1).strip(), tname, m.group(2).strip())


def main():
    rows = []
    for sym in SYMBOLS:
        if sym in INTERNAL_REGISTER:
            d64 = register_typedef(H64, sym)
            d71 = register_typedef(H71, sym)
            f64 = f71 = r"include\hip\amd_detail\hip_api_trace.hpp"
            l64 = l71 = ""
            if d64 is None or d71 is None:
                status = "UNRESOLVED"
            elif d64 == d71:
                status = "INTERNAL_ABI_PROVEN"
            else:
                status = "WRAPPER_TRANSLATION_REQUIRED"
            rows.append({
                "symbol": sym, "category": CATEGORY[sym],
                "hip6_file": f64 or "", "hip6_line": l64 or "",
                "hip7_file": f71 or "", "hip7_line": l71 or "",
                "hip6_normalized_decl": d64 or "", "hip7_normalized_decl": d71 or "",
                "abi_status": status,
            })
            continue
        d64, f64, l64 = decl_of(H64, sym)
        d71, f71, l71 = decl_of(H71, sym)
        if d64 is None or d71 is None:
            status = "UNRESOLVED"
        elif d64 == d71:
            status = "DIRECT_ABI_MATCH"
        else:
            status = "WRAPPER_TRANSLATION_REQUIRED"
        rows.append({
            "symbol": sym, "category": CATEGORY[sym],
            "hip6_file": f64 or "", "hip6_line": l64 or "",
            "hip7_file": f71 or "", "hip7_line": l71 or "",
            "hip6_normalized_decl": d64 or "", "hip7_normalized_decl": d71 or "",
            "abi_status": status,
        })
    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    from collections import Counter
    print("abi matrix rows:", len(rows), dict(Counter(r["abi_status"] for r in rows)))
    for r in rows:
        if r["abi_status"] != "DIRECT_ABI_MATCH":
            print(f"  {r['abi_status']:35s} {r['symbol']}")
            print("    6.4:", r["hip6_normalized_decl"][:160])
            print("    7.1:", r["hip7_normalized_decl"][:160])
    n_unres = sum(1 for r in rows if r["abi_status"] == "UNRESOLVED")
    if n_unres:
        print(f"UNRESOLVED count = {n_unres}; see rows")
    else:
        print("UNRESOLVED = 0")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
