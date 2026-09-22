"""T-PUB step 1: read-only tree snapshot of the private source project.

Walks the whole project tree and records, per file: relative path, byte size,
extension, mtime, and a SHA-256 recomputed from the bytes on disk in THIS
session.  Nothing is written outside p16ax/publication/.

Why a snapshot and not a live view: the source tree is live -- other workers
write into it while this runs.  A snapshot with a recorded instant is the only
honest basis for a classification; files created after the instant are simply
not covered, and the drift re-check at the end measures how many there are.

The SHA-256 is only computed for files at or below HASH_LIMIT.  Above it the
field is null and a reason is recorded, rather than a truncated or synthetic
digest -- padding or synthesising a hash is forbidden.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timezone

SRC = r"<PROJECT_ROOT>"
OUT_DIR = os.path.join(SRC, "p16ax", "publication")

HASH_LIMIT = 64 * 1024 * 1024  # 64 MiB
CHUNK = 1 << 20


def sha256_of(path: str) -> str | None:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for c in iter(lambda: f.read(CHUNK), b""):
                h.update(c)
    except OSError:
        return None
    return h.hexdigest()


def walk(root: str) -> dict:
    files = []
    unreadable = []
    n = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace("\\", "/")
            n += 1
            try:
                st = os.stat(full)
                size = st.st_size
                mtime = st.st_mtime
            except OSError as exc:
                unreadable.append({"path": rel, "error": type(exc).__name__})
                continue
            ext = os.path.splitext(fn)[1].lower()
            digest = None
            hash_skip = None
            if size == 0:
                # An empty file has a well-defined digest; hash it anyway so the
                # field is measured rather than assumed.
                digest = sha256_of(full)
            elif size <= HASH_LIMIT:
                digest = sha256_of(full)
            else:
                hash_skip = f"size {size} exceeds HASH_LIMIT {HASH_LIMIT}"
            if digest is None and hash_skip is None:
                unreadable.append({"path": rel, "error": "OSError_during_read"})
            files.append({
                "source_path": rel,
                "bytes": size,
                "extension": ext,
                "mtime_utc": datetime.fromtimestamp(
                    mtime, tz=timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "sha256": digest,
                "sha256_skipped": hash_skip,
            })
            if n % 2000 == 0:
                print(f"  ...{n} files", file=sys.stderr, flush=True)
    files.sort(key=lambda r: r["source_path"])
    return {
        "schema": "p16ax/publication/tree-snapshot/1",
        "source_root": SRC,
        "generated_by": "p16ax/publication/p16ax_inventory.py",
        "read_only": True,
        "snapshot_note": (
            "the source tree is LIVE; this is a point-in-time snapshot and does "
            "not cover files created after captured_utc"
        ),
        "captured_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "hash_limit_bytes": HASH_LIMIT,
        "file_count": len(files),
        "total_bytes": sum(r["bytes"] for r in files),
        "unreadable": unreadable,
        "files": files,
    }


def main() -> int:
    if not os.path.isdir(SRC):
        raise SystemExit("source root missing")
    snap = walk(SRC)
    os.makedirs(OUT_DIR, exist_ok=True)
    dst = os.path.join(OUT_DIR, "TREE_SNAPSHOT_16AX.json")
    with open(dst, "w", encoding="utf-8", newline="\n") as f:
        json.dump(snap, f, indent=1)
    print(f"wrote {dst}: {snap['file_count']} files, "
          f"{snap['total_bytes']} bytes, {len(snap['unreadable'])} unreadable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
