#!/usr/bin/env python3
"""Phase 16AF section 5 -- measure the publication state FROM GIT, not from prose.

Brief section 5: "Do not infer from prose.  Measure: local public branch, local
HEAD, origin refs, working tree, commits ahead/behind, pushed branch existence,
current origin/main."

Every field below comes from a git command whose stdout is captured, or from a
filesystem stat.  Nothing is read out of a SESSION_REPORT or a status card.

Rule K applies: if git cannot be run, or a command fails, the corresponding
field is `null` with `observed: false` -- never a default that reads as "clean".
The overall verdict is UNKNOWN in that case.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import subprocess
import sys

MIRROR = r"<USER_HOME>\Desktop\gfx1030-dlss-nr-research"
PROJECT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

#: The branch whose state 16AE's report made a claim about.
SUBJECT_BRANCH = "publication-sync/post-astra-16af-20260920"
PUBLICATION_BRANCH_PREFIX = "publication-sync/"


def git(args, timeout=60):
    """Run git and return (observed, stdout_text, stderr_text, returncode)."""
    try:
        p = subprocess.run(["git"] + args, cwd=MIRROR, capture_output=True,
                           text=True, timeout=timeout)
    except Exception as exc:                                   # noqa: BLE001
        return False, "", "the command could not be run: %s" % exc, None
    if p.returncode != 0:
        return False, p.stdout or "", p.stderr or "", p.returncode
    return True, p.stdout or "", p.stderr or "", p.returncode


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for c in iter(lambda: fh.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def iso(ts):
    return datetime.datetime.fromtimestamp(ts).isoformat()


def main():
    out = {
        "schema": "p16af-publication-state/1",
        "phase": "16AF",
        "generated_utc": datetime.datetime.utcnow().isoformat() + "Z",
        "generated_by": "p16af/publication/p16af_measure_publication_state.py",
        "rule": "EVERY FIELD IS MEASURED FROM GIT OR FROM A FILESYSTEM STAT. No "
                "field is transcribed from a report, a status card, or prose. "
                "A field git could not answer is null with observed=false, never "
                "a value that reads as clean.",
        "mirror_root": MIRROR,
        "observed": {},
        "unobserved": [],
    }
    obs = out["observed"]

    if not os.path.isdir(os.path.join(MIRROR, ".git")):
        out["verdict"] = "UNKNOWN"
        out["why"] = "no git repository at mirror_root; nothing could be measured"
        out["unobserved"].append("the whole object: .git is absent")
        _write(out)
        return 0

    # --- current branch and HEAD -------------------------------------------
    ok, so, se, rc = git(["rev-parse", "--abbrev-ref", "HEAD"])
    obs["current_branch"] = so.strip() if ok else None
    if not ok:
        out["unobserved"].append("current_branch: git rev-parse failed rc=%s" % rc)

    ok, so, se, rc = git(["rev-parse", "HEAD"])
    obs["local_HEAD"] = so.strip() if ok else None
    if not ok:
        out["unobserved"].append("local_HEAD: git rev-parse failed rc=%s" % rc)

    # --- working tree -------------------------------------------------------
    ok, so, se, rc = git(["status", "--porcelain"])
    if ok:
        lines = [l for l in so.splitlines() if l.strip()]
        obs["working_tree"] = {
            "clean": len(lines) == 0,
            "n_dirty_paths": len(lines),
            "paths": lines[:50],
            "n_paths_listed": min(len(lines), 50),
        }
    else:
        obs["working_tree"] = None
        out["unobserved"].append("working_tree: git status failed rc=%s" % rc)

    # --- origin/main --------------------------------------------------------
    ok, so, se, rc = git(["rev-parse", "origin/main"])
    obs["origin_main"] = so.strip() if ok else None
    if not ok:
        out["unobserved"].append("origin_main: git rev-parse origin/main failed rc=%s" % rc)

    # --- every publication-sync branch, local and remote --------------------
    ok, so, se, rc = git(["for-each-ref",
                          "--format=%(refname)|%(objectname)|%(committerdate:iso)"])
    branches = {"local": {}, "remote": {}}
    if ok:
        for line in so.splitlines():
            parts = line.split("|")
            if len(parts) != 3:
                continue
            ref, obj, when = parts
            if ref.startswith("refs/heads/"):
                branches["local"][ref[len("refs/heads/"):]] = {"object": obj, "committed": when}
            elif ref.startswith("refs/remotes/"):
                branches["remote"][ref[len("refs/remotes/"):]] = {"object": obj, "committed": when}
        obs["branches"] = branches
    else:
        obs["branches"] = None
        out["unobserved"].append("branches: git for-each-ref failed rc=%s" % rc)

    # --- the subject branch -------------------------------------------------
    pub_local = None
    pub_remote = None
    if obs["branches"]:
        pub_local = obs["branches"]["local"].get(SUBJECT_BRANCH)
        pub_remote = obs["branches"]["remote"].get("origin/" + SUBJECT_BRANCH)

    subject = {
        "name": SUBJECT_BRANCH,
        "exists_locally": pub_local is not None,
        "local_object": (pub_local or {}).get("object"),
        "exists_on_origin": pub_remote is not None,
        "origin_object": (pub_remote or {}).get("object"),
        "local_equals_origin": bool(pub_local and pub_remote
                                    and pub_local["object"] == pub_remote["object"]),
    }
    obs["subject_branch"] = subject

    # --- commits ahead/behind vs origin/main --------------------------------
    if subject["exists_locally"]:
        ok, so, se, rc = git(["rev-list", "--left-right", "--count",
                              "origin/main...%s" % SUBJECT_BRANCH])
        if ok:
            try:
                behind, ahead = (int(x) for x in so.split()[:2])
                subject["commits_ahead_of_origin_main"] = ahead
                subject["commits_behind_origin_main"] = behind
            except Exception:                                   # noqa: BLE001
                subject["commits_ahead_of_origin_main"] = None
                subject["commits_behind_origin_main"] = None
                out["unobserved"].append("ahead/behind: unparseable git output")
        else:
            subject["commits_ahead_of_origin_main"] = None
            subject["commits_behind_origin_main"] = None
            out["unobserved"].append("ahead/behind: git rev-list failed rc=%s" % rc)

        # is origin/main an ancestor of the branch?  (i.e. a fast-forward exists)
        ok, so, se, rc = git(["merge-base", "--is-ancestor", "origin/main",
                              SUBJECT_BRANCH])
        if rc is not None:
            subject["origin_main_is_ancestor_of_branch"] = (rc == 0)
    else:
        subject["commits_ahead_of_origin_main"] = None
        subject["commits_behind_origin_main"] = None
        subject["origin_main_is_ancestor_of_branch"] = None

    # --- when the branch was actually created, from the reflog --------------
    # This is the decisive measurement for the 16AE contradiction: the report
    # said nothing was pushed, the headline said a branch was pushed.  The
    # reflog dates the branch's existence independently of both.
    ok, so, se, rc = git(["reflog", "show", SUBJECT_BRANCH, "--date=iso"])
    if ok:
        subject["reflog"] = [l for l in so.splitlines() if l.strip()]
        created = None
        committed = None
        for line in subject["reflog"]:
            if "branch: Created from" in line:
                created = line.split("@{")[1].split("}")[0] if "@{" in line else None
        if subject["reflog"]:
            last = subject["reflog"][0]
            if "@{" in last and "}" in last:
                committed = last.split("@{")[1].split("}")[0]
        subject["reflog_created_at"] = created
        subject["reflog_latest_commit_at"] = committed
        # the subject branch's commit subject line, from git itself
        ok2, so2, _, rc2 = git(["log", "-1", "--format=%H%n%cI%n%s", SUBJECT_BRANCH])
        if ok2:
            parts = so2.splitlines()
            subject["head_commit"] = parts[0] if len(parts) > 0 else None
            subject["head_committer_date"] = parts[1] if len(parts) > 1 else None
            subject["head_subject"] = parts[2] if len(parts) > 2 else None
    else:
        subject["reflog"] = None
        subject["reflog_created_at"] = None
        subject["reflog_latest_commit_at"] = None
        out["unobserved"].append("reflog: git reflog show failed rc=%s" % rc)

    # --- was the private SESSION_REPORT written before or after that commit? -
    sr = os.path.join(PROJECT, "SESSION_REPORT.md")
    if os.path.exists(sr):
        st = os.stat(sr)
        out["private_status_file"] = {
            "path": "SESSION_REPORT.md",
            "mtime_local": iso(st.st_mtime),
            "size_bytes": st.st_size,
            "mtime_epoch": st.st_mtime,
        }
    else:
        out["private_status_file"] = None
        out["unobserved"].append("private_status_file: SESSION_REPORT.md absent")

    # --- the helper that produced 16AE's PUBLICATION_SYNC_BLOCKED -----------
    helper = os.path.join(MIRROR, "scripts", "prepare_publication_sync.py")
    if os.path.exists(helper):
        out["sync_helper"] = {
            "path": helper,
            "sha256_recomputed": sha256_file(helper),
            "size_bytes": os.path.getsize(helper),
        }
    else:
        out["sync_helper"] = None
        out["unobserved"].append("sync_helper: prepare_publication_sync.py absent")

    # --- derive the typed fields future prose must use ----------------------
    out["derived"] = {
        "main_touched_by_this_work": (
            None if obs["current_branch"] is None else
            obs["current_branch"] not in ("main",)),
        "a_publication_branch_exists": subject["exists_locally"],
        "a_publication_branch_is_on_origin": subject["exists_on_origin"],
        "branch_and_origin_agree": subject["local_equals_origin"],
        "main_was_not_advanced": (
            None if obs["branches"] is None else
            obs["branches"]["local"].get("main", {}).get("object")
            == obs["branches"]["remote"].get("origin/main", {}).get("object")),
        "a_hand_curated_publication_branch_was_pushed": (
            subject["exists_on_origin"] and subject["local_equals_origin"]),
        "the_helper_driven_mapped_sync_was_applied": None,
        "why_helper_field_is_null": (
            "The helper's own --apply behaviour is NOT measurable from git; git "
            "can only show that SOME branch reached origin. Recording `null` "
            "here rather than inferring 'the helper applied' from a branch "
            "existing is the point of Rule K."),
    }

    #: THE single source for the publication status token.  Every generated
    #: document compares its prose to this value; no document may restate the
    #: status from memory.  (Brief section 6.)
    if subject["exists_on_origin"] and subject["local_equals_origin"]:
        token, why_tok = "PUBLISHED_BRANCH", (
            "a publication branch exists on origin and its local object equals "
            "the origin object")
    elif subject["exists_locally"]:
        token, why_tok = "PUBLICATION_SYNC_PENDING", (
            "a publication branch exists locally but does not match origin")
    else:
        token, why_tok = "PUBLICATION_SYNC_NONE", "no publication branch exists"
    out["derived"]["publication_status_token"] = token
    out["derived"]["publication_status_token_why"] = why_tok
    out["derived"]["publication_status_token_is_derived_not_typed"] = True

    if out["unobserved"]:
        out["verdict"] = "UNKNOWN"
        out["why"] = ("at least one decisive field could not be measured; see "
                      "unobserved. An unmeasured field is not a clean field.")
    else:
        out["verdict"] = "MEASURED"

    _write(out)
    return 0


def _write(out):
    dst = os.path.join(PROJECT, "p16af", "publication", "PUBLICATION_STATE.json")
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    print("verdict        :", out.get("verdict"))
    s = out["observed"].get("subject_branch") or {}
    print("subject branch :", s.get("name"))
    print("  exists local :", s.get("exists_locally"), s.get("local_object"))
    print("  on origin    :", s.get("exists_on_origin"), s.get("origin_object"))
    print("  ahead/behind :", s.get("commits_ahead_of_origin_main"),
          "/", s.get("commits_behind_origin_main"))
    print("  created at   :", s.get("reflog_created_at"))
    print("  head commit  :", s.get("head_committer_date"))
    print("origin/main    :", out["observed"].get("origin_main"))
    print("current branch :", out["observed"].get("current_branch"))
    wt = out["observed"].get("working_tree") or {}
    print("working tree   :", "clean" if wt.get("clean") else wt)
    print("unobserved     :", len(out["unobserved"]))
    for u in out["unobserved"]:
        print("   -", u)


if __name__ == "__main__":
    sys.exit(main())
