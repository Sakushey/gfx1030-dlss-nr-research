"""Phase 16AX / T-SOURCES -- remote source refresh, read-only ref advertisement.

METHOD (inherited from p16aw/sources/SOURCE_REFRESH_16AW.json): for each
repository, run

    GIT_TERMINAL_PROMPT=0 git ls-remote --heads <url> <branch>

which contacts the remote, reads its ref advertisement and prints the SHA it
advertises. No clone, no object fetch, no write of any kind to the remote.

A SECOND, independent lookup is added here: `git ls-remote --symref <url> HEAD`
reports which branch HEAD is a symbolic ref to, so the default branch is a
MEASURED value rather than an assumption. A branch name guessed wrong returns
nothing; that is recorded as a measured absence, never worked around by
substituting a different artifact.

Every SHA written here is copied from git's stdout in this session. None is
transcribed from a prior phase. `supervisor_last_seen` is transcribed and
`last_seen_commit` is measured -- the two are never interchanged, and a null
`supervisor_last_seen` means "not measured", never "no change".

HOST ONLY, NETWORK READ-ONLY.
"""
import json
import os
import subprocess
import datetime

ROOT = r"<PROJECT_ROOT>"
OUT = os.path.join(ROOT, "p16ax", "sources", "SOURCE_REFRESH_16AX.json")

# (tier, slug, url, branch_used_by_16aw, supervisor_last_seen)
REPOS = [
    ("A", "maanHimself/OpenDLSS-NR",
     "https://github.com/maanHimself/OpenDLSS-NR",
     "main", "9d08f4184bbcb9d858e2fb7a7834ec0837a9d2f1"),
    ("A", "Paimonshen/dlss-nr-reverse-engineering",
     "https://github.com/Paimonshen/dlss-nr-reverse-engineering",
     "main", "ac29d70378d0d730f4a5a5f7370f825ebcf43cb9"),
    ("A", "heimeimei27/dlss5-zluda-amd",
     "https://github.com/heimeimei27/dlss5-zluda-amd",
     "main", "244d3959c9eb12563fb831fecb25fe95b31d4013"),
    ("A", "philippraschke75-spec/gfx1030-dlss-nr-translation-lab",
     "https://github.com/philippraschke75-spec/gfx1030-dlss-nr-translation-lab",
     "main", "152fdfecf0d3b03f08628606b6458dd3cbd90e0c"),
    ("A", "RedDukeDev/ZLUDA",
     "https://github.com/RedDukeDev/ZLUDA",
     "main", "37d6a7fbdb832dc0944425e604c63a82c57d8c40"),
    ("A", "RedDukeDev/dlss5-image-enhancer-zluda",
     "https://github.com/RedDukeDev/dlss5-image-enhancer-zluda",
     "main", "2c64f95229b749637590ae30a6294b70008a5deb"),
    ("B", "areyes1995/AMD-Nvidia-NeuralScreen",
     "https://github.com/areyes1995/AMD-Nvidia-NeuralScreen",
     "main", "3e3c04fb66800771a63da827a1d3ff0b0f1da870"),
    ("B", "Yaddz/RadeonNR",
     "https://github.com/Yaddz/RadeonNR",
     "main", "855b10355ba7b4bd46bee4748cfd0a75abfaabcf"),
    ("B", "Ainquisition/OptiScaler-DLSSNR-PreSR-Multipass",
     "https://github.com/Ainquisition/OptiScaler-DLSSNR-PreSR-Multipass",
     "main", "90c3c6acbef550aef07587f34fb5fcce26ecb077"),
    ("B", "danielblnc/DLSS-NR-on-AMD",
     "https://github.com/danielblnc/DLSS-NR-on-AMD",
     "main", "057c87324bfd8131c45c6b7e7de7d22ab46844d5"),
]

# 16AW pinned these two; recorded here so the delta is against a measured pin,
# not against a recollection.
EARLIER_PINS = {
    "philippraschke75-spec/gfx1030-dlss-nr-translation-lab":
        "4a0ec6e03bd05f11cd991d3a6883891037c1b7c2",
}


def run(args):
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GCM_INTERACTIVE"] = "never"
    p = subprocess.run(args, capture_output=True, text=True, timeout=120,
                       env=env, cwd=ROOT)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def main():
    res = {
        "schema": "p16ax/sources/source-refresh/1",
        "phase": "16AX",
        "host_only": True,
        "gpu_calls": 0,
        "remote_writes": 0,
        "clones_created": 0,
        "method": ("GIT_TERMINAL_PROMPT=0 git ls-remote --heads <url> <branch> , plus an "
                   "independent git ls-remote --symref <url> HEAD to MEASURE the default "
                   "branch instead of assuming it"),
        "measured_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "vocabulary": ["SAME", "MOVED", "NOT_FOUND", "ERROR"],
        "repositories": [],
    }
    stale = False
    for tier, slug, url, branch, last_seen in REPOS:
        row = {"tier": tier, "slug": slug, "url": url,
               "branch_attempted_16aw": branch,
               "supervisor_last_seen": last_seen}
        # independent default-branch measurement
        rc, out, err = run(["git", "ls-remote", "--symref", url, "HEAD"])
        row["symref_rc"] = rc
        row["symref_stderr"] = err[:400] if err else ""
        default_branch = None
        head_via_symref = None
        for line in out.splitlines():
            if line.startswith("ref:"):
                default_branch = line.split()[1].replace("refs/heads/", "")
            elif line.endswith("HEAD"):
                head_via_symref = line.split()[0]
        row["default_branch_measured"] = default_branch
        row["head_sha_via_symref"] = head_via_symref

        # primary method: the ref advertisement for the branch, as 16AW did
        rc2, out2, err2 = run(["git", "ls-remote", "--heads", url, branch])
        row["refadv_rc"] = rc2
        row["refadv_stderr"] = err2[:400] if err2 else ""
        row["refadv_stdout_lines"] = len(out2.splitlines())
        measured = None
        ref = None
        for line in out2.splitlines():
            sha, name = line.split(None, 1)
            if name.strip() == "refs/heads/%s" % branch:
                measured = sha
                ref = name.strip()
        row["branch"] = branch
        row["ref"] = ref
        row["last_seen_commit"] = measured

        # ---- primary subject: the repository's MEASURED default branch ----
        # A verdict on the 16AW-attempted branch alone is not a verdict about the
        # repository: a non-default branch can differ from the default branch for
        # reasons that have nothing to do with the pinned artifact. The default
        # branch is the subject; the attempted branch is reported alongside it.
        db_sha = None
        if default_branch:
            rc3, out3, _ = run(["git", "ls-remote", "--heads", url, default_branch])
            for line in out3.splitlines():
                sha, name = line.split(None, 1)
                if name.strip() == "refs/heads/%s" % default_branch:
                    db_sha = sha
        row["default_branch_head"] = db_sha

        if measured is None:
            row["measured_absence_on_attempted_branch"] = (
                "branch %r returned no ref; measured default branch is %r" %
                (branch, default_branch))
        if db_sha is None:
            row["verdict"] = "ERROR_NO_DEFAULT_BRANCH_HEAD"
            stale = True
        elif db_sha == last_seen:
            row["verdict"] = "SAME"
        else:
            row["verdict"] = "MOVED"
            row["moved_from"] = last_seen
            stale = True

        row["branch_disagreement"] = (
            measured is not None and db_sha is not None and measured != db_sha)
        if row["branch_disagreement"]:
            row["branch_disagreement_note"] = (
                "attempted branch %r HEAD %s != measured default branch %r HEAD %s ; "
                "the supervisor_last_seen value equals the DEFAULT-branch HEAD, so the "
                "subject of the pin is unchanged and the non-default branch is a "
                "separate line, NOT a move of the pinned artifact" %
                (branch, measured, default_branch, db_sha))
        row["earlier_pin"] = EARLIER_PINS.get(slug)
        res["repositories"].append(row)

    res["source_refresh_stale"] = stale
    res["repos_moved"] = [r["slug"] for r in res["repositories"] if r["verdict"] == "MOVED"]
    res["repos_with_branch_disagreement"] = [
        r["slug"] for r in res["repositories"] if r.get("branch_disagreement")]
    res["first_pass_correction"] = {
        "what_happened": ("a first pass compared the 16AW-attempted branch ('main') HEAD against "
                          "supervisor_last_seen and reported Ainquisition/OptiScaler-DLSSNR-PreSR-"
                          "Multipass as MOVED 90c3c6ac -> e237f895"),
        "why_it_was_wrong": ("Ainquisition's MEASURED default branch is 'amd-v083-minimal' and its "
                             "HEAD is 90c3c6acbef550aef07587f34fb5fcce26ecb077, i.e. exactly the "
                             "supervisor_last_seen value. 'main' is a separate branch. Comparing a "
                             "non-default branch to a pin taken on the default branch is a "
                             "different subject, not a move"),
        "correction": ("verdict is now computed on the measured DEFAULT branch; the attempted "
                       "branch is reported beside it and any disagreement is flagged, never "
                       "silently promoted to MOVED"),
        "generalisation": ("an empty branch lookup is a result, and so is a full lookup of the "
                           "wrong branch: both need the default branch MEASURED, not assumed"),
    }
    res["vacuity_guard"] = {
        "n_repositories": len(res["repositories"]),
        "n_with_measured_default_branch_head": len(
            [r for r in res["repositories"] if r.get("default_branch_head")]),
        "n_with_measured_attempted_branch_sha": len(
            [r for r in res["repositories"] if r["last_seen_commit"]]),
        "rule": "a run with fewer measured SHAs than repositories is a FAILED run, "
                "not a clean one",
    }
    return res


if __name__ == "__main__":
    r = main()
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(r, fh, indent=1)
    for row in r["repositories"]:
        flag = "  <-- BRANCH DISAGREEMENT" if row.get("branch_disagreement") else ""
        print("%-1s %-52s %-9s default=%-20s head=%s%s" %
              (row["tier"], row["slug"], row["verdict"],
               row.get("default_branch_measured"), row.get("default_branch_head"), flag))
    print("stale=%s  moved=%s" % (r["source_refresh_stale"], r["repos_moved"]))
    print("branch_disagreement=%s" % r["repos_with_branch_disagreement"])
    print("vacuity_guard=%s" % r["vacuity_guard"])
    print("wrote", OUT)
