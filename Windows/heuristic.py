# heuristic.py
# Fully local, offline heuristic process risk scorer — the single source of
# truth for "how suspicious is this process?" across the whole application.
#
# Consumers:
#   - monitor.py           → score_all()        (always-on background monitor)
#   - pages.py             → score_process_summary()  (Nextion procs display)
#   - ai_analysis.py       → score_process_summary()  (text analysis report)
#   - discord_notifier.py  → consumes the dict fields produced here
#
# Public API:
#   score_process(proc_dict)         → {"score", "risk", "reasons"}
#   score_process_summary(proc_dict) → (score, reasons)     (tuple helper)
#   score_all(flagged, threshold=60) → list of merged dicts
#
# Score is 0–100.  risk label:
#   "low"    0–39
#   "medium" 40–69
#   "high"   70–100

import math
import os
import re
import string
import time
from collections import Counter

from config import KNOWN_SAFE_PROCESSES


# ── Safe-name set for typosquat detection ────────────────────────────────────
# Derived from the master whitelist in config so there's one source of truth.
# Extensions are stripped ("svchost.exe" → "svchost") because typosquat
# comparisons run on the name stem.

_SAFE_BASE_NAMES = frozenset(
    os.path.splitext(n)[0] for n in KNOWN_SAFE_PROCESSES if n
)

# ── Suspicious path fragments ─────────────────────────────────────────────────
_SUSPICIOUS_PATH_FRAGMENTS = [
    r"\\temp\\",
    r"\\tmp\\",
    r"\\appdata\\local\\temp\\",
    r"\\appdata\\roaming\\",
    r"\\public\\",
    r"\\programdata\\",          # common malware drop location
    r"\\recycle",
    r"\\windows\\fonts\\",       # rare but used for process hiding
    r"\\windows\\tasks\\",
    r"\\windows\\debug\\",
    r"\\users\\.*\\downloads\\",
    r"\\desktop\\",
]
_SUSPICIOUS_PATH_RE = re.compile(
    "|".join(_SUSPICIOUS_PATH_FRAGMENTS), re.IGNORECASE
)

# Legitimate system paths — path starting with these gets a trust boost
_TRUSTED_ROOTS = tuple(
    r.lower() for r in (
        os.environ.get("SystemRoot",         r"C:\Windows"),
        os.environ.get("ProgramFiles",       r"C:\Program Files"),
        os.environ.get("ProgramFiles(x86)",  r"C:\Program Files (x86)"),
    ) if r
)

# Extensions that should almost never be a running process path
_SUSPICIOUS_EXTENSIONS = frozenset({
    ".tmp", ".dat", ".log", ".txt", ".bat", ".vbs", ".ps1",
})

# Double-extension pattern  e.g.  invoice.pdf.exe
_DOUBLE_EXT_RE = re.compile(
    r"\.(pdf|doc|docx|xls|xlsx|txt|jpg|png|zip|rar)\.(exe|bat|cmd|scr|pif|vbs|js)$",
    re.IGNORECASE,
)

# Looks like a GUID or hex blob  e.g.  a3f2b1c9.exe
_GUID_RE = re.compile(
    r"^[{(]?[0-9a-f]{8}[-]?([0-9a-f]{4}[-]?){3}[0-9a-f]{12}[})]?$",
    re.IGNORECASE,
)

# All-digit name   e.g.  12345678.exe
_ALL_DIGITS_RE = re.compile(r"^\d+$")

# Name looks like a hex string  e.g.  a3f2b1c9d4e5f6
_HEX_NAME_RE = re.compile(r"^[0-9a-f]{6,}$", re.IGNORECASE)

# Long run of consonants with no vowels  e.g.  xkzqrtp
_CONSONANT_RUN_RE = re.compile(r"[^aeiou]{4,}")

# High-entropy / random-looking: low ratio of vowels to total letters
_VOWELS = frozenset("aeiouAEIOU")

# Shannon entropy thresholds
_ENTROPY_SUSPICIOUS  = 3.5    # elevated — unusual distribution
_ENTROPY_VERY_RANDOM = 4.2    # very high — almost certainly generated

# Memory thresholds (KB)
_MEM_ELEVATED_KB = 100_000    # ~97  MB
_MEM_HIGH_KB     = 500_000    # ~488 MB
_MEM_EXTREME_KB  = 1_500_000  # ~1.4 GB

# Installation recency thresholds (days).
# On Windows, os.stat().st_ctime returns the file creation time — a reliable
# proxy for when an executable was first installed.  Newer programs carry
# elevated risk because malware is almost always freshly dropped.
_AGE_VERY_RECENT = 7    # +15 pts — installed this week
_AGE_RECENT      = 30   # +8  pts — installed this month
_AGE_MODERATE    = 90   # +4  pts — installed in the last quarter

# Printable character set (cached — avoids Python recomputing per call)
_PRINTABLE = frozenset(string.printable)


# ── Scoring helpers ───────────────────────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string — higher = more random-looking."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _vowel_ratio_score(letters_only: str) -> float:
    """
    Lightweight vowel-ratio randomness check.
    Returns 1.0 (very random), 0.7 (suspicious), or 0.0 (normal).
    """
    if len(letters_only) < 4:
        return 0.0
    ratio = sum(1 for c in letters_only if c in _VOWELS) / len(letters_only)
    if ratio < 0.10:
        return 1.0
    if ratio < 0.18:
        return 0.7
    return 0.0


def _levenshtein(a: str, b: str) -> int:
    """Compute edit distance between two strings."""
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1,
                            prev[j] + (0 if ca == cb else 1)))
        prev = curr
    return prev[-1]


def _is_typosquatting(name_no_ext: str) -> tuple[bool, str]:
    """
    Return (True, matched_safe_name) if name is 1–2 edits away from a known-safe
    process name and is NOT itself in the whitelist.
    """
    n = name_no_ext.lower()
    if n in _SAFE_BASE_NAMES:
        return False, ""
    for safe in _SAFE_BASE_NAMES:
        # Only compare names of similar length (typosquatters keep names short)
        if abs(len(n) - len(safe)) > 3:
            continue
        dist = _levenshtein(n, safe)
        if 0 < dist <= 2:
            return True, safe
    return False, ""


def _drive_letter(path: str) -> str:
    """Return the uppercase drive letter from a Windows path, or ''."""
    if len(path) >= 2 and path[1] == ":":
        return path[0].upper()
    return ""


# ── Public API ────────────────────────────────────────────────────────────────

def score_process(proc: dict) -> dict:
    """
    Analyse a single process dict (as returned by scan_processes flagged list)
    and return a heuristic risk assessment.

    This is the canonical scorer — every consumer that wants a 0–100 risk score
    should call this function (or the tuple helper below).

    Args:
        proc: {
            "name":   str,        # e.g. "svch0st.exe"
            "pid":    int,
            "mem_kb": int,
            "path":   str|None,   # full executable path or None
        }

    Returns:
        {
            "score":   int,        # 0–100 composite risk score
            "risk":    str,        # "low" | "medium" | "high"
            "reasons": [str],      # human-readable list of triggered signals
        }
    """
    name   = proc.get("name") or ""
    path   = (proc.get("path") or "").strip()
    mem_kb = proc.get("mem_kb") or 0

    score   = 0
    reasons = []

    # Normalise
    name_lower  = name.lower()
    name_no_ext = os.path.splitext(name_lower)[0]
    path_lower  = path.lower()

    # ── Signal: no resolved path (process is hiding its binary) ──────────────
    if not path:
        score += 20
        reasons.append("No executable path resolved (possible process hiding)")

    else:
        # ── Path in a suspicious directory ────────────────────────────────────
        if _SUSPICIOUS_PATH_RE.search(path_lower):
            score += 25
            reasons.append(f"Runs from suspicious directory: {os.path.dirname(path)}")

        # ── NOT running from a trusted system root ────────────────────────────
        trusted = any(path_lower.startswith(r) for r in _TRUSTED_ROOTS)
        if not trusted:
            score += 10
            reasons.append("Not in Program Files or Windows system directory")

        # ── Double extension  e.g.  resume.pdf.exe ───────────────────────────
        if _DOUBLE_EXT_RE.search(path_lower):
            score += 30
            reasons.append("Double file extension detected (e.g. .pdf.exe)")

        # ── Suspicious file extension ────────────────────────────────────────
        ext = os.path.splitext(path_lower)[1]
        if ext in _SUSPICIOUS_EXTENSIONS:
            score += 20
            reasons.append(f"Process image has unusual extension: {ext}")

        # ── Running from an unusual drive (not C:) ────────────────────────────
        drive = _drive_letter(path)
        if drive and drive != "C":
            score += 12
            reasons.append(f"Executing from non-system drive ({drive}:)")

    # ── Signal: typosquatting — name close to a known-safe process ───────────
    typo, matched = _is_typosquatting(name_no_ext)
    if typo:
        score += 35
        reasons.append(
            f"Name closely resembles known-safe process '{matched}.exe' "
            f"(possible impersonation)"
        )

    # ── Signal: GUID or all-digit name ───────────────────────────────────────
    if _GUID_RE.match(name_no_ext):
        score += 22
        reasons.append(
            "Process name looks like a GUID/hash (common malware dropper pattern)"
        )
    elif _ALL_DIGITS_RE.match(name_no_ext):
        score += 18
        reasons.append("Process name is all digits (unusual for legitimate software)")

    # ── Signal: hex-string name ──────────────────────────────────────────────
    if _HEX_NAME_RE.match(name_no_ext):
        score += 15
        reasons.append("Name looks like a hex string")

    # ── Signal: Shannon entropy (merged from ai_analysis) ────────────────────
    stem_entropy = _shannon_entropy(name_no_ext)
    if stem_entropy >= _ENTROPY_VERY_RANDOM:
        score += 22
        reasons.append(
            f"Very high name entropy ({stem_entropy:.2f}) — looks randomly generated"
        )
    elif stem_entropy >= _ENTROPY_SUSPICIOUS:
        score += 10
        reasons.append(
            f"Elevated name entropy ({stem_entropy:.2f}) — unusual character distribution"
        )

    # ── Signal: long run of consonants with no vowels ────────────────────────
    longest_consonant_run = max(
        (len(m.group()) for m in _CONSONANT_RUN_RE.finditer(name_no_ext)),
        default=0,
    )
    if longest_consonant_run >= 5:
        score += 10
        reasons.append(
            f"Long consonant run ({longest_consonant_run} chars, no vowels)"
        )

    # ── Signal: lightweight vowel-ratio check (catches cases entropy misses) ─
    letters_only = "".join(c for c in name_no_ext if c.isalpha())
    vowel_score  = _vowel_ratio_score(letters_only)
    if vowel_score >= 1.0:
        score += 12
        reasons.append("Process name has very few vowels — may be randomly generated")
    elif vowel_score >= 0.7:
        score += 6
        reasons.append("Process name has low vowel ratio — possibly generated string")

    # ── Signal: digit-heavy name ─────────────────────────────────────────────
    if name_no_ext:
        digit_ratio = sum(c.isdigit() for c in name_no_ext) / len(name_no_ext)
        if digit_ratio > 0.4 and not _ALL_DIGITS_RE.match(name_no_ext):
            score += 10
            reasons.append(
                f"Name is {digit_ratio:.0%} digits — unusual for a real program"
            )

    # ── Signal: name length extremes ─────────────────────────────────────────
    stem_len = len(name_no_ext)
    if 1 <= stem_len <= 3 and name_no_ext not in ("cmd", "mmc"):
        score += 10
        reasons.append(f"Unusually short process name: '{name_no_ext}'")
    elif stem_len > 25:
        score += 8
        reasons.append(f"Unusually long process name ({stem_len} chars)")

    # ── Signal: non-printable characters in name ─────────────────────────────
    if name_no_ext:
        printable_ratio = sum(c in _PRINTABLE for c in name_no_ext) / len(name_no_ext)
        if printable_ratio < 0.8:
            score += 20
            reasons.append("Name contains non-printable characters")

    # ── Signal: memory usage tiers ───────────────────────────────────────────
    if mem_kb >= _MEM_EXTREME_KB:
        score += 22
        reasons.append(f"Very high memory usage: {mem_kb // 1024} MB")
    elif mem_kb >= _MEM_HIGH_KB:
        score += 12
        reasons.append(f"High memory usage: {mem_kb // 1024} MB")
    elif mem_kb >= _MEM_ELEVATED_KB:
        score += 5
        reasons.append(f"Elevated memory usage: {mem_kb // 1024} MB")

    # ── Signal: recently installed executable ────────────────────────────────
    # On Windows, st_ctime is the file *creation* time — a reliable proxy for
    # when the executable was first placed on disk (installed / dropped).
    # Malware is almost always freshly written; long-established binaries are
    # far less likely to be malicious.  We only check when a path is available.
    if path:
        try:
            age_days = (time.time() - os.stat(path).st_ctime) / 86_400.0
            if age_days < _AGE_VERY_RECENT:
                score += 15
                reasons.append(
                    f"Executable created very recently ({int(age_days)}d ago) — "
                    "newly dropped files are a primary malware indicator"
                )
            elif age_days < _AGE_RECENT:
                score += 8
                reasons.append(
                    f"Executable installed recently ({int(age_days)}d ago) — "
                    "verify this program is expected"
                )
            elif age_days < _AGE_MODERATE:
                score += 4
                reasons.append(
                    f"Executable installed within the last 90 days ({int(age_days)}d ago)"
                )
        except (OSError, PermissionError, ValueError):
            pass   # path exists but stat failed (e.g. access denied) — skip

    # ── Clamp and label ────────────────────────────────────────────────────────────────────────────
    score = min(score, 100)

    if score >= 70:
        risk = "high"
    elif score >= 40:
        risk = "medium"
    else:
        risk = "low"

    return {"score": score, "risk": risk, "reasons": reasons}


def score_process_summary(proc: dict) -> tuple[int, list[str]]:
    """
    Tuple-returning convenience wrapper for callers that want (score, findings).

    Behaviourally identical to score_process — same signals, same score — but
    returns the two values as a tuple. This is the shape ai_analysis and pages
    previously expected from the now-deleted _score_process.
    """
    result = score_process(proc)
    return result["score"], result["reasons"]


def score_all(flagged_procs: list, threshold: int = 60) -> list:
    """
    Score every process in flagged_procs and return only those at or above
    the given risk score threshold.

    Args:
        flagged_procs: list of proc dicts from scan_processes()["flagged"]
        threshold:     minimum score (0–100) to include in the result

    Returns:
        List of dicts: proc dict merged with {"score", "risk", "reasons"}
        Sorted highest score first.
    """
    results = []
    for proc in flagged_procs:
        assessment = score_process(proc)
        if assessment["score"] >= threshold:
            results.append({**proc, **assessment})
    results.sort(key=lambda x: x["score"], reverse=True)
    return results
