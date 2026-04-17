# ai_analysis.py
# Pure-Python heuristic security analysis engine for Nextion Control Station.
#
# No external dependencies, no API keys — all reasoning is deterministic rule-based
# logic that scores and interprets scan data the way a security analyst would.
#
# Entry point:
#   analyse(scan_results: dict) -> generator[str]
#
# Yields analysis text line-by-line so the caller can stream it into a widget
# in real time. Each yielded string is a single line (no trailing newline).

import math
import re

# Unified process scorer — single source of truth for 0–100 risk scoring.
# ai_analysis previously reimplemented this locally with a slightly different
# signal set; we now delegate to the canonical scorer in heuristic.py.
from heuristic import score_process_summary as _score_process


# ─────────────────────────────────────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────────────────────────────────────

# Ports that are almost always safe to have open
BENIGN_PORTS = frozenset({
    135,   # RPC endpoint mapper — normal on Windows
    49152, # dynamic/private range start
})

# Ports that are high-risk depending on context
HIGH_RISK_PORTS = frozenset({
    21, 23, 25, 53, 80, 135, 139, 443, 445,
    1433, 3306, 3389, 5985, 5986, 8080, 8443,
})

# Dangerous port pairs — co-occurrence makes each more suspicious
RISKY_PORT_COMBOS = [
    ({445, 139},  "SMB + NetBIOS both open — classic ransomware lateral-movement surface"),
    ({3389, 22},  "RDP + SSH both exposed — two remote-access vectors simultaneously"),
    ({1433, 3306},"MSSQL + MySQL both listening — unusual, suggests a dev machine or misconfiguration"),
    ({21, 23},    "FTP + Telnet both open — both transmit credentials in plaintext"),
    ({3389, 445}, "RDP + SMB — EternalBlue / BlueKeep attack surface combined"),
]

# Risk score thresholds for overall rating
RISK_LOW      = 25
RISK_MODERATE = 50
RISK_HIGH     = 75

# ── Port range boundaries (IANA) ──────────────────────────────────────────────
_REGISTERED_PORT_MIN = 1024   # 1024–49151: registered / user ports
_EPHEMERAL_PORT_MIN  = 49152  # 49152–65535: dynamic / private / ephemeral

# ── Expected legitimate process owners per well-known port ───────────────────
# Values are frozensets of lowercase process names that are normal owners.
# Any other process bound to that port is suspicious and warrants a finding.
EXPECTED_PORT_OWNERS: dict[int, frozenset] = {
    22:   frozenset({"sshd.exe", "openssh.exe"}),
    53:   frozenset({"svchost.exe", "dns.exe"}),
    80:   frozenset({"svchost.exe", "w3wp.exe", "httpd.exe", "nginx.exe",
                     "inetinfo.exe", "apache.exe", "apache2.exe"}),
    135:  frozenset({"svchost.exe"}),
    139:  frozenset({"system"}),
    389:  frozenset({"lsass.exe"}),
    443:  frozenset({"svchost.exe", "w3wp.exe", "httpd.exe", "nginx.exe",
                     "inetinfo.exe", "apache.exe", "apache2.exe"}),
    445:  frozenset({"system"}),
    636:  frozenset({"lsass.exe"}),
    1433: frozenset({"sqlservr.exe"}),
    1434: frozenset({"sqlservr.exe"}),
    3306: frozenset({"mysqld.exe", "mysqld-nt.exe"}),
    3389: frozenset({"svchost.exe"}),
    5985: frozenset({"svchost.exe"}),
    5986: frozenset({"svchost.exe"}),
    8080: frozenset({"svchost.exe", "w3wp.exe", "httpd.exe", "nginx.exe",
                     "java.exe", "javaw.exe", "tomcat.exe", "node.exe"}),
    8443: frozenset({"svchost.exe", "w3wp.exe", "httpd.exe", "nginx.exe",
                     "java.exe", "javaw.exe", "tomcat.exe", "node.exe"}),
}

# ── Processes that are inherently suspicious when owning a listening socket ───
# Shell engines and LOLBins should never be bound to a port — almost always C2.
_SUSPICIOUS_PORT_PROCESSES = frozenset({
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    "bitsadmin.exe", "msbuild.exe",
})


# ─────────────────────────────────────────────────────────────────────────────
#  Utility helpers
# ─────────────────────────────────────────────────────────────────────────────
# Process scoring (_score_process) is imported from heuristic.py above —
# per-process risk scoring lives in one place now.

def _outlier_memory_processes(flagged: list[dict]) -> list[dict]:
    """
    Identify processes whose memory usage is a statistical outlier.

    Uses mean + 2 standard deviations as the outlier threshold.
    Returns the subset that exceed it.
    """
    mems = [p["mem_kb"] for p in flagged if p.get("mem_kb", 0) > 0]
    if len(mems) < 3:
        return []
    mean  = sum(mems) / len(mems)
    var   = sum((m - mean) ** 2 for m in mems) / len(mems)
    stdev = math.sqrt(var)
    threshold = mean + 2 * stdev
    return [p for p in flagged if p.get("mem_kb", 0) > threshold]


def _port_analysis(listeners: list[dict]) -> list[str]:
    """
    Analyse listening ports for individual risks and dangerous combinations.

    Evaluation layers (in priority order):
      1. Process identity — shell/LOLBin owning ANY port is a critical C2 indicator.
      2. Port/process reputation — compare bound process against EXPECTED_PORT_OWNERS;
         a database port bound to sqlservr.exe is fine; the same port bound to
         powershell.exe or an unknown process is a major red flag.
      3. Port range context — ephemeral ports (>=49152) are low-risk by default;
         registered ports (1024–49151) that aren't in the known table still warrant
         a note if owned by a non-system process.
      4. Dangerous port combinations (unchanged).

    Returns a list of finding strings.
    """
    findings   = []
    open_ports = {lst["port"] for lst in listeners}
    reported   = set()   # avoid double-reporting the same (port, process) pair

    for lst in listeners:
        port            = lst["port"]
        process_raw     = lst.get("process", "Unknown")
        process         = process_raw.lower()
        desc            = _port_description(port)
        key             = (port, process)

        if key in reported:
            continue

        # ── Layer 1: shell / LOLBin owning any listening socket ───────────────
        if process in _SUSPICIOUS_PORT_PROCESSES:
            findings.append(
                f"CRITICAL: Port {port} ({desc}) is bound to '{process_raw}' — "
                f"shell/scripting processes must never own a listening socket "
                f"(likely C2 backdoor or reverse shell)"
            )
            reported.add(key)
            continue

        # ── Layer 2: known port — check expected process owner ────────────────
        if port in EXPECTED_PORT_OWNERS:
            expected = EXPECTED_PORT_OWNERS[port]
            if process not in expected and process not in ("unknown", ""):
                # Unexpected owner — severity depends on port sensitivity
                severity = (
                    "CRITICAL"
                    if port in {445, 1433, 3306, 3389}
                    else "WARNING"
                )
                expected_str = ", ".join(sorted(expected))
                findings.append(
                    f"{severity}: Port {port} ({desc}) bound to unexpected process "
                    f"'{process_raw}' — expected owner(s): {expected_str}"
                )
            elif port in HIGH_RISK_PORTS and port not in BENIGN_PORTS:
                # Correct owner but port is still high-risk — note it
                findings.append(
                    f"Port {port} ({desc}) is open — bound to {process_raw}"
                )
            reported.add(key)
            continue

        # ── Layer 3a: high-risk port without an owner table entry ─────────────
        if port in HIGH_RISK_PORTS and port not in BENIGN_PORTS:
            findings.append(f"Port {port} ({desc}) is open — bound to {process_raw}")
            reported.add(key)
            continue

        # ── Layer 3b: registered port (1024–49151) not in the known table ─────
        # Ephemeral ports (>=49152) are the dynamic/private range — low risk by
        # design (short-lived client sockets).  Only flag registered ports that
        # aren't owned by a core system process.
        if _REGISTERED_PORT_MIN <= port < _EPHEMERAL_PORT_MIN:
            if process not in {"svchost.exe", "system", "lsass.exe"}:
                findings.append(
                    f"Registered port {port} listening — bound to '{process_raw}' "
                    f"(not a known service port; verify this is expected)"
                )
            reported.add(key)

    # ── Dangerous port combinations ───────────────────────────────────────────
    for combo, message in RISKY_PORT_COMBOS:
        if combo.issubset(open_ports):
            findings.append(f"Port combination risk: {message}")

    # ── Unusually high total port count ───────────────────────────────────────
    risky_count = sum(1 for p in open_ports if p in HIGH_RISK_PORTS)
    if risky_count >= 5:
        findings.append(
            f"{risky_count} high-risk ports open simultaneously — significant attack surface"
        )

    return findings


def _port_description(port: int) -> str:
    """Human-readable description of a well-known port number."""
    table = {
        21:   "FTP — cleartext file transfer",
        22:   "SSH — remote shell",
        23:   "Telnet — cleartext remote",
        25:   "SMTP — mail relay",
        53:   "DNS",
        80:   "HTTP — unencrypted web",
        135:  "RPC endpoint mapper",
        139:  "NetBIOS session",
        443:  "HTTPS",
        445:  "SMB — file sharing",
        1433: "MSSQL database",
        3306: "MySQL database",
        3389: "RDP — remote desktop",
        5985: "WinRM HTTP",
        5986: "WinRM HTTPS",
        8080: "HTTP alternate",
        8443: "HTTPS alternate",
    }
    return table.get(port, "known risk port")


def _user_analysis(accounts: list[dict]) -> list[str]:
    """Analyse user accounts for security concerns. Returns finding strings."""
    findings = []
    if not accounts:
        return findings

    admins   = [a for a in accounts if a.get("is_admin")]
    inactive = [a for a in accounts if not a.get("active")]
    never_logged = [a for a in accounts if a.get("last_login", "").lower() == "never"]

    if len(admins) > 2:
        names = ", ".join(a["name"] for a in admins)
        findings.append(
            f"{len(admins)} administrator accounts active ({names}) — "
            "principle of least privilege recommends minimising admin count"
        )

    for acct in never_logged:
        tag = " [ADMIN]" if acct.get("is_admin") else ""
        findings.append(
            f"Account '{acct['name']}'{tag} has never logged in but is still active — "
            "unused accounts should be disabled"
        )

    for acct in inactive:
        if acct.get("is_admin"):
            findings.append(
                f"Inactive admin account '{acct['name']}' exists — "
                "stale admin accounts are a persistence risk"
            )

    return findings


def _firewall_analysis(firewall: dict) -> list[str]:
    """Analyse firewall profile states. Returns finding strings."""
    findings = []
    profiles = firewall.get("profiles", {})

    for profile, info in profiles.items():
        if info.get("state", "ON") == "OFF":
            findings.append(
                f"Firewall profile '{profile}' is DISABLED — "
                "all traffic on this profile is unfiltered"
            )

    rules = firewall.get("rules", {})
    inbound  = rules.get("inbound",  0)
    outbound = rules.get("outbound", 0)

    if inbound < 5:
        findings.append(
            f"Only {inbound} inbound firewall rule(s) — "
            "firewall may not be meaningfully configured"
        )
    if outbound < 5:
        findings.append(
            f"Only {outbound} outbound firewall rule(s) — "
            "consider adding egress filtering"
        )

    return findings


def _overall_risk_score(
    proc_scores: list[int],
    port_findings: list[str],
    user_findings: list[str],
    fw_findings:   list[str],
) -> tuple[int, str]:
    """
    Compute a 0–100 composite risk score and a plain-English rating label.

    Weights:
        Processes  — up to 50 pts (mean of top-3 process scores, scaled)
        Ports      — up to 25 pts (5 pts per finding, capped)
        Users      — up to 15 pts (5 pts per finding, capped)
        Firewall   — up to 10 pts (5 pts per finding, capped)
    """
    # Process component — average of the top 3 scores, scaled to 50
    if proc_scores:
        top3  = sorted(proc_scores, reverse=True)[:3]
        p_raw = sum(top3) / len(top3)          # 0–100
        proc_component = min(50, int(p_raw * 0.5))
    else:
        proc_component = 0

    port_component = min(25, len(port_findings) * 5)
    user_component = min(15, len(user_findings) * 5)
    fw_component   = min(10, len(fw_findings)   * 5)

    total = proc_component + port_component + user_component + fw_component

    if total >= RISK_HIGH:
        label = "HIGH RISK"
    elif total >= RISK_MODERATE:
        label = "MODERATE RISK"
    elif total >= RISK_LOW:
        label = "LOW RISK"
    else:
        label = "CLEAN"

    return total, label


# ─────────────────────────────────────────────────────────────────────────────
#  Report generator
# ─────────────────────────────────────────────────────────────────────────────

def analyse(scan_results: dict):
    """
    Generator — yields lines of a security analysis report one at a time.

    The caller should consume each line and append it to a text widget,
    sleeping briefly between lines to create a streaming effect.

    Args:
        scan_results: dict returned by security_scan.run_full_scan()

    Yields:
        str — one line of the report (no trailing newline)
    """
    proc_data = scan_results.get("processes", {})
    user_data = scan_results.get("users",     {})
    fw_data   = scan_results.get("firewall",  {})

    flagged   = proc_data.get("flagged",   [])
    total     = proc_data.get("total",     0)
    accounts  = user_data.get("accounts",  [])
    listeners = fw_data.get("listeners",   [])

    # ── Score every flagged process ───────────────────────────────────────────
    scored = []
    for proc in flagged:
        score, findings = _score_process(proc)
        scored.append((proc, score, findings))

    scored.sort(key=lambda x: x[1], reverse=True)  # highest risk first

    proc_scores  = [s for _, s, _ in scored]
    port_findings = _port_analysis(listeners)
    user_findings = _user_analysis(accounts)
    fw_findings   = _firewall_analysis(fw_data)
    outliers      = _outlier_memory_processes(flagged)

    overall, label = _overall_risk_score(
        proc_scores, port_findings, user_findings, fw_findings
    )

    ts = scan_results.get("timestamp", "unknown time")

    # ─────────────────────────────────────────────────────────────────────────
    #  Header
    # ─────────────────────────────────────────────────────────────────────────
    yield "═" * 62
    yield "  VITALSCOPE — AI SECURITY ANALYSIS"
    yield f"  Scan timestamp : {ts}"
    yield f"  Overall rating : {label}  ({overall}/100)"
    yield "═" * 62
    yield ""

    # ─────────────────────────────────────────────────────────────────────────
    #  Executive summary
    # ─────────────────────────────────────────────────────────────────────────
    yield "── EXECUTIVE SUMMARY ──────────────────────────────────────"
    yield ""

    risky_procs = [(p, s, f) for p, s, f in scored if s >= 40]

    yield f"  {total} processes running — {len(flagged)} not in trusted whitelist."

    if risky_procs:
        yield (
            f"  {len(risky_procs)} of those score 40+ on the suspicion scale "
            f"and warrant investigation."
        )
    else:
        yield "  No process scored high enough to be considered actively suspicious."

    if len(outliers) > 0:
        names = ", ".join(p["name"] for p in outliers)
        yield f"  Memory outliers detected: {names}."

    yield f"  {len(listeners)} TCP ports listening — "    \
          f"{sum(1 for l in listeners if l['port'] in HIGH_RISK_PORTS)} " \
          f"are classified as high-risk."

    if fw_findings:
        yield f"  Firewall concerns: {len(fw_findings)} issue(s) found."
    else:
        yield "  Firewall: no profile issues detected."

    if user_findings:
        yield f"  User accounts: {len(user_findings)} concern(s) found."

    yield ""

    # ─────────────────────────────────────────────────────────────────────────
    #  Process deep-dive
    # ─────────────────────────────────────────────────────────────────────────
    yield "── PROCESS ANALYSIS ────────────────────────────────────────"
    yield ""

    if not scored:
        yield "  No unknown processes to analyse."
        yield ""
    else:
        shown = [(p, s, f) for p, s, f in scored if s >= 50]
        skipped = len(scored) - len(shown)

        if not shown:
            yield f"  No processes scored 50 or above — {len(scored)} low-risk unknown(s) suppressed."
            yield ""
        else:
            for proc, score, findings in shown:
                name   = proc.get("name", "?")
                mem_kb = proc.get("mem_kb", 0)
                path   = proc.get("path") or "(path unavailable)"
                mb     = mem_kb // 1024

                if score >= 60:
                    risk_label = "[ HIGH ]"
                elif score >= 50:
                    risk_label = "[ MODERATE ]"
                else:
                    risk_label = "[ LOW ]"

                yield f"  {name}  —  score {score}/100  {risk_label}"
                yield f"    PID  : {proc.get('pid', '?')}"
                yield f"    Mem  : {mb} MB"
                yield f"    Path : {path}"

                if findings:
                    yield "    Findings:"
                    for f in findings:
                        yield f"      • {f}"
                else:
                    yield "    No specific concerns beyond whitelist absence."

                yield ""

            if skipped:
                yield f"  ({skipped} process(es) with score < 50 not shown)"
                yield ""

    # ─────────────────────────────────────────────────────────────────────────
    #  Memory outlier section
    # ─────────────────────────────────────────────────────────────────────────
    if outliers:
        yield "── MEMORY OUTLIERS ─────────────────────────────────────────"
        yield ""
        yield (
            "  The following unknown processes consume significantly more "
            "memory than their peers (> 2 standard deviations above mean):"
        )
        yield ""
        for proc in outliers:
            mb = proc.get("mem_kb", 0) // 1024
            yield f"  {proc['name']}  —  {mb} MB"
            yield (
                "    Large memory footprint in an unknown process can indicate "
                "data staging, in-memory payload injection, or crypto-mining."
            )
        yield ""

    # ─────────────────────────────────────────────────────────────────────────
    #  Port analysis
    # ─────────────────────────────────────────────────────────────────────────
    yield "── PORT & NETWORK ANALYSIS ─────────────────────────────────"
    yield ""

    if not port_findings:
        yield "  No port-level concerns detected."
    else:
        for finding in port_findings:
            yield f"  • {finding}"
    yield ""

    # ─────────────────────────────────────────────────────────────────────────
    #  User analysis
    # ─────────────────────────────────────────────────────────────────────────
    yield "── USER ACCOUNT ANALYSIS ───────────────────────────────────"
    yield ""

    if not user_findings:
        yield "  No user account concerns detected."
    else:
        for finding in user_findings:
            yield f"  • {finding}"
    yield ""

    # ────────────────────────────────────────────────────────────────────────────
    #  Firewall analysis
    # ────────────────────────────────────────────────────────────────────────────
    yield "── FIREWALL ANALYSIS ───────────────────────────────────────────"
    yield ""

    if not fw_findings:
        yield "  All firewall profiles are active — no configuration gaps found."
    else:
        for finding in fw_findings:
            yield f"  • {finding}"
    yield ""

    # ────────────────────────────────────────────────────────────────────────────
    #  Prioritised recommendations
    # ────────────────────────────────────────────────────────────────────────────
    yield "── RECOMMENDATIONS ─────────────────────────────────────────────"
    yield ""

    recs = _build_recommendations(scored, port_findings, user_findings, fw_findings, outliers)

    if not recs:
        yield "  No specific actions required at this time."
    else:
        for i, rec in enumerate(recs, 1):
            yield f"  {i}. {rec}"
    yield ""

    yield "═" * 62
    yield "  End of analysis."
    yield "═" * 62


def _build_recommendations(
    scored:        list,
    port_findings: list[str],
    user_findings: list[str],
    fw_findings:   list[str],
    outliers:      list[dict],
) -> list[str]:
    """
    Build a prioritised, deduplicated list of actionable recommendations.

    Ordered by severity: firewall OFF > high-risk processes > port risks >
    memory outliers > user concerns > low-risk processes.
    """
    recs = []

    # Firewall off is the most critical — fix this first
    for f in fw_findings:
        if "DISABLED" in f:
            profile = re.search(r"profile '(\w+)'", f)
            name    = profile.group(1) if profile else "unknown"
            recs.append(
                f"Re-enable the '{name}' firewall profile immediately. "
                f"Run: netsh advfirewall set {name.lower()}profile state on"
            )

    # High-risk processes
    for proc, score, findings in scored:
        if score >= 60:
            name = proc.get("name", "?")
            path = proc.get("path", "")
            recs.append(
                f"Investigate '{name}' urgently (score {score}/100). "
                "Verify its legitimacy, check the publisher signature, "
                f"and confirm why it is running from: {path or 'unknown location'}."
            )
        elif score >= 35:
            name = proc.get("name", "?")
            recs.append(
                f"Review '{name}' (score {score}/100) — it has unusual "
                "characteristics. If you do not recognise it, terminate it and "
                "check startup entries."
            )

    # Port risks
    if any("SMB" in f or "445" in f for f in port_findings):
        recs.append(
            "Close or firewall SMB port 445 if this machine is not a file server. "
            "Run: netsh advfirewall firewall add rule name=\"Block SMB\" "
            "protocol=TCP dir=in localport=445 action=block"
        )
    if any("3389" in f or "RDP" in f for f in port_findings):
        recs.append(
            "Disable RDP (port 3389) if not actively needed, or restrict it to "
            "specific IPs. RDP is among the most commonly brute-forced services."
        )
    if any("Telnet" in f or "21" in f or "FTP" in f for f in port_findings):
        recs.append(
            "Disable FTP (21) and Telnet (23) — both transmit credentials and data "
            "in plaintext. Replace with SFTP/SSH where remote access is needed."
        )

    # Memory outliers
    if outliers:
        names = ", ".join(p["name"] for p in outliers)
        recs.append(
            f"Investigate memory outlier(s): {names}. "
            "Check task manager for sustained high usage and cross-reference "
            "with known-good process lists or VirusTotal."
        )

    # User concerns
    for f in user_findings:
        if "never logged in" in f:
            match = re.search(r"'([^']+)'", f)
            name  = match.group(1) if match else "unknown"
            recs.append(
                f"Disable unused account '{name}': "
                f"net user {name} /active:no"
            )
        elif "administrator accounts" in f:
            recs.append(
                "Reduce the number of administrator accounts. "
                "Create standard user accounts for day-to-day work and reserve "
                "admin accounts for maintenance only."
            )

    # Firewall rule counts
    for f in fw_findings:
        if "inbound firewall rule" in f:
            recs.append(
                "Review and expand inbound firewall rules. A well-configured firewall "
                "should have explicit allow/deny rules for each expected service."
            )

    return recs
