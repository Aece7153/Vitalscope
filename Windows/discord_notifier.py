# discord_notifier.py
# Sends alert embeds to a Discord webhook.
# No bot token needed — just paste a webhook URL into config or the UI.
# All public functions are thread-safe and non-blocking (fire-and-forget threads).

import threading
import time
import json
import urllib.request
from datetime import datetime, timezone


# ── Alert severity levels ─────────────────────────────────────────────────────

SEVERITY_INFO     = "info"
SEVERITY_WARNING  = "warning"
SEVERITY_CRITICAL = "critical"

_EMBED_COLORS = {
    SEVERITY_INFO:     0x00e5ff,   # cyan
    SEVERITY_WARNING:  0xffd600,   # yellow
    SEVERITY_CRITICAL: 0xff3131,   # red
}

# ── Deduplication ─────────────────────────────────────────────────────────────

_sent_cache = {}
_sent_lock  = threading.Lock()
_DEDUP_WINDOW_S = 300   # 5 minutes — same key won't re-fire within this window


def _is_duplicate(key):
    with _sent_lock:
        now  = time.time()
        last = _sent_cache.get(key)
        if last and (now - last) < _DEDUP_WINDOW_S:
            return True
        _sent_cache[key] = now
        cutoff = now - _DEDUP_WINDOW_S
        expired = [k for k, v in _sent_cache.items() if v < cutoff]
        for k in expired:
            del _sent_cache[k]
        return False


# ── Core send function ────────────────────────────────────────────────────────

def send_webhook(webhook_url, title, description, severity=SEVERITY_INFO,
                 fields=None, dedup_key=None):
    """
    POST a Discord embed to the given webhook URL.

    Returns (True, "") on success or (False, reason_string) on any failure
    so callers can surface the exact problem to the user.
    """
    if not webhook_url:
        return False, "Webhook URL is empty — paste it into the MONITOR & DISCORD panel."

    # Discord serves webhooks on several official hostnames.
    # discordapp.com is the legacy host and still works; ptb./canary. are
    # the public/canary builds. Accept all of them.
    _VALID_WEBHOOK_PREFIXES = (
        "https://discord.com/api/webhooks/",
        "https://discordapp.com/api/webhooks/",
        "https://ptb.discord.com/api/webhooks/",
        "https://canary.discord.com/api/webhooks/",
    )
    if not webhook_url.startswith(_VALID_WEBHOOK_PREFIXES):
        return False, (
            f"URL does not look like a Discord webhook.\n"
            f"Expected: https://discord.com/api/webhooks/<id>/<token>\n"
            f"          (discordapp.com / ptb. / canary. hosts also accepted)\n"
            f"Got:      {webhook_url[:80]}"
        )

    if dedup_key and _is_duplicate(dedup_key):
        return True, "deduplicated"   # silently skip, not an error

    icon = {"info": "ℹ️", "warning": "⚠️", "critical": "🚨"}.get(severity, "📡")

    embed = {
        "title":       f"{icon}  {title}",
        "description": description,
        "color":       _EMBED_COLORS.get(severity, 0x00e5ff),
        "timestamp":   datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "footer":      {"text": "Nextion Control Station"},
    }
    if fields:
        embed["fields"] = fields

    payload = json.dumps({"embeds": [embed]}).encode("utf-8")

    try:
        # Discord is fronted by Cloudflare and blocks the default
        # "Python-urllib/3.x" User-Agent (Cloudflare error 1010).
        # Discord's API docs also require a descriptive UA on all requests.
        req = urllib.request.Request(
            webhook_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent":
                    "NextionControlStation (https://github.com/local, 1.0)",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            if resp.status in (200, 204):
                return True, ""
            body = resp.read().decode(errors="ignore")
            return False, f"Discord returned HTTP {resp.status}: {body[:200]}"

    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="ignore")
        # Discord sends JSON error bodies — try to surface the message field
        try:
            detail = json.loads(body).get("message", body)
        except Exception:
            detail = body[:300]
        return False, f"HTTP {e.code} from Discord: {detail}"

    except urllib.error.URLError as e:
        return False, f"Network error — could not reach Discord: {e.reason}"

    except Exception as e:
        return False, f"Unexpected error: {type(e).__name__}: {e}"


def send_async(webhook_url, **kwargs):
    """Fire-and-forget — posts in a daemon thread so callers never block."""
    if not webhook_url:
        return
    threading.Thread(
        target=send_webhook, args=(webhook_url,), kwargs=kwargs, daemon=True
    ).start()


# ── Convenience alert builders ────────────────────────────────────────────────

def alert_resource(webhook_url, resource, value, threshold):
    """CRITICAL alert when a system resource exceeds its threshold."""
    send_async(
        webhook_url,
        title=f"High {resource} Usage",
        description=(
            f"**{resource}** is at **{value:.1f}%**, "
            f"exceeding the alert threshold of {threshold:.0f}%."
        ),
        severity=SEVERITY_CRITICAL,
        dedup_key=f"resource_{resource}_{int(value // 10) * 10}",
    )


def alert_high_risk_process(webhook_url, proc):
    """
    WARNING/CRITICAL alert for a process that scored above the risk threshold.

    proc dict must contain the standard fields from scan_processes() PLUS
    the heuristic fields added by heuristic.score_process():
        score   (int)   0–100
        risk    (str)   "low" | "medium" | "high"
        reasons (list)  human-readable signal descriptions
    """
    name    = proc.get("name", "Unknown")
    pid     = proc.get("pid", 0)
    path    = proc.get("path") or "Path unavailable"
    score   = proc.get("score", 0)
    risk    = proc.get("risk", "medium").lower()
    reasons = proc.get("reasons", [])
    mem_mb  = (proc.get("mem_kb") or 0) // 1024

    severity = SEVERITY_CRITICAL if risk == "high" else SEVERITY_WARNING

    # Format reasons as a numbered list for the embed
    reasons_str = "\n".join(f"{i+1}. {r}" for i, r in enumerate(reasons)) or "No specific signals"

    send_async(
        webhook_url,
        title=f"High-Risk Process Detected — Score {score}/100",
        description=(
            f"Heuristic analysis flagged **{name}** as **{risk.upper()} RISK**.\n"
            f"This process was not in the known-safe whitelist and triggered "
            f"multiple suspicious signals."
        ),
        severity=severity,
        fields=[
            {"name": "Process",       "value": name,         "inline": True},
            {"name": "PID",           "value": str(pid),     "inline": True},
            {"name": "Risk Score",    "value": f"{score}/100 ({risk.upper()})", "inline": True},
            {"name": "Memory",        "value": f"{mem_mb} MB", "inline": True},
            {"name": "Executable",    "value": f"`{path}`",  "inline": False},
            {"name": "Heuristic Signals", "value": reasons_str, "inline": False},
        ],
        dedup_key=f"heuristic_{name}_{pid}",
    )


def alert_security_summary(webhook_url, high_risk_count, risky_ports, open_ports):
    """Periodic security scan summary."""
    severity  = SEVERITY_CRITICAL if (high_risk_count > 0 or risky_ports) else SEVERITY_INFO
    risky_str = ", ".join(str(p) for p in risky_ports[:10]) or "None"
    send_async(
        webhook_url,
        title="Security Scan Complete",
        description="Periodic heuristic + firewall scan finished.",
        severity=severity,
        fields=[
            {"name": "High-Risk Processes", "value": str(high_risk_count), "inline": True},
            {"name": "Open Ports",          "value": str(open_ports),      "inline": True},
            {"name": "High-Risk Ports",     "value": risky_str,            "inline": False},
        ],
        dedup_key=f"scan_summary_{high_risk_count}_{len(risky_ports)}",
    )