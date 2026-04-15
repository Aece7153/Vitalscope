# network_utils.py
# Pure network helper functions — no GUI, no serial dependencies.
# All functions are safe to call from background threads.
#
# Note: get_dns_servers() is Windows-only (uses ipconfig /all).

import socket
import subprocess
import re
import time
import urllib.request  # moved to module level for clarity and import-time error detection

from config import PING_HOST


def get_network_quality():
    """
    Measure network quality with 4 TCP probes to PING_HOST:53 (Google DNS).

    Each probe is scored individually based on round-trip time:
        < 20 ms  → 25 pts   |  < 50 ms  → 20 pts
        < 100 ms → 15 pts   |  < 200 ms → 10 pts
        ≥ 200 ms →  5 pts   |  failure  →  0 pts

    Returns:
        score    (int)        — 0–100 composite quality score
        avg_ms   (float|None) — mean latency across successful probes, or None
        loss_pct (int)        — percentage of probes that failed (0, 25, 50, 75, or 100)
    """
    PROBES = 4

    # Latency thresholds (ms) → points per probe
    SCORE_TABLE = [(20, 25), (50, 20), (100, 15), (200, 10)]

    results = []
    for _ in range(PROBES):
        try:
            start = time.perf_counter()
            with socket.create_connection((PING_HOST, 53), timeout=1.0):
                pass
            results.append((time.perf_counter() - start) * 1000)
        except Exception:
            results.append(None)

    successes = [r for r in results if r is not None]
    loss_pct  = int(((PROBES - len(successes)) / PROBES) * 100)
    avg_ms    = round(sum(successes) / len(successes), 1) if successes else None

    def _probe_score(ms):
        if ms is None:
            return 0
        for threshold, pts in SCORE_TABLE:
            if ms < threshold:
                return pts
        return 5  # ≥ 200 ms

    score = sum(_probe_score(r) for r in results)
    return score, avg_ms, loss_pct


def check_internet():
    """
    Quick connectivity check — returns True if Google DNS (8.8.8.8:53) is reachable.

    Uses a 3-second TCP timeout. Suitable for a fast online/offline determination.
    The socket is always closed after the probe, even on failure.
    """
    try:
        with socket.create_connection(("8.8.8.8", 53), timeout=3):
            return True
    except Exception:
        return False


def get_dns_servers():
    """
    Return the first active DNS server IP found in 'ipconfig /all' output.

    Windows-only. Returns "N/A" if none can be found or the command fails.
    """
    try:
        result  = subprocess.run(
            ["ipconfig", "/all"], capture_output=True, text=True, timeout=5
        )
        matches = re.findall(r"DNS Servers.*?:\s*([\d.]+)", result.stdout)
        if matches:
            return matches[0]
    except Exception:
        pass
    return "N/A"


def get_speed_mbps(stop_flag=None):
    """
    Estimate download speed by streaming a 10 MB test file in 32 KB chunks.

    Tries multiple fallback URLs in order and returns the first successful
    measurement. Aborts early if stop_flag() returns True (used for page changes).

    Upload speed is estimated as 30% of download (no real upload test is performed).

    Args:
        stop_flag: optional callable — if it returns True, the download aborts
                   and (0.0, 0.0) is returned immediately.

    Returns:
        download_mbps (float) — measured download speed in Mbit/s
        upload_mbps   (float) — estimated upload speed (0.3 × download)
    """
    TEST_URLS = [
        "http://speedtest.tele2.net/10MB.zip",
        "http://proof.ovh.net/files/10Mb.dat",
        "http://ipv4.download.thinkbroadband.com/10MB.zip",
        "http://speedtest.ftp.otenet.gr/files/test10Mb.db",
    ]
    CHUNK_SIZE = 32 * 1024        # bytes read per iteration
    MAX_BYTES  = 4 * 1024 * 1024  # stop after 4 MB to keep the test short

    for url in TEST_URLS:
        try:
            start = time.time()
            total = 0
            req   = urllib.request.urlopen(url, timeout=8)

            while total < MAX_BYTES:
                if stop_flag and stop_flag():
                    return 0.0, 0.0
                chunk = req.read(CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)

            elapsed = time.time() - start

            # Only report if we received enough data for a meaningful result
            if elapsed > 0 and total > 100_000:
                dl = round((total * 8) / (elapsed * 1_000_000), 1)  # bits → Mbit/s
                return dl, round(dl * 0.3, 1)

        except Exception:
            continue  # try the next URL on any failure

    return 0.0, 0.0  # all URLs failed


def count_local_devices():
    """
    Count approximate active devices on the LAN by parsing 'arp -a'.

    Counts unique IP addresses listed as 'dynamic' entries, which correspond to
    recently-seen devices. Static entries (e.g. gateways) are excluded.

    Returns 0 on any error.
    """
    try:
        result = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=5
        )
        ips = re.findall(
            r"(\d+\.\d+\.\d+\.\d+)\s+[\da-fA-F-:]+\s+dynamic", result.stdout
        )
        return len(set(ips))
    except Exception:
        return 0


def check_port(host: str, port: int, timeout: float = 1.5) -> bool:
    """
    Test whether a TCP port is open on the given host.

    Args:
        host:    target hostname or IP address
        port:    TCP port number to probe
        timeout: connection timeout in seconds (default 1.5)

    Returns:
        True if the connection succeeds, False otherwise.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False
