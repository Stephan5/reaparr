#!/usr/bin/env python3
"""Watch Transmission and remove torrents containing unwanted file types.

Talks to Transmission's RPC API (enable "Remote" in Transmission > Settings >
Remote, default port 9091). Stdlib only.

Examples:
    ./reaparr.py --dry-run
    ./reaparr.py --dangerous-ext exe iso msi --suspicious-ext zip rar --interval 15
    ./reaparr.py --port 9092
    ./reaparr.py --user me --password secret
    ./reaparr.py --sonarr-url http://localhost:8989
"""
import argparse
import base64
import getpass
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime


# Removed on sight.
DANGEROUS_EXTS = ["arj", "bat", "cmd", "exe", "iso", "lnk", "lzh", "ps1", "scr", "sh", "vbs", "zipx"]
# Plausibly legitimate on their own, so removed only with a second piece of
# evidence: a TV release name (see looks_like_release) or a Sonarr grab.
SUSPICIOUS_EXTS = ["7z", "rar", "zip"]

# Release-name markers, not show names: SxxEyy, resolution, video codec.
RELEASE_RE = re.compile(
    r"\bS\d{1,2}E\d{1,3}\b"
    r"|\b(?:480|576|720|1080|2160)[pi]\b"
    r"|\b[xh]\.?26[45]\b"
    r"|\b(?:hevc|av1|xvid)\b",
    re.IGNORECASE,
)


class AuthError(Exception):
    pass


def keychain_password(account, service="reaparr"):
    """Look up a secret saved with:
    security add-generic-password -a ACCOUNT -s SERVICE -w
    """
    try:
        out = subprocess.run(
            ["security", "find-generic-password", "-a", account, "-s", service, "-w"],
            capture_output=True, text=True, check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return out.stdout.rstrip("\n")


class Transmission:
    def __init__(self, url, user=None, password=None):
        self.url = url
        self.session_id = ""
        self.auth = None
        if user:
            if password is None:
                password = keychain_password(user)
            if password is None and sys.stdin.isatty():
                password = getpass.getpass(f"Transmission password for {user}: ")
            self.set_credentials(user, password or "")

    def set_credentials(self, user, password):
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.auth = f"Basic {token}"

    def prompt_credentials(self):
        user = input("Transmission username: ")
        self.set_credentials(user, getpass.getpass("Transmission password: "))

    def call(self, method, arguments=None):
        body = json.dumps({"method": method, "arguments": arguments or {}}).encode()
        prompted = False
        for _ in range(3):  # retry after a 409 session-id handshake or a 401 prompt
            req = urllib.request.Request(self.url, data=body)
            req.add_header("X-Transmission-Session-Id", self.session_id)
            if self.auth:
                req.add_header("Authorization", self.auth)
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    result = json.load(resp)
            except urllib.error.HTTPError as e:
                if e.code == 409:
                    self.session_id = e.headers.get("X-Transmission-Session-Id", "")
                    continue
                if e.code == 401:
                    if self.auth or prompted or not sys.stdin.isatty():
                        raise AuthError("authentication failed (check --user/--password)")
                    self.prompt_credentials()
                    prompted = True
                    continue
                raise
            if result.get("result") != "success":
                raise RuntimeError(f"{method} failed: {result.get('result')}")
            return result["arguments"]
        raise RuntimeError("could not negotiate Transmission session id")


class Sonarr:
    def __init__(self, url, api_key):
        self.base = url.rstrip("/") + "/api/v3"
        self.api_key = api_key

    def _request(self, method, path, params=None):
        url = f"{self.base}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, method=method)
        req.add_header("X-Api-Key", self.api_key)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise AuthError("Sonarr rejected the API key")
            raise
        return json.loads(body) if body else None

    def queue_by_hash(self):
        """Map upper-case torrent hash -> Sonarr queue record."""
        data = self._request("GET", "/queue", {"page": 1, "pageSize": 1000})
        return {r["downloadId"].upper(): r for r in data["records"] if r.get("downloadId")}

    def blocklist(self, queue_id):
        """Drop the item from the queue and blocklist the release.

        The torrent itself is left to us to remove from Transmission, so
        --keep-data keeps working. Sonarr searches for a replacement.
        """
        self._request("DELETE", f"/queue/{queue_id}", {
            "removeFromClient": "false",
            "blocklist": "true",
            "skipRedownload": "false",
        })


# The Mac app handles torrent-remove asynchronously and can take anywhere from
# seconds to minutes. Torrents we have asked to remove are tracked here (by hash)
# until they disappear, rather than being asked again every sweep.
PENDING = {}  # hash -> {"name", "since" (first request), "sent" (latest request)}
RETRY_AFTER = 300  # seconds before a pending removal is reported and re-sent

CHECKING = (1, 2)  # Transmission status: waiting to verify, verifying


def bad_files(torrent, exts):
    """The file that makes the torrent unwanted: only single-file torrents match."""
    files = [f["name"] for f in torrent.get("files", [])]
    if len(files) == 1 and files[0].lower().endswith(exts):
        return files
    return []


def looks_like_release(name):
    """True for names like 'Show S06E06 Title 1080p WEB H264 - GRP.zip'."""
    return bool(RELEASE_RE.search(name))


def log(msg, file=sys.stdout):
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{stamp} {msg}", file=file, flush=True)


def log_removed(entry, h, now):
    log(f"REMOVED: {entry['name']} [{h}] after {now - entry['since']:.0f}s")


def sweep(client, sonarr, dangerous, delete_data, dry_run, suspicious=()):
    torrents = client.call("torrent-get", {"fields": ["id", "name", "hashString", "files", "status"]})["torrents"]
    now = time.monotonic()
    present = {t["hashString"] for t in torrents}
    for h in [h for h in PENDING if h not in present]:
        log_removed(PENDING.pop(h), h, now)
    queue = None  # fetched lazily, once per sweep

    def queued(t):
        nonlocal queue
        if not sonarr:
            return None
        if queue is None:
            queue = sonarr.queue_by_hash()
        return queue.get(t["hashString"].upper())

    for t in torrents:
        hits = bad_files(t, dangerous)
        sus = [] if hits else bad_files(t, suspicious)
        if not (hits or sus):
            continue
        if t.get("status") in CHECKING:  # mid-verification; Transmission has ignored removal here
            continue
        waiting = PENDING.get(t["hashString"])
        if waiting and now - waiting["sent"] < RETRY_AFTER:
            continue
        why = ""
        if sus:
            if looks_like_release(f"{t['name']} {sus[0]}"):
                why = " (suspicious, release name)"
            elif queued(t):
                why = " (suspicious, in Sonarr queue)"
            elif waiting:  # already judged bad; blocklisting has since dropped it from the queue
                why = " (suspicious)"
            else:
                continue  # no second piece of evidence: leave it alone
        if waiting:
            log(f"error: {t['name']} [{t['hashString']}] still in Transmission "
                f"{now - waiting['since']:.0f}s after removal was requested "
                f"(status {t.get('status')}); retrying", file=sys.stderr)
        record = queued(t)
        via = "; blocklisting in Sonarr" if record else ("; not in Sonarr queue" if sonarr else "")
        action = "WOULD REMOVE" if dry_run else "REMOVING"
        log(f"{action}: {t['name']} [{t['hashString']}]{why}{via}")
        if dry_run:
            continue
        if record:
            sonarr.blocklist(record["id"])
        client.call("torrent-remove", {"ids": [t["id"]], "delete-local-data": delete_data})
        # "success" only means the request was accepted; the next sweep confirms it.
        entry = PENDING.setdefault(t["hashString"], {"name": t["name"], "since": now})
        entry["sent"] = now


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dangerous-ext", "--ext", nargs="*", default=DANGEROUS_EXTS,
                   help="extensions to remove when the torrent is a single file (default: %(default)s)")
    p.add_argument("--suspicious-ext", nargs="*", default=SUSPICIOUS_EXTS,
                   help="extensions to remove when the torrent is a single file AND there is a second piece "
                        "of evidence: its name looks like a TV release (SxxEyy, resolution or codec) or it "
                        "is in Sonarr's queue (default: %(default)s)")
    p.add_argument("--host", default="localhost", help="Transmission host (default: localhost)")
    p.add_argument("--port", type=int, default=9091, help="Transmission RPC port (default: 9091)")
    p.add_argument("--url", help="full RPC URL; overrides --host/--port")
    p.add_argument("--user")
    p.add_argument("--password", help="omit to be prompted when needed")
    p.add_argument("--sonarr-url", help="e.g. http://localhost:8989; enables Sonarr blocklisting")
    p.add_argument("--sonarr-api-key", help="omit to use Keychain (account 'sonarr', service 'reaparr')")
    p.add_argument("--interval", type=float, default=10, help="seconds between checks (default: 10)")
    p.add_argument("--keep-data", action="store_true", help="remove the torrent but keep downloaded files")
    p.add_argument("--dry-run", action="store_true", help="report matches without removing anything")
    p.add_argument("--once", action="store_true", help="check once and exit")
    args = p.parse_args()

    def norm(exts):
        return tuple("." + e.lstrip(".").lower() for e in exts)
    dangerous = norm(args.dangerous_ext)
    suspicious = tuple(e for e in norm(args.suspicious_ext) if e not in dangerous)
    url = args.url or f"http://{args.host}:{args.port}/transmission/rpc"
    client = Transmission(url, args.user, args.password)
    sonarr = None
    if args.sonarr_url:
        key = args.sonarr_api_key or keychain_password("sonarr")
        if not key and sys.stdin.isatty():
            key = getpass.getpass("Sonarr API key: ")
        if not key:
            sys.exit("error: --sonarr-url given but no API key (use --sonarr-api-key or Keychain)")
        sonarr = Sonarr(args.sonarr_url, key)
    log(f"Watching every {args.interval:g}s for single-file torrents of dangerous: "
        f"{', '.join(dangerous) or 'none'}; suspicious: {', '.join(suspicious) or 'none'}"
        f"{' (dry run)' if args.dry_run else ''}{', Sonarr enabled' if sonarr else ''}")

    while True:
        try:
            sweep(client, sonarr, dangerous, not args.keep_data, args.dry_run, suspicious)
        except AuthError as e:
            log(f"error: {e}", file=sys.stderr)
            sys.exit(1)
        except (urllib.error.URLError, RuntimeError, OSError) as e:
            log(f"error: {e}", file=sys.stderr)
        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
