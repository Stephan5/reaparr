#!/usr/bin/env python3
"""Watch Transmission and remove single-file torrents of unwanted file types
that Sonarr or Radarr grabbed, blocklisting the release so they search again.

Torrents that neither of them has in its queue are never touched.

Talks to Transmission's RPC API (enable "Remote" in Transmission > Settings >
Remote, default port 9091). Stdlib only.

Examples:
    ./reaparr.py --sonarr-url http://localhost:8989 --dry-run
    ./reaparr.py --sonarr-url http://localhost:8989 --radarr-url http://localhost:7878
    ./reaparr.py --radarr-url http://localhost:7878 --ext exe iso msi --interval 15
    ./reaparr.py --sonarr-url http://localhost:8989 --user me --password secret
"""
import argparse
import base64
import getpass
import json
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime


DEFAULT_EXTS = ["7z", "arj", "bat", "cmd", "exe", "iso", "lnk", "lzh", "ps1", "scr", "sh", "vbs", "zipx"]


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


class Arr:
    """Sonarr or Radarr: both have the same v3 queue API."""

    def __init__(self, name, url, api_key):
        self.name = name
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
                raise AuthError(f"{self.name} rejected the API key")
            raise
        return json.loads(body) if body else None

    def queue_by_hash(self):
        """Map upper-case torrent hash -> queue record."""
        data = self._request("GET", "/queue", {"page": 1, "pageSize": 1000})
        return {r["downloadId"].upper(): r for r in data["records"] if r.get("downloadId")}

    def blocklist(self, queue_id):
        """Drop the item from the queue and blocklist the release.

        The torrent itself is left to us to remove from Transmission, so
        --keep-data keeps working. Sonarr/Radarr search for a replacement.
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
SKIPPED = set()  # hashes of matching torrents not in any queue, so "SKIPPING" is logged once
RETRY_AFTER = 300  # seconds before a pending removal is reported and re-sent

CHECKING = (1, 2)  # Transmission status: waiting to verify, verifying


def bad_files(torrent, exts):
    """The file that makes the torrent unwanted: only single-file torrents match."""
    files = [f["name"] for f in torrent.get("files", [])]
    if len(files) == 1 and files[0].lower().endswith(exts):
        return files
    return []


def log(msg, file=sys.stdout):
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{stamp} {msg}", file=file, flush=True)


def log_removed(entry, h, now):
    log(f"REMOVED: {entry['name']} [{h}] after {now - entry['since']:.0f}s")


def sweep(client, arrs, exts, delete_data, dry_run):
    torrents = client.call("torrent-get", {"fields": ["id", "name", "hashString", "files", "status"]})["torrents"]
    now = time.monotonic()
    present = {t["hashString"] for t in torrents}
    for h in [h for h in PENDING if h not in present]:
        log_removed(PENDING.pop(h), h, now)
    SKIPPED.intersection_update(present)
    queues = {}  # arr name -> queue, fetched lazily, once per sweep

    def queued(t):
        """(arr, queue record) for the first arr that grabbed this torrent, else (None, None)."""
        for arr in arrs:
            if arr.name not in queues:
                queues[arr.name] = arr.queue_by_hash()
            record = queues[arr.name].get(t["hashString"].upper())
            if record:
                return arr, record
        return None, None

    for t in torrents:
        if not bad_files(t, exts):
            continue
        if t.get("status") in CHECKING:  # mid-verification; Transmission has ignored removal here
            continue
        h = t["hashString"]
        waiting = PENDING.get(h)
        if waiting:
            if now - waiting["sent"] < RETRY_AFTER:
                continue
            # Already blocklisted, so no longer in the queue: just ask Transmission again.
            log(f"error: {t['name']} [{h}] still in Transmission "
                f"{now - waiting['since']:.0f}s after removal was requested "
                f"(status {t.get('status')}); retrying", file=sys.stderr)
            arr = record = None
        else:
            arr, record = queued(t)
            if not record:
                # Not grabbed by Sonarr/Radarr, or not in their queue yet (they poll
                # the client periodically); look again next sweep.
                if h not in SKIPPED:
                    SKIPPED.add(h)
                    log(f"SKIPPING: {t['name']} [{h}]; not in {' or '.join(a.name for a in arrs)} queue")
                continue
            SKIPPED.discard(h)
            action = "WOULD REMOVE" if dry_run else "REMOVING"
            log(f"{action}: {t['name']} [{h}]; blocklisting in {arr.name}")
        if dry_run:
            continue
        if record:
            arr.blocklist(record["id"])
        client.call("torrent-remove", {"ids": [t["id"]], "delete-local-data": delete_data})
        # "success" only means the request was accepted; the next sweep confirms it.
        entry = PENDING.setdefault(h, {"name": t["name"], "since": now})
        entry["sent"] = now


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--ext", nargs="+", default=DEFAULT_EXTS,
                   help="extensions to remove when the torrent is a single file (default: %(default)s)")
    p.add_argument("--host", default="localhost", help="Transmission host (default: localhost)")
    p.add_argument("--port", type=int, default=9091, help="Transmission RPC port (default: 9091)")
    p.add_argument("--url", help="full RPC URL; overrides --host/--port")
    p.add_argument("--user")
    p.add_argument("--password", help="omit to be prompted when needed")
    p.add_argument("--sonarr-url", help="e.g. http://localhost:8989")
    p.add_argument("--sonarr-api-key", help="omit to use Keychain (account 'sonarr', service 'reaparr')")
    p.add_argument("--radarr-url", help="e.g. http://localhost:7878")
    p.add_argument("--radarr-api-key", help="omit to use Keychain (account 'radarr', service 'reaparr')")
    p.add_argument("--interval", type=float, default=10, help="seconds between checks (default: 10)")
    p.add_argument("--keep-data", action="store_true", help="remove the torrent but keep downloaded files")
    p.add_argument("--dry-run", action="store_true", help="report matches without removing anything")
    p.add_argument("--once", action="store_true", help="check once and exit")
    args = p.parse_args()

    exts = tuple("." + e.lstrip(".").lower() for e in args.ext)
    arrs = []
    for name, arr_url, key in [("Sonarr", args.sonarr_url, args.sonarr_api_key),
                               ("Radarr", args.radarr_url, args.radarr_api_key)]:
        if not arr_url:
            continue
        key = key or keychain_password(name.lower())
        if not key and sys.stdin.isatty():
            key = getpass.getpass(f"{name} API key: ")
        if not key:
            sys.exit(f"error: --{name.lower()}-url given but no API key "
                     f"(use --{name.lower()}-api-key or Keychain)")
        arrs.append(Arr(name, arr_url, key))
    if not arrs:
        sys.exit("error: give --sonarr-url and/or --radarr-url; only torrents they grabbed are removed")
    url = args.url or f"http://{args.host}:{args.port}/transmission/rpc"
    client = Transmission(url, args.user, args.password)
    log(f"Watching every {args.interval:g}s for single-file torrents grabbed by "
        f"{' or '.join(a.name for a in arrs)} of {', '.join(exts)}{' (dry run)' if args.dry_run else ''}")

    while True:
        try:
            sweep(client, arrs, exts, not args.keep_data, args.dry_run)
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
