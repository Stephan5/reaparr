#!/usr/bin/env python3
"""Watch Transmission and remove torrents containing unwanted file types.

Talks to Transmission's RPC API (enable "Remote" in Transmission > Settings >
Remote, default port 9091). Stdlib only.

Examples:
    ./reaparr.py --dry-run
    ./reaparr.py --ext exe iso msi --interval 15
    ./reaparr.py --port 9092
    ./reaparr.py --user me --password secret
    ./reaparr.py --sonarr-url http://localhost:8989
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


DEFAULT_EXTS = ["arj", "bat", "cmd", "exe", "iso", "lnk", "lzh", "ps1", "scr", "sh", "vbs", "zipx"]


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


def bad_files(torrent, exts):
    """The file that makes the torrent unwanted: only single-file torrents match."""
    files = [f["name"] for f in torrent.get("files", [])]
    if len(files) == 1 and files[0].lower().endswith(exts):
        return files
    return []


def log(msg, file=sys.stdout):
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{stamp} {msg}", file=file, flush=True)


def sweep(client, sonarr, exts, delete_data, dry_run):
    torrents = client.call("torrent-get", {"fields": ["id", "name", "hashString", "files"]})["torrents"]
    queue = None  # fetched lazily, once per sweep
    for t in torrents:
        hits = bad_files(t, exts)
        if not hits:
            continue
        record = None
        if sonarr:
            if queue is None:
                queue = sonarr.queue_by_hash()
            record = queue.get(t["hashString"].upper())
        via = "; blocklisting in Sonarr" if record else ("; not in Sonarr queue" if sonarr else "")
        action = "WOULD REMOVE" if dry_run else "REMOVING"
        log(f"{action}: {t['name']} [{t['hashString']}]{via}")
        if dry_run:
            continue
        if record:
            sonarr.blocklist(record["id"])
        client.call("torrent-remove", {"ids": [t["id"]], "delete-local-data": delete_data})
        # "success" only means the request was accepted; confirm it is gone.
        left = client.call("torrent-get", {"ids": [t["id"]], "fields": ["id", "status", "errorString"]})["torrents"]
        if left:
            log(f"error: {t['name']} [{t['hashString']}] still in Transmission after removal "
                f"(status {left[0].get('status')}, error {left[0].get('errorString') or 'none'!r})",
                file=sys.stderr)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--ext", nargs="+", default=DEFAULT_EXTS,
                   help="extensions to remove when the torrent is a single file (default: %(default)s)")
    p.add_argument("--host", default="localhost", help="Transmission host (default: localhost)")
    p.add_argument("--port", type=int, default=9091, help="Transmission RPC port (default: 9091)")
    p.add_argument("--url", help="full RPC URL; overrides --host/--port")
    p.add_argument("--user")
    p.add_argument("--password", help="omit to be prompted when needed")
    p.add_argument("--sonarr-url", help="e.g. http://localhost:8989; enables Sonarr blocklisting")
    p.add_argument("--sonarr-api-key", help="omit to use Keychain (account 'sonarr', service 'reaparr')")
    p.add_argument("--interval", type=float, default=30, help="seconds between checks (default: 30)")
    p.add_argument("--keep-data", action="store_true", help="remove the torrent but keep downloaded files")
    p.add_argument("--dry-run", action="store_true", help="report matches without removing anything")
    p.add_argument("--once", action="store_true", help="check once and exit")
    args = p.parse_args()

    exts = tuple("." + e.lstrip(".").lower() for e in args.ext)
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
    log(f"Watching for single-file torrents of {', '.join(exts)} every {args.interval:g}s"
        f"{' (dry run)' if args.dry_run else ''}{', Sonarr enabled' if sonarr else ''}")

    while True:
        try:
            sweep(client, sonarr, exts, not args.keep_data, args.dry_run)
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
