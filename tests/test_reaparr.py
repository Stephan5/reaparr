import io
import json
import os
import sys
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import reaparr  # noqa: E402

EXTS = (".exe", ".iso")


def http_error(code, headers=None):
    return urllib.error.HTTPError("http://x", code, "err", headers or {}, io.BytesIO())


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def json_response(obj):
    return FakeResponse(json.dumps(obj).encode())


class BadFilesTest(unittest.TestCase):
    def test_single_matching_file(self):
        self.assertEqual(reaparr.bad_files({"files": [{"name": "setup.EXE"}]}, EXTS), ["setup.EXE"])

    def test_single_non_matching_file(self):
        self.assertEqual(reaparr.bad_files({"files": [{"name": "movie.mkv"}]}, EXTS), [])

    def test_multi_file_torrent_never_matches(self):
        t = {"files": [{"name": "a.exe"}, {"name": "b.mkv"}]}
        self.assertEqual(reaparr.bad_files(t, EXTS), [])

    def test_no_files_yet(self):
        self.assertEqual(reaparr.bad_files({}, EXTS), [])
        self.assertEqual(reaparr.bad_files({"files": []}, EXTS), [])


class LooksLikeReleaseTest(unittest.TestCase):
    def test_release_names(self):
        for name in [
            "Abbott Elementary S06E06 Competition 1080p WEB H264 - CAKES.zip",
            "Scrubs 2026 S02E08 My Emergency 1080p WEB H264 - ETHEL.zip",
            "Show.S1E2.zip",
            "Some.Show.720p.HDTV.zip",
            "something x265.zip",
            "thing.HEVC-GRP.zip",
        ]:
            self.assertTrue(reaparr.looks_like_release(name), name)

    def test_ordinary_names(self):
        for name in ["photos.zip", "fonts-2026.zip", "Season 1 artwork.zip", "1080.zip", "S06.zip"]:
            self.assertFalse(reaparr.looks_like_release(name), name)


class KeychainTest(unittest.TestCase):
    def test_returns_stripped_secret(self):
        with mock.patch("subprocess.run", return_value=mock.Mock(stdout="s3cret\n")) as run:
            self.assertEqual(reaparr.keychain_password("me"), "s3cret")
        self.assertIn("me", run.call_args[0][0])

    def test_missing_entry_or_binary(self):
        import subprocess
        for exc in (subprocess.CalledProcessError(44, "security"), FileNotFoundError()):
            with mock.patch("subprocess.run", side_effect=exc):
                self.assertIsNone(reaparr.keychain_password("me"))


class TransmissionTest(unittest.TestCase):
    def test_basic_auth_header(self):
        c = reaparr.Transmission("http://x", "user", "pw")
        self.assertEqual(c.auth, "Basic dXNlcjpwdw==")

    def test_no_user_no_auth(self):
        self.assertIsNone(reaparr.Transmission("http://x").auth)

    def test_success_returns_arguments(self):
        c = reaparr.Transmission("http://x")
        with mock.patch("urllib.request.urlopen",
                        return_value=json_response({"result": "success", "arguments": {"a": 1}})):
            self.assertEqual(c.call("session-get"), {"a": 1})

    def test_409_handshake_retries_with_session_id(self):
        c = reaparr.Transmission("http://x")
        seen = []

        def fake(req, timeout):
            seen.append(req.get_header("X-transmission-session-id"))
            if len(seen) == 1:
                raise http_error(409, {"X-Transmission-Session-Id": "abc"})
            return json_response({"result": "success", "arguments": {}})

        with mock.patch("urllib.request.urlopen", side_effect=fake):
            c.call("x")
        self.assertEqual(seen, ["", "abc"])

    def test_endless_409_gives_up(self):
        c = reaparr.Transmission("http://x")
        with mock.patch("urllib.request.urlopen", side_effect=lambda *a, **k: (_ for _ in ()).throw(http_error(409))):
            with self.assertRaises(RuntimeError):
                c.call("x")

    def test_401_with_credentials_raises_auth_error(self):
        c = reaparr.Transmission("http://x", "u", "p")
        with mock.patch("urllib.request.urlopen", side_effect=http_error(401)):
            with self.assertRaises(reaparr.AuthError):
                c.call("x")

    def test_401_without_tty_raises_auth_error(self):
        c = reaparr.Transmission("http://x")
        with mock.patch("urllib.request.urlopen", side_effect=http_error(401)), \
                mock.patch("sys.stdin.isatty", return_value=False):
            with self.assertRaises(reaparr.AuthError):
                c.call("x")

    def test_401_with_tty_prompts_then_succeeds(self):
        c = reaparr.Transmission("http://x")
        responses = [http_error(401), json_response({"result": "success", "arguments": {"ok": True}})]

        def fake(req, timeout):
            r = responses.pop(0)
            if isinstance(r, Exception):
                raise r
            return r

        with mock.patch("urllib.request.urlopen", side_effect=fake), \
                mock.patch("sys.stdin.isatty", return_value=True), \
                mock.patch("builtins.input", return_value="u"), \
                mock.patch("getpass.getpass", return_value="p"):
            self.assertEqual(c.call("x"), {"ok": True})
        self.assertTrue(c.auth.startswith("Basic "))

    def test_other_http_error_propagates(self):
        c = reaparr.Transmission("http://x")
        with mock.patch("urllib.request.urlopen", side_effect=http_error(500)):
            with self.assertRaises(urllib.error.HTTPError):
                c.call("x")

    def test_non_success_result_raises(self):
        c = reaparr.Transmission("http://x")
        with mock.patch("urllib.request.urlopen", return_value=json_response({"result": "nope"})):
            with self.assertRaisesRegex(RuntimeError, "nope"):
                c.call("x")


class SonarrTest(unittest.TestCase):
    def setUp(self):
        self.s = reaparr.Sonarr("http://sonarr:8989/", "KEY")

    def test_base_strips_trailing_slash(self):
        self.assertEqual(self.s.base, "http://sonarr:8989/api/v3")

    def test_queue_by_hash_uppercases_and_skips_missing(self):
        data = {"records": [{"id": 1, "downloadId": "abc"}, {"id": 2}, {"id": 3, "downloadId": ""}]}
        with mock.patch.object(self.s, "_request", return_value=data):
            self.assertEqual(self.s.queue_by_hash(), {"ABC": {"id": 1, "downloadId": "abc"}})

    def test_blocklist_request(self):
        with mock.patch.object(self.s, "_request") as req:
            self.s.blocklist(7)
        method, path, params = req.call_args[0]
        self.assertEqual((method, path), ("DELETE", "/queue/7"))
        self.assertEqual(params["blocklist"], "true")
        self.assertEqual(params["removeFromClient"], "false")

    def test_request_sends_api_key_and_query(self):
        captured = {}

        def fake(req, timeout):
            captured["req"] = req
            return FakeResponse(b'{"x": 1}')

        with mock.patch("urllib.request.urlopen", side_effect=fake):
            self.assertEqual(self.s._request("GET", "/queue", {"page": 1}), {"x": 1})
        r = captured["req"]
        self.assertEqual(r.full_url, "http://sonarr:8989/api/v3/queue?page=1")
        self.assertEqual(r.get_header("X-api-key"), "KEY")
        self.assertEqual(r.get_method(), "GET")

    def test_empty_body_returns_none(self):
        with mock.patch("urllib.request.urlopen", return_value=FakeResponse(b"")):
            self.assertIsNone(self.s._request("DELETE", "/queue/1"))

    def test_401_raises_auth_error(self):
        with mock.patch("urllib.request.urlopen", side_effect=http_error(401)):
            with self.assertRaises(reaparr.AuthError):
                self.s._request("GET", "/queue")


class SweepBase(unittest.TestCase):
    def setUp(self):
        self.torrents = [
            {"id": 1, "name": "bad", "hashString": "aa11", "files": [{"name": "x.exe"}]},
            {"id": 2, "name": "good", "hashString": "bb22", "files": [{"name": "x.mkv"}]},
            {"id": 3, "name": "pack", "hashString": "cc33", "files": [{"name": "a.exe"}, {"name": "b.txt"}]},
        ]
        reaparr.PENDING.clear()
        self.now = 1000.0
        self.log = mock.Mock()  # accumulates across sweeps
        self.client = mock.Mock()
        self.client.call.side_effect = self.fake_call
        self.removals = lambda: [c for c in self.client.call.call_args_list if c[0][0] == "torrent-remove"]

    def fake_call(self, method, args=None):
        """Transmission stand-in: torrent-remove really removes unless self.stuck."""
        if method == "torrent-get":
            ids = (args or {}).get("ids")
            return {"torrents": [t for t in self.torrents if ids is None or t["id"] in ids]}
        if method == "torrent-remove" and not getattr(self, "stuck", False):
            self.torrents[:] = [t for t in self.torrents if t["id"] not in args["ids"]]
        return {}

    def run_sweep(self, sonarr=None, delete_data=True, dry_run=False, suspicious=(".7z", ".rar", ".zip")):
        def sleep(seconds):
            self.now += seconds
            self.slept += seconds
        self.slept = 0
        with mock.patch("reaparr.log", self.log), \
                mock.patch("reaparr.time.monotonic", side_effect=lambda: self.now), \
                mock.patch("reaparr.time.sleep", side_effect=sleep):
            reaparr.sweep(self.client, sonarr, EXTS, delete_data, dry_run, suspicious)


class SweepTest(SweepBase):
    def test_removes_only_matching(self):
        self.run_sweep()
        calls = self.removals()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0][1], {"ids": [1], "delete-local-data": True})

    def test_keep_data(self):
        self.run_sweep(delete_data=False)
        self.assertFalse(self.removals()[0][0][1]["delete-local-data"])

    def test_dry_run_removes_nothing(self):
        sonarr = mock.Mock()
        sonarr.queue_by_hash.return_value = {"AA11": {"id": 9}}
        self.run_sweep(sonarr=sonarr, dry_run=True)
        self.assertEqual(self.removals(), [])
        sonarr.blocklist.assert_not_called()

    def test_blocklists_in_sonarr_before_removing(self):
        order = []
        sonarr = mock.Mock()
        sonarr.queue_by_hash.return_value = {"AA11": {"id": 9}}
        sonarr.blocklist.side_effect = lambda i: order.append(("blocklist", i))
        self.client.call.side_effect = lambda m, a=None: (
            order.append((m, a)) if m == "torrent-remove" else None) or self.fake_call(m, a)
        self.run_sweep(sonarr=sonarr)
        self.assertEqual(order[0], ("blocklist", 9))
        self.assertEqual(order[1][0], "torrent-remove")

    def test_skips_torrent_while_verifying_then_removes(self):
        self.torrents[0]["status"] = 2
        self.run_sweep()
        self.assertEqual(self.removals(), [])
        self.torrents[0]["status"] = 4
        self.run_sweep()
        self.assertEqual(len(self.removals()), 1)

    def sweep_at(self, t):
        self.now = 1000.0 + t
        self.run_sweep()

    def logged(self):
        return [c[0][0] for c in self.log.call_args_list]

    def test_removal_confirmed_on_next_sweep(self):
        self.run_sweep()
        self.assertEqual(len(self.logged()), 1)  # only REMOVING
        self.assertIn("aa11", reaparr.PENDING)
        self.assertEqual(self.slept, 0)
        self.sweep_at(10)
        self.assertEqual(self.logged()[-1], "REMOVED: bad [aa11] after 10s")
        self.assertEqual(reaparr.PENDING, {})

    def test_no_stop_call(self):
        self.run_sweep()
        self.assertNotIn("torrent-stop", [c[0][0] for c in self.client.call.call_args_list])

    def test_logs_time_taken_once_removal_is_seen(self):
        self.stuck = True
        self.sweep_at(0)
        self.stuck = False
        self.torrents[:] = [t for t in self.torrents if t["id"] != 1]  # Transmission catches up
        self.sweep_at(41)
        self.assertEqual(self.logged()[-1], "REMOVED: bad [aa11] after 41s")
        self.assertEqual(reaparr.PENDING, {})
        self.sweep_at(71)
        self.assertEqual(len(self.logged()), 2)  # nothing further

    def test_pending_removal_is_not_resent_each_sweep(self):
        self.stuck = True
        self.sweep_at(0)
        self.sweep_at(30)
        self.sweep_at(60)
        self.assertEqual(len(self.removals()), 1)
        self.assertEqual(len(self.log.call_args_list), 1)

    def test_pending_removal_retried_with_error_after_timeout(self):
        self.stuck = True
        self.torrents[0]["status"] = 4
        self.sweep_at(0)
        self.sweep_at(reaparr.RETRY_AFTER + 1)
        self.assertEqual(len(self.removals()), 2)
        self.assertIn("still in Transmission 301s after removal was requested", self.logged()[1])
        self.assertEqual(self.log.call_args_list[1][1], {"file": sys.stderr})

    def test_dry_run_leaves_nothing_pending(self):
        self.run_sweep(dry_run=True)
        self.assertEqual(reaparr.PENDING, {})

    def test_logs_hash_on_removal(self):
        self.run_sweep()
        self.assertIn("[aa11]", self.log.call_args_list[0][0][0])

    def test_not_in_sonarr_queue_still_removed(self):
        sonarr = mock.Mock()
        sonarr.queue_by_hash.return_value = {}
        self.run_sweep(sonarr=sonarr)
        sonarr.blocklist.assert_not_called()
        self.assertEqual(len(self.removals()), 1)

    def test_queue_fetched_once_and_lazily(self):
        sonarr = mock.Mock()
        sonarr.queue_by_hash.return_value = {}
        self.torrents.append({"id": 4, "name": "bad2", "hashString": "dd44", "files": [{"name": "y.iso"}]})
        self.run_sweep(sonarr=sonarr)
        sonarr.queue_by_hash.assert_called_once()

        sonarr.reset_mock()
        self.torrents[:] = [self.torrents[1]]
        self.run_sweep(sonarr=sonarr)
        sonarr.queue_by_hash.assert_not_called()


class SuspiciousSweepTest(SweepBase):
    """Suspicious extensions need a release name or a Sonarr grab as well."""

    def add(self, id_, name, h, ext=".zip"):
        self.torrents.append({"id": id_, "name": name, "hashString": h, "files": [{"name": name + ext}]})

    def test_each_default_suspicious_ext(self):
        for i, ext in enumerate((".7z", ".rar", ".zip")):
            self.add(10 + i, f"Show S01E0{i} 1080p", f"e{i}", ext)
            self.add(20 + i, f"photos {i}", f"f{i}", ext)
        self.run_sweep()
        self.assertEqual(self.removed_ids(), [1, 10, 11, 12])

    def test_logs_the_evidence(self):
        self.torrents[:] = []
        self.add(4, "Show S01E01 720p", "dd44")
        self.add(5, "photos", "ee55")
        sonarr = mock.Mock()
        sonarr.queue_by_hash.return_value = {"EE55": {"id": 9}}
        self.run_sweep(sonarr=sonarr, dry_run=True)
        lines = [c[0][0] for c in self.log.call_args_list]
        self.assertIn("(suspicious, release name); not in Sonarr queue", lines[0])
        self.assertIn("(suspicious, in Sonarr queue); blocklisting in Sonarr", lines[1])

    def test_dangerous_needs_no_evidence(self):
        sonarr = mock.Mock()
        sonarr.queue_by_hash.return_value = {}
        self.run_sweep(sonarr=sonarr)
        self.assertEqual(self.removed_ids(), [1])  # "bad"/x.exe: no release name, not queued

    def removed_ids(self):
        return [c[0][1]["ids"][0] for c in self.removals()]

    def test_release_named_zip_removed_without_sonarr(self):
        self.add(4, "Scrubs 2026 S02E08 My Emergency 1080p WEB H264 - ETHEL", "dd44")
        self.run_sweep()
        self.assertEqual(self.removed_ids(), [1, 4])

    def test_plain_zip_left_alone_without_sonarr(self):
        self.add(4, "holiday photos", "dd44")
        self.run_sweep()
        self.assertEqual(self.removed_ids(), [1])

    def test_plain_zip_removed_and_blocklisted_if_sonarr_grabbed_it(self):
        self.add(4, "holiday photos", "dd44")
        sonarr = mock.Mock()
        sonarr.queue_by_hash.return_value = {"DD44": {"id": 9}}
        self.run_sweep(sonarr=sonarr)
        self.assertEqual(self.removed_ids(), [1, 4])
        sonarr.blocklist.assert_called_once_with(9)

    def test_plain_zip_not_in_sonarr_queue_left_alone(self):
        self.add(4, "holiday photos", "dd44")
        sonarr = mock.Mock()
        sonarr.queue_by_hash.return_value = {}
        self.run_sweep(sonarr=sonarr)
        self.assertEqual(self.removed_ids(), [1])

    def test_release_named_zip_in_queue_is_blocklisted(self):
        self.torrents[:] = []
        self.add(4, "Show S01E01 720p", "dd44")
        sonarr = mock.Mock()
        sonarr.queue_by_hash.return_value = {"DD44": {"id": 9}}
        self.run_sweep(sonarr=sonarr)
        sonarr.blocklist.assert_called_once_with(9)
        sonarr.queue_by_hash.assert_called_once()

    def test_suspicious_disabled(self):
        self.add(4, "Show S01E01 720p", "dd44")
        self.run_sweep(suspicious=())
        self.assertEqual(self.removed_ids(), [1])

    def test_multi_file_zip_never_matches(self):
        self.torrents.append({"id": 4, "name": "Show S01E01 720p", "hashString": "dd44",
                              "files": [{"name": "a.zip"}, {"name": "b.nfo"}]})
        self.run_sweep()
        self.assertEqual(self.removed_ids(), [1])

    def test_sonarr_grabbed_zip_retried_after_leaving_queue(self):
        self.stuck = True
        self.add(4, "holiday photos", "dd44")
        sonarr = mock.Mock()
        sonarr.queue_by_hash.return_value = {"DD44": {"id": 9}}
        self.run_sweep(sonarr=sonarr)
        sonarr.queue_by_hash.return_value = {}  # blocklisting dropped it from the queue
        self.now += reaparr.RETRY_AFTER + 1
        self.run_sweep(sonarr=sonarr)
        self.assertEqual(self.removed_ids().count(4), 2)


class MainTest(unittest.TestCase):
    def run_main(self, argv):
        with mock.patch("sys.argv", ["reaparr.py"] + argv), \
                mock.patch("reaparr.sweep") as sweep, \
                mock.patch("reaparr.log"), \
                mock.patch("reaparr.Transmission") as tm:
            reaparr.main()
        return sweep, tm

    def test_once_runs_single_sweep_with_normalised_exts(self):
        sweep, tm = self.run_main(["--once", "--ext", "EXE", ".Iso"])
        sweep.assert_called_once()
        client, sonarr, exts, delete_data, dry_run, _ = sweep.call_args[0]  # --ext still works
        self.assertEqual(exts, (".exe", ".iso"))
        self.assertIsNone(sonarr)
        self.assertTrue(delete_data)
        self.assertFalse(dry_run)

    def test_default_lists(self):
        sweep, _ = self.run_main(["--once"])
        self.assertEqual(sweep.call_args[0][5], (".7z", ".rar", ".zip"))
        self.assertIn(".exe", sweep.call_args[0][2])
        self.assertNotIn(".7z", sweep.call_args[0][2])

    def test_suspicious_override_and_disable(self):
        sweep, _ = self.run_main(["--once", "--suspicious-ext", "ZIP", ".tar"])
        self.assertEqual(sweep.call_args[0][5], (".zip", ".tar"))
        sweep, _ = self.run_main(["--once", "--suspicious-ext"])
        self.assertEqual(sweep.call_args[0][5], ())

    def test_dangerous_wins_over_suspicious(self):
        sweep, _ = self.run_main(["--once", "--dangerous-ext", "exe", "ZIP"])
        self.assertEqual(sweep.call_args[0][2], (".exe", ".zip"))
        self.assertEqual(sweep.call_args[0][5], (".7z", ".rar"))

    def test_ext_is_alias_for_dangerous(self):
        sweep, _ = self.run_main(["--once", "--ext", "exe"])
        self.assertEqual(sweep.call_args[0][2], (".exe",))

    def test_url_built_from_host_and_port(self):
        _, tm = self.run_main(["--once", "--host", "h", "--port", "1234"])
        self.assertEqual(tm.call_args[0][0], "http://h:1234/transmission/rpc")

    def test_flags_propagate(self):
        sweep, _ = self.run_main(["--once", "--keep-data", "--dry-run"])
        self.assertEqual(sweep.call_args[0][3:5], (False, True))

    def test_sonarr_without_key_exits(self):
        with mock.patch("reaparr.keychain_password", return_value=None), \
                mock.patch("sys.stdin.isatty", return_value=False):
            with self.assertRaises(SystemExit):
                self.run_main(["--once", "--sonarr-url", "http://s"])

    def test_auth_error_exits_nonzero(self):
        with mock.patch("sys.argv", ["reaparr.py", "--once"]), \
                mock.patch("reaparr.sweep", side_effect=reaparr.AuthError("bad")), \
                mock.patch("reaparr.log"), mock.patch("reaparr.Transmission"):
            with self.assertRaises(SystemExit) as cm:
                reaparr.main()
        self.assertEqual(cm.exception.code, 1)

    def test_transient_error_does_not_exit(self):
        with mock.patch("sys.argv", ["reaparr.py", "--once"]), \
                mock.patch("reaparr.sweep", side_effect=RuntimeError("boom")), \
                mock.patch("reaparr.log"), mock.patch("reaparr.Transmission"):
            reaparr.main()


if __name__ == "__main__":
    unittest.main()
