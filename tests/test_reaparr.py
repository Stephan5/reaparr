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


class ArrTest(unittest.TestCase):
    def setUp(self):
        self.s = reaparr.Arr("Sonarr", "http://sonarr:8989/", "KEY")

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

    def test_401_raises_auth_error_naming_the_arr(self):
        r = reaparr.Arr("Radarr", "http://radarr:7878", "KEY")
        with mock.patch("urllib.request.urlopen", side_effect=http_error(401)):
            with self.assertRaisesRegex(reaparr.AuthError, "Radarr"):
                r._request("GET", "/queue")


def fake_arr(name, queue):
    arr = mock.Mock()
    arr.name = name
    arr.queue_by_hash.return_value = queue
    return arr


class SweepBase(unittest.TestCase):
    def setUp(self):
        self.torrents = [
            {"id": 1, "name": "bad", "hashString": "aa11", "files": [{"name": "x.exe"}]},
            {"id": 2, "name": "good", "hashString": "bb22", "files": [{"name": "x.mkv"}]},
            {"id": 3, "name": "pack", "hashString": "cc33", "files": [{"name": "a.exe"}, {"name": "b.txt"}]},
        ]
        reaparr.PENDING.clear()
        reaparr.SKIPPED.clear()
        self.now = 1000.0
        self.log = mock.Mock()  # accumulates across sweeps
        self.client = mock.Mock()
        self.client.call.side_effect = self.fake_call
        self.removals = lambda: [c for c in self.client.call.call_args_list if c[0][0] == "torrent-remove"]
        self.removed_ids = lambda: [c[0][1]["ids"][0] for c in self.removals()]
        self.sonarr = fake_arr("Sonarr", {"AA11": {"id": 9}})
        self.radarr = fake_arr("Radarr", {})
        self.arrs = [self.sonarr, self.radarr]

    def fake_call(self, method, args=None):
        """Transmission stand-in: torrent-remove really removes unless self.stuck."""
        if method == "torrent-get":
            ids = (args or {}).get("ids")
            return {"torrents": [t for t in self.torrents if ids is None or t["id"] in ids]}
        if method == "torrent-remove" and not getattr(self, "stuck", False):
            self.torrents[:] = [t for t in self.torrents if t["id"] not in args["ids"]]
        return {}

    def add(self, id_, h, filename, name=None):
        self.torrents.append({"id": id_, "name": name or filename, "hashString": h, "files": [{"name": filename}]})

    def run_sweep(self, delete_data=True, dry_run=False):
        def sleep(seconds):
            self.now += seconds
            self.slept += seconds
        self.slept = 0
        with mock.patch("reaparr.log", self.log), \
                mock.patch("reaparr.time.monotonic", side_effect=lambda: self.now), \
                mock.patch("reaparr.time.sleep", side_effect=sleep):
            reaparr.sweep(self.client, self.arrs, EXTS, delete_data, dry_run)

    def sweep_at(self, t):
        self.now = 1000.0 + t
        self.run_sweep()

    def logged(self):
        return [c[0][0] for c in self.log.call_args_list]


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
        self.run_sweep(dry_run=True)
        self.assertEqual(self.removals(), [])
        self.sonarr.blocklist.assert_not_called()
        self.assertEqual(self.logged(), ["WOULD REMOVE: bad [aa11]; blocklisting in Sonarr"])

    def test_blocklists_before_removing(self):
        order = []
        self.sonarr.blocklist.side_effect = lambda i: order.append(("blocklist", i))
        self.client.call.side_effect = lambda m, a=None: (
            order.append((m, a)) if m == "torrent-remove" else None) or self.fake_call(m, a)
        self.run_sweep()
        self.assertEqual(order[0], ("blocklist", 9))
        self.assertEqual(order[1][0], "torrent-remove")

    def test_skips_torrent_while_verifying_then_removes(self):
        self.torrents[0]["status"] = 2
        self.run_sweep()
        self.assertEqual(self.removals(), [])
        self.torrents[0]["status"] = 4
        self.run_sweep()
        self.assertEqual(len(self.removals()), 1)

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
        self.sonarr.queue_by_hash.return_value = {}  # blocklisting dropped it from the queue
        self.sweep_at(reaparr.RETRY_AFTER + 1)
        self.assertEqual(len(self.removals()), 2)
        self.sonarr.blocklist.assert_called_once()  # not blocklisted twice
        self.assertIn("still in Transmission 301s after removal was requested", self.logged()[1])
        self.assertEqual(self.log.call_args_list[1][1], {"file": sys.stderr})

    def test_dry_run_leaves_nothing_pending(self):
        self.run_sweep(dry_run=True)
        self.assertEqual(reaparr.PENDING, {})

    def test_queues_fetched_once_and_lazily(self):
        self.add(4, "dd44", "y.iso")
        self.run_sweep()
        self.sonarr.queue_by_hash.assert_called_once()
        self.radarr.queue_by_hash.assert_called_once()  # y.iso isn't in Sonarr's queue

        self.sonarr.reset_mock()
        self.radarr.reset_mock()
        self.torrents[:] = [self.torrents[1]]
        self.run_sweep()
        self.sonarr.queue_by_hash.assert_not_called()
        self.radarr.queue_by_hash.assert_not_called()

    def test_later_arr_not_asked_if_earlier_has_it(self):
        self.run_sweep()
        self.radarr.queue_by_hash.assert_not_called()


class GrabbedOnlyTest(SweepBase):
    """Nothing is removed unless Sonarr or Radarr has it in its queue."""

    def test_not_in_any_queue_left_alone_and_logged_once(self):
        self.sonarr.queue_by_hash.return_value = {}
        self.run_sweep()
        self.run_sweep()
        self.assertEqual(self.removals(), [])
        self.assertEqual(self.logged(), ["SKIPPING: bad [aa11]; not in Sonarr or Radarr queue"])

    def test_picked_up_once_it_appears_in_a_queue(self):
        self.sonarr.queue_by_hash.return_value = {}
        self.run_sweep()
        self.radarr.queue_by_hash.return_value = {"AA11": {"id": 3}}  # arr polled the client
        self.run_sweep()
        self.radarr.blocklist.assert_called_once_with(3)
        self.assertEqual(self.removed_ids(), [1])
        self.assertEqual(self.logged()[-1], "REMOVING: bad [aa11]; blocklisting in Radarr")
        self.assertEqual(reaparr.SKIPPED, set())

    def test_skipped_forgotten_once_torrent_is_gone(self):
        self.sonarr.queue_by_hash.return_value = {}
        self.run_sweep()
        self.torrents[:] = []
        self.run_sweep()
        self.assertEqual(reaparr.SKIPPED, set())


class MainTest(unittest.TestCase):
    SONARR = ["--sonarr-url", "http://s", "--sonarr-api-key", "K"]

    def run_main(self, argv, arr=True, sweep_error=None):
        with mock.patch("sys.argv", ["reaparr.py"] + argv + (self.SONARR if arr else [])), \
                mock.patch("reaparr.sweep", side_effect=sweep_error) as sweep, \
                mock.patch("reaparr.log"), \
                mock.patch("reaparr.Transmission") as tm:
            reaparr.main()
        return sweep, tm

    def test_once_runs_single_sweep_with_normalised_exts(self):
        sweep, tm = self.run_main(["--once", "--ext", "EXE", ".Iso"])
        sweep.assert_called_once()
        client, arrs, exts, delete_data, dry_run = sweep.call_args[0]
        self.assertEqual(exts, (".exe", ".iso"))
        self.assertEqual([a.name for a in arrs], ["Sonarr"])
        self.assertTrue(delete_data)
        self.assertFalse(dry_run)

    def test_url_built_from_host_and_port(self):
        _, tm = self.run_main(["--once", "--host", "h", "--port", "1234"])
        self.assertEqual(tm.call_args[0][0], "http://h:1234/transmission/rpc")

    def test_flags_propagate(self):
        sweep, _ = self.run_main(["--once", "--keep-data", "--dry-run"])
        self.assertEqual(sweep.call_args[0][3:], (False, True))

    def test_sonarr_and_radarr(self):
        sweep, _ = self.run_main(["--once", "--radarr-url", "http://r:7878/", "--radarr-api-key", "R"])
        arrs = sweep.call_args[0][1]
        self.assertEqual([(a.name, a.base, a.api_key) for a in arrs],
                         [("Sonarr", "http://s/api/v3", "K"), ("Radarr", "http://r:7878/api/v3", "R")])

    def test_radarr_key_from_keychain(self):
        with mock.patch("reaparr.keychain_password", return_value="KC") as kc:
            sweep, _ = self.run_main(["--once", "--radarr-url", "http://r"], arr=False)
        kc.assert_called_with("radarr")
        self.assertEqual(sweep.call_args[0][1][0].api_key, "KC")

    def test_no_arr_exits(self):
        with self.assertRaisesRegex(SystemExit, "sonarr-url and/or --radarr-url"):
            self.run_main(["--once"], arr=False)

    def test_arr_without_key_exits(self):
        for flag in ("--sonarr-url", "--radarr-url"):
            with mock.patch("reaparr.keychain_password", return_value=None), \
                    mock.patch("sys.stdin.isatty", return_value=False):
                with self.assertRaises(SystemExit):
                    self.run_main(["--once", flag, "http://x"], arr=False)

    def test_auth_error_exits_nonzero(self):
        with self.assertRaises(SystemExit) as cm:
            self.run_main(["--once"], sweep_error=reaparr.AuthError("bad"))
        self.assertEqual(cm.exception.code, 1)

    def test_transient_error_does_not_exit(self):
        self.run_main(["--once"], sweep_error=RuntimeError("boom"))


if __name__ == "__main__":
    unittest.main()
