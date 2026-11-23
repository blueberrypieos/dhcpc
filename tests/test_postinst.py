#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 The Blueberry Pie OS Authors
"""Exercise postinst's restart path for package configuration scenarios.

Process commands are stand-ins. The unchanged resolver migration is
omitted, and the final client command is redirected to a synchronous stand-in, so
the tests cannot signal live clients or change the host's resolver.
The temporary package database describes upgrade and downgrade cases;
the restart decision must not depend on querying it.
"""

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest


POSTINST = Path(__file__).resolve().parents[1] / "debian" / "postinst"
MOCK = r'''
import json
import os
from pathlib import Path
import sys

op, args = Path(sys.argv[0]).name, sys.argv[1:]
state_path = Path(os.environ["DHCPC_TEST_STATE"])
state = json.loads(state_path.read_text())

def log(event, args):
    with open(os.environ["DHCPC_TEST_LOG"], "a") as f:
        f.write(json.dumps({"event": event, "args": args}) + "\n")

log(op, args)
if op == "ps":
    columns = args[-1].split(",")
    for p in json.loads(os.environ["DHCPC_TEST_PS"]):
        values = {"pid=": p[0], "ruid=": str(p[1]), "uid=": str(p[2]), "args=": " ".join(p[3])}
        print(" ".join(values[c] for c in columns))
elif op == "kill":
    pid = args[-1]
    if args[0] == "-0":
        sys.exit(0 if pid in state["alive"] else 1)
    if pid not in state["alive"]:
        sys.exit(1)
    state["signalled"].append(pid)
    if state["exit_after"] == 0:
        state["alive"].remove(pid)
    state_path.write_text(json.dumps(state))
elif op == "sleep":
    state["ticks"] += 1
    if state["exit_after"] is not None and state["ticks"] >= state["exit_after"]:
        state["alive"] = [p for p in state["alive"] if p not in state["signalled"]]
    state_path.write_text(json.dumps(state))
elif op == "client":
    if any(p in state["alive"] for p in state["lock_holders"]):
        log("lock-held", args)
        sys.exit(1)
    log("started", args)
else:
    sys.exit("unknown stand-in: " + op)
'''


class PostinstTests(unittest.TestCase):
    def run_postinst(self, old, new="5", *, exit_after=0, root="", package="dhcpc",
                     processes=True, action="configure", process_rows=None):
        with tempfile.TemporaryDirectory(prefix="dhcpc-postinst-") as tmp:
            work = Path(tmp)
            bindir = work / "bin"
            bindir.mkdir()
            helper = work / "helper.py"
            helper.write_text("#!" + sys.executable + "\n" + MOCK)
            helper.chmod(0o755)
            for name in ("ps", "kill", "sleep", "client"):
                (bindir / name).symlink_to(helper)

            db = work / "dpkg"
            db.mkdir()
            (db / "status").write_text(
                "Package: dhcpc\nStatus: install ok unpacked\n"
                "Architecture: all\nVersion: " + new + "\n"
                "Maintainer: Maxwell <Maxwell>\nDescription: test package\n\n")
            if process_rows is None:
                process_rows = [
                    ["101", 0, 0, ["dhcpc", "-a"]],
                    ["202", 0, 0, ["/sbin/dhcpc", "-t", "30", "en0"]],
                    ["303", 0, 0, ["other-process"]],
                ] if processes else []
            lock_holders = [p[0] for p in process_rows
                            if p[1] == 0 and p[3][0] in ("dhcpc", "/sbin/dhcpc")]
            state = work / "state.json"
            state.write_text(json.dumps({
                "alive": [p[0] for p in process_rows], "lock_holders": lock_holders,
                "signalled": [], "ticks": 0, "exit_after": exit_after,
            }))
            log = work / "events.jsonl"
            log.touch()

            script = POSTINST.read_text()
            dns = 'if [ ! -L "$r/etc/resolv.conf" ]; then\n'
            restart = 'echo "$running" | awk \'NF { $1 = ""; $2 = ""; print }\''
            self.assertEqual(script.count(dns), 1)
            self.assertEqual(script.count(restart), 1)
            before, rest = script.split(dns, 1)
            _, after = rest.split(restart, 1)
            script = before + ": # Resolver migration is outside this test.\n" + restart + after
            client = "\t/sbin/dhcpc $args > /dev/null 2>&1 &"
            self.assertEqual(script.count(client), 1)
            script = script.replace(client, "\t" + shlex.quote(str(bindir / "client")) + " $args")
            tested = work / "postinst"
            tested.write_text(script)
            wrapper = work / "run.sh"
            wrapper.write_text(
                "kill() { " + shlex.quote(str(bindir / "kill")) + ' "$@"; }\n'
                ". " + shlex.quote(str(tested)) + "\n")

            env = os.environ.copy()
            env.update({
                "PATH": str(bindir) + os.pathsep + env["PATH"],
                "LC_ALL": "C", "DPKG_ADMINDIR": str(db), "DPKG_ROOT": root,
                "DPKG_MAINTSCRIPT_PACKAGE": package,
                "DHCPC_TEST_STATE": str(state), "DHCPC_TEST_LOG": str(log),
                "DHCPC_TEST_PS": json.dumps(process_rows),
            })
            command = ["/bin/sh", str(wrapper), action]
            if old is not None:
                command.append(old)
            result = subprocess.run(command, env=env, text=True, capture_output=True, timeout=10)

            def events():
                return [json.loads(line) for line in log.read_text().splitlines()]

            return result, events()

    def assert_restarted(self, old, new, **kwargs):
        result, events = self.run_postinst(old, new, **kwargs)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertCountEqual([e["args"] for e in events if e["event"] == "started"],
                              [["-a"], ["-t", "30", "en0"]])
        self.assertFalse(any(e["event"] == "lock-held" for e in events))
        self.assertEqual([e["args"] for e in events if e["event"] == "ps"],
                         [["-axo", "pid=,ruid=,args="]])
        self.assertEqual([e["args"] for e in events if e["event"] == "kill" and e["args"][0] != "-0"],
                         [["101"], ["202"]])
        return events

    def assert_untouched(self, old, new="5", **kwargs):
        result, events = self.run_postinst(old, new, **kwargs)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(events, [])

    def test_upgrade_from_three(self):
        self.assert_restarted("3", "4")

    def test_future_upgrade(self):
        self.assert_restarted("4", "5")

    def test_revision_upgrade(self):
        self.assert_restarted("5-1", "5-2")

    def test_prerelease_upgrade(self):
        self.assert_restarted("5~rc1", "5")

    def test_epoch_upgrade(self):
        self.assert_restarted("1:9", "2:1")

    def test_same_version(self):
        self.assert_restarted("5", "5")

    def test_downgrade(self):
        self.assert_restarted("6", "5")

    def test_first_install_without_clients_starts_nothing(self):
        self.assert_untouched(None, package="missing", processes=False)

    def test_first_install_does_not_adopt_existing_clients(self):
        self.assert_untouched(None, package="missing")

    def test_empty_previous_version_does_not_adopt_existing_clients(self):
        self.assert_untouched("", package="missing")

    def test_unprivileged_name_spoofs_are_ignored(self):
        rows = [["401", 501, 501, ["dhcpc", "-t", "1", "en7"]],
                ["402", 501, 501, ["/sbin/dhcpc", "-1", "en8"]]]
        result, events = self.run_postinst("4", process_rows=rows)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([e["event"] for e in events], ["ps"])

    def test_setuid_root_name_spoofs_are_ignored(self):
        rows = [["501", 501, 0, ["dhcpc", "-a"]],
                ["502", 501, 0, ["/sbin/dhcpc", "-t", "1", "en8"]]]
        result, events = self.run_postinst("4", process_rows=rows)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([e["event"] for e in events], ["ps"])

    def test_only_real_root_clients_are_restarted(self):
        rows = [["101", 0, 0, ["dhcpc", "-a"]],
                ["202", 0, 501, ["/sbin/dhcpc", "-t", "30", "en0"]],
                ["401", 501, 501, ["dhcpc", "-1", "en7"]],
                ["501", 501, 0, ["/sbin/dhcpc", "-t", "1", "en8"]],
                ["601", 0, 0, ["unrelated", "dhcpc", "-a"]]]
        events = self.assert_restarted("4", "5", process_rows=rows)
        self.assertTrue(all(e["args"][-1] in ("101", "202")
                            for e in events if e["event"] == "kill"))

    def test_staged_root_does_not_query_or_restart(self):
        self.assert_untouched("4", root="/stage", package="missing")

    def test_other_actions(self):
        self.assert_untouched("4", action="triggered", package="missing")

    def test_restart_does_not_need_package_version(self):
        self.assert_restarted("4", "5", package="missing")

    def test_no_running_clients(self):
        result, events = self.run_postinst("4", processes=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([e["event"] for e in events], ["ps"])

    def test_waits_for_old_supervisor(self):
        events = self.assert_restarted("4", "5", exit_after=2)
        self.assertEqual(sum(e["event"] == "sleep" for e in events), 2)

    def test_wait_has_a_deadline(self):
        result, events = self.run_postinst("4", exit_after=None)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not stop", result.stderr)
        self.assertFalse(any(e["event"] in ("client", "started") for e in events))
        self.assertEqual(sum(e["event"] == "sleep" for e in events), 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
