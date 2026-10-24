"""Linear-time dangerous command matchers (ger/hazards.py): the same result as the regular expressions they replace,
on a large random corpus, and bounded time on adversarial inputs up to the 1 MB edit limit. Standard library unittest only."""
from __future__ import annotations

import random
import re
import time
import unittest

from ger import fsutil, hazards

# The regular expressions as they were before the token scanners (ger-hazards-3; round 4). They are the reference:
#   MCP_DANGER equals ZES's MCP_DANGER_RE (POSIX ERE, C locale) and must not change without a HAZARD_VERSION bump
_OLD_OPTS = r'(\s+-\S*)*\s+'
OLD_MCP_DANGER = re.compile(
    r'(^|[\s"/])(curl|wget)([\s"]|$)|base64'
    r'|(^|[\s"/])(ba|z|da|k|a|fi)?sh(\.exe)?' + _OLD_OPTS + r'-[a-z]*c[a-z]*(\s|$)'
    r'|(^|[\s"/])(node|nodejs|bun)(\.exe)?' + _OLD_OPTS + r'(-e|--eval|-p|--print)([\s=]|$)'
    r'|(^|[\s"/])deno(\.exe)?\s+eval(\s|$)'
    r'|(^|[\s"/])python[0-9.]*(\.exe)?' + _OLD_OPTS + r'-[a-z]*c(\s|$)'
    r'|(^|[\s"/])(perl|ruby)[0-9.]*(\.exe)?' + _OLD_OPTS + r'-[a-z]*e(\s|$)'
    r'|(^|[\s"/])php[0-9.]*(\.exe)?' + _OLD_OPTS + r'-r(\s|$)'
    r'|(^|[\s"/])(osascript|lua[0-9.]*)' + _OLD_OPTS + r'-e(\s|$)'
    r'|(^|[\s"/])cmd(\.exe)?\s+/[ck](\s|$)',
    re.IGNORECASE | re.ASCII)
# ZES's pwsh branch in one piece (round 4 split it into two linear searches with the same result)
OLD_PWSH = re.compile(r'(^|[\s"/])(pwsh|powershell)(\.exe)?(\s+\S+)*\s+[-/](c|command|e|ec|enc|encodedcommand)(\s|$)',
                      re.IGNORECASE | re.ASCII)
OLD_DANGEROUS_CMD = re.compile(
    r'(^|[\s"/])(curl|wget)([\s"]|$)|bash -c|sh -c|powershell(\.exe)? .*-(e|enc|encodedcommand)\s|node -e|python[0-9.]* -c|base64')


def old_mcp(line: str) -> bool:
    return OLD_MCP_DANGER.search(line) is not None or OLD_PWSH.search(line) is not None


def old_hook(cmd: str) -> bool:
    return OLD_DANGEROUS_CMD.search(cmd) is not None


# Token pool of the round 5 differential harness (commands, flags, separators, look-alike and control characters)
HEADS = ["sh", "bash", "zsh", "dash", "ksh", "ash", "fish", "sh.exe", "bash.EXE", "SH", "Bash", "/bin/sh", '"sh', "x/bash",
         'a"zsh', "mybash", "shx", "fsh", "node", "nodejs", "bun", "node.exe", "NODE", "deno", "deno.exe", "python",
         "python3", "python3.11", "python3.11.exe", "python.", "Python3", "perl", "ruby", "perl5.36", "ruby3.2.exe", "php",
         "php8.2", "osascript", "lua", "lua5.4", "luajit", "cmd", "cmd.exe", "CMD", "pwsh", "powershell", "powershell.exe",
         "PowerShell", "pwsh.exe", "curl", "wget", "CURL", "base64", "Base64", "eval", "npx", "uvx", "x/python",
         "a/b/node", "baſh", "ſh", "ı", "İ", "K", "-/sh", '-x"sh', "-/python", "-/node", "-/pwsh"]
FLAGS = ["-c", "-xc", "-cx", "-Ic", "-ic", "-C", "-xC", "-cl", "-lc", "-e", "-ne", "-E", "-p", "-P", "--eval", "--EVAL",
         "--print", "-e=1", "--eval=x", "-p=", "-r", "-R", "-Command", "-command", "/command", "/c", "/k", "/C", "/K", "-EC",
         "-ec", "-enc", "-encodedcommand", "-EncodedCommand", "-NoProfile", "-x", "-", "--", "--norc", "-i", "-", "-c1",
         "-cc", "-Kc", "-ſc", "-ee", "-er", "-rr", "-q", "-m", "eval", "x", "1", "server.js", "-/sh", "-e x"]
SEPS = [" ", " ", " ", "  ", "\t", "\n", "\r", "\v", "\f", "", '"', "/", "\\", "=", " ", "　", "\u0085", " ",
        "\x1f", "\x1c", "\0", " -", "'"]


def corpus(rnd: random.Random, n: int):
    pool = HEADS + FLAGS
    for _ in range(n):
        parts = []
        for _ in range(rnd.randint(1, 9)):
            r = rnd.random()
            parts.append(rnd.choice(HEADS) if r < 0.35 else rnd.choice(FLAGS) if r < 0.85 else rnd.choice(pool) + rnd.choice(pool))
            parts.append(rnd.choice(SEPS))
        if rnd.random() < 0.5:
            parts.pop()
        yield "".join(parts)


class TestDifferential(unittest.TestCase):
    def test_mcp_danger_equals_the_regular_expressions(self):
        rnd = random.Random(20261024)
        n = hits = 0
        for s in corpus(rnd, 60000):
            want = old_mcp(s)
            self.assertEqual(hazards.mcp_danger(s), want, repr(s))
            n += 1
            hits += want
        self.assertGreater(hits, n // 10)  # the corpus has many matches and many non-matches
        self.assertLess(hits, n - n // 10)

    def test_dangerous_cmd_equals_the_regular_expression(self):
        rnd = random.Random(7)
        n = hits = 0
        extra = ["powershell ", "powershell.exe ", "powershell", "x -e ", "-enc\n", "-encodedcommand ", "-e ", "\n-e "]
        for s in corpus(rnd, 40000):
            if rnd.random() < 0.5:
                s = "".join(rnd.choice(extra) if rnd.random() < 0.4 else c for c in s.split(" "))
            want = old_hook(s)
            self.assertEqual(hazards.dangerous_cmd(s), want, repr(s))
            n += 1
            hits += want
        self.assertGreater(hits, n // 30)
        self.assertLess(hits, n - n // 10)

    def test_known_cases(self):
        for line in ("sh -c x", "bash --norc -c x", "x/bash -xc y", '"sh -c', "SH.EXE -C x", "node -e=1", "bun --print x",
                     "python3.11.exe -Ic x", "perl -ne x", "ruby3 -e x", "php -r x", "lua5.4 -e x", "cmd.exe /k x",
                     "deno\teval x", "a -/sh -x -c", "sh -x - -c", "pwsh -NoProfile -Command x"):
            self.assertTrue(hazards.mcp_danger(line), line)
            self.assertTrue(old_mcp(line), line)
        for line in ("sh x -c", "mybash -c", "sh -cx1", "node -ex", "python -cx", "php -rx", "sh -c", "sh -/sh",
                     "node --inspect srv.js", "lua -e1"):
            self.assertFalse(hazards.mcp_danger(line), line)
            self.assertFalse(old_mcp(line), line)
        for cmd in ("powershell x -enc AA", "powershell.exe -e\nx", "a powershell b\nc -e x"):
            self.assertEqual(hazards.dangerous_cmd(cmd), old_hook(cmd), cmd)
        self.assertTrue(hazards.dangerous_cmd("powershell x -enc AA"))
        self.assertFalse(hazards.dangerous_cmd("powershell x\n-enc AA"))


class TestLinearTime(unittest.TestCase):
    LIMIT = fsutil.EDIT_MAX_BYTES  # files up to this size are read and matched

    def fit(self, unit: str, head: str = "") -> str:
        return head + unit * ((self.LIMIT - len(head)) // len(unit))

    def assert_fast(self, fn, s: str, want: bool):
        t0 = time.perf_counter()
        got = fn(s)
        took = time.perf_counter() - t0
        self.assertEqual(got, want, repr(s)[:60])
        self.assertLess(took, 1.0, f"{repr(s)[:60]}: {took:.2f}s")

    def test_mcp_danger_adversarial_1mb(self):
        for unit, head in ((" -/sh", "sh"), (' -x"sh', "sh"), (" -/python", "python"), (" -/node", "node"),
                           (" -/perl", "perl"), (" -/php", "php"), (" -/lua", "lua"), (" -/bash", "bash"), ("pwsh ", ""),
                           ("powershell.exe x ", ""), ("sh ", ""), (" -", "sh"), ("deno ", ""), ("cmd ", ""), (" ", "deno"),
                           (" ", "cmd"), ("9", "python"), ("/", ""), ('"', ""), ("-", ""), ("sh -x", ""), ("a", ""), ("sh -x ", ""), ("sh -/sh ", ""), ("xsh ", ""), ("curlx ", ""), (" -" + "c" * 4000 + "1", "sh"),
                           (" -" + "e" * 4000 + "1", "perl"), (" -" + "c" * 4000 + "=", "python"), (" -e" + "=" * 4000, "x")):
            s = self.fit(unit, head)
            self.assertGreater(len(s), self.LIMIT - len(unit) - len(head))
            self.assert_fast(hazards.mcp_danger, s, False)
            # With a flag at the end: the reference result of the same shape with fewer repetitions (it does not depend on the count)
            for tail in (" -c", " -e"):
                self.assert_fast(hazards.mcp_danger, s + tail, old_mcp(head + unit * (40 if len(unit) < 100 else 2) + tail))

    def test_dangerous_cmd_adversarial_1mb(self):
        for unit in ("powershell ", "powershell.exe ", "powershell x\n", "powershell -x ", "python", "python9 ", "base6",
                     "curlx ", "sh -", " "):
            s = self.fit(unit)
            self.assert_fast(hazards.dangerous_cmd, s, old_hook(unit * 40))
        self.assert_fast(hazards.dangerous_cmd, self.fit("powershell ") + "-enc ", True)

    def test_dangerous_server_and_hook_1mb(self):
        # Through the callers that preview uses: an MCP server definition and a hook value
        args = ["-/sh"] * (self.LIMIT // 7)
        self.assert_fast(lambda a: hazards.dangerous_server({"command": "sh", "args": a}), args, False)
        hook = {"hooks": [{"type": "command", "command": self.fit("powershell ")}]}
        self.assert_fast(hazards.dangerous_hook, hook, False)


if __name__ == "__main__":
    unittest.main()
