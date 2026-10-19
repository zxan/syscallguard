# test_policy.py: unprivileged unit tests for guard/policy.py. Run anywhere:
#   python3 -m unittest tests/test_policy.py
# Track: G (Guard runtime & bridge)
# Contract: ARCHITECTURE.md Contract 2 (policy file).
#
# Static fixtures in tests/fixtures/policy/ cover files rejected before any path is checked.
# Valid policies need a protected file that really exists, so they are written to a temp dir.
import ipaddress
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "guard"))
import policy  # noqa: E402
from policy import PolicyError  # noqa: E402

FIXTURES = os.path.join(HERE, "fixtures", "policy")


class TestPolicy(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        self.secret = os.path.join(self.dir, ".env")
        open(self.secret, "w").close()

    def write(self, text):
        path = os.path.join(self.dir, "policy.toml")
        with open(path, "w") as f:
            f.write(text)
        return path

    def rejects(self, path, pattern, mode=None):
        with self.assertRaisesRegex(PolicyError, pattern):
            policy.load(path, mode)

    def test_valid(self):
        p = policy.load(self.write(
            f'mode = "enforce"\nprotect = ["{self.secret}"]\nallow = ["127.0.0.1/8", "::1/128"]\n'))
        self.assertEqual(p.mode, "enforce")
        self.assertEqual(p.protect, [self.secret])
        self.assertEqual(p.allow, [ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128")])

    def test_example_file_parses_except_path(self):
        # The committed example points at the VM path; everything before the path check passes.
        self.rejects(os.path.join(HERE, "..", "policy", "policy.example.toml"), "protect entry .*No such file")

    def test_empty_protect_rejected(self):
        self.rejects(os.path.join(FIXTURES, "empty_protect.toml"), "protect must be a non-empty list")

    def test_missing_protect_rejected(self):
        self.rejects(self.write('allow = []\n'), "protect must be a non-empty list")

    def test_empty_allow_valid(self):
        p = policy.load(self.write(f'protect = ["{self.secret}"]\nallow = []\n'))
        self.assertEqual(p.allow, [])

    def test_missing_mode_defaults_to_audit(self):
        p = policy.load(self.write(f'protect = ["{self.secret}"]\nallow = []\n'))
        self.assertEqual(p.mode, "audit")

    def test_unknown_key_rejected(self):
        self.rejects(os.path.join(FIXTURES, "unknown_key.toml"), "unknown key.*extra")

    def test_malformed_toml_rejected(self):
        self.rejects(os.path.join(FIXTURES, "malformed.toml"), "invalid TOML")

    def test_no_map_size_cap(self):
        # Beyond protected_inodes (256) and allow_v4 (1024) map sizes: still accepted.
        protect = ", ".join(f'"{self.secret}"' for _ in range(300))
        allow = ", ".join(f'"10.{i // 256}.{i % 256}.0/24"' for i in range(1100))
        p = policy.load(self.write(f'protect = [{protect}]\nallow = [{allow}]\n'))
        self.assertEqual((len(p.protect), len(p.allow)), (300, 1100))

    def test_bad_mode_rejected(self):
        self.rejects(self.write(f'mode = "block"\nprotect = ["{self.secret}"]\n'), "mode must be")

    def test_cli_mode_overrides_file(self):
        path = self.write(f'mode = "audit"\nprotect = ["{self.secret}"]\n')
        self.assertEqual(policy.load(path, "enforce").mode, "enforce")
        self.rejects(path, "mode must be", mode="block")

    def test_relative_path_rejected(self):
        self.rejects(self.write('protect = ["demo/project/.env"]\n'), "absolute path")

    def test_missing_path_rejected(self):
        self.rejects(self.write(f'protect = ["{self.dir}/nope"]\n'), "No such file")

    def test_bad_cidr_rejected(self):
        self.rejects(self.write(f'protect = ["{self.secret}"]\nallow = ["10.0.0.0/33"]\n'), "not a valid CIDR")

    def test_non_string_cidr_rejected(self):
        self.rejects(self.write(f'protect = ["{self.secret}"]\nallow = [5]\n'), "CIDR string")

    def test_unreadable_file_rejected(self):
        self.rejects(os.path.join(self.dir, "missing.toml"), "cannot read")


if __name__ == "__main__":
    unittest.main()
