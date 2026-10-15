"""Deterministic source swap race regressions; no untrusted subprocess."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from universal.continuity import source_sha
from universal.core import GuardError


class ContinuitySourceRaceTests(unittest.TestCase):
    def test_path_open_substitution_cannot_redirect_checked_source(self):
        with tempfile.TemporaryDirectory(prefix='source-race-') as d:
            base = Path(d)
            src = base/'source.txt'
            other = base/'other.txt'
            src.write_bytes(b'original-owner-data')
            other.write_bytes(b'attacker-controlled')
            actual_open = Path.open

            def swap_on_path_open(path, *args, **kwargs):
                if path == src:
                    src.unlink()
                    src.symlink_to(other)
                return actual_open(path, *args, **kwargs)

            with patch.object(Path, 'open', swap_on_path_open):
                with self.assertRaises(GuardError):
                    source_sha(str(src))

    def test_directory_fifo_and_missing_source_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix='source-race-') as d:
            base = Path(d)
            with self.assertRaises(GuardError):
                source_sha(str(base))
            with self.assertRaises(GuardError):
                source_sha(str(base/'missing'))
            fifo = base/'pipe'
            os.mkfifo(fifo)
            with self.assertRaises(GuardError):
                source_sha(str(fifo))


if __name__ == '__main__':
    unittest.main()
