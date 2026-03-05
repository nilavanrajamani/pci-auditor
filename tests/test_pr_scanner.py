"""Tests for pci_auditor.scanner.pr_scanner."""

import pytest
from pci_auditor.scanner.pr_scanner import _parse_diff, DiffFile


SAMPLE_DIFF = """\
diff --git a/payment/processor.py b/payment/processor.py
index abc1234..def5678 100644
--- a/payment/processor.py
+++ b/payment/processor.py
@@ -10,3 +10,6 @@
 def process():
+    pan = "4111111111111111"
+    cvv = "123"
+    password = "hardcoded"
 def old_func():
diff --git a/utils/helper.py b/utils/helper.py
index 111aaaa..222bbbb 100644
--- a/utils/helper.py
+++ b/utils/helper.py
@@ -1,2 +1,4 @@
+import hashlib
+md5_hash = hashlib.md5(password.encode()).hexdigest()
 existing_line = True
"""


class TestParseDiff:
    def test_detects_two_files(self):
        files = _parse_diff(SAMPLE_DIFF)
        paths = [f.path for f in files]
        assert "payment/processor.py" in paths
        assert "utils/helper.py" in paths

    def test_added_line_numbers_are_correct(self):
        files = {f.path: f for f in _parse_diff(SAMPLE_DIFF)}
        proc = files["payment/processor.py"]
        # Lines 11, 12, 13 are added (hunk starts at 10, first context line is 10)
        assert 11 in proc.added_line_numbers
        assert 12 in proc.added_line_numbers
        assert 13 in proc.added_line_numbers

    def test_added_line_content_captured(self):
        files = {f.path: f for f in _parse_diff(SAMPLE_DIFF)}
        proc = files["payment/processor.py"]
        assert any("4111111111111111" in v for v in proc.added_lines.values())

    def test_helper_file_lines(self):
        files = {f.path: f for f in _parse_diff(SAMPLE_DIFF)}
        helper = files["utils/helper.py"]
        assert 1 in helper.added_line_numbers
        assert 2 in helper.added_line_numbers

    def test_unchanged_lines_not_in_added(self):
        files = {f.path: f for f in _parse_diff(SAMPLE_DIFF)}
        proc = files["payment/processor.py"]
        # Line 10 is context (not added)
        assert 10 not in proc.added_line_numbers

    def test_empty_diff_returns_empty_list(self):
        result = _parse_diff("")
        assert result == []
