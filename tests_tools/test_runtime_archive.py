"""Only a fully qualified image can become a deployment artifact."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def run_qualification(tmp_path, failed=False):
    binaries = tmp_path / 'bin'
    binaries.mkdir()
    docker = binaries / 'docker'
    docker.write_text('''#!/usr/bin/env python3
import pathlib, sys
if sys.argv[1] == 'save':
    pathlib.Path(sys.argv[sys.argv.index('-o') + 1]).write_bytes(b'qualified-runtime')
''')
    uv = binaries / 'uv'
    uv.write_text('#!/bin/sh\nexit '+('1' if failed else '0')+'\n')
    docker.chmod(0o755)
    uv.chmod(0o755)
    output = tmp_path / 'image'
    env = dict(os.environ, PATH=str(binaries)+':'+os.environ['PATH'], TESTED_IMAGE_DIR=str(output))
    env.pop('DEPENDENCY_READ_TOKEN_FILE', None)
    result = subprocess.run(['bash', 'scripts/check-container.sh'], cwd=ROOT, env=env, capture_output=True)
    return result, output


class RuntimeArchiveTests(unittest.TestCase):
    def test_exact_runtime_is_retained_after_qualification(self):
        with tempfile.TemporaryDirectory() as directory:
            result, output = run_qualification(Path(directory))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((output / 'image.tar').read_bytes(), b'qualified-runtime')
            self.assertEqual((output / 'image.sha256').read_text().strip(), hashlib.sha256(b'qualified-runtime').hexdigest())
            self.assertTrue((output / 'image.ref').read_text().startswith('user-service-closure:qualification-'))

    def test_failed_qualification_does_not_export_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            result, output = run_qualification(Path(directory), failed=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())

if __name__ == '__main__':
    unittest.main()
