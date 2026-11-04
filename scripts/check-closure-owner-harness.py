#!/usr/bin/env python3
"""Check staged closure sources in a pinned external owner harness, not a standalone install."""

from __future__ import annotations

import argparse
import io
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

SOURCE_COMMIT = "7356887667b0f142bac7504223ebf9446e0f5411"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--owner-root",
        type=Path,
        required=True,
        help="Existing checkout containing the reviewed source commit and its test environment",
    )
    parser.add_argument(
        "--python", type=Path, help="Owner harness Python (defaults to its .venv)"
    )
    args = parser.parse_args()
    owner = args.owner_root.resolve()
    python = args.python or owner / ".venv/bin/python"
    component = Path(__file__).resolve().parents[1]
    archive = subprocess.check_output(
        ["git", "-C", str(owner), "archive", SOURCE_COMMIT]
    )
    with tempfile.TemporaryDirectory(prefix="closure-owner-harness-") as temporary:
        root = Path(temporary)
        with tarfile.open(fileobj=io.BytesIO(archive)) as snapshot:
            snapshot.extractall(root, filter="data")
        shutil.copytree(
            component / "core/user-service",
            root / "core/user-service",
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", ".venv"),
        )
        # Adapt only the matching source harness. Frozen database migrations and
        # registry bytes stay intact. This is not qualification of installed deps.
        replacements = {
            "panopticon_models": "spanopticon_models",
            "panopticon_auth": "spanopticon_auth",
            "https://panopticon.internal/": "https://spanopticon.internal/",
            "https://panopticon.dev/tenant_id": "https://spanopticon.dev/tenant_id",
        }
        for path in (root / "core").rglob("*.py"):
            if "migration_chains" in path.parts or "alembic" in path.parts:
                continue
            text = path.read_text()
            for old, new in replacements.items():
                text = re.sub(r"(?<![A-Za-z0-9_])" + re.escape(old), new, text)
            text = re.sub(r"(?<![A-Za-z0-9_])PANOPTICON_", "SPANOPTICON_", text)
            path.write_text(text)
        (root / "core/models/src/panopticon_models").rename(
            root / "core/models/src/spanopticon_models"
        )
        paths = [
            root / "core/user-service/src",
            root / "core/user-service/contracts/src",
        ]
        paths += sorted((root / "core").glob("*/src")) + sorted(
            (root / "core/lib").glob("*/src")
        )
        print(
            f"External owner harness {SOURCE_COMMIT}; namespace-adapted source dependencies; no standalone/deployed claim",
            flush=True,
        )
        subprocess.run(
            [str(python), "-m", "pytest", "tests", "-q", "--override-ini", "addopts="],
            cwd=root / "core/user-service",
            env={**os.environ, "PYTHONPATH": os.pathsep.join(map(str, paths))},
            check=True,
        )


if __name__ == "__main__":
    main()
