"""Default-off deployment entrypoint for the private TLS authority and poller."""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import ssl
import stat
import sys

import uvicorn

from user_service.closure_daemon import run_command
from user_service.closure_worker import WorkerUnavailable


def check_image():
    if not re.fullmatch(r"(?:ghcr\.io/hyperme-sh/user-service(?:/runtime)?|acrfybercg47\.azurecr\.io/user-service)@sha256:[0-9a-f]{64}",
                        os.environ.get("ACCOUNT_CLOSURE_IMAGE", "")):
        raise WorkerUnavailable()


def certificate_paths():
    try:
        paths = [os.environ[name] for name in ("ACCOUNT_CLOSURE_TLS_CERT_FILE", "ACCOUNT_CLOSURE_TLS_KEY_FILE")]
        for index, path in enumerate(paths):
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                details = os.fstat(descriptor)
                if not stat.S_ISREG(details.st_mode) or not 0 < details.st_size <= 1024 * 1024:
                    raise WorkerUnavailable()
                if index == 1 and stat.S_IMODE(details.st_mode) & 0o077:
                    raise WorkerUnavailable()
            finally:
                os.close(descriptor)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        # An encrypted/mismatched key must fail instead of prompting on stdin.
        context.load_cert_chain(*paths, password=lambda: "")
        return paths
    except (KeyError, OSError, ValueError):
        raise WorkerUnavailable() from None


def authority_config():
    check_image()
    cert, key = certificate_paths()
    return uvicorn.Config(
        "user_service.closure_authority:app", host="0.0.0.0", port=8443,
        ssl_certfile=cert, ssl_keyfile=key, ssl_version=ssl.PROTOCOL_TLS_SERVER,
        access_log=False, proxy_headers=False, server_header=False,
        log_level="warning", lifespan="on", ws="none",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("authority", "worker"))
    parser.add_argument("--max-jobs", type=int, choices=range(1, 101), default=10)
    parser.add_argument("--poll-seconds", type=int, choices=range(5, 301), default=30)
    args = parser.parse_args()
    try:
        check_image()
        if args.mode == "authority":
            server = uvicorn.Server(authority_config())
            server.run()
            if not server.started:
                raise WorkerUnavailable()
        else:
            asyncio.run(run_command(max_jobs=args.max_jobs, poll_seconds=args.poll_seconds))
    except (KeyboardInterrupt, asyncio.CancelledError):
        return 130
    except Exception:  # noqa: BLE001 - startup must never print secrets or provider bodies
        print("Private account closure runtime unavailable", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
