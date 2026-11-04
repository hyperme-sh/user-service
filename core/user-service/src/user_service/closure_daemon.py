"""Private polling process for durable account closure jobs."""

from __future__ import annotations

import argparse
import asyncio
import signal
import sys

from user_service.closure_worker import execute


async def _wait(seconds):
    await asyncio.sleep(seconds)


async def serve(*, max_jobs, poll_seconds):
    if type(max_jobs) is not int or not 1 <= max_jobs <= 100:
        raise ValueError("Worker batch must contain 1 to 100 jobs")
    if type(poll_seconds) is not int or not 5 <= poll_seconds <= 300:
        raise ValueError("Worker poll interval must be 5 to 300 seconds")
    while True:
        # Each tick repeats configuration, native installation and role checks.
        # Provider clients and database pools close before the next idle wait.
        await execute(max_jobs=max_jobs)
        await _wait(poll_seconds)


async def run_command(*, max_jobs, poll_seconds):
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    loop.add_signal_handler(signal.SIGTERM, task.cancel)
    try:
        await serve(max_jobs=max_jobs, poll_seconds=poll_seconds)
    finally:
        loop.remove_signal_handler(signal.SIGTERM)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-jobs", type=int, choices=range(1, 101), default=10)
    parser.add_argument("--poll-seconds", type=int, choices=range(5, 301), default=30)
    args = parser.parse_args()
    try:
        asyncio.run(run_command(max_jobs=args.max_jobs, poll_seconds=args.poll_seconds))
    except (KeyboardInterrupt, asyncio.CancelledError):
        return 130
    except Exception:  # noqa: BLE001 - never expose provider bodies or credentials
        print("Account closure worker unavailable", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
