"""Password recovery orchestration."""

from __future__ import annotations

import atexit
from concurrent.futures import FIRST_COMPLETED, Future, ProcessPoolExecutor, wait
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from time import monotonic
from typing import Iterable, Iterator, Sequence, TextIO
import sys

import pyzipper

from .candidates import estimate_charset_count, iter_charset, iter_charset_range
from .errors import CruxError, PasswordNotFound
from .zip_ops import (
    WinZipAesVerifier,
    build_winzip_aes_verifier,
    choose_probe_member,
    extract_archive,
    fast_password_opens_member_in_zip,
    password_opens_member,
    password_opens_member_in_zip,
)


DEFAULT_BATCH_SIZE = 10_000

_WORKER_ZIP: pyzipper.AESZipFile | None = None
_WORKER_PROBE_MEMBER: str | None = None
_WORKER_VERIFIER: WinZipAesVerifier | None = None


@dataclass(frozen=True)
class RecoveryResult:
    password: str
    extracted_to: Path
    attempts: int


@dataclass(frozen=True)
class BatchResult:
    attempts: int
    password: str | None = None


def _format_duration(seconds: float) -> str:
    seconds_int = max(0, int(seconds))
    hours, remainder = divmod(seconds_int, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def _format_long_duration(seconds: float) -> str:
    seconds_int = max(0, int(seconds))
    years, remainder = divmod(seconds_int, 365 * 24 * 3600)
    months, remainder = divmod(remainder, 30 * 24 * 3600)
    days, remainder = divmod(remainder, 24 * 3600)
    hours, remainder = divmod(remainder, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{years:04d}:{months:02d}:{days:02d}:{hours:02d}:{minutes:02d}:{secs:02d}"


def _format_estimated_remaining(attempts: int, total: int | None, elapsed: float) -> str:
    if not total or total <= 0 or attempts <= 0 or elapsed <= 0:
        return "----:--:--:--:--:--"

    remaining_attempts = max(total - attempts, 0)
    if remaining_attempts == 0:
        return _format_long_duration(0)

    seconds_per_attempt = elapsed / attempts
    return _format_long_duration(remaining_attempts * seconds_per_attempt)


class ProgressDisplay:
    """Render a compact three-line progress display."""

    def __init__(self, stream: TextIO, total: int | None, *, width: int = 32) -> None:
        self.stream = stream
        self.total = total
        self.width = width
        self.started = monotonic()
        self.dynamic = bool(getattr(stream, "isatty", lambda: False)())
        self.drawn = False

    def update(self, attempts: int, status: str) -> None:
        elapsed = monotonic() - self.started
        rate = attempts / elapsed if elapsed > 0 else 0.0
        lines = self._lines(attempts, rate, elapsed, status)

        if self.dynamic:
            if self.drawn:
                self.stream.write("\x1b[3F")
            for line in lines:
                self.stream.write("\x1b[2K" + line + "\n")
            self.stream.flush()
            self.drawn = True
            return

        if attempts == 0 or status != "running":
            for line in lines:
                print(line, file=self.stream)
        else:
            print(lines[1], file=self.stream)

    def _lines(self, attempts: int, rate: float, elapsed: float, status: str) -> list[str]:
        if self.total and self.total > 0:
            ratio = min(attempts / self.total, 1.0)
            filled = int(self.width * ratio)
            bar = "#" * filled + "-" * (self.width - filled)
            progress = f"{ratio * 100:6.2f}% ({attempts}/{self.total})"
        else:
            filled = attempts % (self.width + 1)
            bar = "#" * filled + "-" * (self.width - filled)
            progress = f"{attempts} tried"

        return [
            f"Progress: [{bar}] {progress}",
            f"Tried: {attempts} | Rate: {rate:.1f}/s | "
            f"Elapsed: {_format_duration(elapsed)} | "
            f"Estimated: {_format_estimated_remaining(attempts, self.total, elapsed)}",
            f"Status: {status}",
        ]


def _iter_batches(candidates: Iterable[str], batch_size: int) -> Iterator[list[str]]:
    iterator = iter(candidates)
    while batch := list(islice(iterator, batch_size)):
        yield batch


def _close_worker_zip() -> None:
    global _WORKER_ZIP, _WORKER_PROBE_MEMBER, _WORKER_VERIFIER

    if _WORKER_ZIP is not None:
        _WORKER_ZIP.close()
        _WORKER_ZIP = None
    _WORKER_PROBE_MEMBER = None
    _WORKER_VERIFIER = None


def _init_password_worker(archive_path: str, probe_member: str) -> None:
    global _WORKER_ZIP, _WORKER_PROBE_MEMBER, _WORKER_VERIFIER

    _close_worker_zip()
    _WORKER_ZIP = pyzipper.AESZipFile(archive_path)
    _WORKER_PROBE_MEMBER = probe_member
    _WORKER_VERIFIER = build_winzip_aes_verifier(_WORKER_ZIP, probe_member)


atexit.register(_close_worker_zip)


def _password_opens_in_zip_batch(
    zf: pyzipper.AESZipFile,
    probe_member: str,
    batch: Iterable[str],
    verifier: WinZipAesVerifier | None = None,
) -> BatchResult:
    attempts = 0
    for attempts, candidate in enumerate(batch, start=1):
        if fast_password_opens_member_in_zip(zf, verifier, candidate, probe_member):
            return BatchResult(attempts, candidate)
    return BatchResult(attempts, None)


def _password_opens_in_batch(
    archive_path: str,
    probe_member: str,
    batch: Sequence[str],
) -> BatchResult:
    if _WORKER_ZIP is not None and _WORKER_PROBE_MEMBER == probe_member:
        return _password_opens_in_zip_batch(_WORKER_ZIP, probe_member, batch, _WORKER_VERIFIER)

    with pyzipper.AESZipFile(archive_path) as zf:
        verifier = build_winzip_aes_verifier(zf, probe_member)
        return _password_opens_in_zip_batch(zf, probe_member, batch, verifier)


def _password_opens_in_charset_range(
    archive_path: str,
    probe_member: str,
    charset: str,
    min_length: int,
    max_length: int,
    start: int,
    count: int,
) -> BatchResult:
    candidates = iter_charset_range(charset, min_length, max_length, start, count)
    if _WORKER_ZIP is not None and _WORKER_PROBE_MEMBER == probe_member:
        return _password_opens_in_zip_batch(_WORKER_ZIP, probe_member, candidates, _WORKER_VERIFIER)

    with pyzipper.AESZipFile(archive_path) as zf:
        verifier = build_winzip_aes_verifier(zf, probe_member)
        return _password_opens_in_zip_batch(zf, probe_member, candidates, verifier)


def _print_found(out: TextIO, password: str, extracted_to: Path) -> None:
    print(f"FOUND password: {password}", file=out)
    print(f"Extracted to: {extracted_to}", file=out)


def _recover_archive_serial(
    archive: Path,
    candidates: Iterable[str],
    *,
    probe_member: str,
    output_dir: str | Path | None,
    progress_every: int,
    total_candidates: int | None,
    out: TextIO,
) -> RecoveryResult:
    attempts = 0
    next_progress = progress_every if progress_every > 0 else None
    progress = ProgressDisplay(out, total_candidates)

    progress.update(attempts, f"archive={archive} | probe={probe_member} | workers=1")

    for candidate in candidates:
        attempts += 1
        if password_opens_member(archive, candidate, probe_member):
            progress.update(attempts, "password found; extracting")
            extracted_to = extract_archive(archive, candidate, output_dir)
            progress.update(attempts, "complete")
            _print_found(out, candidate, extracted_to)
            return RecoveryResult(candidate, extracted_to, attempts)

        if next_progress is not None and attempts >= next_progress:
            progress.update(attempts, "running")
            while next_progress <= attempts:
                next_progress += progress_every

    progress.update(attempts, "failed")
    raise PasswordNotFound(f"Password not found after {attempts} attempts.")


def _recover_archive_parallel(
    archive: Path,
    candidates: Iterable[str],
    *,
    probe_member: str,
    output_dir: str | Path | None,
    progress_every: int,
    total_candidates: int | None,
    out: TextIO,
    workers: int,
    batch_size: int,
) -> RecoveryResult:
    attempts = 0
    next_progress = progress_every if progress_every > 0 else None
    progress = ProgressDisplay(out, total_candidates)
    progress.update(
        attempts,
        f"archive={archive} | probe={probe_member} | "
        f"workers={workers} | batch_size={batch_size}",
    )

    batches = _iter_batches(candidates, batch_size)
    pending: set[Future[BatchResult]] = set()
    max_pending = max(workers * 2, workers)
    archive_arg = str(archive)
    executor = ProcessPoolExecutor(
        max_workers=workers,
        initializer=_init_password_worker,
        initargs=(archive_arg, probe_member),
    )
    executor_shutdown = False
    exhausted = False

    def submit_until_full() -> None:
        nonlocal exhausted
        while not exhausted and len(pending) < max_pending:
            try:
                batch = next(batches)
            except StopIteration:
                exhausted = True
                return
            pending.add(executor.submit(_password_opens_in_batch, archive_arg, probe_member, batch))

    try:
        submit_until_full()
        while pending:
            done, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                pending.remove(future)
                result = future.result()
                attempts += result.attempts

                if result.password is not None:
                    progress.update(attempts, "password found; extracting")
                    for pending_future in pending:
                        pending_future.cancel()
                    executor.shutdown(wait=False, cancel_futures=True)
                    executor_shutdown = True
                    extracted_to = extract_archive(archive, result.password, output_dir)
                    progress.update(attempts, "complete")
                    _print_found(out, result.password, extracted_to)
                    return RecoveryResult(result.password, extracted_to, attempts)

                if next_progress is not None and attempts >= next_progress:
                    progress.update(attempts, "running")
                    while next_progress <= attempts:
                        next_progress += progress_every

            submit_until_full()
    finally:
        if not executor_shutdown:
            executor.shutdown(cancel_futures=True)

    progress.update(attempts, "failed")
    raise PasswordNotFound(f"Password not found after {attempts} attempts.")


def _recover_charset_archive_parallel(
    archive: Path,
    *,
    charset: str,
    min_length: int,
    max_length: int,
    probe_member: str,
    output_dir: str | Path | None,
    progress_every: int,
    total_candidates: int,
    out: TextIO,
    workers: int,
    batch_size: int,
) -> RecoveryResult:
    attempts = 0
    next_progress = progress_every if progress_every > 0 else None
    progress = ProgressDisplay(out, total_candidates)
    progress.update(
        attempts,
        f"archive={archive} | probe={probe_member} | workers={workers} | "
        f"batch_size={batch_size} | dispatch=index-range",
    )

    pending: set[Future[BatchResult]] = set()
    max_pending = max(workers * 2, workers)
    archive_arg = str(archive)
    next_start = 0
    executor = ProcessPoolExecutor(
        max_workers=workers,
        initializer=_init_password_worker,
        initargs=(archive_arg, probe_member),
    )
    executor_shutdown = False

    def submit_until_full() -> None:
        nonlocal next_start
        while len(pending) < max_pending and next_start < total_candidates:
            count = min(batch_size, total_candidates - next_start)
            pending.add(
                executor.submit(
                    _password_opens_in_charset_range,
                    archive_arg,
                    probe_member,
                    charset,
                    min_length,
                    max_length,
                    next_start,
                    count,
                )
            )
            next_start += count

    try:
        submit_until_full()
        while pending:
            done, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                pending.remove(future)
                result = future.result()
                attempts += result.attempts

                if result.password is not None:
                    progress.update(attempts, "password found; extracting")
                    for pending_future in pending:
                        pending_future.cancel()
                    executor.shutdown(wait=False, cancel_futures=True)
                    executor_shutdown = True
                    extracted_to = extract_archive(archive, result.password, output_dir)
                    progress.update(attempts, "complete")
                    _print_found(out, result.password, extracted_to)
                    return RecoveryResult(result.password, extracted_to, attempts)

                if next_progress is not None and attempts >= next_progress:
                    progress.update(attempts, "running")
                    while next_progress <= attempts:
                        next_progress += progress_every

            submit_until_full()
    finally:
        if not executor_shutdown:
            executor.shutdown(cancel_futures=True)

    progress.update(attempts, "failed")
    raise PasswordNotFound(f"Password not found after {attempts} attempts.")


def recover_archive(
    archive_path: str | Path,
    candidates: Iterable[str],
    *,
    output_dir: str | Path | None = None,
    progress_every: int = 10_000,
    total_candidates: int | None = None,
    stream: TextIO | None = None,
    workers: int = 1,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> RecoveryResult:
    """Try candidates, extract on success, and return the recovery result."""

    if workers < 1:
        raise CruxError("--workers must be at least 1.")
    if batch_size < 1:
        raise CruxError("--batch-size must be at least 1.")

    out = stream or sys.stdout
    archive = Path(archive_path)
    probe_member = choose_probe_member(archive)
    if workers == 1:
        return _recover_archive_serial(
            archive,
            candidates,
            probe_member=probe_member,
            output_dir=output_dir,
            progress_every=progress_every,
            total_candidates=total_candidates,
            out=out,
        )

    return _recover_archive_parallel(
        archive,
        candidates,
        probe_member=probe_member,
        output_dir=output_dir,
        progress_every=progress_every,
        total_candidates=total_candidates,
        out=out,
        workers=workers,
        batch_size=batch_size,
    )


def recover_charset_archive(
    archive_path: str | Path,
    *,
    charset: str,
    min_length: int,
    max_length: int,
    output_dir: str | Path | None = None,
    progress_every: int = 10_000,
    stream: TextIO | None = None,
    workers: int = 1,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> RecoveryResult:
    """Recover a pure charset search using non-overlapping index ranges."""

    total_candidates = estimate_charset_count(charset, min_length, max_length)
    candidates = iter_charset(charset, min_length, max_length)
    if workers == 1:
        return recover_archive(
            archive_path,
            candidates,
            output_dir=output_dir,
            progress_every=progress_every,
            total_candidates=total_candidates,
            stream=stream,
            workers=workers,
            batch_size=batch_size,
        )

    if workers < 1:
        raise CruxError("--workers must be at least 1.")
    if batch_size < 1:
        raise CruxError("--batch-size must be at least 1.")

    out = stream or sys.stdout
    archive = Path(archive_path)
    probe_member = choose_probe_member(archive)
    return _recover_charset_archive_parallel(
        archive,
        charset=charset,
        min_length=min_length,
        max_length=max_length,
        probe_member=probe_member,
        output_dir=output_dir,
        progress_every=progress_every,
        total_candidates=total_candidates,
        out=out,
        workers=workers,
        batch_size=batch_size,
    )
