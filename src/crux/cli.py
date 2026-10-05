"""Command line interface for CRUX."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import sys
import subprocess
from time import monotonic
from typing import TextIO

from .candidates import CHARSETS, build_candidates, estimate_candidates_count, resolve_charset
from .cracker import DEFAULT_BATCH_SIZE, recover_archive, recover_charset_archive
from .errors import CruxError
from .zip_ops import build_hashcat_hash


def default_workers() -> int:
    return max(1, min(os.cpu_count() or 1, 4))


HASHCAT_BUILTIN_MASKS = {
    "lower": "?l",
    "upper": "?u",
    "digits": "?d",
}
HASHCAT_STATUS_TEXT = {
    0: "initializing",
    1: "running",
    2: "paused",
    3: "exhausted",
    4: "cracked",
    5: "aborted",
    6: "cracked",
    7: "quit",
    8: "bypass",
    9: "checkpoint",
    10: "aborted",
}
HASHCAT_STATUS_KEYS = {
    "STATUS",
    "SPEED",
    "EXEC_RUNTIME",
    "CURKU",
    "PROGRESS",
    "RECHASH",
    "RECSALT",
    "TEMP",
    "REJECTED",
    "UTIL",
    "POWER",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="crux",
        description="Recover an authorized ZIP password and extract the archive.",
    )
    subparsers = parser.add_subparsers(dest="command")

    recover = subparsers.add_parser(
        "recover",
        help="recover a ZIP password and extract the archive",
    )
    recover.add_argument(
        "archive",
        nargs="?",
        default="lock.zip",
        help="ZIP archive path; defaults to lock.zip",
    )
    recover.add_argument(
        "--wordlist",
        help="newline-delimited password wordlist to try before generated candidates",
    )
    recover.add_argument(
        "--mask",
        help="mask to try before charset enumeration, such as CRUX?d?d",
    )
    recover.add_argument(
        "--charset",
        default="alnum",
        choices=["lower", "upper", "digits", "alpha", "alnum", "symbols", "all"],
        help="charset used for generated candidates",
    )
    recover.add_argument(
        "--min-length",
        type=int,
        default=1,
        help="minimum generated candidate length",
    )
    recover.add_argument(
        "--max-length",
        type=int,
        default=5,
        help="maximum generated candidate length",
    )
    recover.add_argument(
        "--output-dir",
        help="directory to extract into; defaults to <archive>_extracted",
    )
    recover.add_argument(
        "--progress-every",
        type=int,
        default=10_000,
        help="refresh progress every N attempts; use 0 to disable periodic refreshes",
    )
    recover.add_argument(
        "--workers",
        type=int,
        default=default_workers(),
        help="worker process count; defaults to min(cpu count, 4)",
    )
    recover.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"password candidates per worker task; defaults to {DEFAULT_BATCH_SIZE}",
    )

    hashcat = subparsers.add_parser(
        "hashcat",
        help="export a ZIP hash and optionally run hashcat",
    )
    hashcat.add_argument(
        "archive",
        nargs="?",
        default="lock.zip",
        help="ZIP archive path; defaults to lock.zip",
    )
    hashcat.add_argument(
        "--member",
        help="archive member to export; defaults to the first encrypted file",
    )
    hashcat.add_argument(
        "--hash-file",
        help="output hash file; defaults to <archive>.hash",
    )
    hashcat.add_argument(
        "--hashcat-path",
        default="hashcat",
        help="hashcat executable path or command name; defaults to hashcat",
    )
    hashcat.add_argument(
        "--mask",
        help='run hashcat mask attack, such as "?a?a?a?a?a?a"',
    )
    hashcat.add_argument(
        "--wordlist",
        help="run hashcat straight attack with this wordlist",
    )
    hashcat.add_argument(
        "--charset",
        choices=list(CHARSETS),
        help="run hashcat mask attack over this named charset",
    )
    hashcat.add_argument(
        "--min-length",
        type=int,
        default=1,
        help="minimum generated hashcat mask length; used with --charset",
    )
    hashcat.add_argument(
        "--max-length",
        type=int,
        default=5,
        help="maximum generated hashcat mask length; used with --charset",
    )
    hashcat.add_argument(
        "--no-run",
        action="store_true",
        help="only export the hash file; do not invoke hashcat",
    )
    hashcat.add_argument(
        "-w",
        "--workload-profile",
        type=int,
        default=3,
        choices=[1, 2, 3, 4],
        help="hashcat workload profile; defaults to 3",
    )
    hashcat.add_argument(
        "--device",
        help="hashcat device list passed to -d, such as 1 or 1,2",
    )
    hashcat.add_argument(
        "--extra-arg",
        action="append",
        default=[],
        help="extra argument appended to the hashcat command; repeat as needed",
    )
    hashcat.add_argument(
        "--raw-output",
        action="store_true",
        help="show hashcat's original verbose output instead of CRUX compact progress",
    )
    return parser


def run_recover(args: argparse.Namespace) -> int:
    archive = Path(args.archive)
    if not archive.exists():
        raise CruxError(f"Archive not found: {archive}")
    if args.workers < 1:
        raise CruxError("--workers must be at least 1.")
    if args.batch_size < 1:
        raise CruxError("--batch-size must be at least 1.")

    total = estimate_candidates_count(
        wordlist=args.wordlist,
        mask=args.mask,
        charset=args.charset,
        min_length=args.min_length,
        max_length=args.max_length,
    )
    print(
        "Search: wordlist="
        f"{args.wordlist or 'none'}, mask={args.mask or 'none'}, "
        f"charset={args.charset}, lengths={args.min_length}-{args.max_length}, "
        f"total={total}, workers={args.workers}, batch_size={args.batch_size}",
    )

    if args.wordlist is None and args.mask is None:
        recover_charset_archive(
            archive,
            charset=args.charset,
            min_length=args.min_length,
            max_length=args.max_length,
            output_dir=args.output_dir,
            progress_every=args.progress_every,
            workers=args.workers,
            batch_size=args.batch_size,
        )
    else:
        candidates = build_candidates(
            wordlist=args.wordlist,
            mask=args.mask,
            charset=args.charset,
            min_length=args.min_length,
            max_length=args.max_length,
        )
        recover_archive(
            archive,
            candidates,
            output_dir=args.output_dir,
            progress_every=args.progress_every,
            total_candidates=total,
            workers=args.workers,
            batch_size=args.batch_size,
        )
    return 0


def _default_hash_file(archive: Path) -> Path:
    return archive.with_suffix(".hash")


def _resolve_hashcat_executable(command: str) -> str:
    path = Path(command)
    if path.exists():
        return str(path.resolve())

    resolved = shutil.which(command)
    if resolved is None:
        raise CruxError(
            "hashcat executable not found. Install hashcat or pass "
            "--hashcat-path PATH; use --no-run if you only want to export the hash."
        )
    return str(Path(resolved).resolve())


def _hashcat_charset_attack_args(
    charset: str,
    min_length: int,
    max_length: int,
) -> list[str]:
    if min_length < 1:
        raise CruxError("--min-length must be at least 1.")
    if max_length < min_length:
        raise CruxError("--max-length must be greater than or equal to --min-length.")

    if charset in HASHCAT_BUILTIN_MASKS:
        unit = HASHCAT_BUILTIN_MASKS[charset]
        args: list[str] = []
    else:
        unit = "?1"
        args = ["-1", resolve_charset(charset)]

    mask = unit * max_length
    if min_length != max_length:
        args.extend(["--increment", "--increment-min", str(min_length), "--increment-max", str(max_length)])

    args.extend(["-a", "3", mask])
    return args


def _format_hashcat_rate(rate: float) -> str:
    units = ["H/s", "KH/s", "MH/s", "GH/s", "TH/s"]
    value = float(max(rate, 0.0))
    unit = units[0]
    for unit in units:
        if value < 1000 or unit == units[-1]:
            break
        value /= 1000
    return f"{value:.1f} {unit}"


def _format_hashcat_duration(seconds: float) -> str:
    seconds_int = max(0, int(seconds))
    hours, remainder = divmod(seconds_int, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


class HashcatProgressDisplay:
    """Render compact hashcat progress."""

    def __init__(self, stream: TextIO, *, width: int = 32) -> None:
        self.stream = stream
        self.width = width
        self.started = monotonic()
        self.dynamic = bool(getattr(stream, "isatty", lambda: False)())
        self.drawn = False

    def update(self, current: int, total: int, speed: float, status: str) -> None:
        elapsed = monotonic() - self.started
        lines = self._lines(current, total, speed, elapsed, status)

        if self.dynamic:
            if self.drawn:
                self.stream.write("\x1b[3F")
            for line in lines:
                self.stream.write("\x1b[2K" + line + "\n")
            self.stream.flush()
            self.drawn = True
            return

        if current == 0 or status != "running":
            for line in lines:
                print(line, file=self.stream)
        else:
            print(lines[1], file=self.stream)

    def _lines(
        self,
        current: int,
        total: int,
        speed: float,
        elapsed: float,
        status: str,
    ) -> list[str]:
        if total > 0:
            ratio = min(current / total, 1.0)
            filled = int(self.width * ratio)
            progress = f"{ratio * 100:6.2f}% ({current}/{total})"
        else:
            filled = current % (self.width + 1)
            progress = f"{current} tried"
        bar = "#" * filled + "-" * (self.width - filled)
        if total > 0 and speed > 0:
            remaining = max(total - current, 0)
            estimated = _format_hashcat_duration(remaining / speed)
        else:
            estimated = "--:--:--"
        return [
            f"Progress: [{bar}] {progress}",
            f"Tried: {current} | Rate: {_format_hashcat_rate(speed)} | "
            f"Elapsed: {_format_hashcat_duration(elapsed)} | Estimated: {estimated}",
            f"Status: {status}",
        ]


def _parse_hashcat_status(line: str) -> tuple[int, int, float, str] | None:
    if not line.startswith("STATUS\t"):
        return None

    parts = line.strip().split("\t")
    values: dict[str, list[str]] = {}
    index = 0
    while index < len(parts):
        key = parts[index]
        index += 1
        collected: list[str] = []
        while index < len(parts) and parts[index] not in HASHCAT_STATUS_KEYS:
            collected.append(parts[index])
            index += 1
        values[key] = collected

    status_code = _parse_int(values.get("STATUS", ["1"])[0], default=1)
    progress = values.get("PROGRESS", ["0", "0"])
    speed_values = values.get("SPEED", [])
    current = _parse_int(progress[0] if progress else "0", default=0)
    total = _parse_int(progress[1] if len(progress) > 1 else "0", default=0)
    speed = sum(_parse_float(speed_values[i], default=0.0) for i in range(0, len(speed_values), 2))
    status = HASHCAT_STATUS_TEXT.get(status_code, f"status={status_code}")
    return current, total, speed, status


def _parse_int(value: str, *, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _parse_float(value: str, *, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _read_found_passwords(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [
        line.rstrip("\r\n")
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.rstrip("\r\n")
    ]


def _hashcat_potfile_args(extra_args: list[str]) -> list[str] | None:
    potfile_args: list[str] = []
    index = 0
    while index < len(extra_args):
        arg = extra_args[index]
        if arg == "--potfile-disable":
            return None
        if arg == "--potfile-path":
            if index + 1 >= len(extra_args):
                raise CruxError("--potfile-path requires a path argument.")
            potfile_args.extend([arg, extra_args[index + 1]])
            index += 2
            continue
        if arg.startswith("--potfile-path="):
            potfile_args.append(arg)
        index += 1
    return potfile_args


def _show_hashcat_passwords(
    *,
    executable: str,
    mode: int,
    hash_file: Path,
    cwd: Path,
    potfile_args: list[str] | None,
) -> list[str]:
    if potfile_args is None:
        return []

    command = [
        executable,
        "-m",
        str(mode),
        "--show",
        str(hash_file.resolve()),
        "--outfile-format=2",
        "--logfile-disable",
    ]
    command.extend(potfile_args)
    result = subprocess.run(
        command,
        check=False,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode not in {0, 1}:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _print_found_passwords(passwords: list[str]) -> None:
    for password in passwords:
        print(f"FOUND password: {password}")


def _run_hashcat_compact(
    command: list[str],
    *,
    cwd: Path,
    outfile: Path,
    executable: str,
    mode: int,
    hash_file: Path,
    potfile_args: list[str] | None,
) -> int:
    progress = HashcatProgressDisplay(sys.stdout)
    progress.update(0, 0, 0, "starting hashcat")

    with subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    ) as process:
        assert process.stdout is not None
        last_update: tuple[int, int, float, str] | None = None
        for line in process.stdout:
            parsed = _parse_hashcat_status(line)
            if parsed is None:
                continue
            last_update = parsed
            progress.update(*parsed)
        returncode = process.wait()

    passwords = _read_found_passwords(outfile)
    if not passwords:
        passwords = _show_hashcat_passwords(
            executable=executable,
            mode=mode,
            hash_file=hash_file,
            cwd=cwd,
            potfile_args=potfile_args,
        )
    if passwords:
        current, total, speed, _ = last_update or (0, 0, 0, "cracked")
        if last_update is None or last_update[3] != "cracked":
            progress.update(current, total, speed, "cracked")
        _print_found_passwords(passwords)
        return returncode

    current, total, speed, status = last_update or (0, 0, 0, "failed")
    if returncode == 0 and status != "cracked":
        status = "exhausted"
    progress.update(current, total, speed, status)
    if returncode == 0:
        print("Password not found in selected hashcat attack range.")
    return returncode


def run_hashcat(args: argparse.Namespace) -> int:
    archive = Path(args.archive)
    if not archive.exists():
        raise CruxError(f"Archive not found: {archive}")
    attack_sources = sum(
        value is not None
        for value in (
            args.mask,
            args.wordlist,
            args.charset,
        )
    )
    if attack_sources > 1:
        raise CruxError("--mask, --wordlist, and --charset are mutually exclusive.")

    hash_record = build_hashcat_hash(archive, args.member)
    hash_file = Path(args.hash_file) if args.hash_file else _default_hash_file(archive)
    hash_file.parent.mkdir(parents=True, exist_ok=True)
    hash_file.write_text(hash_record.hash_line + "\n", encoding="utf-8")
    outfile = hash_file.with_suffix(f"{hash_file.suffix}.found")
    if outfile.exists():
        outfile.unlink()

    print(f"Hashcat mode: {hash_record.mode} ({hash_record.mode_name})")
    print(f"Hash file: {hash_file}")
    print(f"Members: {', '.join(hash_record.members)}")
    print(f"Hash data bytes: {hash_record.data_bytes}")

    if args.no_run or attack_sources == 0:
        if attack_sources == 0 and not args.no_run:
            print("Attack: none; exported hash only. Add --mask, --wordlist, or --charset to crack.")
        return 0

    executable = _resolve_hashcat_executable(args.hashcat_path)
    hashcat_cwd = Path(executable).parent
    command = [
        executable,
        "-m",
        str(hash_record.mode),
        "-w",
        str(args.workload_profile),
    ]
    if args.device:
        command.extend(["-d", args.device])

    if args.wordlist:
        print(f"Attack: wordlist={args.wordlist}")
        wordlist = Path(args.wordlist)
        if not wordlist.exists():
            raise CruxError(f"Wordlist not found: {wordlist}")
        command.extend(["-a", "0", str(hash_file.resolve()), str(wordlist.resolve())])
    elif args.mask:
        print(f"Attack: mask={args.mask}")
        command.extend(["-a", "3", str(hash_file.resolve()), args.mask])
    else:
        print(f"Attack: charset={args.charset}, lengths={args.min_length}-{args.max_length}")
        attack_args = _hashcat_charset_attack_args(args.charset, args.min_length, args.max_length)
        mask = attack_args.pop()
        command.extend(attack_args)
        command.extend([str(hash_file.resolve()), mask])

    command.extend(args.extra_arg)
    if args.raw_output:
        print("Running:", subprocess.list2cmdline(command), flush=True)
        return subprocess.run(command, check=False, cwd=hashcat_cwd).returncode

    potfile_args = _hashcat_potfile_args(args.extra_arg)
    known_passwords = _show_hashcat_passwords(
        executable=executable,
        mode=hash_record.mode,
        hash_file=hash_file,
        cwd=hashcat_cwd,
        potfile_args=potfile_args,
    )
    if known_passwords:
        print("Status: already cracked (potfile)")
        _print_found_passwords(known_passwords)
        return 0

    command.extend(
        [
            "--machine-readable",
            "--status",
            "--status-timer=2",
            "--outfile",
            str(outfile.resolve()),
            "--outfile-format=2",
            "--outfile-autohex-disable",
            "--logfile-disable",
        ]
    )
    return _run_hashcat_compact(
        command,
        cwd=hashcat_cwd,
        outfile=outfile,
        executable=executable,
        mode=hash_record.mode,
        hash_file=hash_file,
        potfile_args=potfile_args,
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 2

    try:
        if args.command == "recover":
            return run_recover(args)
        if args.command == "hashcat":
            return run_hashcat(args)
    except CruxError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
