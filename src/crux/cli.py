"""Command line interface for CRUX."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic
from typing import TextIO

from . import __version__
from .candidates import CHARSETS, resolve_charset
from .errors import CruxError
from .zip_ops import HASHCAT_PKZIP_STREAM_MODE, build_hashcat_hash

HASHCAT_BUILTIN_MASKS = {
    "lower": "?l",
    "upper": "?u",
    "digits": "?d",
}
HASHCAT_STATUS_TEXT = {
    0: "initializing",
    1: "autotuning",
    2: "self-test",
    3: "running",
    4: "paused",
    5: "exhausted",
    6: "cracked",
    7: "aborted",
    8: "quit",
    9: "bypass",
    10: "checkpoint",
    11: "runtime limit",
    13: "failed",
    14: "finish",
    16: "autodetecting",
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
        description="Recover a ZIP password with hashcat using a charset or wordlist.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument("archive", help="ZIP archive path")
    attacks = parser.add_mutually_exclusive_group()
    attacks.add_argument(
        "--charset",
        choices=list(CHARSETS),
        help="normal search charset; defaults to alnum when --wordlist is omitted",
    )
    attacks.add_argument(
        "--wordlist", help="UTF-8 password file, one candidate per line"
    )
    parser.add_argument(
        "--min",
        dest="min_length",
        type=int,
        default=1,
        help="minimum password length, inclusive; defaults to 1",
    )
    parser.add_argument(
        "--max",
        dest="max_length",
        type=int,
        help="maximum length, inclusive; defaults to 5 for charset, unlimited for wordlist",
    )
    parser.add_argument(
        "--hashcat",
        "--hashcat-path",
        dest="hashcat_path",
        help="hashcat executable or directory; otherwise auto-detected (also uses HASHCAT)",
    )
    parser.add_argument("--member", help="ZIP member to use for hash export")
    parser.add_argument(
        "--hash-file", help="hash output path; defaults to <archive>.hash"
    )
    parser.add_argument(
        "--no-run", action="store_true", help="export the hash without running hashcat"
    )
    parser.add_argument(
        "-w",
        "--workload-profile",
        type=int,
        choices=[1, 2, 3, 4],
        default=2,
        help="hashcat workload profile; defaults to 2",
    )
    parser.add_argument("--device", help="hashcat device list, such as 1 or 1,2")
    parser.add_argument(
        "--extra-arg",
        action="append",
        default=[],
        help="extra hashcat argument; repeat --extra-arg=VALUE as needed",
    )
    parser.add_argument(
        "--raw-output", action="store_true", help="show the original hashcat output"
    )
    return parser


def _default_hash_file(archive: Path) -> Path:
    return archive.with_suffix(".hash")


HASHCAT_FORK_URL = "https://github.com/GusterNovar/hashcat/tree/feature/pkzip-streaming"


def _hashcat_in_directory(directory: Path) -> Path | None:
    names = ("hashcat.exe",) if os.name == "nt" else ("hashcat", "hashcat.bin")
    for name in names:
        candidate = directory / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.resolve()
    return None


def _resolve_hashcat_executable(command: str | None = None) -> str:
    configured = command if command is not None else os.environ.get("HASHCAT")
    if configured is not None:
        path = Path(configured).expanduser()
        if path.is_dir():
            executable = _hashcat_in_directory(path)
        elif path.is_file() and os.access(path, os.X_OK):
            executable = path.resolve()
        else:
            resolved = shutil.which(configured) if configured else None
            executable = Path(resolved).resolve() if resolved else None
        if executable is None:
            raise CruxError(
                f"hashcat executable not found: {configured!r}. Set --hashcat PATH or HASHCAT."
            )
        return str(executable)

    for name in ("hashcat.exe",) if os.name == "nt" else ("hashcat", "hashcat.bin"):
        resolved = shutil.which(name)
        if resolved:
            return str(Path(resolved).resolve())

    project = Path(__file__).resolve().parents[2]
    directories = []
    for root in (Path.cwd(), project):
        tools = root / ".tools"
        directories.extend((root / "hashcat", tools / "hashcat", tools))
        if tools.is_dir():
            directories.extend(sorted(tools.glob("hashcat-*"), reverse=True))
    for directory in directories:
        executable = _hashcat_in_directory(directory)
        if executable is not None:
            return str(executable)
    raise CruxError(
        "hashcat executable not found. Install a complete hashcat binary release, "
        "set HASHCAT, or pass --hashcat PATH. A source directory alone cannot run hashcat."
    )


@contextmanager
def _filtered_wordlist(
    source: Path,
    min_length: int,
    max_length: int | None,
    *,
    directory: Path,
) -> Iterator[Path]:
    # Stream to disk so large dictionaries do not have to fit in memory.
    with TemporaryDirectory(prefix=".crux-wordlist-", dir=directory) as temporary:
        filtered = Path(temporary) / "passwords.txt"
        count = 0
        with (
            source.open("r", encoding="utf-8-sig") as incoming,
            filtered.open("w", encoding="utf-8", newline="\n") as outgoing,
        ):
            for line in incoming:
                password = line.rstrip("\r\n")
                if len(password) < min_length or (
                    max_length is not None and len(password) > max_length
                ):
                    continue
                outgoing.write(password + "\n")
                count += 1
        if count == 0:
            raise CruxError(
                "Wordlist has no passwords within the selected length range."
            )
        print(f"Wordlist candidates: {count}")
        yield filtered


def _hashcat_charset_attack_args(
    charset: str,
    min_length: int,
    max_length: int,
) -> list[str]:
    if min_length < 1:
        raise CruxError("--min must be at least 1.")
    if max_length < min_length:
        raise CruxError("--max must be greater than or equal to --min.")

    if charset in HASHCAT_BUILTIN_MASKS:
        unit = HASHCAT_BUILTIN_MASKS[charset]
        args: list[str] = []
    else:
        unit = "?1"
        args = ["-1", resolve_charset(charset)]

    mask = unit * max_length
    if min_length != max_length:
        args.extend(
            [
                "--increment",
                "--increment-min",
                str(min_length),
                "--increment-max",
                str(max_length),
            ]
        )

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
            (
                f"Tried: {current} | Rate: {_format_hashcat_rate(speed)} | "
                f"Elapsed: {_format_hashcat_duration(elapsed)} | Estimated: {estimated}"
            ),
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

    status_code = _parse_int(values.get("STATUS", ["3"])[0], default=3)
    progress = values.get("PROGRESS", ["0", "0"])
    speed_values = values.get("SPEED", [])
    current = _parse_int(progress[0] if progress else "0", default=0)
    total = _parse_int(progress[1] if len(progress) > 1 else "0", default=0)
    speed = sum(
        _parse_float(speed_values[i], default=0.0)
        for i in range(0, len(speed_values), 2)
    )
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


def _decode_hashcat_password(value: str) -> str:
    if value.startswith("$HEX[") and value.endswith("]"):
        try:
            return bytes.fromhex(value[5:-1]).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            pass
    return value


def _password_lines(value: str, *, autohex: bool = True) -> list[str]:
    return [
        _decode_hashcat_password(line.rstrip("\r")) if autohex else line.rstrip("\r")
        for line in value.split("\n")
        if line.rstrip("\r")
    ]


def _read_found_passwords(path: Path) -> list[str]:
    if not path.exists():
        return []
    return _password_lines(
        path.read_text(encoding="utf-8", errors="replace"), autohex=False
    )


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
    return _password_lines(result.stdout)


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
        diagnostics: deque[str] = deque(maxlen=40)
        try:
            for line in process.stdout:
                parsed = _parse_hashcat_status(line)
                if parsed is None:
                    if line.strip():
                        diagnostics.append(line.rstrip())
                    continue
                last_update = parsed
                progress.update(*parsed)
            returncode = process.wait()
        except KeyboardInterrupt:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            raise

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

    current, total, speed, _ = last_update or (0, 0, 0, "failed")
    status = "exhausted" if returncode in {0, 1} else "failed"
    progress.update(current, total, speed, status)
    if returncode in {0, 1}:
        print("Password not found in selected hashcat attack range.")
    else:
        for line in diagnostics:
            print(line, file=sys.stderr)
        print(f"hashcat exited with code {returncode}.", file=sys.stderr)
    return returncode or 1


def run_hashcat(args: argparse.Namespace) -> int:
    archive = Path(args.archive)
    if not archive.is_file():
        raise CruxError(f"Archive not found: {archive}")
    if args.min_length < 1:
        raise CruxError("--min must be at least 1.")
    if args.wordlist is None:
        args.charset = args.charset or "alnum"
        args.max_length = args.max_length if args.max_length is not None else 5
    if args.max_length is not None and args.max_length < args.min_length:
        raise CruxError("--max must be greater than or equal to --min.")
    wordlist = Path(args.wordlist).resolve() if args.wordlist is not None else None
    if wordlist is not None and not wordlist.is_file():
        raise CruxError(f"Wordlist not found: {wordlist}")

    hash_file = (
        Path(args.hash_file) if args.hash_file else _default_hash_file(archive)
    ).resolve()
    outfile = hash_file.with_suffix(f"{hash_file.suffix}.found")
    if archive.resolve() in {hash_file, outfile} or (
        wordlist is not None and wordlist in {hash_file, outfile}
    ):
        raise CruxError(
            "Hash and result files must not overwrite the archive or wordlist."
        )
    executable = None if args.no_run else _resolve_hashcat_executable(args.hashcat_path)
    hash_record = build_hashcat_hash(archive, args.member)
    if hash_record.mode == HASHCAT_PKZIP_STREAM_MODE and executable is not None:
        suffix = ".dll" if os.name == "nt" else ".so"
        plugin = Path(executable).parent / "modules" / f"module_17240{suffix}"
        if not plugin.is_file():
            raise CruxError(
                "This ZIP requires the hashcat PKZIP streaming extension (mode 17240). "
                f"Build {HASHCAT_FORK_URL} and select it with --hashcat PATH."
            )
    hash_file.parent.mkdir(parents=True, exist_ok=True)
    hash_file.write_text(hash_record.hash_line + "\n", encoding="utf-8")

    print(f"Hashcat mode: {hash_record.mode} ({hash_record.mode_name})")
    print(f"Hash file: {hash_file}")
    print(f"Members: {', '.join(hash_record.members)}")
    if args.no_run:
        return 0

    assert executable is not None
    hashcat_cwd = Path(executable).parent
    print(f"Hashcat: {executable}")
    command = [
        executable,
        "-m",
        str(hash_record.mode),
        "-w",
        str(args.workload_profile),
    ]
    if args.device:
        command.extend(["-d", args.device])
    if wordlist is not None:
        maximum = args.max_length if args.max_length is not None else "unlimited"
        print(f"Attack: wordlist={wordlist}, lengths={args.min_length}-{maximum}")
        with _filtered_wordlist(
            wordlist, args.min_length, args.max_length, directory=hash_file.parent
        ) as filtered:
            command.extend(["-a", "0", str(hash_file), str(filtered)])
            return _invoke_hashcat(
                args,
                command,
                executable,
                hash_record.mode,
                hash_file,
                outfile,
                hashcat_cwd,
            )

    print(
        f"Attack: charset={args.charset}, lengths={args.min_length}-{args.max_length}"
    )
    attack_args = _hashcat_charset_attack_args(
        args.charset, args.min_length, args.max_length
    )
    mask = attack_args.pop()
    command.extend(attack_args)
    command.extend([str(hash_file), mask])
    return _invoke_hashcat(
        args, command, executable, hash_record.mode, hash_file, outfile, hashcat_cwd
    )


def _invoke_hashcat(
    args: argparse.Namespace,
    command: list[str],
    executable: str,
    mode: int,
    hash_file: Path,
    outfile: Path,
    cwd: Path,
) -> int:
    command.extend(args.extra_arg)
    potfile_args = _hashcat_potfile_args(args.extra_arg)
    known_passwords = _show_hashcat_passwords(
        executable=executable,
        mode=mode,
        hash_file=hash_file,
        cwd=cwd,
        potfile_args=potfile_args,
    )
    if known_passwords:
        print("Status: already cracked (potfile)")
        _print_found_passwords(known_passwords)
        return 0

    if outfile.exists():
        outfile.unlink()
    command.extend(
        [
            "--outfile",
            str(outfile),
            "--outfile-format=2",
            "--outfile-autohex-disable",
            "--logfile-disable",
        ]
    )
    if args.raw_output:
        print("Running:", subprocess.list2cmdline(command), flush=True)
        result = subprocess.run(command, check=False, cwd=cwd)
        passwords = _read_found_passwords(outfile)
        if not passwords:
            passwords = _show_hashcat_passwords(
                executable=executable,
                mode=mode,
                hash_file=hash_file,
                cwd=cwd,
                potfile_args=potfile_args,
            )
        _print_found_passwords(passwords)
        return result.returncode if passwords else (result.returncode or 1)

    command.extend(["--machine-readable", "--status", "--status-timer=2"])
    return _run_hashcat_compact(
        command,
        cwd=cwd,
        outfile=outfile,
        executable=executable,
        mode=mode,
        hash_file=hash_file,
        potfile_args=potfile_args,
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run_hashcat(args)
    except (CruxError, OSError, UnicodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
