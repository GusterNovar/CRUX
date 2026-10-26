from pathlib import Path
import io
import struct
import zipfile
import zlib

import pyzipper
import pytest

from crux.candidates import build_candidates
from crux.cli import _parse_hashcat_status, main
from crux.cracker import ProgressDisplay, recover_archive
from crux.errors import ArchiveError
from crux.zip_ops import (
    HASHCAT_PKZIP_CHECKSUM_ONLY_MODE,
    HASHCAT_WINZIP_MODE,
    build_hashcat_hash,
    build_hashcat_winzip_hash,
    build_winzip_aes_verifier,
    extract_archive,
    fast_password_opens_member_in_zip,
    password_opens_member,
    password_opens_member_in_zip,
)


def make_encrypted_zip(path: Path, password: str) -> None:
    with pyzipper.AESZipFile(
        path,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as zf:
        zf.setpassword(password.encode("utf-8"))
        zf.writestr("1-8/01.mp4", b"video-one")
        zf.writestr("1-8/02.mp4", b"video-two")


def make_pkzip_crypto_stub(path: Path, file_count: int = 3) -> None:
    records = []
    offset = 0
    mod_time = 0x49AD
    mod_date = 0x5997

    with path.open("wb") as handle:
        for index in range(file_count):
            filename = f"file-{index}.bin".encode("utf-8")
            plaintext = bytes(range(256)) * (index + 2)
            compressor = zlib.compressobj(level=6, wbits=-15)
            deflated = compressor.compress(plaintext) + compressor.flush()
            encrypted_payload = bytes(range(12)) + deflated
            crc = zlib.crc32(plaintext) & 0xFFFFFFFF
            compressed_size = len(encrypted_payload)
            file_size = len(plaintext)

            local_header = struct.pack(
                "<IHHHHHIIIHH",
                0x04034B50,
                20,
                0x1,
                zipfile.ZIP_DEFLATED,
                mod_time,
                mod_date,
                crc,
                compressed_size,
                file_size,
                len(filename),
                0,
            )
            handle.write(local_header)
            handle.write(filename)
            handle.write(encrypted_payload)
            records.append((filename, crc, compressed_size, file_size, offset))
            offset = handle.tell()

        central_start = handle.tell()
        for filename, crc, compressed_size, file_size, header_offset in records:
            central_header = struct.pack(
                "<IHHHHHHIIIHHHHHII",
                0x02014B50,
                20,
                20,
                0x1,
                zipfile.ZIP_DEFLATED,
                mod_time,
                mod_date,
                crc,
                compressed_size,
                file_size,
                len(filename),
                0,
                0,
                0,
                0,
                0,
                header_offset,
            )
            handle.write(central_header)
            handle.write(filename)

        central_size = handle.tell() - central_start
        eocd = struct.pack(
            "<IHHHHIIH",
            0x06054B50,
            0,
            0,
            len(records),
            len(records),
            central_size,
            central_start,
            0,
        )
        handle.write(eocd)


def test_recover_archive_finds_password_and_extracts(tmp_path: Path):
    archive = tmp_path / "lock.zip"
    make_encrypted_zip(archive, "A1")

    result = recover_archive(
        archive,
        ["nope", "A1"],
        output_dir=tmp_path / "out",
        progress_every=0,
        total_candidates=2,
    )

    assert result.password == "A1"
    assert result.attempts == 2
    assert (result.extracted_to / "1-8" / "01.mp4").read_bytes() == b"video-one"
    assert (result.extracted_to / "1-8" / "02.mp4").read_bytes() == b"video-two"


def test_recover_archive_stops_after_found_password(tmp_path: Path):
    archive = tmp_path / "lock.zip"
    make_encrypted_zip(archive, "A1")

    def candidates():
        yield "nope"
        yield "A1"
        raise AssertionError("recovery should stop after the password is found")

    result = recover_archive(
        archive,
        candidates(),
        output_dir=tmp_path / "out",
        progress_every=1,
        total_candidates=3,
    )

    assert result.password == "A1"
    assert result.attempts == 2


def test_recover_archive_parallel_finds_password_and_extracts(tmp_path: Path):
    archive = tmp_path / "lock.zip"
    make_encrypted_zip(archive, "A1")

    result = recover_archive(
        archive,
        ["nope", "A1", "later"],
        output_dir=tmp_path / "out",
        progress_every=1,
        total_candidates=3,
        workers=2,
        batch_size=2,
    )

    assert result.password == "A1"
    assert 2 <= result.attempts <= 3
    assert (result.extracted_to / "1-8" / "01.mp4").read_bytes() == b"video-one"


def test_recover_archive_uses_three_line_tty_progress(tmp_path: Path):
    class TTYBuffer(io.StringIO):
        def isatty(self):
            return True

    archive = tmp_path / "lock.zip"
    make_encrypted_zip(archive, "0")
    stream = TTYBuffer()

    recover_archive(
        archive,
        ["0"],
        output_dir=tmp_path / "out",
        progress_every=1,
        total_candidates=1,
        stream=stream,
    )

    output = stream.getvalue()
    assert "Progress:" in output
    assert "Tried: 1" in output
    assert "Estimated:" in output
    assert "\x1b[3F" in output


def test_progress_display_includes_estimated_remaining():
    progress = ProgressDisplay(io.StringIO(), total=10)

    lines = progress._lines(2, 1.0, 20.0, "running")

    assert (
        lines[1]
        == "Tried: 2 | Rate: 1.0/s | Elapsed: 00:00:20 | "
        "Estimated: 0000:00:00:00:01:20"
    )


def test_wrong_password_zlib_error_is_treated_as_failed_candidate(monkeypatch):
    class BrokenHandle:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def read(self, size):
            raise zlib.error("invalid distance too far back")

    class BrokenZip:
        def __init__(self, archive):
            self.archive = archive
            self.pwd = None

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def open(self, member, mode, pwd=None):
            return BrokenHandle()

    monkeypatch.setattr(pyzipper, "AESZipFile", BrokenZip)

    assert password_opens_member("lock.zip", "wrong", "1-8/01.mp4") is False


def test_reusable_zip_object_handles_wrong_then_right_password(tmp_path: Path):
    archive = tmp_path / "lock.zip"
    make_encrypted_zip(archive, "A1")

    with pyzipper.AESZipFile(archive) as zf:
        assert password_opens_member_in_zip(zf, "wrong", "1-8/01.mp4") is False
        assert password_opens_member_in_zip(zf, "still-wrong", "1-8/01.mp4") is False
        assert password_opens_member_in_zip(zf, "A1", "1-8/01.mp4") is True


def test_fast_winzip_aes_verifier_rejects_wrong_password(tmp_path: Path):
    archive = tmp_path / "lock.zip"
    make_encrypted_zip(archive, "A1")

    with pyzipper.AESZipFile(archive) as zf:
        verifier = build_winzip_aes_verifier(zf, "1-8/01.mp4")

        assert verifier is not None
        assert fast_password_opens_member_in_zip(zf, verifier, "wrong", "1-8/01.mp4") is False
        assert fast_password_opens_member_in_zip(zf, verifier, "A1", "1-8/01.mp4") is True


def test_build_hashcat_winzip_hash_exports_zip2_hash(tmp_path: Path):
    archive = tmp_path / "lock.zip"
    make_encrypted_zip(archive, "A1")

    result = build_hashcat_winzip_hash(archive, "1-8/01.mp4")

    assert result.member == "1-8/01.mp4"
    assert result.encrypted_data_length > 0
    assert result.hash_line.startswith("$zip2$*0*")
    assert result.hash_line.endswith("*$/zip2$")

    parts = result.hash_line.split("*")
    assert parts[1] == "0"
    assert parts[2] in {"1", "2", "3"}
    assert parts[3] == "0"
    assert int(parts[5], 16) < 0x10000
    assert int(parts[6], 16) == result.encrypted_data_length
    assert len(parts[8]) == 20


def test_build_hashcat_hash_exports_pkzip_checksum_only_hash(tmp_path: Path):
    archive = tmp_path / "pkzip.zip"
    make_pkzip_crypto_stub(archive, file_count=3)

    result = build_hashcat_hash(archive)

    assert result.mode == HASHCAT_PKZIP_CHECKSUM_ONLY_MODE
    assert result.mode_name == "PKZIP checksum-only"
    assert result.members == ("file-0.bin", "file-1.bin", "file-2.bin")
    assert result.data_bytes == 36 * 3
    assert result.hash_line.startswith("$pkzip2$3*1*1*0*8*24*")
    assert result.hash_line.endswith("*$/pkzip2$")


def test_build_hashcat_winzip_hash_rejects_too_large_member(tmp_path: Path):
    archive = tmp_path / "lock.zip"
    make_encrypted_zip(archive, "A1")

    with pytest.raises(ArchiveError, match="requires inline encrypted member data"):
        build_hashcat_winzip_hash(archive, "1-8/01.mp4", inline_data_limit=1)


def test_hashcat_cli_exports_hash_without_running(tmp_path: Path, capsys):
    archive = tmp_path / "lock.zip"
    hash_file = tmp_path / "lock.hash"
    make_encrypted_zip(archive, "A1")

    exit_code = main(
        [
            str(archive),
            "--member",
            "1-8/01.mp4",
            "--hash-file",
            str(hash_file),
            "--no-run",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert f"Hashcat mode: {HASHCAT_WINZIP_MODE} (WinZip)" in captured.out
    assert "Members: 1-8/01.mp4" in captured.out
    assert hash_file.read_text(encoding="utf-8").startswith("$zip2$")


def test_hashcat_cli_exports_pkzip_hash_without_running(tmp_path: Path, capsys):
    archive = tmp_path / "pkzip.zip"
    hash_file = tmp_path / "pkzip.hash"
    make_pkzip_crypto_stub(archive, file_count=3)

    exit_code = main(
        [
            str(archive),
            "--hash-file",
            str(hash_file),
            "--no-run",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert f"Hashcat mode: {HASHCAT_PKZIP_CHECKSUM_ONLY_MODE} (PKZIP checksum-only)" in captured.out
    assert "Members: file-0.bin, file-1.bin, file-2.bin" in captured.out
    assert hash_file.read_text(encoding="utf-8").startswith("$pkzip2$3")


def test_hashcat_cli_charset_range_runs_increment_mask(tmp_path: Path, monkeypatch):
    archive = tmp_path / "pkzip.zip"
    fake_hashcat = tmp_path / "hashcat.exe"
    make_pkzip_crypto_stub(archive, file_count=3)
    fake_hashcat.write_text("", encoding="utf-8")
    captured = {}

    def fake_run(command, check, cwd, **kwargs):
        if "--show" in command:
            from types import SimpleNamespace
            return SimpleNamespace(returncode=0, stdout="")
        Path(command[command.index("--outfile") + 1]).write_text("12345678\n", encoding="utf-8")
        captured["command"] = command
        captured["check"] = check
        captured["cwd"] = cwd

        class Result:
            returncode = 0

        return Result()

    monkeypatch.setattr("crux.cli.subprocess.run", fake_run)

    exit_code = main(
        [
            str(archive),
            "--hashcat-path",
            str(fake_hashcat),
            "--charset",
            "digits",
            "--min",
            "8",
            "--max",
            "12",
            "--raw-output",
        ]
    )

    assert exit_code == 0
    command = captured["command"]
    assert command[:6] == [str(fake_hashcat.resolve()), "-m", "17230", "-w", "2", "--increment"]
    assert "--increment-min" in command
    assert command[command.index("--increment-min") + 1] == "8"
    assert "--increment-max" in command
    assert command[command.index("--increment-max") + 1] == "12"
    assert str(archive.with_suffix(".hash").resolve()) in command
    assert "?d" * 12 in command
    assert captured["cwd"] == fake_hashcat.parent


def test_hashcat_cli_prints_password_from_existing_potfile(tmp_path: Path, monkeypatch, capsys):
    archive = tmp_path / "pkzip.zip"
    fake_hashcat = tmp_path / "hashcat.exe"
    make_pkzip_crypto_stub(archive, file_count=3)
    fake_hashcat.write_text("", encoding="utf-8")

    def fake_run(command, **kwargs):
        assert "--show" in command
        assert "--outfile-autohex-disable" not in command

        class Result:
            returncode = 0
            stdout = "12345678\n"

        return Result()

    def fail_popen(*args, **kwargs):
        raise AssertionError("hashcat attack should not start when potfile already has password")

    monkeypatch.setattr("crux.cli.subprocess.run", fake_run)
    monkeypatch.setattr("crux.cli.subprocess.Popen", fail_popen)

    exit_code = main(
        [
            str(archive),
            "--hashcat-path",
            str(fake_hashcat),
            "--charset",
            "digits",
            "--min",
            "8",
            "--max",
            "12",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Status: already cracked (potfile)" in captured.out
    assert "FOUND password: 12345678" in captured.out


def test_parse_hashcat_machine_readable_status():
    parsed = _parse_hashcat_status(
        "STATUS\t3\tSPEED\t6625054617\t1000\t204700000\t1000\t"
        "EXEC_RUNTIME\t3.66\t42.0\tPROGRESS\t28444672\t100000000\t"
        "RECHASH\t0\t1\tRECSALT\t0\t1\tTEMP\t57\t-1\t"
    )

    assert parsed == (28444672, 100000000, 6829754617.0, "running")


def test_extract_rejects_path_traversal(tmp_path: Path):
    archive = tmp_path / "unsafe.zip"
    with pyzipper.AESZipFile(
        archive,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as zf:
        zf.setpassword(b"pw")
        zf.writestr("../escape.txt", b"bad")

    with pytest.raises(ArchiveError):
        extract_archive(archive, "pw", tmp_path / "out")

    assert not (tmp_path / "escape.txt").exists()


def test_build_candidates_can_combine_wordlist_mask_and_charset(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("pw\n", encoding="utf-8")

    candidates = build_candidates(
        wordlist=wordlist,
        mask="A?d",
        charset="digits",
        min_length=1,
        max_length=1,
    )

    assert list(candidates)[:5] == ["pw", "A0", "A1", "A2", "A3"]
