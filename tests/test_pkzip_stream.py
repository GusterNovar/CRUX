import struct
import zipfile
from pathlib import Path

from crux.cli import main
from crux.zip_ops import HASHCAT_PKZIP_STREAM_MODE, build_hashcat_hash


def make_large_stub(path: Path, method=zipfile.ZIP_STORED):
    content = bytes(range(256)) * 2048
    with zipfile.ZipFile(path, "w", compression=method, compresslevel=0) as archive:
        archive.writestr("large.bin", content)
    raw = bytearray(path.read_bytes())
    struct.pack_into("<H", raw, 6, 1)
    directory = raw.index(b"PK\x01\x02")
    struct.pack_into("<H", raw, directory + 8, 1)
    path.write_bytes(raw)


def test_large_member_uses_archive_input(tmp_path):
    path = tmp_path / "large archive.zip"
    make_large_stub(path)
    record = build_hashcat_hash(path)
    assert record.mode == HASHCAT_PKZIP_STREAM_MODE
    assert record.data_bytes > 320 * 1024
    assert record.hash_line == ""
    assert record.member_index == 0
    assert record.compression_method == zipfile.ZIP_STORED


def test_large_deflated_member_uses_streaming_mode(tmp_path):
    path = tmp_path / "large.zip"
    make_large_stub(path, zipfile.ZIP_DEFLATED)
    record = build_hashcat_hash(path)
    assert record.mode == HASHCAT_PKZIP_STREAM_MODE
    assert record.compression_method == zipfile.ZIP_DEFLATED


def test_streaming_preview_does_not_require_hashcat(tmp_path, monkeypatch, capsys):
    path = tmp_path / "large.zip"
    make_large_stub(path)
    monkeypatch.setenv("HASHCAT", str(tmp_path / "missing.exe"))
    assert main([str(path), "--no-run"]) == 0
    assert not path.with_suffix(".hash").exists()
    output = capsys.readouterr().out
    assert "ZIP input:" in output
    assert "--pkzip-member-index 0" in output
    assert "Preview:" in output


def test_streaming_rejects_hash_file_export(tmp_path, capsys):
    path = tmp_path / "large.zip"
    make_large_stub(path)
    assert main([str(path), "--no-run", "--hash-file", str(tmp_path / "out.hash")]) == 1
    assert "--hash-file is not supported" in capsys.readouterr().err
    assert not (tmp_path / "out.hash").exists()


def test_streaming_missing_member_reports_error(tmp_path, capsys):
    path = tmp_path / "large.zip"
    make_large_stub(path)
    assert main([str(path), "--member", "missing", "--no-run"]) == 1
    assert "member not found" in capsys.readouterr().err


def test_unmodified_hashcat_reports_required_extension(tmp_path, capsys):
    path = tmp_path / "large.zip"
    make_large_stub(path)
    executable = tmp_path / "hashcat.exe"
    executable.touch()
    executable.chmod(0o755)
    assert main([str(path), "--hashcat", str(executable)]) == 1
    error = capsys.readouterr().err
    assert "streaming extension (mode 17240)" in error
    assert "https://github.com/GusterNovar/hashcat/tree/feature/pkzip-streaming" in error
    assert not path.with_suffix(".hash").exists()
