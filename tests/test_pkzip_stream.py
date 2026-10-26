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


def test_large_member_exports_a_bounded_reference(tmp_path):
    path = tmp_path / "large archive.zip"
    make_large_stub(path)
    record = build_hashcat_hash(path)
    parts = record.hash_line.split("*")
    assert record.mode == HASHCAT_PKZIP_STREAM_MODE
    assert record.data_bytes == 256
    assert len(record.hash_line) < 2000
    assert int(parts[3], 16) > 320 * 1024
    assert bytes.fromhex(parts[8]).decode("utf-8") == str(path.resolve())
    with path.open("rb") as source:
        source.seek(int(parts[2], 16))
        assert source.read(256) == bytes.fromhex(parts[7])


def test_large_deflated_member_uses_streaming_mode(tmp_path):
    path = tmp_path / "large.zip"
    make_large_stub(path, zipfile.ZIP_DEFLATED)
    record = build_hashcat_hash(path)
    assert record.mode == HASHCAT_PKZIP_STREAM_MODE
    assert record.hash_line.startswith("$pkzip-stream$*8*")


def test_streaming_export_does_not_require_hashcat(tmp_path, monkeypatch):
    path = tmp_path / "large.zip"
    make_large_stub(path)
    monkeypatch.setenv("HASHCAT", str(tmp_path / "missing.exe"))
    assert main([str(path), "--no-run"]) == 0
    assert path.with_suffix(".hash").read_text().startswith("$pkzip-stream$")


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
