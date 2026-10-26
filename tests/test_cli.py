import io
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
import pyzipper

from crux.cli import (
    _filtered_wordlist,
    _parse_hashcat_status,
    _password_lines,
    _resolve_hashcat_executable,
    build_parser,
    main,
)
from crux.errors import CruxError


@pytest.fixture
def archive(tmp_path):
    path = tmp_path / "archive with spaces.zip"
    with pyzipper.AESZipFile(path, "w", encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(b"12")
        zf.writestr("hello.txt", b"hello")
    return path


@pytest.fixture
def hashcat(tmp_path):
    path = tmp_path / ("hashcat.exe" if os.name == "nt" else "hashcat")
    path.touch()
    path.chmod(0o755)
    return path


def test_parser_accepts_the_two_direct_commands():
    normal = build_parser().parse_args(
        ["a.zip", "--charset", "digits", "--min", "8", "--max", "12"]
    )
    dictionary = build_parser().parse_args(
        ["a.zip", "--wordlist", "words.txt", "--min", "8", "--max", "12"]
    )
    assert normal.charset == "digits"
    assert dictionary.wordlist == "words.txt"
    assert (normal.min_length, normal.max_length) == (8, 12)
    assert (dictionary.min_length, dictionary.max_length) == (8, 12)


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["a.zip", "--charset", "digits", "--wordlist", "words.txt"],
        ["hashcat", "a.zip"],
        ["recover", "a.zip"],
        ["a.zip", "--mask", "?d?d"],
    ],
)
def test_parser_rejects_missing_archive_and_removed_or_mixed_modes(arguments):
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(arguments)
    assert exc.value.code == 2


@pytest.mark.parametrize("bounds", [["--min", "0"], ["--min", "4", "--max", "2"]])
def test_invalid_lengths_do_not_export_hash(archive, bounds, capsys):
    assert main([str(archive), "--no-run", *bounds]) == 1
    assert not archive.with_suffix(".hash").exists()
    assert "ERROR:" in capsys.readouterr().err


def test_filtered_wordlist_includes_both_bounds_preserves_spaces_and_cleans_up(
    tmp_path,
):
    source = tmp_path / "words.txt"
    source.write_bytes("\ufeff1\r\n12\r\n  \r\n\u2603\u2602\r\n123\r\n1234\r\n".encode("utf-8"))
    with _filtered_wordlist(source, 2, 3, directory=tmp_path) as filtered:
        assert filtered.read_text(encoding="utf-8") == "12\n  \n\u2603\u2602\n123\n"
    assert not filtered.exists()
    assert not list(tmp_path.glob(".crux-wordlist-*"))
    assert source.read_text(encoding="utf-8").startswith("\ufeff1\n12\n")


def test_filtered_wordlist_rejects_empty_range_and_cleans_up(tmp_path):
    source = tmp_path / "words.txt"
    source.write_text("1\n1234\n", encoding="utf-8")
    with (
        pytest.raises(CruxError, match="no passwords"),
        _filtered_wordlist(source, 2, 3, directory=tmp_path),
    ):
        pytest.fail("An empty wordlist must not start an attack")
    assert not list(tmp_path.glob(".crux-wordlist-*"))


def test_dictionary_mode_passes_only_filtered_words_to_hashcat(
    archive, hashcat, tmp_path, monkeypatch, capsys
):
    words = tmp_path / "words.txt"
    words.write_text("1\n12\n123\n", encoding="utf-8")
    captured = {}

    def run(command, **kwargs):
        captured["command"] = command
        captured["cwd"] = kwargs["cwd"]
        assert command[command.index("-a") + 1] == "0"
        filtered = Path(command[command.index("-a") + 3])
        assert filtered.read_text(encoding="utf-8") == "12\n"
        captured["filtered"] = filtered
        Path(command[command.index("--outfile") + 1]).write_text(
            "12\n", encoding="utf-8"
        )
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("crux.cli.subprocess.run", run)
    assert (
        main(
            [
                str(archive),
                "--hashcat",
                str(hashcat),
                "--wordlist",
                str(words),
                "--min",
                "2",
                "--max",
                "2",
                "--raw-output",
                "--extra-arg=--potfile-disable",
            ]
        )
        == 0
    )
    assert captured["cwd"] == hashcat.parent
    assert not captured["filtered"].exists()
    assert "--increment" not in captured["command"]
    assert "FOUND password: 12" in capsys.readouterr().out


def test_dictionary_default_does_not_exclude_long_passwords(
    archive, hashcat, tmp_path, monkeypatch
):
    words = tmp_path / "words.txt"
    words.write_text("long-password\n", encoding="utf-8")

    def run(command, **kwargs):
        filtered = Path(command[command.index("-a") + 3])
        assert filtered.read_text(encoding="utf-8") == "long-password\n"
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr("crux.cli.subprocess.run", run)
    assert (
        main(
            [
                str(archive),
                "--hashcat",
                str(hashcat),
                "--wordlist",
                str(words),
                "--raw-output",
                "--extra-arg=--potfile-disable",
            ]
        )
        == 1
    )


def test_default_mode_runs_alnum_search(archive, hashcat, monkeypatch):
    def run(command, **kwargs):
        assert command[command.index("-a") + 1] == "3"
        assert "?1" * 5 in command
        assert "--increment" in command
        Path(command[command.index("--outfile") + 1]).write_text(
            "12\n", encoding="utf-8"
        )
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("crux.cli.subprocess.run", run)
    assert (
        main(
            [
                str(archive),
                "--hashcat",
                str(hashcat),
                "--raw-output",
                "--extra-arg=--potfile-disable",
            ]
        )
        == 0
    )


def test_explicit_hashcat_overrides_environment(hashcat, tmp_path, monkeypatch):
    monkeypatch.setenv("HASHCAT", str(tmp_path / "missing"))
    assert _resolve_hashcat_executable(str(hashcat)) == str(hashcat.resolve())


def test_environment_accepts_a_directory(hashcat, monkeypatch):
    monkeypatch.setenv("HASHCAT", str(hashcat.parent))
    assert _resolve_hashcat_executable() == str(hashcat.resolve())


def test_bad_explicit_hashcat_does_not_silently_fall_back(monkeypatch):
    monkeypatch.setenv("HASHCAT", "missing-hashcat-command")
    monkeypatch.setattr("crux.cli.shutil.which", lambda _: None)
    with pytest.raises(CruxError, match="executable not found"):
        _resolve_hashcat_executable()


def test_hashcat_is_found_on_path(hashcat, monkeypatch):
    monkeypatch.delenv("HASHCAT", raising=False)
    monkeypatch.setattr("crux.cli.shutil.which", lambda _: str(hashcat))
    assert _resolve_hashcat_executable() == str(hashcat.resolve())


@pytest.mark.parametrize("location", ["hashcat", ".tools/hashcat", ".tools", ".tools/hashcat-test"])
@pytest.mark.parametrize("base", ["working", "project"])
def test_hashcat_is_found_in_portable_directories(tmp_path, monkeypatch, location, base):
    working = tmp_path / "working"
    project = tmp_path / "project"
    working.mkdir()
    project.mkdir()
    directory = (working if base == "working" else project) / location
    directory.mkdir(parents=True, exist_ok=True)
    executable = directory / ("hashcat.exe" if os.name == "nt" else "hashcat")
    executable.touch()
    executable.chmod(0o755)
    monkeypatch.chdir(working)
    monkeypatch.delenv("HASHCAT", raising=False)
    monkeypatch.setattr("crux.cli.shutil.which", lambda _: None)
    monkeypatch.setattr(
        "crux.cli.__file__", str(project / "src" / "crux" / "cli.py")
    )
    assert _resolve_hashcat_executable() == str(executable.resolve())


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (1, "autotuning"),
        (2, "self-test"),
        (3, "running"),
        (4, "paused"),
        (5, "exhausted"),
        (6, "cracked"),
        (7, "aborted"),
    ],
)
def test_status_matches_hashcat_codes(code, expected):
    assert (
        _parse_hashcat_status(f"STATUS\t{code}\tPROGRESS\t2\t10\tSPEED\t5\t1000")[3]
        == expected
    )


def test_passwords_preserve_spaces_and_decode_autohex():
    assert _password_lines("  secret  \r\n$HEX[e29883e29882]\n\n") == [
        "  secret  ",
        "\u2603\u2602",
    ]
    assert _password_lines("$HEX[6162]\n", autohex=False) == ["$HEX[6162]"]


@pytest.mark.parametrize("returncode", [1, 4294967292])
def test_compact_output_reports_exhaustion_and_backend_errors(
    archive, hashcat, monkeypatch, capsys, returncode
):
    class Process:
        stdout = io.StringIO("Not enough allocatable device memory.\n")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def wait(self):
            return returncode

    monkeypatch.setattr("crux.cli.subprocess.Popen", lambda *args, **kwargs: Process())
    assert (
        main([str(archive), "--hashcat", str(hashcat), "--extra-arg=--potfile-disable"])
        != 0
    )
    captured = capsys.readouterr()
    if returncode == 1:
        assert "Status: exhausted" in captured.out
        assert "Password not found" in captured.out
    else:
        assert "Status: failed" in captured.out
        assert "Not enough allocatable device memory." in captured.err


def test_hash_export_cannot_overwrite_input(archive, capsys):
    original = archive.read_bytes()
    assert main([str(archive), "--hash-file", str(archive), "--no-run"]) == 1
    assert archive.read_bytes() == original
    assert "must not overwrite" in capsys.readouterr().err
