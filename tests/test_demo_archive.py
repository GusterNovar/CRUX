from pathlib import Path

import pyzipper

from crux.zip_ops import HASHCAT_WINZIP_MODE, build_hashcat_hash


def test_public_demo_contains_only_synthetic_text_and_neutral_metadata():
    path = Path(__file__).resolve().parents[1] / "codes.zip"
    with pyzipper.AESZipFile(path) as archive:
        assert archive.comment == b""
        assert archive.namelist() == ["demo/README.txt"]
        member = archive.infolist()[0]
        assert member.date_time == (2000, 1, 1, 0, 0, 0)
        assert member.comment == b""
        assert member.flag_bits & 1
        # The AES field describes encryption; no source filesystem metadata.
        assert member.extra == b"\x01\x99\x07\x00\x02\x00AE\x03\x08\x00"
        assert archive.read(member, pwd=b"crux-demo") == (
            b"CRUX public demonstration archive.\n"
            b"This file contains synthetic English text only.\n"
            b"Demo password: crux-demo\n"
        )
    assert build_hashcat_hash(path).mode == HASHCAT_WINZIP_MODE
