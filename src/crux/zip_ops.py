"""ZIP validation and extraction helpers."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path, PurePosixPath
import shutil
import struct
from typing import Sequence
import zipfile
import zlib

import pyzipper
from pyzipper.zipfile import (
    _FH_EXTRA_FIELD_LENGTH,
    _FH_FILENAME_LENGTH,
    _FH_SIGNATURE,
    sizeFileHeader,
    stringFileHeader,
    structFileHeader,
)

from .errors import ArchiveError


READ_CHUNK_SIZE = 64 * 1024
HASHCAT_WINZIP_MODE = 13600
HASHCAT_WINZIP_DATA_LIMIT = 0x200000 * 4
HASHCAT_PKZIP_COMPRESSED_MODE = 17200
HASHCAT_PKZIP_UNCOMPRESSED_MODE = 17210
HASHCAT_PKZIP_CHECKSUM_ONLY_MODE = 17230
HASHCAT_PKZIP_STREAM_MODE = 17240
HASHCAT_PKZIP_DATA_LIMIT = 320 * 1024
HASHCAT_PKZIP_STREAM_SAMPLE = 256
WZ_AES_PBKDF2_COUNT = 1000
WZ_AES_PWD_VERIFY_LENGTH = 2
WZ_AES_AUTH_LENGTH = 10
ZIP_CRYPTO_HEADER_LENGTH = 12
PKZIP_CHECKSUM_SAMPLE_LENGTH = 36
WZ_AES_KEY_LENGTHS = {
    1: 16,
    2: 24,
    3: 32,
}
WZ_AES_SALT_LENGTHS = {
    1: 8,
    2: 12,
    3: 16,
}


@dataclass(frozen=True)
class WinZipAesVerifier:
    salt: bytes
    pwd_verify: bytes
    dklen: int

    def password_matches(self, password: str) -> bool:
        keymaterial = hashlib.pbkdf2_hmac(
            "sha1",
            password.encode("utf-8"),
            self.salt,
            WZ_AES_PBKDF2_COUNT,
            self.dklen,
        )
        return keymaterial[-WZ_AES_PWD_VERIFY_LENGTH:] == self.pwd_verify


@dataclass(frozen=True)
class HashcatWinZipHash:
    member: str
    hash_line: str
    encrypted_data_length: int


@dataclass(frozen=True)
class HashcatArchiveHash:
    mode: int
    mode_name: str
    members: tuple[str, ...]
    hash_line: str
    data_bytes: int


def choose_probe_member(archive_path: str | Path) -> str:
    """Choose one encrypted file member for password validation."""

    archive = Path(archive_path)
    try:
        with pyzipper.AESZipFile(archive) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                if info.flag_bits & 0x1:
                    return info.filename
            for info in zf.infolist():
                if not info.is_dir():
                    return info.filename
    except zipfile.BadZipFile as exc:
        raise ArchiveError(f"Not a valid ZIP archive: {archive}") from exc

    raise ArchiveError(f"ZIP archive has no file entries: {archive}")


def password_opens_member(
    archive_path: str | Path,
    password: str,
    member: str | None = None,
) -> bool:
    """Return True if password can open the selected ZIP member."""

    archive = Path(archive_path)
    probe_member = member or choose_probe_member(archive)

    try:
        with pyzipper.AESZipFile(archive) as zf:
            return password_opens_member_in_zip(zf, password, probe_member)
    except (
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        pyzipper.BadZipFile,
        pyzipper.LargeZipFile,
    ):
        return False


def password_opens_member_in_zip(
    zf: pyzipper.AESZipFile,
    password: str,
    member: str,
) -> bool:
    """Return True if password can open member in an already-open ZIP."""

    pwd = password.encode("utf-8")
    try:
        zf.pwd = pwd
        with zf.open(member, "r", pwd=pwd) as handle:
            handle.read(READ_CHUNK_SIZE)
        return True
    except (
        RuntimeError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        pyzipper.BadZipFile,
        pyzipper.LargeZipFile,
        zlib.error,
    ):
        return False


def build_winzip_aes_verifier(
    zf: pyzipper.AESZipFile,
    member: str,
) -> WinZipAesVerifier | None:
    """Build a fast WinZip AES password verifier for an open ZIP member."""

    info = zf.getinfo(member)
    strength = getattr(info, "wz_aes_strength", None)
    if strength not in WZ_AES_KEY_LENGTHS:
        return None

    salt_length = WZ_AES_SALT_LENGTHS[strength]
    header_length = salt_length + WZ_AES_PWD_VERIFY_LENGTH
    encryption_header = _read_encryption_header(zf, info, header_length)
    salt = encryption_header[:salt_length]
    pwd_verify = encryption_header[salt_length:]
    key_length = WZ_AES_KEY_LENGTHS[strength]
    return WinZipAesVerifier(
        salt=salt,
        pwd_verify=pwd_verify,
        dklen=(2 * key_length) + WZ_AES_PWD_VERIFY_LENGTH,
    )


def build_hashcat_winzip_hash(
    archive_path: str | Path,
    member: str | None = None,
    *,
    inline_data_limit: int = HASHCAT_WINZIP_DATA_LIMIT,
) -> HashcatWinZipHash:
    """Return a hashcat mode 13600 $zip2$ hash for a WinZip AES member."""

    archive = Path(archive_path)
    probe_member = member or choose_probe_member(archive)

    with pyzipper.AESZipFile(archive) as zf:
        info = zf.getinfo(probe_member)
        strength = getattr(info, "wz_aes_strength", None)
        if strength not in WZ_AES_KEY_LENGTHS:
            raise ArchiveError(f"Archive member is not WinZip AES encrypted: {probe_member}")

        salt_length = WZ_AES_SALT_LENGTHS[strength]
        header_length = salt_length + WZ_AES_PWD_VERIFY_LENGTH
        encrypted_data_length = info.compress_size - header_length - WZ_AES_AUTH_LENGTH
        if encrypted_data_length < 0:
            raise ArchiveError(f"Invalid WinZip AES payload length for member: {probe_member}")
        if encrypted_data_length > inline_data_limit:
            raise ArchiveError(
                "Hashcat WinZip mode requires inline encrypted member data, "
                f"but {probe_member} has {encrypted_data_length} bytes; "
                f"configured limit is {inline_data_limit} bytes."
            )

        salt_verify, encrypted_data, auth_code = _read_winzip_aes_payload(
            zf,
            info,
            header_length,
            encrypted_data_length,
        )
        salt = salt_verify[:salt_length]
        pwd_verify = salt_verify[salt_length:]
        hash_line = (
            "$zip2$*"
            f"0*{strength}*0*"
            f"{salt.hex()}*"
            f"{int.from_bytes(pwd_verify, 'big'):04x}*"
            f"{encrypted_data_length:x}*"
            f"{encrypted_data.hex()}*"
            f"{auth_code.hex()}*"
            "$/zip2$"
        )
        return HashcatWinZipHash(probe_member, hash_line, encrypted_data_length)


def build_hashcat_hash(
    archive_path: str | Path,
    member: str | None = None,
) -> HashcatArchiveHash:
    """Return a hashcat-compatible hash for the selected ZIP archive."""

    archive = Path(archive_path)
    probe_member = member or choose_probe_member(archive)

    try:
        winzip_hash = build_hashcat_winzip_hash(archive, probe_member)
    except ArchiveError as winzip_error:
        with zipfile.ZipFile(archive) as zf:
            infos = _select_pkzip_infos(zf, probe_member, member is not None)
            if not infos:
                raise winzip_error

            if len(infos) >= 3:
                return _build_hashcat_pkzip_checksum_hash(zf, infos[:8])

            info = infos[0] if member is not None else min(infos, key=lambda entry: entry.compress_size)
            if 16 <= info.compress_size <= HASHCAT_PKZIP_DATA_LIMIT:
                return _build_hashcat_pkzip_full_hash(zf, info)

            return _build_hashcat_pkzip_stream_hash(zf, info)

    return HashcatArchiveHash(
        mode=HASHCAT_WINZIP_MODE,
        mode_name="WinZip",
        members=(winzip_hash.member,),
        hash_line=winzip_hash.hash_line,
        data_bytes=winzip_hash.encrypted_data_length,
    )


def fast_password_opens_member_in_zip(
    zf: pyzipper.AESZipFile,
    verifier: WinZipAesVerifier | None,
    password: str,
    member: str,
) -> bool:
    """Fast reject wrong WinZip AES passwords, then confirm candidates."""

    if verifier is not None and not verifier.password_matches(password):
        return False
    return password_opens_member_in_zip(zf, password, member)


def _select_pkzip_infos(
    zf: zipfile.ZipFile,
    probe_member: str,
    member_requested: bool,
) -> list[zipfile.ZipInfo]:
    infos = [
        info
        for info in zf.infolist()
        if not info.is_dir()
        and info.flag_bits & 0x1
        and info.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
    ]
    if member_requested:
        selected = [info for info in infos if info.filename == probe_member]
        if not selected:
            raise ArchiveError(f"Archive member is not traditional PKZIP encrypted: {probe_member}")
        return selected + [info for info in infos if info.filename != probe_member]
    return infos


def _build_hashcat_pkzip_checksum_hash(
    zf: zipfile.ZipFile,
    infos: Sequence[zipfile.ZipInfo],
) -> HashcatArchiveHash:
    if len(infos) < 3:
        raise ArchiveError("Hashcat PKZIP checksum-only mode requires at least 3 members.")
    if len(infos) > 8:
        raise ArchiveError("Hashcat PKZIP checksum-only mode supports at most 8 members.")

    segments: list[str] = []
    data_bytes = 0
    for info in infos:
        data_length = min(PKZIP_CHECKSUM_SAMPLE_LENGTH, info.compress_size)
        if data_length < 16:
            raise ArchiveError(f"PKZIP member is too small for checksum-only mode: {info.filename}")

        data = _read_member_payload(zf, info, data_length)
        data_bytes += len(data)
        segments.append(
            "*".join(
                [
                    "1",
                    "0",
                    str(info.compress_type),
                    f"{len(data):x}",
                    f"{_pkzip_checksum_from_crc(info):04x}",
                    f"{_pkzip_checksum_from_timestamp(info):04x}",
                    data.hex(),
                ]
            )
        )

    hash_line = f"$pkzip2${len(infos)}*1*" + "*".join(segments) + "*$/pkzip2$"
    return HashcatArchiveHash(
        mode=HASHCAT_PKZIP_CHECKSUM_ONLY_MODE,
        mode_name="PKZIP checksum-only",
        members=tuple(info.filename for info in infos),
        hash_line=hash_line,
        data_bytes=data_bytes,
    )


def _build_hashcat_pkzip_stream_hash(
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
) -> HashcatArchiveHash:
    if info.compress_size < ZIP_CRYPTO_HEADER_LENGTH:
        raise ArchiveError(f"Truncated PKZIP encryption header: {info.filename}")
    data = _read_member_payload(zf, info, min(HASHCAT_PKZIP_STREAM_SAMPLE, info.compress_size))
    offset = _member_data_offset(zf, info)
    checksum = (
        _pkzip_checksum_from_timestamp(info) >> 8
        if info.flag_bits & 0x8
        else info.CRC >> 24
    )
    reference = str(Path(zf.filename).resolve()).encode("utf-8")
    if len(reference) > 4095:
        raise ArchiveError("ZIP reference path is too long for the hashcat streaming plugin.")
    hash_line = (
        f"$pkzip-stream$*{info.compress_type}*{offset:x}*{info.compress_size:x}*"
        f"{info.file_size:x}*{info.CRC:08x}*{checksum:02x}*{data.hex()}*{reference.hex()}"
    )
    return HashcatArchiveHash(
        mode=HASHCAT_PKZIP_STREAM_MODE,
        mode_name="PKZIP streaming",
        members=(info.filename,),
        hash_line=hash_line,
        data_bytes=len(data),
    )


def _build_hashcat_pkzip_full_hash(
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
) -> HashcatArchiveHash:
    if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
        raise ArchiveError(f"Unsupported PKZIP compression type: {info.compress_type}")
    if info.compress_size > HASHCAT_PKZIP_DATA_LIMIT:
        raise ArchiveError(
            f"PKZIP member has {info.compress_size} bytes, "
            f"but hashcat single-file mode is limited to {HASHCAT_PKZIP_DATA_LIMIT} bytes."
        )
    if info.compress_size < 16:
        raise ArchiveError(f"PKZIP member is too small for hashcat mode: {info.filename}")

    data = _read_member_payload(zf, info, info.compress_size)
    mode = (
        HASHCAT_PKZIP_COMPRESSED_MODE
        if info.compress_type == zipfile.ZIP_DEFLATED
        else HASHCAT_PKZIP_UNCOMPRESSED_MODE
    )
    mode_name = "PKZIP compressed" if info.compress_type == zipfile.ZIP_DEFLATED else "PKZIP stored"
    data_offset = _member_data_offset(zf, info)
    hash_line = (
        "$pkzip2$1*1*"
        "2*0*"
        f"{info.compress_size:x}*"
        f"{info.file_size:x}*"
        f"{info.CRC:08x}*"
        "0*"
        f"{data_offset:x}*"
        f"{info.compress_type}*"
        f"{len(data):x}*"
        f"{_pkzip_checksum_from_crc(info):04x}*"
        f"{_pkzip_checksum_from_timestamp(info):04x}*"
        f"{data.hex()}*"
        "$/pkzip2$"
    )
    return HashcatArchiveHash(
        mode=mode,
        mode_name=mode_name,
        members=(info.filename,),
        hash_line=hash_line,
        data_bytes=len(data),
    )


def _pkzip_checksum_from_crc(info: zipfile.ZipInfo) -> int:
    return (info.CRC >> 16) & 0xffff


def _pkzip_checksum_from_timestamp(info: zipfile.ZipInfo) -> int:
    return getattr(info, "_raw_time", 0) & 0xffff


def _read_member_payload(
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    length: int,
) -> bytes:
    lock = getattr(zf, "_lock", None)
    if lock is None:
        return _read_member_payload_unlocked(zf, info, length)

    with lock:
        return _read_member_payload_unlocked(zf, info, length)


def _read_member_payload_unlocked(
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    length: int,
) -> bytes:
    _seek_to_member_data(zf, info)
    data = zf.fp.read(length)
    if len(data) != length:
        raise ArchiveError(f"Truncated ZIP member payload: {info.filename}")
    return data


def _member_data_offset(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> int:
    lock = getattr(zf, "_lock", None)
    if lock is None:
        return _member_data_offset_unlocked(zf, info)

    with lock:
        return _member_data_offset_unlocked(zf, info)


def _member_data_offset_unlocked(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> int:
    _seek_to_member_data(zf, info)
    return zf.fp.tell()


def _read_winzip_aes_payload(
    zf: pyzipper.AESZipFile,
    info: zipfile.ZipInfo,
    header_length: int,
    encrypted_data_length: int,
) -> tuple[bytes, bytes, bytes]:
    lock = getattr(zf, "_lock", None)
    if lock is None:
        return _read_winzip_aes_payload_unlocked(zf, info, header_length, encrypted_data_length)

    with lock:
        return _read_winzip_aes_payload_unlocked(zf, info, header_length, encrypted_data_length)


def _read_winzip_aes_payload_unlocked(
    zf: pyzipper.AESZipFile,
    info: zipfile.ZipInfo,
    header_length: int,
    encrypted_data_length: int,
) -> tuple[bytes, bytes, bytes]:
    _seek_to_member_data(zf, info)
    salt_verify = zf.fp.read(header_length)
    encrypted_data = zf.fp.read(encrypted_data_length)
    auth_code = zf.fp.read(WZ_AES_AUTH_LENGTH)
    if len(salt_verify) != header_length:
        raise ArchiveError(f"Truncated encryption header for archive member: {info.filename}")
    if len(encrypted_data) != encrypted_data_length:
        raise ArchiveError(f"Truncated encrypted data for archive member: {info.filename}")
    if len(auth_code) != WZ_AES_AUTH_LENGTH:
        raise ArchiveError(f"Truncated authentication code for archive member: {info.filename}")
    return salt_verify, encrypted_data, auth_code


def _read_encryption_header(
    zf: pyzipper.AESZipFile,
    info: zipfile.ZipInfo,
    header_length: int,
) -> bytes:
    lock = getattr(zf, "_lock", None)
    if lock is None:
        return _read_encryption_header_unlocked(zf, info, header_length)

    with lock:
        return _read_encryption_header_unlocked(zf, info, header_length)


def _read_encryption_header_unlocked(
    zf: pyzipper.AESZipFile,
    info: zipfile.ZipInfo,
    header_length: int,
) -> bytes:
    _seek_to_member_data(zf, info)
    encryption_header = zf.fp.read(header_length)
    if len(encryption_header) != header_length:
        raise ArchiveError(f"Truncated encryption header for archive member: {info.filename}")
    return encryption_header


def _seek_to_member_data(zf: pyzipper.AESZipFile, info: zipfile.ZipInfo) -> None:
    if not zf.fp:
        raise ArchiveError("Attempt to read a closed ZIP archive.")

    zf.fp.seek(info.header_offset)
    file_header = zf.fp.read(sizeFileHeader)
    if len(file_header) != sizeFileHeader:
        raise ArchiveError(f"Truncated local header for archive member: {info.filename}")

    fields = struct.unpack(structFileHeader, file_header)
    if fields[_FH_SIGNATURE] != stringFileHeader:
        raise ArchiveError(f"Bad local header for archive member: {info.filename}")

    filename_length = fields[_FH_FILENAME_LENGTH]
    extra_length = fields[_FH_EXTRA_FIELD_LENGTH]
    zf.fp.seek(filename_length + extra_length, 1)


def default_output_dir(archive_path: str | Path) -> Path:
    """Return the default extraction directory for an archive."""

    archive = Path(archive_path)
    return archive.with_name(f"{archive.stem}_extracted")


def next_available_dir(base_dir: str | Path) -> Path:
    """Return base_dir or the next numbered sibling if it already exists."""

    base = Path(base_dir)
    if not base.exists():
        return base

    counter = 2
    while True:
        candidate = base.with_name(f"{base.name}_{counter}")
        if not candidate.exists():
            return candidate
        counter += 1


def _safe_member_target(destination: Path, member_name: str) -> Path:
    member = PurePosixPath(member_name)
    if member.is_absolute() or any(part in {"", ".", ".."} for part in member.parts):
        raise ArchiveError(f"Unsafe archive member path: {member_name}")

    target = destination.joinpath(*member.parts)
    destination_resolved = destination.resolve()
    target_parent_resolved = target.parent.resolve()
    try:
        target_parent_resolved.relative_to(destination_resolved)
    except ValueError as exc:
        raise ArchiveError(f"Archive member escapes destination: {member_name}") from exc
    return target


def assert_safe_members(archive_path: str | Path) -> None:
    """Reject ZIP entries that would write outside the destination."""

    with pyzipper.AESZipFile(archive_path) as zf:
        for info in zf.infolist():
            _safe_member_target(Path.cwd(), info.filename)


def extract_archive(
    archive_path: str | Path,
    password: str,
    output_dir: str | Path | None = None,
) -> Path:
    """Extract an archive with a known password and return the output path."""

    archive = Path(archive_path)
    destination = next_available_dir(output_dir or default_output_dir(archive))
    temp_destination = destination.with_name(f".{destination.name}.partial")
    if temp_destination.exists():
        shutil.rmtree(temp_destination)
    temp_destination.mkdir(parents=True)

    pwd = password.encode("utf-8")
    try:
        with pyzipper.AESZipFile(archive) as zf:
            for info in zf.infolist():
                target = _safe_member_target(temp_destination, info.filename)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue

                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info, "r", pwd=pwd) as source, target.open("wb") as dest:
                    shutil.copyfileobj(source, dest)
        temp_destination.rename(destination)
    except Exception:
        if temp_destination.exists():
            shutil.rmtree(temp_destination)
        raise

    return destination
