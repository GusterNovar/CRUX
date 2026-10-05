"""Candidate password generation."""

from __future__ import annotations

from itertools import product
from pathlib import Path
import string
from typing import Iterator, Sequence

from .errors import CandidateError


LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>/"

CHARSETS: dict[str, str] = {
    "lower": LOWER,
    "upper": UPPER,
    "digits": DIGITS,
    "alpha": LOWER + UPPER,
    "alnum": LOWER + UPPER + DIGITS,
    "symbols": SYMBOLS,
    "all": LOWER + UPPER + DIGITS + SYMBOLS,
}

MASK_TOKENS: dict[str, str] = {
    "l": LOWER,
    "u": UPPER,
    "d": DIGITS,
    "s": SYMBOLS,
}


def iter_wordlist(path: str | Path) -> Iterator[str]:
    """Yield unique non-empty passwords from a newline-delimited wordlist."""

    seen: set[str] = set()
    with Path(path).open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            candidate = line.rstrip("\r\n")
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            yield candidate


def count_wordlist(path: str | Path) -> int:
    """Count unique non-empty passwords in a wordlist."""

    return sum(1 for _ in iter_wordlist(path))


def parse_mask(mask: str) -> list[Sequence[str]]:
    """Parse a simple mask string into character choices per position."""

    parts: list[Sequence[str]] = []
    i = 0
    while i < len(mask):
        char = mask[i]
        if char != "?":
            parts.append((char,))
            i += 1
            continue

        if i + 1 >= len(mask):
            raise CandidateError("Mask cannot end with a bare '?'.")

        token = mask[i + 1]
        if token == "?":
            parts.append(("?",))
        elif token in MASK_TOKENS:
            parts.append(tuple(MASK_TOKENS[token]))
        else:
            raise CandidateError(
                f"Unsupported mask token '?{token}'. "
                "Use ?l, ?u, ?d, ?s, or ??."
            )
        i += 2

    return parts


def iter_mask(mask: str) -> Iterator[str]:
    """Yield candidates produced by a mask."""

    parts = parse_mask(mask)
    if not parts:
        return
    for combo in product(*parts):
        yield "".join(combo)


def estimate_mask_count(mask: str) -> int:
    """Return the number of candidates a mask will generate."""

    total = 1
    for choices in parse_mask(mask):
        total *= len(choices)
    return total


def resolve_charset(name: str) -> str:
    """Resolve a named charset."""

    try:
        return CHARSETS[name]
    except KeyError as exc:
        choices = ", ".join(sorted(CHARSETS))
        raise CandidateError(f"Unknown charset '{name}'. Choose one of: {choices}.") from exc


def iter_charset(charset: str, min_length: int, max_length: int) -> Iterator[str]:
    """Yield candidates from a charset over an inclusive length range."""

    if min_length < 1:
        raise CandidateError("--min-length must be at least 1.")
    if max_length < min_length:
        raise CandidateError("--max-length must be greater than or equal to --min-length.")

    chars = resolve_charset(charset)
    for length in range(min_length, max_length + 1):
        for combo in product(chars, repeat=length):
            yield "".join(combo)


def iter_charset_range(
    charset: str,
    min_length: int,
    max_length: int,
    start: int,
    count: int,
) -> Iterator[str]:
    """Yield a non-overlapping slice of the charset candidate space."""

    if start < 0:
        raise CandidateError("charset range start must be at least 0.")
    if count < 0:
        raise CandidateError("charset range count must be at least 0.")
    if count == 0:
        return
    if min_length < 1:
        raise CandidateError("--min-length must be at least 1.")
    if max_length < min_length:
        raise CandidateError("--max-length must be greater than or equal to --min-length.")

    chars = resolve_charset(charset)
    base = len(chars)
    remaining_start = start
    remaining_count = count

    for length in range(min_length, max_length + 1):
        length_count = base**length
        if remaining_start >= length_count:
            remaining_start -= length_count
            continue

        local_index = remaining_start
        available = length_count - local_index
        to_emit = min(remaining_count, available)
        for offset in range(to_emit):
            yield _charset_candidate_at(chars, length, local_index + offset)

        remaining_count -= to_emit
        if remaining_count <= 0:
            return
        remaining_start = 0


def _charset_candidate_at(chars: str, length: int, index: int) -> str:
    base = len(chars)
    result = [""] * length
    for position in range(length - 1, -1, -1):
        index, char_index = divmod(index, base)
        result[position] = chars[char_index]
    return "".join(result)


def build_candidates(
    *,
    wordlist: str | Path | None = None,
    mask: str | None = None,
    charset: str | None = "alnum",
    min_length: int = 1,
    max_length: int = 5,
) -> Iterator[str]:
    """Yield candidates in the configured order."""

    if wordlist is not None:
        yield from iter_wordlist(wordlist)
    if mask is not None:
        yield from iter_mask(mask)
    if charset is not None:
        yield from iter_charset(charset, min_length, max_length)


def estimate_charset_count(charset: str, min_length: int, max_length: int) -> int:
    """Return the count for a charset range."""

    if min_length < 1 or max_length < min_length:
        return 0
    base = len(resolve_charset(charset))
    return sum(base**length for length in range(min_length, max_length + 1))


def estimate_candidates_count(
    *,
    wordlist: str | Path | None = None,
    mask: str | None = None,
    charset: str | None = "alnum",
    min_length: int = 1,
    max_length: int = 5,
) -> int:
    """Return the total configured candidate count."""

    total = 0
    if wordlist is not None:
        total += count_wordlist(wordlist)
    if mask is not None:
        total += estimate_mask_count(mask)
    if charset is not None:
        total += estimate_charset_count(charset, min_length, max_length)
    return total
