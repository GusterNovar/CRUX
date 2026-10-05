from pathlib import Path

import pytest

from crux.candidates import (
    SYMBOLS,
    estimate_candidates_count,
    estimate_mask_count,
    iter_charset,
    iter_charset_range,
    iter_mask,
    iter_wordlist,
    resolve_charset,
)
from crux.errors import CandidateError


def test_iter_charset_order_and_lengths():
    assert list(iter_charset("digits", 1, 2))[:13] == [
        "0",
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        "8",
        "9",
        "00",
        "01",
        "02",
    ]


def test_iter_charset_range_matches_global_order():
    assert list(iter_charset_range("digits", 1, 2, start=8, count=6)) == [
        "8",
        "9",
        "00",
        "01",
        "02",
        "03",
    ]


def test_all_charset_contains_alnum_and_symbols():
    charset = resolve_charset("all")

    assert charset.startswith("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    for symbol in SYMBOLS:
        assert symbol in charset


def test_iter_mask_supports_tokens_and_literal_question_mark():
    assert list(iter_mask("A?d??")) == [
        "A0?",
        "A1?",
        "A2?",
        "A3?",
        "A4?",
        "A5?",
        "A6?",
        "A7?",
        "A8?",
        "A9?",
    ]


def test_estimate_mask_count():
    assert estimate_mask_count("A?d?s") == 10 * len(SYMBOLS)


def test_iter_mask_rejects_unknown_token():
    with pytest.raises(CandidateError):
        list(iter_mask("?x"))


def test_iter_wordlist_deduplicates_non_empty_lines(tmp_path: Path):
    wordlist = tmp_path / "passwords.txt"
    wordlist.write_text("alpha\n\nbeta\nalpha\n", encoding="utf-8")
    assert list(iter_wordlist(wordlist)) == ["alpha", "beta"]


def test_estimate_candidates_count_includes_wordlist_mask_and_charset(tmp_path: Path):
    wordlist = tmp_path / "passwords.txt"
    wordlist.write_text("alpha\nbeta\nalpha\n", encoding="utf-8")

    assert (
        estimate_candidates_count(
            wordlist=wordlist,
            mask="?d?d",
            charset="digits",
            min_length=1,
            max_length=1,
        )
        == 2 + 100 + 10
    )
