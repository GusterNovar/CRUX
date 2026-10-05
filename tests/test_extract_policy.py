from pathlib import Path

from crux.zip_ops import default_output_dir, next_available_dir


def test_default_output_dir_uses_archive_stem(tmp_path: Path):
    archive = tmp_path / "lock.zip"
    assert default_output_dir(archive) == tmp_path / "lock_extracted"


def test_next_available_dir_numbers_existing_paths(tmp_path: Path):
    base = tmp_path / "lock_extracted"
    base.mkdir()
    (tmp_path / "lock_extracted_2").mkdir()

    assert next_available_dir(base) == tmp_path / "lock_extracted_3"
