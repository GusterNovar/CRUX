# CRUX

CRUX `1.0.0` is a command line tool for recovering ZIP passwords locally with
**hashcat**. It supports traditional PKZIP and WinZip AES archives, with two attack
types: a character set search and a wordlist search.

## Installation

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), Python 3.11 or
newer, and a complete hashcat build with the drivers or runtimes required by your
device. From the CRUX project directory, run:

```text
uv sync --locked
uv run crux --version
uv run crux --help
```

CRUX uses the [hashcat fork's `feature/pkzip-streaming` branch](https://github.com/GusterNovar/hashcat/tree/feature/pkzip-streaming)
for large traditional PKZIP members. The fork's default `master` branch does not
contain that extension. The fork currently provides source code rather than a
binary release; cloning it alone does not install a working executable.

To place the fork in a directory CRUX can discover automatically:

```text
git clone --branch feature/pkzip-streaming --single-branch https://github.com/GusterNovar/hashcat.git .tools/hashcat
```

Build it using the fork's [build instructions](https://github.com/GusterNovar/hashcat/blob/feature/pkzip-streaming/BUILD.md)
or [Windows MSYS2 instructions](https://github.com/GusterNovar/hashcat/blob/feature/pkzip-streaming/BUILD_MSYS2.md).
On a configured Unix build environment, run `make -C .tools/hashcat`. Keep the
executable, shared libraries, `modules`, `OpenCL`, and other runtime resources
together. Mode `17240` also needs a working zlib runtime. The verified source
reference for this integration is commit `9bb795a376c9857294cfc93d1d8874945e32644a`.

An [upstream hashcat release](https://hashcat.net/hashcat/) can run the standard ZIP
modes. Upstream `7.1.2` does not include the streaming extension. CRUX reports a
missing extension before starting a search that requires it. `uv sync` installs
Python dependencies; build hashcat and install device drivers separately.

## Usage

Search a character set within an inclusive length range:

```text
uv run crux path/to/archive.zip --charset digits --min 8 --max 12
```

Search only matching entries in a wordlist:

```text
uv run crux path/to/archive.zip --wordlist passwords.txt --min 8 --max 12
```

`--charset` and `--wordlist` are mutually exclusive. Without `--wordlist`, the
defaults are `alnum` and lengths `1-5`. Wordlist mode defaults to a minimum length
of `1` and has no maximum unless `--max` is supplied.

Wordlists use UTF-8, with one password per line. CRUX accepts a BOM and Windows
line endings, preserves leading and trailing spaces, and counts characters for
length filtering. Empty lines are skipped. It streams matching entries into a
temporary file, removes that file after the run, and leaves the source wordlist
unchanged. An empty filtered wordlist produces an error.

A successful search prints `FOUND password: ...` and exits with code `0`. An
exhausted search or backend failure returns a nonzero code and displays the
corresponding status.

## Selecting hashcat

CRUX resolves hashcat in this order:

1. `--hashcat PATH`, also accepted as `--hashcat-path PATH`.
2. The `HASHCAT` environment variable.
3. An executable on `PATH`.
4. `hashcat`, `.tools/hashcat`, `.tools`, and `.tools/hashcat-*` directories under
   the current working directory, followed by the same locations under the
   project directory.

Explicit configuration accepts an executable path, a command name, or a directory
that directly contains the executable. Invalid explicit configuration raises an
error. Windows uses `hashcat.exe`; Linux and macOS use `hashcat` or `hashcat.bin`.

Select the fork explicitly on Windows:

```text
uv run crux path/to/archive.zip --charset digits --min 8 --max 12 --hashcat .tools/hashcat/hashcat.exe
```

Or set a PowerShell session environment variable:

```powershell
$env:HASHCAT = (Resolve-Path .tools/hashcat/hashcat.exe).Path
uv run crux path/to/archive.zip --wordlist passwords.txt
```

On Linux or macOS:

```sh
uv run crux path/to/archive.zip --wordlist passwords.txt --hashcat .tools/hashcat/hashcat
```

CRUX starts hashcat in the executable's directory and passes absolute input and
output paths so hashcat can load its runtime resources. When more than one
hashcat is installed, use `--hashcat` or `HASHCAT` to select the build with the
streaming extension.

## Character sets

| Name | Contents |
| --- | --- |
| `lower` | `a-z` |
| `upper` | `A-Z` |
| `digits` | `0-9` |
| `alpha` | Lowercase and uppercase letters |
| `alnum` | Lowercase letters, uppercase letters, and digits; the default |
| `symbols` | `!@#$%^&*()-_=+[]{};:,.<>/` |
| `all` | `alnum` plus the symbols above |

## Advanced options

| Option | Purpose |
| --- | --- |
| `--no-run` | Export a hash without starting or requiring hashcat |
| `--hash-file PATH` | Hash output path; defaults to `<archive>.hash` next to the ZIP |
| `--member NAME` | Select a ZIP member for hash export |
| `-w` / `--workload-profile` | Workload from `1` to `4`; the default is `2` |
| `--device LIST` | Select hashcat devices, such as `1` or `1,2` |
| `--raw-output` | Display original hashcat output |
| `--extra-arg ARG` | Append a hashcat argument; repeat as needed and use `--extra-arg=VALUE` for values beginning with `-` |
| `--version` | Print the CRUX version |

## Demo archive

`codes.zip` is a synthetic WinZip AES fixture containing only `demo/README.txt`.
Its public demonstration password is `crux-demo`.

Export its hash without installing hashcat:

```text
uv run crux codes.zip --no-run
```

For a short recovery check, create a UTF-8 `passwords.txt` containing `crux-demo`
on its own line, then run:

```text
uv run crux codes.zip --wordlist passwords.txt
```

## ZIP modes and output

CRUX selects WinZip AES `13600`, compressed PKZIP `17200`, stored PKZIP `17210`,
multi-member checksum mode `17230`, or the fork's streaming mode `17240`.
Traditional PKZIP archives with one or two members prefer the smaller supported
member. Members that exceed the native mode's `320 KiB` data buffer use the
streaming extension automatically.

A streaming hash stores at most `256` encrypted sample bytes, lengths, a CRC, and
the original archive path. GPU filtering is followed by host-side decryption,
optional DEFLATE decompression, and full CRC and length verification in chunks.
The archive must remain available at the same path and must not change during
the search. Verification buffers do not grow with the full member size; speed
still depends on candidate filtering, CPU, disk, and device performance.

CRUX displays compact progress by default and retains backend diagnostics on
failure. It reuses hashcat's potfile; an existing result prints
`already cracked (potfile)`. To force a fresh search, append
`--extra-arg=--potfile-disable`. A search writes `.hash` and, when a new result is
found, `.hash.found`. Hashcat also maintains its own cache and potfile.

These generated files are private runtime data. Hashes can include archive paths
(hex-encoded in streaming mode), results contain recovered passwords, and raw
backend output may identify devices or drivers. Review them before sharing
logs or screenshots. CRUX does not upload archive contents or recovered passwords.

## Upgrading

`1.0.0` keeps the two-mode CLI introduced in `0.3.0`. Configure your hashcat
installation with `PATH`, `HASHCAT`, `--hashcat`, or one of the portable
directories above. The demo archive now uses the password `crux-demo`.

For `0.2.0` users, replace
`crux hashcat archive.zip --charset digits --min-length 8 --max-length 12` with
`crux archive.zip --charset digits --min 8 --max 12`. The `recover` and `hashcat`
subcommands and standalone `--mask` option are no longer part of the CLI.

## Development

Source is in `src/crux` and tests are in `tests`. Run:

```text
uv sync --locked
uv run python -m pytest
```

Tests create their own ZIP archives and wordlists and mock hashcat subprocesses;
they do not require a GPU. Real device recovery should be checked separately.

## License

CRUX uses the Apache-2.0 license; see [LICENSE](LICENSE). Hashcat has its own
license in its source tree and distribution.
