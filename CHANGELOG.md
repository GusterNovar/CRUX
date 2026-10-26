# Changelog

## 1.0.0

- First stable release.
- Discover portable hashcat installations in the working directory or project
  directory, including `.tools/hashcat`.
- Support the hashcat fork's `feature/pkzip-streaming` branch and show its URL
  when a search requires mode `17240`.
- Provide a synthetic WinZip AES demo archive with the public password
  `crux-demo`.

## 0.3.0

- Add support for the companion hashcat PKZIP streaming mode `17240` for large
  members, using a bounded sample and source archive reference with chunked
  decryption, decompression, and CRC verification.
- Prefer the smaller member in traditional PKZIP archives with one or two
  members and report when the streaming extension is unavailable.
- Accept the archive path directly and use hashcat for both character set and
  wordlist searches.
- Use `--min` and `--max` for inclusive length limits; filter wordlists before
  running hashcat and remove the temporary filtered file afterward.
- Discover hashcat automatically and accept `HASHCAT`, `--hashcat`, and
  `--hashcat-path` overrides for executable paths or directories.
- Correct status handling for exhausted searches and retain backend errors.
- Read recovered passwords consistently in compact and raw output modes,
  preserving spaces and decoding potfile hexadecimal output.
- Set the default hashcat workload profile to `2`.
- Remove the `recover` and `hashcat` CLI subcommands and standalone `--mask`
  option; require a ZIP archive path.
