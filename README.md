# hashcheck

A small, dependency-free command-line tool for computing and verifying file hashes — built for quick forensic triage.

- Hash a single file or an entire folder (recursively) with **MD5, SHA-1 and SHA-256** in one pass
- **Verify** a download or evidence file against an expected hash
- **Compare** a folder against a known-hash list (known-bad IOCs or a known-good baseline) and flag matches
- Export results as **CSV** or **JSON** for reports and case notes

Python 3.8+, standard library only.

## Usage

```bash
# Hash a file or a whole folder
python hashcheck.py evidence/

# Only SHA-256, as CSV
python hashcheck.py evidence/ -a sha256 -f csv -o hashes.csv

# Verify a file (algorithm is detected from the hash length)
python hashcheck.py installer.exe -v 5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03

# Flag any files that appear in a known-hash list
python hashcheck.py C:\Users\Public -k iocs.txt --matches-only
```

### Example output

```
$ python hashcheck.py samples/
samples/a.txt
  MD5     b1946ac92492d2347c6235b4d2611184
  SHA1    f572d396fae9206628714fb2ce00f72e94f2258f
  SHA256  5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03

$ python hashcheck.py samples/ -k iocs.txt --matches-only
samples/sub/b.bin  <-- MATCH (dropper.bin)
  MD5     78b9861f74e15d7d0f077ba22421b8e4
  ...
[*] 1 match(es) against 1 known hash(es).
```

## Options

| Flag | Description |
|---|---|
| `-a, --algo` | `md5`, `sha1` or `sha256` (repeatable; default: all three) |
| `-v, --verify HASH` | Verify a single file against an expected hash |
| `-k, --known FILE` | Compare against a known-hash list and flag matches |
| `--matches-only` | With `--known`, only report matching files |
| `-n, --no-recurse` | Don't descend into subfolders |
| `-f, --format` | `table` (default), `csv` or `json` |
| `-o, --output FILE` | Write CSV/JSON output to a file |

## Known-hash list format

One hash per line; MD5, SHA-1 and SHA-256 can be mixed. Lines starting with `#` are ignored.

```
# plain hash
78b9861f74e15d7d0f077ba22421b8e4
# md5sum / sha256sum output
886b67480dbe73b406ad83a1dd6d9596f93089d90c220ccfc91944c95f1c68c4  dropper.bin
# CSV with a label
fe45d304523ba62242503a06ad0e64d98df4f986,known-bad sample
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success / hash verified / no known-hash matches |
| `1` | Hash mismatch, or at least one known-hash match |
| `2` | Bad input (missing path, invalid hash, empty hash list) |

This makes it easy to use in scripts, e.g. `python hashcheck.py file -v <hash> && echo trusted`.

## Notes

MD5 and SHA-1 are included because they're still common in case files, threat-intel feeds and vendor checksums — but they're not collision-resistant. Prefer SHA-256 when you have the choice.

## License

MIT
