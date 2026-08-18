# avtool

A hash-based antivirus CLI and background watcher for macOS.

`avtool` detects known-malicious files by comparing file hashes
against a local database of known-bad SHA256 hashes, sourced from a
manually-maintained list plus a periodic sync from a public threat
intel feed (MalwareBazaar). It has two modes:

- **`avtool scan <path>`** — on-demand, interactive scan. Walks a
  path, hashes files, and on a match prompts you to quarantine,
  delete, ignore, or just report it.
- **`avtool watch`** — a background daemon that watches
  user-specified directories in real time and queues any matches for
  later review via `avtool review` (it can't prompt interactively
  since it runs headless under launchd).

Detection is intentionally hash-based only in this first version — no
heuristics, no signature/pattern matching (YARA/ClamAV), no behavioral
analysis. It will not catch anything that isn't byte-identical to a
known-bad sample. See the full design rationale and scope in
[`docs/superpowers/specs/2026-08-18-antivirus-tool-design.md`](docs/superpowers/specs/2026-08-18-antivirus-tool-design.md).

## Status

Design complete, implementation not yet started.

## Platform

macOS only.

## License

MIT — see [LICENSE](LICENSE).
