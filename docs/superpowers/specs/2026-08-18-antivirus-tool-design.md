# avtool — Hash-Based Antivirus Tool for macOS

Status: Approved for planning
Date: 2026-08-18

## Purpose

A CLI + background daemon that detects known-malicious files on this
laptop by comparing file hashes against a local database of known-bad
SHA256 hashes. Two modes: on-demand interactive scanning, and a
real-time filesystem watcher over user-specified directories.

This is v1 scope, deliberately narrow:
- Detection is hash-based only (no heuristics, no signature/pattern
  matching, no behavioral analysis). It will miss anything not
  byte-identical to a known-bad sample. This tradeoff was chosen
  explicitly over integrating an existing engine (ClamAV/YARA) to keep
  the first version simple and fully owned.
- Platform is macOS only (this laptop). No cross-platform support.
- No auto-remediation. Every action on a match is either explicit user
  choice (scan) or queued for later user choice (watch).

## Non-goals (v1)

- Network traffic monitoring, process behavior monitoring, kernel
  extensions/system extensions.
- Signature/pattern-based detection (YARA), ClamAV integration.
- Automatic quarantine/deletion without user confirmation.
- Multi-machine management, central reporting, remote configuration.
- Scheduling of scans (cron/launchd calendar triggers) — v1 ships the
  watcher and manual `scan` invocation only.

## Architecture

Two entry points share one core:

- **`avtool scan <path>`** — on-demand, interactive, run in a
  terminal. Walks the path, hashes files, checks against the local
  hash database, and for each match prompts the user: quarantine /
  delete / ignore / report-only.
- **`avtool watch`** — a launchd-managed daemon (no TTY available) that
  watches user-specified paths via `fsnotify`, hashes new/modified
  files as they land, and on a match cannot prompt interactively — it
  logs the detection, writes it to a review queue, and fires a macOS
  user notification. Queued detections are resolved later via
  `avtool review`, which reuses the same interactive prompt as `scan`.

This split exists because the daemon runs headless under launchd and
has no terminal to prompt against; the interactive prompt logic is
implemented once and invoked from both `scan` (immediately) and
`review` (deferred).

## Components

- **`internal/hashdb`** — SQLite-backed store of known-bad SHA256
  hashes with metadata (name/label, source, date added). Populated
  from two sources that merge into one table:
  - A manually-maintained local list (`avtool hashes add <sha256>
    <name>`, `avtool hashes list`, `avtool hashes rm <sha256>`).
  - A periodic sync job (`avtool sync`) that pulls known-malware
    hashes from a public threat intel feed (MalwareBazaar) and
    upserts them, tagging their source distinctly from manual
    entries so a manual removal isn't silently reintroduced by the
    next sync.
- **`internal/scanner`** — walks a given path, computes SHA256 for
  each regular file, checks against `hashdb`. Shared by both `scan`
  and `watch`. Skips symlinks (does not follow) and files above a
  configurable size cap to bound scan time on large files.
- **`internal/watcher`** — `fsnotify`-based watcher over the
  directories passed to `avtool watch`. Debounces write events (a file
  being written generates multiple events) before handing a settled
  file to `internal/scanner`. Directories to watch are always
  explicit — no default watch paths.
- **`internal/quarantine`** — on user choice to quarantine, moves the
  matched file to `~/Library/Application Support/avtool/quarantine/`,
  strips the execute bit, and records the original path and hash so it
  can be restored (`avtool quarantine restore <id>`) or purged.
- **`internal/detections`** — a queue (SQLite table) of watcher-found
  matches awaiting interactive review: file path, hash, matched
  signature, detected-at timestamp, resolved/unresolved state.
- **`cmd/avtool`** — Cobra-based CLI wiring the above:
  `scan`, `watch`, `review`, `sync`, `hashes add|list|rm`,
  `quarantine restore|list|purge`.

## Data flow

```
avtool sync ──► hashdb (merge: local list + feed, deduped by hash)
                   │
                   ├─ avtool scan <path> ──► scanner ──► match? ──► interactive prompt ──► quarantine/delete/ignore/report
                   │
                   └─ avtool watch ──► watcher ──► scanner ──► match? ──► detections queue + user notification
                                                                              │
                                                                     avtool review ──► same interactive prompt
```

## Storage

One SQLite database at
`~/Library/Application Support/avtool/avtool.db` containing three
tables: hash entries (hashdb), queued detections, and quarantine
records. Quarantined file bodies live as files under
`~/Library/Application Support/avtool/quarantine/`, named by their
hash; the DB row is the source of truth for original path and status.

## Detection handling flow (the prompt)

Shared by `scan` and `review`. On a match, present:

```
MATCH: <path>
  hash:   <sha256>
  known:  <name/label from hashdb>
  source: <feed|manual>

[q]uarantine  [d]elete  [i]gnore  [r]eport-only (log and move on)
```

- **quarantine**: moves file via `internal/quarantine`, marks the
  detections-queue row (if any) resolved.
- **delete**: removes the file directly (no recovery). Requires
  explicit confirmation given it's irreversible.
- **ignore**: marks resolved, takes no filesystem action. Does not add
  to an allowlist in v1 — a re-scan will match again. (An allowlist is
  a plausible v2 addition, not built now.)
- **report-only**: logs the match (path, hash, timestamp) to a
  detections log file and marks resolved.

## Sync source

`avtool sync` pulls from MalwareBazaar's public hash feed (no API key
required for the CSV recent-additions endpoint). Sync is manual
(user-invoked), not scheduled, in v1. Each synced hash is tagged
`source=feed`; manually added hashes are tagged `source=manual` and
are never overwritten or removed by sync.

## Error handling

- Unreadable files (permissions) during scan/watch: log and skip, do
  not abort the run.
- SQLite unavailable/corrupt: fail fast with a clear error on startup;
  no silent fallback to an in-memory store, since that would silently
  drop persisted hash data.
- Sync feed unreachable: `sync` reports the failure and leaves the
  existing hashdb untouched; does not clear existing entries.
- Watcher: an fsnotify error on one watched path is logged and that
  path's watch is dropped; other watched paths continue.

## Testing

- `internal/hashdb`: unit tests for merge/dedupe logic (manual vs feed
  precedence, upsert behavior).
- `internal/scanner`: matches against a fixture directory containing a
  synthetic test file with a known test hash (EICAR test string, not
  real malware) seeded into a test hashdb.
- `internal/watcher`: temp-dir test that drops files via the real
  filesystem and asserts the watcher hands settled files to the
  scanner, including debounce behavior on multi-write files.
- `internal/quarantine`: round-trip test (quarantine then restore
  reproduces original file and path).
- CLI: table-driven tests per subcommand using a temp SQLite DB,
  no network calls (sync tested against a fake/local HTTP server).

## Project layout

```
cmd/avtool/            CLI entry point (Cobra commands)
internal/hashdb/
internal/scanner/
internal/watcher/
internal/quarantine/
internal/detections/
docs/                  this spec and future docs
```

## Open items deferred past v1

- Scheduled scans (launchd calendar-interval scan job).
- Allowlist for repeated "ignore" decisions.
- Default watch paths / setup wizard.
- Alternate/additional signature feeds.
