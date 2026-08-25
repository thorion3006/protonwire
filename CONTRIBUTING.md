# Contributing to ProtonWire

Read the specification set before changing behavior — the PRD is normative:

- `docs/PRD-proton-wire.md` — product requirements (the contract)
- `docs/ADR-0001-monorepo-core-and-clients.md` — architecture invariants
- `docs/spike-2026-08.md` — dependency decisions and MSRV evidence
- `docs/review-log.md` — every SDLC review's triage; nothing reviewed
  silently disappears, so check it before re-proposing something

## Workflow

1. **TDD is standing practice**: failing test first (run it, watch it fail
   for the right reason), then the minimal implementation, then refactor
   with the suite green.
2. Branch per coherent unit (`feat/...`, `fix/...`), commit per unit,
   conventional-commit style.
3. Each coherent unit passes the matching reviewer before it counts as
   done (rust-reviewer for Rust, sec-auditor for trust surfaces,
   qa-engineer against the PRD test plan, refactorer for structure,
   compliance-reviewer for control mapping, doc-writer for docs).
4. Findings land in `docs/review-log.md` — fixed now or tracked with a
   milestone.

## Development environment

The repository builds on any mainstream Linux distro (CI runs stock
Ubuntu); pick one of two supported paths:

**Nix devshell (recommended, reproducible)** — with direnv it activates
on entry:

```sh
direnv allow                        # core: rustc/cargo/rustfmt/clippy,
                                    # gcc, cargo-audit, git
PROTONWIRE_GUI=1 direnv allow       # + webkit2gtk stack for protonwire-gui
```

Without direnv: `nix-shell` / `nix-shell --arg gui true`. Works on any
distro where Nix is installed.

**Plain toolchain** — Rust 1.97+ (`rust-toolchain.toml` pins the version
for rustup users), a C toolchain, and for GUI work the webkit2gtk
development packages (see README for the list). No Nix required.

The shell pins the verified toolchain (rustc 1.97.1); `rust-toolchain.toml`
is inert inside it (no rustup) and only serves rustup-based contributors
and CI, which installs its own pinned toolchains. A flake-based devshell
is blocked until Nix's libgit2 supports this repository's reftable ref
storage (tracked with the M8 packaging work).

## Concurrent lanes & environment-gated tests

Concurrent lanes share one working tree; these rules keep them out of
each other's commits and test runs.

1. **Commit by pathspec, never through the shared index** — `git
   commit -m … -- <paths>` commits exactly those paths. Do NOT `git
   add -A`, and do NOT `git add <paths> && git commit` either: `git
   add` stages into the SHARED index and a plain `git commit` commits
   the entire index, so a sibling's staged hunk rides along (the round-4
   `-A` incident; the M2 index-sweep incident cb33bd2).
2. **A red test ships in the SAME commit as its fix**, never in an
   unrelated lane's commit — split staging leaves commits that are
   individually red and breaks `git bisect` (three such commits in
   round 4).
3. **Gate in a temp `git worktree` at your own commit** when the
   shared tree carries siblings' uncommitted edits, and remove the
   worktree afterwards. `direnv exec <dir> <cmd>` does NOT chdir —
   cd into the worktree first.
4. **Format scoped**: `cargo fmt -p <pkg>` from a concurrent lane;
   bare `cargo fmt --all` rewrites siblings' in-flight files.
5. **Root/userns-gated tests skip FIRST on `!getuid().is_root()`**
   (NOTICE skip), then on the user-namespace check (NOTICE skip) —
   the keep-id-sandbox false negative came from gating in the wrong
   order. The NOTICEs are invisible under bare `cargo test` (libtest
   captures per-test output); see them with `-- --nocapture` or
   `-- --show-output`, and prefer observable skip patterns where the
   skip itself matters.
6. **Label red evidence honestly in the commit message**: behavioral
   red (preferred); compile-red (disclosed as such — say what was
   removed to build it); inspection-level (disclosed, naming what was
   inspected). Wall-clock reds state their bounds and where they
   depend on kernel behavior.
7. **Reuse the seam-injection idiom** for testability — inject
   collaborators as `&dyn Fn` parameters (`bind_with_resolved`,
   `serve_observed`, the daemon's `run`) or extract a pure function
   (`checks_for`) rather than inventing per-site variants.
8. **No `git commit --amend` while lanes are active** — history is
   append-only while any concurrent lane may hold a ref to it. Twice
   in M2 an amend landed on a commit another lane had already built
   on; both repairs needed hash-pinned rewrites of everything
   downstream. If a commit must change, revert-and-recommit (or wait
   for the lane to land) — never rewrite.

## Local gates (must be green before push; run inside the devshell)

```sh
cargo fmt --all --check               # formatting
cargo clippy --all-targets -- -D warnings
cargo test                            # 29 test targets
cargo xtask all                       # parity manifest, groups, M49,
                                       # registry freshness, dep-graph,
                                       # license inventory, schema freshness
```
Toolchain floor: see `rust-toolchain.toml` and the spike record.

## Repo rules enforced by tooling

- `unsafe_code = deny` workspace-wide (the Tauri shell is the single,
  documented exception for its macro boundary).
- One root `Cargo.lock`, **committed** — it is the resolution authority
  for the pinned ProTUN/Muon engines (FR-127A). `cargo xtask dep-graph`
  fails if it is untracked; never add it to any gitignore.
- Dependency direction is machine-checked: clients never link the
  engines, core, or adapters; `clap`/`ratatui`/`tauri` never appear below
  the client boundary.
- Wire types live in `protonwire-frontend-api` only; after changing them,
  regenerate and commit `schemas/frontend/v1` (`cargo xtask schema-gen`).
- No wildcard dependency versions; new dependencies need a spike-record
  entry (stdlib-first policy).

## The GUI

`protonwire-gui` needs `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`,
`librsvg2-dev`, and `libayatana-appindicator3-dev`; it is a workspace
member but not a default member, so plain `cargo build` skips it and CI
builds it in a dedicated job.

## Distribution is blocked

Do not publish binaries or source containing the Proton registry crates
until their license terms are cleared (`COPYING.md`, PRD OQ-2).
